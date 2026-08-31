//! Регистрация Windows-сервиса через Service Control Manager.
//!
//! `install` — добавляет сервис, ставит автозапуск, сразу стартует.
//! `uninstall` — останавливает и удаляет.
//! `service_main` — точка входа, которую SCM вызывает при старте сервиса.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

use super::pipe;
use super::protocol::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};
use super::security;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const PRODUCT_DIRECTORY: &str = "KwikProxy Secure";
const HELPER_FILENAME: &str = "kwik-helper-x86_64-pc-windows-msvc.exe";
const UI_FILENAME: &str = "vpn-client.exe";
// Tauri 2 resolves the target-suffixed externalBin source at build time and
// deliberately strips the target triple when it copies the installed sidecar.
const MIHOMO_FILENAME: &str = "mihomo.exe";
const WINTUN_FILENAME: &str = "wintun.dll";
const GEOIP_RELATIVE_PATH: &str = r"resources\geoip.dat";
const GEOSITE_RELATIVE_PATH: &str = r"resources\geosite.dat";
const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
const SERVICE_STATE_TIMEOUT: Duration = Duration::from_secs(40);
const SERVICE_DELETE_TIMEOUT: Duration = Duration::from_secs(15);
const STARTUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(25);
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(35);
const SHUTDOWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
const SERVICE_SPECIFIC_RUNTIME_FAILURE: u32 = 1;
const MAX_STARTUP_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Debug)]
struct InstalledPaths {
    install_dir: PathBuf,
    ui_path: PathBuf,
    helper_path: PathBuf,
    mihomo_path: PathBuf,
    wintun_path: PathBuf,
    geoip_path: PathBuf,
    geosite_path: PathBuf,
}

fn normalized(path: &Path) -> String {
    path.as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
}

fn require_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_file() {
        bail!(
            "{label} is missing from protected install layout: {}",
            path.display()
        );
    }
    std::fs::canonicalize(path).with_context(|| format!("canonicalize {label}"))
}

fn protected_install_dir() -> Result<PathBuf> {
    let program_files = std::fs::canonicalize(security::known_program_files()?)
        .context("canonicalize Program Files")?;
    let expected_dir = program_files.join(PRODUCT_DIRECTORY);
    std::fs::canonicalize(&expected_dir).with_context(|| {
        format!(
            "KwikProxy Secure must be installed per-machine at {}",
            expected_dir.display()
        )
    })
}

/// Validate just the helper's fixed protected location. Uninstall/repair must
/// remain possible when other product files are damaged or missing.
fn validate_helper_location() -> Result<(PathBuf, PathBuf)> {
    let install_dir = protected_install_dir()?;
    let helper_path = require_regular_file(&std::env::current_exe()?, "helper")?;
    if normalized(&helper_path) != normalized(&install_dir.join(HELPER_FILENAME)) {
        bail!(
            "service registration is installer-only; helper must be {}",
            install_dir.join(HELPER_FILENAME).display()
        );
    }
    Ok((install_dir, helper_path))
}

/// Accept service installation only from the complete per-machine bundle.
/// Canonicalization rejects helper/UI/Mihomo junctions that escape Program Files.
fn validate_installed_layout() -> Result<InstalledPaths> {
    let (install_dir, helper_path) = validate_helper_location()?;

    let ui_path = require_regular_file(&install_dir.join(UI_FILENAME), "desktop executable")?;
    let mihomo_path = require_regular_file(&install_dir.join(MIHOMO_FILENAME), "Mihomo")?;
    let wintun_path = require_regular_file(&install_dir.join(WINTUN_FILENAME), "WinTUN")?;
    let geoip_path = require_regular_file(&install_dir.join(GEOIP_RELATIVE_PATH), "GeoIP")?;
    let geosite_path = require_regular_file(&install_dir.join(GEOSITE_RELATIVE_PATH), "GeoSite")?;
    let install_dir_normalized = normalized(&install_dir);
    for (label, path) in [
        ("desktop executable", &ui_path),
        ("Mihomo", &mihomo_path),
        ("WinTUN", &wintun_path),
    ] {
        if path.parent().map(normalized).as_deref() != Some(install_dir_normalized.as_str()) {
            bail!("{label} resolves outside the protected install directory");
        }
    }
    let resource_dir = normalized(&install_dir.join("resources"));
    for (label, path) in [("GeoIP", &geoip_path), ("GeoSite", &geosite_path)] {
        if path.parent().map(normalized).as_deref() != Some(resource_dir.as_str()) {
            bail!("{label} resolves outside the protected resources directory");
        }
    }

    Ok(InstalledPaths {
        install_dir,
        ui_path,
        helper_path,
        mihomo_path,
        wintun_path,
        geoip_path,
        geosite_path,
    })
}

fn valid_sid_text(value: &str) -> bool {
    value.len() >= 5
        && value.len() <= 184
        && value.starts_with("S-1-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
}

/// Installer-owned HKLM manifest consumed by the service at startup.
/// Every clean install enrolls the Explorer shell owner in the same interactive
/// session and creates a fresh generation UUID. Neither value is inherited from
/// stale state, and the elevated token is never treated as the initiating user.
fn write_install_manifest(paths: &InstalledPaths) -> Result<()> {
    let owner_sid = security::interactive_shell_user_sid()
        .context("enroll the initiating interactive desktop SID")?;
    if !valid_sid_text(&owner_sid) {
        bail!("initiating interactive desktop returned an invalid SID");
    }
    security::provision_install_manifest(
        &owner_sid,
        &paths.install_dir,
        &paths.ui_path,
        &paths.helper_path,
        &paths.mihomo_path,
        &paths.wintun_path,
        &paths.geoip_path,
        &paths.geosite_path,
    )
    .context("write and verify protected atomic install manifest")
}

#[cfg(test)]
mod tests {
    use super::{
        normalized, valid_sid_text, GEOIP_RELATIVE_PATH, GEOSITE_RELATIVE_PATH, HELPER_FILENAME,
        MIHOMO_FILENAME, UI_FILENAME, WINTUN_FILENAME,
    };
    use std::path::Path;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_service::service::ServiceState;

    #[test]
    fn validates_owner_sid_shape() {
        assert!(valid_sid_text("S-1-5-21-123-456-789-1001"));
        assert!(!valid_sid_text("S-1-5-21-123\\..\\evil"));
        assert!(!valid_sid_text("BA"));
    }

    #[test]
    fn normalizes_windows_paths_for_canonical_comparison() {
        assert_eq!(
            normalized(Path::new(r"C:\Program Files\KwikProxy Secure")),
            normalized(Path::new(r"c:/program files/kwikproxy secure"))
        );
    }

    #[test]
    fn installed_bundle_names_match_tauri_two_layout() {
        assert_eq!(UI_FILENAME, "vpn-client.exe");
        assert_eq!(HELPER_FILENAME, "kwik-helper-x86_64-pc-windows-msvc.exe");
        assert_eq!(MIHOMO_FILENAME, "mihomo.exe");
        assert_eq!(WINTUN_FILENAME, "wintun.dll");
        assert_eq!(GEOIP_RELATIVE_PATH, r"resources\geoip.dat");
        assert_eq!(GEOSITE_RELATIVE_PATH, r"resources\geosite.dat");
    }

    #[test]
    fn waits_out_uncontrollable_pending_states() {
        assert!(super::is_uncontrollable_pending(ServiceState::StartPending));
        assert!(super::is_uncontrollable_pending(
            ServiceState::ContinuePending
        ));
        assert!(super::is_uncontrollable_pending(ServiceState::PausePending));
        assert!(!super::is_uncontrollable_pending(ServiceState::Running));
        assert!(!super::is_uncontrollable_pending(ServiceState::StopPending));
    }

    #[test]
    fn stop_timeout_covers_rpc_drain_and_cleanup() {
        assert!(
            super::SERVICE_STOP_TIMEOUT
                >= super::pipe::RPC_DRAIN_TIMEOUT + super::SHUTDOWN_CLEANUP_TIMEOUT
        );
        assert!(super::SERVICE_STATE_TIMEOUT >= super::SERVICE_STOP_TIMEOUT);
    }

    #[test]
    fn entered_current_thread_runtime_allows_sync_named_pipe_creation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let pipe_name = format!(
            r"\\.\pipe\KwikProxySecure.RuntimeContextTest.{}",
            std::process::id()
        );

        let pipe = super::with_runtime_entered(&runtime, || {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
        })
        .expect("named pipe must bind while the current-thread runtime is entered");

        drop(pipe);
    }
}

// ─── install / uninstall ──────────────────────────────────────────────────────

fn service_registry_exists(name: &str) -> bool {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"{SERVICES_KEY}\{name}"))
        .is_ok()
}

fn wait_for_service_deletion(reuse_mgr: &ServiceManager, name: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + SERVICE_DELETE_TIMEOUT;
    loop {
        let scm_visible = reuse_mgr
            .open_service(name, ServiceAccess::QUERY_STATUS)
            .is_ok();
        let registry_visible = service_registry_exists(name);
        if !scm_visible && !registry_visible {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "protected service deletion did not settle within {SERVICE_DELETE_TIMEOUT:?} \
                 (scm_visible={scm_visible}, registry_visible={registry_visible})"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn is_uncontrollable_pending(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::StartPending | ServiceState::ContinuePending | ServiceState::PausePending
    )
}

/// Stop and remove only this product's service, with bounded state polling.
/// Absence is idempotent; access errors and stuck states fail closed.
fn stop_and_delete_service(reuse_mgr: &ServiceManager, name: &str) -> Result<()> {
    let existing = match reuse_mgr.open_service(
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(_error) if !service_registry_exists(name) => return Ok(()),
        // A service already marked for deletion can reject OpenService while
        // its SCM/database entry still exists. Poll that state to completion;
        // access-denied/corrupt states remain visible and time out fail-closed.
        Err(_error) => return wait_for_service_deletion(reuse_mgr, name),
    };

    let deadline = std::time::Instant::now() + SERVICE_STATE_TIMEOUT;
    let status = loop {
        let status = existing
            .query_status()
            .context("query protected service state")?;
        match status.current_state {
            state if is_uncontrollable_pending(state) => {
                if std::time::Instant::now() >= deadline {
                    bail!("protected service remained pending for {SERVICE_STATE_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            _ => break status,
        }
    };
    if status.current_state != ServiceState::Stopped
        && status.current_state != ServiceState::StopPending
    {
        existing.stop().context("request protected service stop")?;
    }
    if status.current_state != ServiceState::Stopped {
        let deadline = std::time::Instant::now() + SERVICE_STATE_TIMEOUT;
        loop {
            let state = existing
                .query_status()
                .context("poll protected service stop")?
                .current_state;
            if state == ServiceState::Stopped {
                break;
            }
            if std::time::Instant::now() >= deadline {
                bail!("protected service did not stop within {SERVICE_STATE_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    existing.delete().context("delete protected service")?;
    drop(existing);

    wait_for_service_deletion(reuse_mgr, name)
}

pub fn install() -> Result<()> {
    let installed_paths = validate_installed_layout()?;
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("не удалось открыть Service Control Manager (нужны admin-права)")?;

    // Clean-install-only security preview: never tear down a known-good
    // service from the install path. Transactional staging/rollback must be
    // implemented before in-place upgrades are enabled.
    if service_registry_exists(SERVICE_NAME)
        || service_manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .is_ok()
    {
        bail!("in-place helper upgrade is disabled; uninstall the existing service first");
    }
    write_install_manifest(&installed_paths)?;
    let installation = security::Installation::load()
        .context("validate the completed protected installation manifest")?;
    security::provision_runtime_dir(&installation)
        .context("provision protected per-owner runtime directory")?;

    let exe_path = installed_paths.helper_path;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        // SCM вызывает `kwik-helper.exe service` — флаг для main-а.
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // SYSTEM
        account_password: None,
    };

    let service = service_manager
        .create_service(
            &service_info,
            ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::DELETE
                | ServiceAccess::QUERY_STATUS,
        )
        .context("не удалось создать сервис")?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .context("не удалось установить описание сервиса")?;

    // 13.D шаг E: failure actions — Windows SCM сам перезапускает helper
    // при крахе. Три попытки с возрастающими задержками, после успешного
    // запуска счётчик неудач сбрасывается через сутки. Без этого, если
    // helper упал, пользователю пришлось бы вручную его перезапускать.
    //
    let failure_actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(1),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(3),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
        ]),
    };
    service
        .update_failure_actions(failure_actions)
        .context("не удалось задать failure actions")?;

    service
        .start(&[] as &[&str])
        .context("не удалось запустить сервис")?;

    let deadline = std::time::Instant::now() + SERVICE_START_TIMEOUT;
    loop {
        let status = service
            .query_status()
            .context("poll protected service start")?;
        if status.current_state == ServiceState::Running {
            break;
        }
        if status.current_state == ServiceState::Stopped {
            let diagnostic = super::helper_log::recent(MAX_STARTUP_DIAGNOSTIC_BYTES)
                .unwrap_or_else(|| "protected startup diagnostic unavailable".to_string());
            bail!(
                "protected service stopped during startup ({:?}): {diagnostic}",
                status.exit_code
            );
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "protected service did not reach Running within {SERVICE_START_TIMEOUT:?} \
                 (last_state={:?}, exit={:?})",
                status.current_state,
                status.exit_code
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    println!("сервис «{SERVICE_NAME}» установлен и запущен");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    validate_helper_location()?;
    // Load before service removal while the protected manifest still exists.
    // A damaged/missing manifest must not prevent repair/uninstall of SCM state.
    let installation = security::Installation::load().ok();
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("не удалось открыть Service Control Manager (нужны admin-права)")?;
    stop_and_delete_service(&service_manager, SERVICE_NAME)?;
    let mut exact_cleanup_succeeded = false;
    if let Some(installation) = installation.as_ref() {
        // SCM deletion is the authoritative uninstall result. Runtime cleanup
        // remains tightly scoped and no-follow, but a missing/corrupt marker
        // or damaged data file must not resurrect/brick the deleted service.
        match security::cleanup_runtime_after_uninstall(installation) {
            Ok(()) => exact_cleanup_succeeded = true,
            Err(error) => {
                eprintln!("[uninstall] exact protected runtime cleanup incomplete: {error:#}")
            }
        }
    }
    if !exact_cleanup_succeeded {
        if let Err(error) = security::cleanup_product_runtime_after_uninstall() {
            eprintln!("[uninstall] bounded corrupt-manifest cleanup incomplete: {error:#}");
        }
    }
    println!("сервис «{SERVICE_NAME}» удалён");
    Ok(())
}

// ─── service entry-point ──────────────────────────────────────────────────────

define_windows_service!(ffi_service_main, my_service_main);

/// Запустить процесс как сервис (вызывается из main-а если args[1] == "service").
/// SCM вызовет ffi_service_main → my_service_main.
pub fn run_as_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow!("service_dispatcher::start: {e}"))
}

/// Тело сервиса. Вызывается SCM. Запускает tokio runtime + named pipe сервер.
fn my_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = service_loop() {
        eprintln!("[helper-service] фатальная ошибка: {e:#}");
    }
}

fn with_runtime_entered<T>(runtime: &tokio::runtime::Runtime, operation: impl FnOnce() -> T) -> T {
    let _runtime_guard = runtime.enter();
    operation()
}

fn service_loop() -> Result<()> {
    // Флаг shutdown, который выставит SCM при ServiceControl::Stop
    let shutdown = Arc::new(AtomicBool::new(false));
    let status_slot: Arc<StdMutex<Option<service_control_handler::ServiceStatusHandle>>> =
        Arc::new(StdMutex::new(None));

    let shutdown_for_handler = shutdown.clone();
    let status_for_handler = status_slot.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_for_handler.store(true, Ordering::SeqCst);
                if let Ok(slot) = status_for_handler.lock() {
                    if let Some(handle) = *slot {
                        let _ = handle.set_service_status(ServiceStatus {
                            service_type: SERVICE_TYPE,
                            current_state: ServiceState::StopPending,
                            controls_accepted: ServiceControlAccept::empty(),
                            exit_code: ServiceExitCode::Win32(0),
                            checkpoint: 1,
                            wait_hint: SERVICE_STOP_TIMEOUT,
                            process_id: None,
                        });
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    *status_slot
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(status_handle);

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: SERVICE_START_TIMEOUT,
        process_id: None,
    })?;

    let service_result = (|| -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("не удалось создать tokio runtime")?;

        let cleanup_result = rt.block_on(async {
            tokio::time::timeout(STARTUP_CLEANUP_TIMEOUT, async {
                super::firewall::cleanup_on_startup()
                    .await
                    .context("startup WFP cleanup")?;
                super::tun::cleanup_orphan_resources()
                    .await
                    .context("startup exact-prefix TUN cleanup")?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("bounded startup network cleanup timed out")??;
            Ok::<(), anyhow::Error>(())
        });
        if let Err(error) = cleanup_result {
            // A timed-out spawn_blocking cleanup is never allowed to race a
            // live tunnel. Stop the runtime promptly and fail startup before
            // pipe publication instead of proceeding in the background.
            rt.shutdown_timeout(Duration::from_secs(2));
            return Err(error);
        }
        if shutdown.load(Ordering::SeqCst) {
            return Err(anyhow!("service stop requested during startup cleanup"));
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 2,
            wait_hint: SERVICE_START_TIMEOUT,
            process_id: None,
        })?;
        // NamedPipeServer construction registers its handle with Tokio's I/O
        // driver even though the constructor itself is synchronous. block_on
        // exits the runtime context after startup cleanup, so enter it again
        // for this constructor and drop the guard before the next block_on.
        let prepared = with_runtime_entered(&rt, pipe::prepare_pipe_server)
            .context("manifest/runtime/pipe readiness checks failed")?;
        if shutdown.load(Ordering::SeqCst) {
            return Err(anyhow!("service stop requested before pipe publication"));
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let pipe_result =
            rt.block_on(async { pipe::run_prepared_pipe_server(prepared, shutdown.clone()).await });

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 2,
            wait_hint: SHUTDOWN_CLEANUP_TIMEOUT,
            process_id: None,
        })?;
        let cleanup_result = rt.block_on(async {
            tokio::time::timeout(
                SHUTDOWN_CLEANUP_TIMEOUT,
                super::dispatch::shutdown_cleanup(),
            )
            .await
            .context("service shutdown cleanup timed out")?
        });
        rt.shutdown_timeout(Duration::from_secs(2));
        pipe_result.context("pipe accept/drain failed")?;
        cleanup_result.context("privileged shutdown transaction failed")
    })();

    // Persist the precise error in the ACL-protected runtime before reporting
    // Stopped. The installing parent can then include it in its captured error
    // chain before rollback removes the runtime leaf.
    let exit_code = match &service_result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(error) => {
            super::helper_log::log(&format!("[helper-service] fatal error: {error:#}"));
            ServiceExitCode::ServiceSpecific(SERVICE_SPECIFIC_RUNTIME_FAILURE)
        }
    };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    service_result
}
