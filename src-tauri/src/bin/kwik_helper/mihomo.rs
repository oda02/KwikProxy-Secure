//! Fixed-path SYSTEM Mihomo lifecycle.
//!
//! The client supplies YAML bytes only. Executable, data, configuration and
//! log paths come from the protected installation context.

use std::ffi::c_void;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

use super::security::Installation;

const MAX_CONFIG_BYTES: usize = 1400 * 1024;
const SECURE_TUN_PREFIX: &str = "kwikproxy-secure-";
const READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const READINESS_POLL: std::time::Duration = std::time::Duration::from_millis(100);
const READINESS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

struct Job(OwnedHandle);

struct State {
    child: Child,
    pid: u32,
    /// Closing this handle terminates the process tree even if explicit stop
    /// or helper shutdown is interrupted.
    _job: Job,
    session_id: u32,
    generation: String,
    tun_device: String,
    instance_id: String,
}

pub struct StartedTunnel {
    pub tun_device: String,
    pub pid: u32,
    pub instance_id: String,
}

static STATE: Mutex<Option<State>> = Mutex::const_new(None);

pub async fn start(
    config_yaml: &str,
    allow_lan: bool,
    installation: &Installation,
    session_id: u32,
) -> Result<StartedTunnel> {
    if config_yaml.len() > MAX_CONFIG_BYTES {
        bail!("mihomo config exceeds {MAX_CONFIG_BYTES} bytes");
    }
    if config_yaml.as_bytes().contains(&0) {
        bail!("mihomo config contains NUL bytes");
    }
    let validated = validate_privileged_config(config_yaml, allow_lan)?;
    let tun_device = validated.tun_device;
    super::helper_log::log("[helper-mihomo] stage=config_validated outcome=ok code=accepted");

    let mut state = STATE.lock().await;
    if state.is_some() {
        bail!("mihomo is already running; stop it first");
    }

    let runtime_dir = installation.existing_runtime_dir()?;
    provision_protected_geofiles(installation, &runtime_dir)?;
    let config_path = runtime_dir.join("mihomo-config.yaml");
    write_config(installation, config_yaml.as_bytes())?;

    let log_file = installation.replace_runtime_file("mihomo.log")?;
    let log_clone = log_file.try_clone().context("clone mihomo log handle")?;

    let job = create_kill_on_close_job()?;
    let windows_dir = super::security::known_windows_directory()?;
    let mut cmd = Command::new(&installation.mihomo_path);
    cmd.arg("-f")
        .arg(&config_path)
        .arg("-d")
        .arg(&runtime_dir)
        .current_dir(&runtime_dir)
        .env_clear()
        .env("SystemRoot", &windows_dir)
        .env("WINDIR", &windows_dir)
        .env("TEMP", &runtime_dir)
        .env("TMP", &runtime_dir)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_clone))
        .kill_on_drop(true);

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd.spawn().context("spawn protected Mihomo")?;
    let pid = child.id().unwrap_or(0);
    let process = child
        .raw_handle()
        .ok_or_else(|| anyhow!("spawned Mihomo has no process handle"))?
        as HANDLE;
    if unsafe { AssignProcessToJobObject(job.0.as_raw_handle() as HANDLE, process) } == 0 {
        let _ = child.kill().await;
        bail!("AssignProcessToJobObject failed");
    }

    eprintln!("[helper-mihomo] started protected pid={pid}");
    if let Err(error) = wait_for_child_readiness(
        &mut child,
        validated.controller_addr,
        Some(&tun_device),
        READINESS_TIMEOUT,
    )
    .await
    {
        super::helper_log::log("[helper-mihomo] stage=readiness outcome=error code=not_ready");
        let _ = child.kill().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), child.wait()).await;
        let _ = super::tun::cleanup_owned_device(&tun_device).await;
        return Err(error);
    }
    super::helper_log::log(
        "[helper-mihomo] stage=readiness outcome=ok code=controller_and_tun_ready",
    );
    let instance_id = uuid::Uuid::new_v4().to_string();
    *state = Some(State {
        child,
        pid,
        _job: job,
        session_id,
        generation: installation.generation.clone(),
        tun_device: tun_device.clone(),
        instance_id: instance_id.clone(),
    });
    drop(state);
    spawn_exit_monitor(
        pid,
        session_id,
        installation.generation.clone(),
        tun_device.clone(),
        instance_id.clone(),
    );
    Ok(StartedTunnel {
        tun_device,
        pid,
        instance_id,
    })
}

async fn loopback_listener_ready(address: std::net::SocketAddr) -> bool {
    tokio::time::timeout(
        READINESS_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(address),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn wait_for_child_readiness(
    child: &mut Child,
    controller_addr: std::net::SocketAddr,
    expected_tun: Option<&str>,
    timeout: std::time::Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("query Mihomo readiness process")? {
            bail!("Mihomo exited before readiness with status {status}");
        }
        let controller_ready = loopback_listener_ready(controller_addr).await;
        let tun_ready = match expected_tun {
            Some(alias) => super::tun::owned_tun_interface_ready(alias).await,
            None => true,
        };
        if controller_ready && tun_ready {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("Mihomo readiness timed out after {timeout:?}");
        }
        tokio::time::sleep(READINESS_POLL).await;
    }
}

fn spawn_exit_monitor(
    pid: u32,
    session_id: u32,
    generation: String,
    tun_device: String,
    instance_id: String,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let exit_observed = {
                let mut state = STATE.lock().await;
                let Some(active) = state.as_mut() else {
                    return;
                };
                if active.pid != pid
                    || active.session_id != session_id
                    || active.generation != generation
                    || active.instance_id != instance_id
                {
                    return;
                }
                let exited = !matches!(active.child.try_wait(), Ok(None));
                if exited {
                    let _ = state.take();
                }
                exited
            };
            if !exit_observed {
                continue;
            }
            super::helper_log::log(
                "[helper-mihomo] stage=child_monitor outcome=exited code=child_exit",
            );
            if super::tun::cleanup_owned_device(&tun_device).await.is_err() {
                super::helper_log::log(
                    "[helper-mihomo] stage=orphan_cleanup outcome=error code=cleanup_failed",
                );
            }
            super::dispatch::on_tunnel_process_exit(session_id, &generation, pid, &instance_id)
                .await;
            return;
        }
    });
}

fn write_config(installation: &Installation, bytes: &[u8]) -> Result<()> {
    let mut file = installation.replace_runtime_file("mihomo-config.yaml")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn provision_protected_geofiles(
    installation: &Installation,
    _runtime_dir: &std::path::Path,
) -> Result<()> {
    for name in ["geoip.dat", "geosite.dat"] {
        // Re-open through the manifest-bound no-follow verifier on every
        // tunnel start. A size-only or path-only check is never trusted.
        let mut input = match name {
            "geoip.dat" => installation.open_verified_geoip()?,
            "geosite.dat" => installation.open_verified_geosite()?,
            _ => unreachable!(),
        };
        let mut output = installation.replace_runtime_file(name)?;
        let mut source_hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            source_hash.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        output.sync_all()?;
        output.seek(SeekFrom::Start(0))?;
        let mut actual_hash = Sha256::new();
        loop {
            let read = output.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            actual_hash.update(&buffer[..read]);
        }
        if source_hash.finalize().as_slice() != actual_hash.finalize().as_slice() {
            bail!("protected geofile content verification failed: {name}");
        }
    }
    Ok(())
}

fn create_kill_on_close_job() -> Result<Job> {
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle.is_null() {
        bail!("CreateJobObjectW failed");
    }
    // SAFETY: CreateJobObjectW returned a fresh owned job HANDLE.
    let job = Job(unsafe { OwnedHandle::from_raw_handle(handle) });
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.0.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        bail!("SetInformationJobObject failed");
    }
    Ok(job)
}

/// Defense in depth at the privileged sink. The normal config sanitizer runs
/// in the application, but these settings must never reach a SYSTEM network
/// engine even if a future caller regresses.
struct ValidatedConfig {
    tun_device: String,
    controller_addr: std::net::SocketAddr,
}

fn validate_privileged_config(yaml: &str, allow_lan: bool) -> Result<ValidatedConfig> {
    let value: Value = serde_yaml::from_str(yaml).context("parse Mihomo YAML")?;
    let root = value
        .as_mapping()
        .ok_or_else(|| anyhow!("Mihomo config root must be a mapping"))?;

    for forbidden in [
        "listeners",
        "inbounds",
        "tunnels",
        "script",
        "external-ui",
        "external-ui-url",
        "external-controller-pipe",
        "external-controller-unix",
        "external-controller-cors",
        "geox-url",
        // Mihomo shortcut server inbounds. These would expose privileged
        // listeners even though the general listeners/inbounds keys are off.
        "ss-config",
        "vmess-config",
        "tuic-server",
    ] {
        if has_key(root, forbidden) {
            bail!("privileged Mihomo config forbids `{forbidden}`");
        }
    }

    let controller = string_value(root, "external-controller")
        .ok_or_else(|| anyhow!("external-controller must be explicitly configured"))?;
    let controller_addr = controller
        .parse::<std::net::SocketAddr>()
        .context("external-controller must be a numeric loopback socket")?;
    if !controller_addr.ip().is_loopback() || controller_addr.port() == 0 {
        bail!("external-controller must bind loopback only");
    }
    let secret = string_value(root, "secret").unwrap_or_default();
    if secret.is_empty() || secret.len() > 256 {
        bail!("external-controller requires a bounded non-empty secret");
    }

    let config_allows_lan = root
        .get(&key("allow-lan"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if config_allows_lan != allow_lan {
        bail!("config LAN exposure does not match the explicit request");
    }
    let bind = string_value(root, "bind-address").unwrap_or("127.0.0.1");
    if !allow_lan && bind != "127.0.0.1" && bind != "::1" && bind != "localhost" {
        bail!("non-LAN tunnel must bind proxy listeners to loopback");
    }

    if let Some(dns) = mapping_value(root, "dns") {
        if let Some(listen) = string_value(dns, "listen") {
            if !listen.is_empty()
                && listen != "0.0.0.0:0"
                && !listen.starts_with("127.0.0.1:")
                && !listen.starts_with("[::1]:")
                && !listen.starts_with("198.18.0.1:")
            {
                bail!("DNS listener must bind loopback or the fixed TUN gateway");
            }
        }
    }
    let tun = mapping_value(root, "tun")
        .ok_or_else(|| anyhow!("privileged tunnel requires an explicit tun mapping"))?;
    if tun.get(&key("enable")).and_then(Value::as_bool) != Some(true) {
        bail!("privileged tunnel requires tun.enable=true");
    }
    let device = string_value(tun, "device")
        .ok_or_else(|| anyhow!("privileged tunnel requires an owned tun.device"))?;
    if !device.starts_with(SECURE_TUN_PREFIX)
        || device.len() > 96
        || !device
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("tun.device must use the reserved KwikProxy Secure prefix");
    }
    validate_provider_paths(root, "proxy-providers")?;
    validate_provider_paths(root, "rule-providers")?;
    Ok(ValidatedConfig {
        tun_device: device.to_string(),
        controller_addr,
    })
}

fn key(name: &str) -> Value {
    Value::String(name.to_string())
}

fn has_key(map: &Mapping, name: &str) -> bool {
    map.contains_key(&key(name))
}

fn string_value<'a>(map: &'a Mapping, name: &str) -> Option<&'a str> {
    map.get(&key(name)).and_then(Value::as_str)
}

fn mapping_value<'a>(map: &'a Mapping, name: &str) -> Option<&'a Mapping> {
    map.get(&key(name)).and_then(Value::as_mapping)
}

fn validate_provider_paths(root: &Mapping, section: &str) -> Result<()> {
    let Some(providers) = mapping_value(root, section) else {
        return Ok(());
    };
    for (_, provider) in providers {
        let Some(provider) = provider.as_mapping() else {
            bail!("{section} entries must be mappings");
        };
        if let Some(path) = string_value(provider, "path") {
            let path = Path::new(path);
            if path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                bail!("{section} provider path must stay relative to runtime data");
            }
        }
        if let Some(url) = string_value(provider, "url") {
            if !url.starts_with("https://") {
                bail!("{section} provider URL must use HTTPS");
            }
        }
    }
    Ok(())
}

pub async fn stop() -> Result<()> {
    let mut state = STATE.lock().await;
    let Some(mut state_value) = state.take() else {
        return Ok(());
    };
    eprintln!("[helper-mihomo] kill pid={}", state_value.pid);
    if let Err(error) = state_value.child.kill().await {
        eprintln!("[helper-mihomo] kill failed: {error}");
    }
    match tokio::time::timeout(std::time::Duration::from_secs(3), state_value.child.wait()).await {
        Ok(Ok(status)) => eprintln!("[helper-mihomo] exited with {status}"),
        Ok(Err(error)) => eprintln!("[helper-mihomo] wait failed: {error}"),
        Err(_) => return Err(anyhow!("mihomo did not stop within 3 seconds")),
    }
    Ok(())
}

pub async fn stop_owned(session_id: u32, generation: &str) -> Result<()> {
    {
        let state = STATE.lock().await;
        if let Some(active) = state.as_ref() {
            if active.session_id != session_id || active.generation != generation {
                bail!("Mihomo belongs to another session or install generation");
            }
        }
    }
    stop().await
}

#[allow(dead_code)]
pub async fn is_running() -> bool {
    let mut state = STATE.lock().await;
    state
        .as_mut()
        .is_some_and(|active| matches!(active.child.try_wait(), Ok(None)))
}

#[allow(dead_code)]
pub async fn active_owner() -> Option<(u32, String, String)> {
    STATE.lock().await.as_ref().map(|state| {
        (
            state.session_id,
            state.generation.clone(),
            state.tun_device.clone(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE: &str = r#"
external-controller: 127.0.0.1:9090
secret: strong-random-secret
allow-lan: false
bind-address: 127.0.0.1
tun:
  enable: true
  device: kwikproxy-secure-0123456789abcdef
proxy-providers:
  main:
    type: http
    url: https://example.invalid/sub
    path: providers/main.yaml
"#;

    #[test]
    fn accepts_bounded_loopback_config() {
        validate_privileged_config(SAFE, false).unwrap();
    }

    #[test]
    fn rejects_external_listener_and_path_escape() {
        assert!(validate_privileged_config(&format!("{SAFE}\nlisteners: []"), false).is_err());
        assert!(validate_privileged_config(
            &SAFE.replace("providers/main.yaml", "../../evil"),
            false
        )
        .is_err());
    }

    #[test]
    fn rejects_non_https_provider_and_public_controller() {
        assert!(validate_privileged_config(&SAFE.replace("https://", "http://"), false).is_err());
        assert!(validate_privileged_config(&SAFE.replace("127.0.0.1", "0.0.0.0"), false).is_err());
    }

    #[test]
    fn lan_exposure_requires_explicit_match() {
        let lan = SAFE
            .replace("allow-lan: false", "allow-lan: true")
            .replace("bind-address: 127.0.0.1", "bind-address: 0.0.0.0");
        assert!(validate_privileged_config(&lan, false).is_err());
        validate_privileged_config(&lan, true).unwrap();
    }

    #[test]
    fn rejects_unowned_tun_device_identity() {
        assert!(validate_privileged_config(
            &SAFE.replace("kwikproxy-secure-0123456789abcdef", "kwik-1234"),
            false
        )
        .is_err());
        assert!(validate_privileged_config(
            &SAFE.replace("kwikproxy-secure-0123456789abcdef", "Ethernet 7"),
            false
        )
        .is_err());
    }

    #[test]
    fn rejects_all_shortcut_server_inbounds() {
        for key in ["ss-config", "vmess-config", "tuic-server"] {
            let injected = format!("{SAFE}\n{key}: {{listen: 0.0.0.0, port: 443}}");
            assert!(
                validate_privileged_config(&injected, false).is_err(),
                "shortcut inbound {key} must be rejected"
            );
        }
    }

    fn unused_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[tokio::test(flavor = "current_thread")]
    async fn immediate_child_exit_fails_readiness() {
        let mut child = tokio::process::Command::new("cmd.exe")
            .args(["/C", "exit 23"])
            .spawn()
            .unwrap();
        let error = wait_for_child_readiness(
            &mut child,
            ([127, 0, 0, 1], unused_loopback_port()).into(),
            None,
            std::time::Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("exited before readiness"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn readiness_timeout_is_bounded() {
        let mut child = tokio::process::Command::new("cmd.exe")
            .args(["/C", "ping -n 10 127.0.0.1 >NUL"])
            .spawn()
            .unwrap();
        let error = wait_for_child_readiness(
            &mut child,
            ([127, 0, 0, 1], unused_loopback_port()).into(),
            None,
            std::time::Duration::from_millis(250),
        )
        .await
        .unwrap_err();
        let _ = child.kill().await;
        let _ = child.wait().await;
        assert!(error.to_string().contains("timed out"));
    }
}
