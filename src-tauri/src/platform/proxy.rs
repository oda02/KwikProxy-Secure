//! Управление системным прокси Windows через реестр.
//!
//! Устанавливает SOCKS5 + HTTP proxy в Internet Settings текущего пользователя.
//! Bypass включает localhost, 127.*, LAN-диапазоны и <local> (имена без точки).
//!
//! Backup/restore (9.D): перед перезаписью значений мы сохраняем оригиналы
//! `ProxyEnable` / `ProxyServer` / `ProxyOverride` в JSON-файл
//! `%LOCALAPPDATA%\KwikProxy Secure\proxy_backup.json`. Restore requires the
//! exact attempt token. An exact saved-original state is accepted as an
//! idempotent success; an unrelated state is preserved and releases the local
//! listener only when WinINet no longer points at our published endpoint. This
//! makes interrupted per-field restore retryable without granting authority
//! over foreign changes. Если приложение
//! крашнется в режиме proxy и не успеет очистить — на старте next-run-а мы
//! детектим backup-файл и предлагаем пользователю восстановить.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[cfg(windows)]
use winreg::types::FromRegValue;
#[cfg(windows)]
use winreg::{enums::*, RegKey};

#[cfg(windows)]
const INET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

const BACKUP_DIR: &str = "KwikProxy Secure";
const BACKUP_FILE: &str = "proxy_backup.json";
pub const MANUAL_RESTORE_REQUIRED_CODE: &str = "proxy_restore_confirmation_required";
static RESTORE_MUTEX: Mutex<()> = Mutex::new(());
const KWIK_PROXY_OVERRIDE: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;\
172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;\
172.29.*;172.30.*;172.31.*;192.168.*;<local>";

fn exact_write_set_matches(
    expected_server: &str,
    expected_override: &str,
    proxy_enable: Option<u32>,
    proxy_server: Option<&str>,
    proxy_override: Option<&str>,
) -> bool {
    !expected_server.is_empty()
        && !expected_override.is_empty()
        && proxy_enable == Some(1)
        && proxy_server == Some(expected_server)
        && proxy_override == Some(expected_override)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailedPublicationField {
    AlreadyOriginal,
    RestoreOwnedValue,
    ForeignConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestorePlan {
    /// Another VPN (or a previous retry) already restored the exact snapshot.
    AlreadyOriginal,
    /// Every changed field is still either our publication or its original,
    /// so field-wise compare-before-write recovery is safe.
    RestoreOwnedFields,
    /// A foreign state replaced our endpoint. Never overwrite it; merely
    /// release the stale ownership marker so the local listener can stop.
    PreserveForeignState,
    /// Foreign fields exist but WinINet is still actively using our endpoint.
    /// Stopping the listener would strand clients on a dead loopback proxy.
    ManualResolutionRequired,
}

fn classify_failed_publication_field<T: PartialEq>(
    current: &Option<T>,
    original: &Option<T>,
    published: &Option<T>,
) -> FailedPublicationField {
    if current == original {
        FailedPublicationField::AlreadyOriginal
    } else if current == published {
        FailedPublicationField::RestoreOwnedValue
    } else {
        FailedPublicationField::ForeignConflict
    }
}

fn exact_proxy_state_matches(left: &ProxyBackup, right: &ProxyBackup) -> bool {
    left.proxy_enable == right.proxy_enable
        && left.proxy_server == right.proxy_server
        && left.proxy_override == right.proxy_override
}

fn points_to_published_endpoint(current: &ProxyBackup, backup: &ProxyBackup) -> bool {
    current.proxy_enable == Some(1)
        && current.proxy_server.as_deref().is_some_and(|current| {
            backup
                .published_proxy_server
                .as_deref()
                .is_some_and(|published| proxy_strings_share_owned_loopback(current, published))
        })
}

/// Return loopback ports referenced by a WinINet `ProxyServer` string.
///
/// WinINet accepts either one endpoint (`host:port`) or a semicolon-separated
/// protocol map (`http=host:port;https=host:port`). Other VPN clients commonly
/// reorder the map, change protocol-name case, or add spaces. This parser is
/// deliberately conservative: it is used only to decide whether our local
/// listener must remain alive, never as authority to overwrite registry data.
fn loopback_ports(proxy_server: &str) -> Vec<u16> {
    proxy_server
        .split(';')
        .filter_map(|component| {
            let endpoint = component
                .split_once('=')
                .map_or(component, |(_, endpoint)| endpoint)
                .trim();
            let endpoint = endpoint
                .split_once("://")
                .filter(|(scheme, _)| {
                    matches!(
                        scheme.to_ascii_lowercase().as_str(),
                        "http" | "https" | "socks" | "socks5"
                    )
                })
                .map_or(endpoint, |(_, endpoint)| endpoint)
                .trim_end_matches('/');
            let (host, port) = endpoint.rsplit_once(':')?;
            let host = host.trim().trim_start_matches('[').trim_end_matches(']');
            let is_loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            is_loopback
                .then(|| port.trim().parse::<u16>().ok())
                .flatten()
        })
        .collect()
}

fn proxy_strings_share_owned_loopback(current: &str, published: &str) -> bool {
    let owned = loopback_ports(published);
    !owned.is_empty()
        && loopback_ports(current)
            .into_iter()
            .any(|port| owned.contains(&port))
}

fn plan_restore(current: &ProxyBackup, backup: &ProxyBackup) -> RestorePlan {
    if exact_proxy_state_matches(current, backup) {
        return RestorePlan::AlreadyOriginal;
    }

    let published_enable = Some(1u32);
    let actions = [
        classify_failed_publication_field(
            &current.proxy_enable,
            &backup.proxy_enable,
            &published_enable,
        ),
        classify_failed_publication_field(
            &current.proxy_server,
            &backup.proxy_server,
            &backup.published_proxy_server,
        ),
        classify_failed_publication_field(
            &current.proxy_override,
            &backup.proxy_override,
            &backup.published_proxy_override,
        ),
    ];
    if !actions.contains(&FailedPublicationField::ForeignConflict) {
        RestorePlan::RestoreOwnedFields
    } else if points_to_published_endpoint(current, backup) {
        RestorePlan::ManualResolutionRequired
    } else {
        RestorePlan::PreserveForeignState
    }
}

fn exact_attempt_matches(backup: &ProxyBackup, attempt_id: &str) -> bool {
    !attempt_id.is_empty()
        && backup
            .attempt_id
            .as_deref()
            .is_some_and(|owner| !owner.is_empty() && owner == attempt_id)
}

/// Снимок настроек системного прокси для backup/restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBackup {
    /// Unique connect attempt that created this backup. Legacy backups have
    /// no owner and are intentionally not restorable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    /// Exact value published by this attempt. Rollback refuses to overwrite
    /// registry state if another application changed it in the meantime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_proxy_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_proxy_override: Option<String>,
    /// Значение `ProxyEnable` (0/1). None — ключ отсутствовал.
    pub proxy_enable: Option<u32>,
    /// Значение `ProxyServer`. None — ключ отсутствовал.
    pub proxy_server: Option<String>,
    /// Значение `ProxyOverride`. None — ключ отсутствовал.
    pub proxy_override: Option<String>,
}

/// Путь к файлу backup'а в %LOCALAPPDATA%\KwikProxy Secure\proxy_backup.json.
fn backup_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let local = std::env::var_os("LOCALAPPDATA")?;
        Some(PathBuf::from(local).join(BACKUP_DIR).join(BACKUP_FILE))
    }
    #[cfg(not(windows))]
    {
        // На *nix используем XDG_DATA_HOME или ~/.local/share
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
        Some(base.join(BACKUP_DIR).join(BACKUP_FILE))
    }
}

/// Прочитать текущие значения registry-ключей в ProxyBackup.
#[cfg(windows)]
fn read_current_proxy_state() -> Result<ProxyBackup> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = match hkcu.open_subkey(INET_SETTINGS) {
        Ok(key) => Some(key),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("не удалось открыть Internet Settings в реестре"),
    };

    let read = |name: &str| -> Result<Option<winreg::RegValue>> {
        let Some(key) = key.as_ref() else {
            return Ok(None);
        };
        match key.get_raw_value(name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("read registry value {name}")),
        }
    };

    fn decode<T: FromRegValue>(name: &str, value: Option<winreg::RegValue>) -> Result<Option<T>> {
        value
            .map(|value| {
                T::from_reg_value(&value)
                    .with_context(|| format!("registry value {name} has an unexpected type"))
            })
            .transpose()
    }

    Ok(ProxyBackup {
        attempt_id: None,
        published_proxy_server: None,
        published_proxy_override: None,
        proxy_enable: decode("ProxyEnable", read("ProxyEnable")?)?,
        proxy_server: decode("ProxyServer", read("ProxyServer")?)?,
        proxy_override: decode("ProxyOverride", read("ProxyOverride")?)?,
    })
}

/// Сохранить backup до registry publication. Ошибка записи fail-closed:
/// без устойчивого ownership marker системный proxy не меняется.
fn save_backup(backup: &ProxyBackup) -> Result<()> {
    let path = backup_path().context("LOCALAPPDATA is unavailable")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create proxy backup directory")?;
    }
    let json = serde_json::to_vec_pretty(backup).context("serialize proxy backup")?;
    std::fs::write(&path, json).context("write proxy backup")?;
    Ok(())
}

/// Удалить ownership marker только после подтверждённого restore. Ошибка
/// удаления fail-closed: оставшийся marker нельзя выдавать за завершённый
/// cleanup, иначе следующая публикация окажется заблокирована неожиданно.
fn delete_backup() -> Result<()> {
    let path = backup_path().context("LOCALAPPDATA is unavailable")?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove proxy ownership backup"),
    }
}

/// Проверить, существует ли файл backup'а. Используется на старте app
/// для детекции прерванной прошлой сессии (краш или kill).
pub fn has_pending_backup() -> bool {
    backup_path().map(|p| p.is_file()).unwrap_or(false)
}

/// Прочитать backup из файла. Вернёт None если файла нет / битый JSON.
pub fn read_backup() -> Option<ProxyBackup> {
    let path = backup_path()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// True only for the durable marker created by this exact connect attempt.
/// Used when publication returned an error after it may already have written
/// registry values: rollback must retain the listener until that marker is
/// reconciled instead of assuming no publication occurred.
pub fn has_pending_backup_for_attempt(attempt_id: &str) -> bool {
    read_backup().is_some_and(|backup| exact_attempt_matches(&backup, attempt_id))
}

/// Включить системный прокси: SOCKS5 на socks_port, HTTP/HTTPS на http_port.
///
/// Перед перезаписью значений сохраняет оригиналы в backup-файл. Если в
/// rollback текущей попытки мы находим её exact-token backup и
/// восстанавливаем точно эти значения.
pub fn set_system_proxy_owned(socks_port: u16, http_port: u16, attempt_id: &str) -> Result<()> {
    #[cfg(windows)]
    {
        if attempt_id.is_empty() {
            anyhow::bail!("proxy publication requires a non-empty attempt id");
        }
        // 9.D: сохраняем текущее состояние ДО изменений, чтобы пережить
        // краш приложения. Если backup уже есть (например, мы apply-нули
        // прокси, а пользователь вызвал set ещё раз) — не перезаписываем,
        // чтобы не потерять оригинал.
        if has_pending_backup() {
            anyhow::bail!(
                "proxy backup from another connection is pending; recover it before connecting"
            );
        }
        let proxy_server = format!(
            "socks=127.0.0.1:{socks_port};http=127.0.0.1:{http_port};https=127.0.0.1:{http_port}"
        );
        let mut snapshot = read_current_proxy_state()?;
        snapshot.attempt_id = Some(attempt_id.to_string());
        snapshot.published_proxy_server = Some(proxy_server.clone());
        snapshot.published_proxy_override = Some(KWIK_PROXY_OVERRIDE.to_string());
        save_backup(&snapshot)?;

        let publication = (|| -> Result<()> {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let (key, _) = hkcu
                .create_subkey(INET_SETTINGS)
                .context("не удалось открыть Internet Settings в реестре")?;

            // Формат строки: "protocol=host:port;..."
            key.set_value("ProxyServer", &proxy_server)
                .context("ProxyServer")?;
            key.set_value("ProxyEnable", &1u32).context("ProxyEnable")?;
            // Bypass: локальные адреса и LAN не идут через прокси
            key.set_value("ProxyOverride", &KWIK_PROXY_OVERRIDE)
                .context("ProxyOverride")?;
            notify_proxy_settings_changed()
        })();
        if let Err(publication_error) = publication {
            if let Err(restore_error) = restore_owned_publication(&snapshot, Some(attempt_id)) {
                anyhow::bail!(
                    "proxy publication failed ({publication_error:#}); immediate restore also failed ({restore_error:#})"
                );
            }
            return Err(publication_error);
        }

        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = (socks_port, http_port, attempt_id);
        Ok(()) // на macOS/Linux — заглушка, реализуем при портировании
    }
}

fn restore_guard() -> Result<std::sync::MutexGuard<'static, ()>> {
    RESTORE_MUTEX
        .lock()
        .map_err(|_| anyhow::anyhow!("system proxy restore lock is poisoned"))
}

#[cfg(windows)]
fn restore_owned_publication_locked(
    backup: &ProxyBackup,
    expected_attempt: Option<&str>,
) -> Result<bool> {
    let attempt = backup
        .attempt_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("proxy backup has no exact attempt ownership token")?;
    if expected_attempt.is_some_and(|expected| expected != attempt) {
        return Ok(false);
    }
    let published_server = backup
        .published_proxy_server
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("proxy backup has no exact published value")?;
    let published_override = backup
        .published_proxy_override
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("proxy backup has no exact published bypass value")?;

    let current = read_current_proxy_state()?;
    match plan_restore(&current, backup) {
        RestorePlan::AlreadyOriginal => {
            // Idempotent registry state does not prove that WinINet observed
            // it. A previous restore may have written the snapshot and then
            // failed its notification. Always retry the non-mutating refresh
            // before releasing the marker and stopping the listener.
            let revalidated = read_current_proxy_state()?;
            if !exact_proxy_state_matches(&revalidated, backup) {
                anyhow::bail!("system proxy changed while confirming an already-restored state");
            }
            notify_proxy_settings_changed()?;
            let notified = read_current_proxy_state()?;
            if !exact_proxy_state_matches(&notified, backup) {
                anyhow::bail!("system proxy changed while notifying an already-restored state");
            }
            delete_backup()?;
            return Ok(true);
        }
        RestorePlan::PreserveForeignState => {
            // The active proxy endpoint is no longer ours. Preserve all
            // foreign values byte-for-byte, but release the stale marker so
            // the now-unreferenced local Mihomo listener can be stopped.
            let revalidated = read_current_proxy_state()?;
            if !exact_proxy_state_matches(&revalidated, &current)
                || points_to_published_endpoint(&revalidated, backup)
            {
                anyhow::bail!("system proxy changed while preserving foreign state");
            }
            delete_backup()?;
            return Ok(true);
        }
        RestorePlan::ManualResolutionRequired => {
            anyhow::bail!(
                "[{MANUAL_RESTORE_REQUIRED_CODE}] system proxy still references this KwikProxy endpoint, but other proxy fields were changed by another application; explicit confirmation is required before restoring the saved snapshot"
            );
        }
        RestorePlan::RestoreOwnedFields => {}
    }

    let published_enable = Some(1u32);
    let published_server = Some(published_server.to_string());
    let published_override = Some(published_override.to_string());
    let enable_action = classify_failed_publication_field(
        &current.proxy_enable,
        &backup.proxy_enable,
        &published_enable,
    );
    let server_action = classify_failed_publication_field(
        &current.proxy_server,
        &backup.proxy_server,
        &published_server,
    );
    let override_action = classify_failed_publication_field(
        &current.proxy_override,
        &backup.proxy_override,
        &published_override,
    );
    debug_assert!(![enable_action, server_action, override_action]
        .contains(&FailedPublicationField::ForeignConflict));

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(INET_SETTINGS)
        .context("open Internet Settings for owned partial restore")?;

    // Revalidate each owned field immediately before its write. Registry has
    // no compare-and-swap primitive, so no field is touched based only on the
    // earlier multi-field snapshot.
    if enable_action == FailedPublicationField::RestoreOwnedValue {
        if read_current_proxy_state()?.proxy_enable != published_enable {
            anyhow::bail!("ProxyEnable changed during owned partial restore");
        }
        match backup.proxy_enable {
            Some(value) => key
                .set_value("ProxyEnable", &value)
                .context("restore ProxyEnable")?,
            None => key
                .delete_value("ProxyEnable")
                .context("remove owned ProxyEnable")?,
        }
    }
    if server_action == FailedPublicationField::RestoreOwnedValue {
        if read_current_proxy_state()?.proxy_server != published_server {
            anyhow::bail!("ProxyServer changed during owned partial restore");
        }
        match &backup.proxy_server {
            Some(value) => key
                .set_value("ProxyServer", value)
                .context("restore ProxyServer")?,
            None => key
                .delete_value("ProxyServer")
                .context("remove owned ProxyServer")?,
        }
    }
    if override_action == FailedPublicationField::RestoreOwnedValue {
        if read_current_proxy_state()?.proxy_override != published_override {
            anyhow::bail!("ProxyOverride changed during owned partial restore");
        }
        match &backup.proxy_override {
            Some(value) => key
                .set_value("ProxyOverride", value)
                .context("restore ProxyOverride")?,
            None => key
                .delete_value("ProxyOverride")
                .context("remove owned ProxyOverride")?,
        }
    }
    // A partial previous attempt may already have restored one or more
    // fields. Verify that the complete write-set is now exactly original
    // before releasing the durable ownership marker.
    let restored = read_current_proxy_state()?;
    if restored.proxy_enable != backup.proxy_enable
        || restored.proxy_server != backup.proxy_server
        || restored.proxy_override != backup.proxy_override
    {
        anyhow::bail!("system proxy restore did not reach the exact original write-set");
    }
    // Always retry notification, including a later invocation after a prior
    // restore wrote the original registry values but WinINet refresh failed.
    notify_proxy_settings_changed()?;
    delete_backup()?;
    Ok(true)
}

#[cfg(windows)]
fn restore_owned_publication(backup: &ProxyBackup, expected_attempt: Option<&str>) -> Result<bool> {
    let _guard = restore_guard()?;
    restore_owned_publication_locked(backup, expected_attempt)
}

#[cfg(windows)]
fn write_original_snapshot(backup: &ProxyBackup) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(INET_SETTINGS)
        .context("open Internet Settings for confirmed proxy restore")?;

    let set_enable = |value: Option<u32>| -> Result<()> {
        match value {
            Some(value) => key
                .set_value("ProxyEnable", &value)
                .context("restore confirmed ProxyEnable"),
            None => match key.delete_value("ProxyEnable") {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error).context("remove confirmed ProxyEnable"),
            },
        }
    };
    let set_string = |name: &str, value: &Option<String>| -> Result<()> {
        match value {
            Some(value) => key
                .set_value(name, value)
                .with_context(|| format!("restore confirmed {name}")),
            None => match key.delete_value(name) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error).with_context(|| format!("remove confirmed {name}")),
            },
        }
    };

    // If the saved state was disabled, disable first so no request observes a
    // half-restored endpoint. If it was enabled, publish server/bypass first
    // and enable last. The local listener remains alive throughout.
    if backup.proxy_enable != Some(1) {
        set_enable(backup.proxy_enable)?;
    }
    set_string("ProxyServer", &backup.proxy_server)?;
    set_string("ProxyOverride", &backup.proxy_override)?;
    if backup.proxy_enable == Some(1) {
        set_enable(backup.proxy_enable)?;
    }
    Ok(())
}

/// Explicit, user-confirmed recovery for the one ambiguous case where the
/// enabled WinINet mapping still references this attempt's loopback listener
/// but another field changed. Exact attempt ownership is mandatory. A foreign
/// endpoint can never be force-restored by this API.
pub fn force_restore_owned_proxy(attempt_id: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let _guard = restore_guard()?;
        let Some(backup) = read_backup() else {
            return Ok(false);
        };
        if !exact_attempt_matches(&backup, attempt_id) {
            return Ok(false);
        }

        let current = read_current_proxy_state()?;
        match plan_restore(&current, &backup) {
            RestorePlan::ManualResolutionRequired => {
                // Revalidate the complete observed state and semantic owned
                // endpoint immediately before the confirmed write. Windows
                // registry has no compare-and-swap; the remaining external
                // writer race is best-effort, while our in-process attempts
                // are serialized by RESTORE_MUTEX.
                let revalidated = read_current_proxy_state()?;
                if !exact_proxy_state_matches(&current, &revalidated)
                    || !points_to_published_endpoint(&revalidated, &backup)
                {
                    anyhow::bail!(
                        "system proxy changed before confirmed restore; retry Disconnect"
                    );
                }
                write_original_snapshot(&backup)?;
                let restored = read_current_proxy_state()?;
                if !exact_proxy_state_matches(&restored, &backup) {
                    anyhow::bail!("confirmed proxy restore did not reach the saved snapshot");
                }
                notify_proxy_settings_changed()?;
                delete_backup()?;
                Ok(true)
            }
            // State may have changed while the confirmation dialog was open.
            // Fall back to the ordinary exact/preserve-foreign policy; it
            // either reaches a safe-to-stop state or fails closed.
            _ => restore_owned_publication_locked(&backup, Some(attempt_id)),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = attempt_id;
        Ok(false)
    }
}

/// Roll back only the system-proxy publication owned by `attempt_id`.
/// Absence or a different/legacy marker is a successful no-op.
pub fn clear_system_proxy_owned(attempt_id: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let Some(backup) = read_backup() else {
            return Ok(false);
        };
        restore_owned_publication(&backup, Some(attempt_id))
    }
    #[cfg(not(windows))]
    {
        let _ = attempt_id;
        Ok(false)
    }
}

/// Crash-recovery path for a previous process incarnation. The backup token
/// and exact currently-published value are both mandatory; a legacy marker,
/// localhost port heuristic, or changed registry value grants no authority.
pub fn restore_pending_owned_proxy() -> Result<bool> {
    #[cfg(windows)]
    {
        let Some(backup) = read_backup() else {
            return Ok(false);
        };
        restore_owned_publication(&backup, None)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

#[cfg(windows)]
fn notify_proxy_settings_changed() -> Result<()> {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    let mut failures = Vec::new();
    for attempt in 1..=2 {
        failures.clear();
        for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
            if unsafe { InternetSetOptionW(std::ptr::null_mut(), option, std::ptr::null_mut(), 0) }
                == 0
            {
                failures.push(option);
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        if attempt == 2 {
            break;
        }
    }
    anyhow::bail!(
        "WinINet proxy notification failed after retry for options {:?}",
        failures
    )
}

#[cfg(windows)]
fn read_proxy_enable() -> Option<u32> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey(INET_SETTINGS).ok()?;
    key.get_value::<u32, _>("ProxyEnable").ok()
}

/// Прочитать `ProxyServer` напрямую — для startup poison check и
/// pre-flight check при connect. None если ключа нет.
#[cfg(windows)]
pub fn read_proxy_server() -> Option<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey(INET_SETTINGS).ok()?;
    key.get_value::<String, _>("ProxyServer").ok()
}

#[cfg(windows)]
fn read_proxy_override() -> Option<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey(INET_SETTINGS).ok()?;
    key.get_value::<String, _>("ProxyOverride").ok()
}

#[cfg(not(windows))]
pub fn read_proxy_server() -> Option<String> {
    None
}

/// True only when a non-legacy backup carries an exact attempt token and its
/// exact publication is still enabled in WinINet. Port ranges are never used
/// as ownership evidence.
pub fn is_proxy_pointing_to_us() -> bool {
    #[cfg(windows)]
    {
        read_backup().is_some_and(|backup| {
            backup
                .attempt_id
                .as_deref()
                .is_some_and(|value| !value.is_empty())
                && backup
                    .published_proxy_server
                    .as_deref()
                    .is_some_and(|published| {
                        backup.published_proxy_override.as_deref().is_some_and(
                            |published_override| {
                                exact_write_set_matches(
                                    published,
                                    published_override,
                                    read_proxy_enable(),
                                    read_proxy_server().as_deref(),
                                    read_proxy_override().as_deref(),
                                )
                            },
                        )
                    })
        })
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Удалить backup-файл без применения значений. Используется когда
/// пользователь в диалоге crash-recovery нажимает «не восстанавливать»
/// (значит наши значения он уже не считает актуальными — продолжаем
/// с текущим состоянием реестра).
pub fn discard_backup() -> Result<()> {
    delete_backup()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_backup() -> ProxyBackup {
        ProxyBackup {
            attempt_id: Some("attempt-a".into()),
            published_proxy_server: Some("http=127.0.0.1:56800".into()),
            published_proxy_override: Some(KWIK_PROXY_OVERRIDE.into()),
            proxy_enable: Some(1),
            proxy_server: Some("http=127.0.0.1:10808".into()),
            proxy_override: Some("<local>".into()),
        }
    }

    fn state(enable: u32, server: &str, bypass: &str) -> ProxyBackup {
        state_optional(Some(enable), Some(server), Some(bypass))
    }

    fn state_optional(
        enable: Option<u32>,
        server: Option<&str>,
        bypass: Option<&str>,
    ) -> ProxyBackup {
        ProxyBackup {
            attempt_id: None,
            published_proxy_server: None,
            published_proxy_override: None,
            proxy_enable: enable,
            proxy_server: server.map(str::to_string),
            proxy_override: bypass.map(str::to_string),
        }
    }

    #[test]
    fn legacy_backup_has_no_attempt_owner() {
        let backup: ProxyBackup =
            serde_json::from_str(r#"{"proxy_enable":0,"proxy_server":null,"proxy_override":null}"#)
                .unwrap();
        assert_eq!(backup.attempt_id, None);
    }

    #[test]
    fn attempt_owner_roundtrips() {
        let backup = ProxyBackup {
            attempt_id: Some("attempt-a".into()),
            published_proxy_server: Some("http=127.0.0.1:30000".into()),
            published_proxy_override: Some(KWIK_PROXY_OVERRIDE.into()),
            proxy_enable: Some(0),
            proxy_server: None,
            proxy_override: None,
        };
        let json = serde_json::to_string(&backup).unwrap();
        let decoded: ProxyBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.attempt_id.as_deref(), Some("attempt-a"));
        assert_eq!(
            decoded.published_proxy_server.as_deref(),
            Some("http=127.0.0.1:30000")
        );
        assert_eq!(
            decoded.published_proxy_override.as_deref(),
            Some(KWIK_PROXY_OVERRIDE)
        );
    }

    #[test]
    fn exact_publication_requires_the_complete_write_set() {
        let server = "http=127.0.0.1:30000";
        let bypass = KWIK_PROXY_OVERRIDE;
        assert!(exact_write_set_matches(
            server,
            bypass,
            Some(1),
            Some(server),
            Some(bypass),
        ));
        assert!(!exact_write_set_matches(
            server,
            bypass,
            Some(1),
            Some(server),
            Some("foreign bypass"),
        ));
        assert!(!exact_write_set_matches(
            server,
            bypass,
            Some(0),
            Some(server),
            Some(bypass),
        ));
    }

    #[test]
    fn failed_publication_restores_only_original_or_exact_owned_values() {
        assert_eq!(
            classify_failed_publication_field(&Some(0), &Some(0), &Some(1)),
            FailedPublicationField::AlreadyOriginal
        );
        assert_eq!(
            classify_failed_publication_field(&Some(1), &Some(0), &Some(1)),
            FailedPublicationField::RestoreOwnedValue
        );
        assert_eq!(
            classify_failed_publication_field(&Some(2), &Some(0), &Some(1)),
            FailedPublicationField::ForeignConflict
        );
    }

    #[test]
    fn interrupted_fieldwise_restore_remains_retryable() {
        let actions = [
            classify_failed_publication_field(&Some(0), &Some(0), &Some(1)),
            classify_failed_publication_field(&Some("owned"), &Some("original"), &Some("owned")),
            classify_failed_publication_field(
                &Some("original-bypass"),
                &Some("original-bypass"),
                &Some("owned-bypass"),
            ),
        ];
        assert_eq!(
            actions,
            [
                FailedPublicationField::AlreadyOriginal,
                FailedPublicationField::RestoreOwnedValue,
                FailedPublicationField::AlreadyOriginal,
            ]
        );
        assert!(!actions.contains(&FailedPublicationField::ForeignConflict));
    }

    #[test]
    fn published_state_is_restored_to_saved_snapshot() {
        let backup = owned_backup();
        let current = state(
            1,
            backup.published_proxy_server.as_deref().unwrap(),
            backup.published_proxy_override.as_deref().unwrap(),
        );
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::RestoreOwnedFields
        );
    }

    #[test]
    fn exact_saved_snapshot_is_idempotent_success_without_registry_restore() {
        let backup = owned_backup();
        let current = state(1, "http=127.0.0.1:10808", "<local>");
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::AlreadyOriginal
        );
        assert!(!points_to_published_endpoint(&current, &backup));
    }

    #[test]
    fn foreign_endpoint_is_preserved_and_local_listener_may_stop() {
        let backup = owned_backup();
        let current = state(1, "http=127.0.0.1:20808", "foreign-bypass");
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::PreserveForeignState
        );
        assert!(!points_to_published_endpoint(&current, &backup));
    }

    #[test]
    fn foreign_fields_require_manual_resolution_while_owned_endpoint_is_live() {
        let backup = owned_backup();
        let current = state(1, "http=127.0.0.1:56800", "foreign-bypass");
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::ManualResolutionRequired
        );
        assert!(points_to_published_endpoint(&current, &backup));
    }

    #[test]
    fn semantic_owned_endpoint_detection_ignores_order_case_and_spacing() {
        let backup = owned_backup();
        let published = "socks=127.0.0.1:56800;http=127.0.0.1:56801;https=127.0.0.1:56801";
        let current = " HTTPS = LOCALHOST:56801 ; SOCKS = 127.0.0.1:56800 ; HTTP=127.0.0.1:56801 ";
        assert!(proxy_strings_share_owned_loopback(current, published));
        assert!(proxy_strings_share_owned_loopback(
            "HTTP://127.42.7.9:56801",
            published
        ));
        assert!(proxy_strings_share_owned_loopback(
            "https=[::1]:56801",
            published
        ));
        assert!(!proxy_strings_share_owned_loopback(
            "http=127.0.0.1:20808",
            published
        ));

        let current_state = state(1, current, "foreign-bypass");
        let mut backup = backup;
        backup.published_proxy_server = Some(published.into());
        assert_eq!(
            plan_restore(&current_state, &backup),
            RestorePlan::ManualResolutionRequired
        );
    }

    #[test]
    fn disabled_proxy_with_retained_owned_server_is_safe_to_stop() {
        let backup = owned_backup();
        let current = state(
            0,
            backup.published_proxy_server.as_deref().unwrap(),
            "foreign-bypass",
        );
        assert!(!points_to_published_endpoint(&current, &backup));
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::PreserveForeignState
        );
    }

    #[test]
    fn missing_original_values_restore_from_exact_publication() {
        let mut backup = owned_backup();
        backup.proxy_enable = None;
        backup.proxy_server = None;
        backup.proxy_override = None;
        let published = state(
            1,
            backup.published_proxy_server.as_deref().unwrap(),
            backup.published_proxy_override.as_deref().unwrap(),
        );
        assert_eq!(
            plan_restore(&published, &backup),
            RestorePlan::RestoreOwnedFields
        );

        let partially_restored = state_optional(
            None,
            Some(backup.published_proxy_server.as_deref().unwrap()),
            None,
        );
        assert_eq!(
            plan_restore(&partially_restored, &backup),
            RestorePlan::RestoreOwnedFields
        );
        assert_eq!(
            plan_restore(&state_optional(None, None, None), &backup),
            RestorePlan::AlreadyOriginal
        );
    }

    #[test]
    fn confirmed_restore_requires_exact_nonempty_attempt_token() {
        let backup = owned_backup();
        assert!(exact_attempt_matches(&backup, "attempt-a"));
        assert!(!exact_attempt_matches(&backup, "attempt-b"));
        assert!(!exact_attempt_matches(&backup, ""));

        let mut legacy = backup;
        legacy.attempt_id = None;
        assert!(!exact_attempt_matches(&legacy, "attempt-a"));
    }
}
