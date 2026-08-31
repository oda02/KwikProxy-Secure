//! Управление системным прокси Windows через реестр.
//!
//! Устанавливает SOCKS5 + HTTP proxy в Internet Settings текущего пользователя.
//! Bypass включает localhost, 127.*, LAN-диапазоны и <local> (имена без точки).
//!
//! Backup/restore (9.D): перед перезаписью значений мы сохраняем оригиналы
//! `ProxyEnable` / `ProxyServer` / `ProxyOverride` в JSON-файл
//! `%LOCALAPPDATA%\KwikProxy Secure\proxy_backup.json`. Restore requires the
//! exact attempt token; every field must still equal either that attempt's
//! publication or its saved original. This makes interrupted per-field restore
//! retryable without granting authority over foreign changes. Если приложение
//! крашнется в режиме proxy и не успеет очистить — на старте next-run-а мы
//! детектим backup-файл и предлагаем пользователю восстановить.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(windows)]
use winreg::{enums::*, RegKey};

#[cfg(windows)]
const INET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

const BACKUP_DIR: &str = "KwikProxy Secure";
const BACKUP_FILE: &str = "proxy_backup.json";
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
    let key = hkcu
        .open_subkey(INET_SETTINGS)
        .context("не удалось открыть Internet Settings в реестре")?;

    Ok(ProxyBackup {
        attempt_id: None,
        published_proxy_server: None,
        published_proxy_override: None,
        proxy_enable: key.get_value("ProxyEnable").ok(),
        proxy_server: key.get_value("ProxyServer").ok(),
        proxy_override: key.get_value("ProxyOverride").ok(),
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

#[cfg(windows)]
fn restore_owned_publication(backup: &ProxyBackup, expected_attempt: Option<&str>) -> Result<bool> {
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
    if [enable_action, server_action, override_action]
        .contains(&FailedPublicationField::ForeignConflict)
    {
        anyhow::bail!("system proxy changed concurrently; refusing to overwrite foreign state");
    }

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(INET_SETTINGS)
        .context("open Internet Settings for owned partial restore")?;

    // Revalidate each owned field immediately before its write. Registry has
    // no compare-and-swap primitive, so no field is touched based only on the
    // earlier multi-field snapshot.
    if enable_action == FailedPublicationField::RestoreOwnedValue {
        if read_proxy_enable() != published_enable {
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
        if read_proxy_server() != published_server {
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
        if read_proxy_override() != published_override {
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
}
