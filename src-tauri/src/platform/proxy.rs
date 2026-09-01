//! Управление системным прокси Windows через реестр.
//!
//! Устанавливает SOCKS5 + HTTP proxy в Internet Settings текущего пользователя.
//! Bypass включает localhost, 127.*, LAN-диапазоны и <local> (имена без точки).
//!
//! Backup/restore (9.D): перед перезаписью значений мы сохраняем оригиналы
//! `ProxyEnable` / `ProxyServer` / `ProxyOverride` в JSON-файл
//! `%LOCALAPPDATA%\KwikProxy Secure\proxy_backup.json`. Restore requires the
//! exact attempt token. An exact saved-original state is accepted as an
//! idempotent success. A foreign state is preserved while the marker/listener
//! remain retained until that application's delayed restore is reconciled.
//! This makes interrupted and multi-VPN restore ordering retryable without
//! granting authority over foreign changes. Если приложение
//! крашнется в режиме proxy и не успеет очистить — на старте next-run-а мы
//! детектим backup-файл и предлагаем пользователю восстановить.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
pub const MANUAL_INTERVENTION_REQUIRED_CODE: &str = "proxy_restore_manual_intervention_required";
pub const FOREIGN_PROXY_PENDING_CODE: &str = "proxy_restore_foreign_state_pending";
static RESTORE_MUTEX: Mutex<()> = Mutex::new(());
static RESTORE_CHALLENGE: Mutex<RestoreChallengeSlot> =
    Mutex::new(RestoreChallengeSlot { current: None });
const KWIK_PROXY_OVERRIDE: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;\
172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;\
172.29.*;172.30.*;172.31.*;192.168.*;<local>";

#[cfg(test)]
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
    /// A foreign state currently replaced our endpoint. Retain marker and
    /// listener because that VPN may later restore the stale Kwik mapping it
    /// captured when it started.
    ForeignStatePending,
    /// Foreign fields exist but WinINet is still actively using our endpoint.
    /// Stopping the listener would strand clients on a dead loopback proxy.
    ManualResolutionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscardPlan {
    NotifyExactOriginal,
    RefuseLiveEndpoint,
    RefuseForeignOrDisabled,
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

/// Strict authority for a confirmed overwrite. Unlike the broad listener
/// retention predicate above, this accepts only the exact protocol ->
/// 127.0.0.1:port mapping published by this build. Reordering, protocol-name
/// case and surrounding whitespace are harmless; aliases, URL forms, extra
/// protocols, duplicate protocols and other 127/8 addresses are rejected.
fn strict_proxy_mapping(proxy_server: &str) -> Option<BTreeMap<String, u16>> {
    let mut mapping = BTreeMap::new();
    for component in proxy_server.split(';') {
        let component = component.trim();
        if component.is_empty() {
            return None;
        }
        let (protocol, endpoint) = component.split_once('=')?;
        let protocol = protocol.trim().to_ascii_lowercase();
        if protocol.is_empty() {
            return None;
        }
        let (host, port) = endpoint.trim().rsplit_once(':')?;
        if host.trim() != "127.0.0.1" {
            return None;
        }
        let port = port.trim().parse::<u16>().ok()?;
        if mapping.insert(protocol, port).is_some() {
            return None;
        }
    }
    (!mapping.is_empty()).then_some(mapping)
}

fn strict_published_mapping_matches(current: &ProxyBackup, backup: &ProxyBackup) -> bool {
    current.proxy_enable == Some(1)
        && current.proxy_server.as_deref().is_some_and(|current| {
            backup
                .published_proxy_server
                .as_deref()
                .and_then(strict_proxy_mapping)
                .filter(|published| {
                    published.len() == 3
                        && published.contains_key("http")
                        && published.contains_key("https")
                        && published.contains_key("socks")
                        && published.get("http") == published.get("https")
                })
                .is_some_and(|published| strict_proxy_mapping(current) == Some(published))
        })
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
        RestorePlan::ForeignStatePending
    }
}

fn plan_discard(current: &ProxyBackup, backup: &ProxyBackup) -> DiscardPlan {
    if exact_proxy_state_matches(current, backup) {
        DiscardPlan::NotifyExactOriginal
    } else if points_to_published_endpoint(current, backup) {
        DiscardPlan::RefuseLiveEndpoint
    } else {
        DiscardPlan::RefuseForeignOrDisabled
    }
}

fn exact_attempt_matches(backup: &ProxyBackup, attempt_id: &str) -> bool {
    !attempt_id.is_empty()
        && backup
            .attempt_id
            .as_deref()
            .is_some_and(|owner| !owner.is_empty() && owner == attempt_id)
}

fn has_complete_ownership_metadata(backup: &ProxyBackup) -> bool {
    backup
        .attempt_id
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        && backup
            .published_proxy_server
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && backup
            .published_proxy_override
            .as_deref()
            .is_some_and(|value| !value.is_empty())
}

/// Снимок настроек системного прокси для backup/restore.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct RestoreChallenge {
    token: String,
    attempt_id: String,
    backup: ProxyBackup,
    observed: ProxyBackup,
}

#[derive(Default)]
struct RestoreChallengeSlot {
    current: Option<RestoreChallenge>,
}

impl RestoreChallengeSlot {
    fn issue(&mut self, attempt_id: &str, backup: &ProxyBackup, observed: &ProxyBackup) -> String {
        if let Some(existing) = self.current.as_ref().filter(|existing| {
            existing.attempt_id == attempt_id
                && existing.backup == *backup
                && existing.observed == *observed
        }) {
            return existing.token.clone();
        }
        let token = uuid::Uuid::new_v4().to_string();
        self.current = Some(RestoreChallenge {
            token: token.clone(),
            attempt_id: attempt_id.to_string(),
            backup: backup.clone(),
            observed: observed.clone(),
        });
        token
    }

    /// Consume before validating. Any wrong/stale caller or changed state
    /// invalidates the one-use correlation token.
    fn take(&mut self, token: &str, expected_attempt: Option<&str>) -> Option<RestoreChallenge> {
        let challenge = self.current.take()?;
        (!token.is_empty()
            && challenge.token == token
            && expected_attempt.is_none_or(|attempt| challenge.attempt_id == attempt))
        .then_some(challenge)
    }

    fn invalidate(&mut self) {
        self.current = None;
    }
}

fn challenge_guard() -> Result<std::sync::MutexGuard<'static, RestoreChallengeSlot>> {
    RESTORE_CHALLENGE
        .lock()
        .map_err(|_| anyhow::anyhow!("proxy restore challenge lock is poisoned"))
}

fn invalidate_restore_challenge() -> Result<()> {
    challenge_guard()?.invalidate();
    Ok(())
}

fn manual_restore_error(backup: &ProxyBackup, current: &ProxyBackup) -> Result<bool> {
    let attempt = backup
        .attempt_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("proxy backup has no exact attempt ownership token")?;
    let token = challenge_guard()?.issue(attempt, backup, current);
    anyhow::bail!(
        "[{MANUAL_RESTORE_REQUIRED_CODE}] challenge={token}; system proxy still references this KwikProxy endpoint, but other proxy fields were changed by another application; explicit confirmation is required before restoring the saved snapshot"
    )
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
    let temp_path = path.with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4().simple()));
    std::fs::write(&temp_path, json).context("write temporary proxy backup")?;
    if let Err(error) = std::fs::rename(&temp_path, &path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error).context("publish proxy backup atomically");
    }
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

fn delete_backup_if_matches(backup: &ProxyBackup, expected_state: &ProxyBackup) -> Result<()> {
    let current_backup = read_backup_strict()?
        .context("proxy ownership backup disappeared before verified deletion")?;
    if current_backup != *backup {
        anyhow::bail!("proxy ownership backup changed before verified deletion");
    }
    #[cfg(windows)]
    if !exact_proxy_state_matches(&read_current_proxy_state()?, expected_state) {
        anyhow::bail!("system proxy changed before verified backup deletion");
    }
    delete_backup()?;
    #[cfg(windows)]
    {
        let after_delete = read_current_proxy_state()?;
        if !exact_proxy_state_matches(&after_delete, expected_state) {
            // Restore the exact durable marker before denying teardown. This
            // cannot close the external registry race, but prevents a detected
            // delete->republish window from becoming unrecoverable.
            save_backup(backup).context("restore backup after post-delete proxy change")?;
            anyhow::bail!("system proxy changed immediately after backup deletion");
        }
    }
    Ok(())
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

/// Mutation paths must distinguish an absent marker from an unreadable or
/// malformed one. Treating parse/access errors as "no backup" could release a
/// listener or overwrite a recoverable snapshot without authority.
fn read_backup_strict() -> Result<Option<ProxyBackup>> {
    let path = backup_path().context("LOCALAPPDATA is unavailable")?;
    let data = match std::fs::read_to_string(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read proxy ownership backup"),
    };
    serde_json::from_str(&data)
        .context("parse proxy ownership backup")
        .map(Some)
}

/// True only for the durable marker created by this exact connect attempt.
/// Used when publication returned an error after it may already have written
/// registry values: rollback must retain the listener until that marker is
/// reconciled instead of assuming no publication occurred.
pub fn has_pending_backup_for_attempt(attempt_id: &str) -> bool {
    match read_backup_strict() {
        Ok(Some(backup)) => exact_attempt_matches(&backup, attempt_id),
        Ok(None) => false,
        // Unknown marker ownership is not permission to kill a listener after
        // a publication that may already have reached the registry.
        Err(_) => has_pending_backup(),
    }
}

/// Включить системный прокси: SOCKS5 на socks_port, HTTP/HTTPS на http_port.
///
/// Перед перезаписью значений сохраняет оригиналы в backup-файл. Если в
/// rollback текущей попытки мы находим её exact-token backup и
/// восстанавливаем точно эти значения.
pub fn set_system_proxy_owned(socks_port: u16, http_port: u16, attempt_id: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let _guard = restore_guard()?;
        invalidate_restore_challenge()?;
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
            if let Err(restore_error) =
                restore_owned_publication_locked(&snapshot, Some(attempt_id))
            {
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
        invalidate_restore_challenge()?;
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
            invalidate_restore_challenge()?;
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
            delete_backup_if_matches(backup, &notified)?;
            return Ok(true);
        }
        RestorePlan::ForeignStatePending => {
            invalidate_restore_challenge()?;
            // A second VPN may have captured our mapping before replacing it,
            // then restore that stale mapping when it later stops. Releasing
            // our listener/marker because its foreign mapping is active *now*
            // would recreate a dead loopback endpoint later.
            let revalidated = read_current_proxy_state()?;
            if !exact_proxy_state_matches(&revalidated, &current)
                || points_to_published_endpoint(&revalidated, backup)
            {
                anyhow::bail!("system proxy changed while preserving foreign state");
            }
            anyhow::bail!(
                "[{FOREIGN_PROXY_PENDING_CODE}] another application currently owns the system proxy; stop that VPN/application, then retry Disconnect so its delayed proxy restore can be reconciled safely"
            );
        }
        RestorePlan::ManualResolutionRequired => {
            if strict_published_mapping_matches(&current, backup) {
                return manual_restore_error(backup, &current);
            }
            invalidate_restore_challenge()?;
            anyhow::bail!(
                "[{MANUAL_INTERVENTION_REQUIRED_CODE}] the enabled proxy still references a KwikProxy listener port, but its protocol mapping is not the exact mapping published by this attempt; change or disable the Windows system proxy manually"
            );
        }
        RestorePlan::RestoreOwnedFields => invalidate_restore_challenge()?,
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
    let notified = read_current_proxy_state()?;
    if !exact_proxy_state_matches(&notified, backup) {
        anyhow::bail!("system proxy changed while notifying the restored original write-set");
    }
    delete_backup_if_matches(backup, &notified)?;
    Ok(true)
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

#[cfg(windows)]
fn force_restore_owned_proxy_locked(
    backup: &ProxyBackup,
    attempt_id: &str,
    challenge: &RestoreChallenge,
) -> Result<bool> {
    if !exact_attempt_matches(backup, attempt_id) {
        invalidate_restore_challenge()?;
        return Ok(false);
    }

    let current = read_current_proxy_state()?;
    if challenge.attempt_id != attempt_id
        || challenge.backup != *backup
        || challenge.observed != current
    {
        anyhow::bail!("proxy restore confirmation challenge is stale or changed");
    }
    if plan_restore(&current, backup) != RestorePlan::ManualResolutionRequired
        || !strict_published_mapping_matches(&current, backup)
    {
        anyhow::bail!(
            "system proxy no longer has the exact published protocol mapping; retry ordinary recovery"
        );
    }

    // The challenge is bound to the byte-exact observed state. Revalidate as
    // close as possible to the write; the Windows registry has no multi-value
    // compare-and-swap, so external writers remain a minimized best-effort
    // race. All in-process restore attempts are serialized by RESTORE_MUTEX.
    let revalidated = read_current_proxy_state()?;
    if !exact_proxy_state_matches(&current, &revalidated)
        || !strict_published_mapping_matches(&revalidated, backup)
    {
        anyhow::bail!("system proxy changed before confirmed restore; retry ordinary recovery");
    }
    write_original_snapshot(backup)?;
    let restored = read_current_proxy_state()?;
    if !exact_proxy_state_matches(&restored, backup) {
        anyhow::bail!("confirmed proxy restore did not reach the saved snapshot");
    }
    notify_proxy_settings_changed()?;
    let notified = read_current_proxy_state()?;
    if !exact_proxy_state_matches(&notified, backup) {
        anyhow::bail!("system proxy changed while notifying confirmed restore");
    }
    delete_backup_if_matches(backup, &notified)?;
    Ok(true)
}

/// Explicit, user-confirmed recovery for the one ambiguous case where the
/// enabled WinINet mapping still has the exact protocol/127.0.0.1/port map
/// published by this attempt but another field changed. The one-use challenge
/// is minted only by an immediately preceding ordinary restore request. It is
/// correlation against direct invocation by the renderer, not a privileged
/// security boundary: the renderer is part of the trusted application.
pub fn force_restore_owned_proxy(attempt_id: &str, challenge: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let _guard = restore_guard()?;
        let challenge = challenge_guard()?
            .take(challenge, Some(attempt_id))
            .context("proxy restore confirmation challenge is missing, invalid, or already used")?;
        let Some(backup) = read_backup_strict()? else {
            return Ok(false);
        };
        force_restore_owned_proxy_locked(&backup, attempt_id, &challenge)
    }
    #[cfg(not(windows))]
    {
        let _ = (attempt_id, challenge);
        Ok(false)
    }
}

/// Roll back only the system-proxy publication owned by `attempt_id`.
/// Absence or a different/legacy marker is a successful no-op.
pub fn clear_system_proxy_owned(attempt_id: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let _guard = restore_guard()?;
        let Some(backup) = read_backup_strict()? else {
            return Ok(false);
        };
        restore_owned_publication_locked(&backup, Some(attempt_id))
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
        let _guard = restore_guard()?;
        let Some(backup) = read_backup_strict()? else {
            invalidate_restore_challenge()?;
            return Ok(false);
        };
        restore_owned_publication_locked(&backup, None)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// Confirmed crash/startup recovery. It uses the durable exact attempt token
/// from the backup, so no in-memory Mihomo state is required, but otherwise
/// enforces the same one-use challenge and strict mapping as live disconnect.
pub fn force_restore_pending_owned_proxy(challenge: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let _guard = restore_guard()?;
        let challenge = challenge_guard()?
            .take(challenge, None)
            .context("proxy restore confirmation challenge is missing, invalid, or already used")?;
        let Some(backup) = read_backup_strict()? else {
            return Ok(false);
        };
        let attempt_id = backup
            .attempt_id
            .clone()
            .filter(|value| !value.is_empty())
            .context("proxy backup has no exact attempt ownership token")?;
        force_restore_owned_proxy_locked(&backup, &attempt_id, &challenge)
    }
    #[cfg(not(windows))]
    {
        let _ = challenge;
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

/// Прочитать `ProxyServer` напрямую — для startup poison check и
/// pre-flight check при connect. None если ключа нет.
#[cfg(windows)]
pub fn read_proxy_server() -> Option<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey(INET_SETTINGS).ok()?;
    key.get_value::<String, _>("ProxyServer").ok()
}

#[cfg(not(windows))]
pub fn read_proxy_server() -> Option<String> {
    None
}

/// Startup-facing classification. The broad endpoint flag is only a signal to
/// keep/recover state; overwrite authority still comes exclusively from exact
/// ordinary ownership or the strict confirmed mapping.
pub fn proxy_recovery_status() -> (bool, &'static str) {
    #[cfg(windows)]
    {
        let backup = match read_backup_strict() {
            Ok(Some(backup)) => backup,
            Ok(None) => return (false, "none"),
            Err(_) => return (false, "unreadable"),
        };
        let current = match read_current_proxy_state() {
            Ok(current) => current,
            Err(_) => return (false, "unreadable"),
        };
        if !has_complete_ownership_metadata(&backup) {
            return (false, "unreadable");
        }
        let endpoint_live = points_to_published_endpoint(&current, &backup);
        let disposition = match plan_restore(&current, &backup) {
            RestorePlan::ManualResolutionRequired
                if strict_published_mapping_matches(&current, &backup) =>
            {
                "confirmation_required"
            }
            RestorePlan::ManualResolutionRequired => "manual_intervention_required",
            RestorePlan::ForeignStatePending => "foreign_state_pending",
            _ => "automatic",
        };
        (endpoint_live, disposition)
    }
    #[cfg(not(windows))]
    {
        (false, "none")
    }
}

pub fn is_proxy_pointing_to_us() -> bool {
    proxy_recovery_status().0
}

/// Удалить backup-файл без применения значений. Используется когда
/// пользователь в диалоге crash-recovery нажимает «не восстанавливать»
/// (значит наши значения он уже не считает актуальными — продолжаем
/// с текущим состоянием реестра).
pub fn discard_backup() -> Result<()> {
    let _guard = restore_guard()?;
    invalidate_restore_challenge()?;
    let Some(backup) = read_backup_strict()? else {
        return Ok(());
    };
    let attempt = backup
        .attempt_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("refusing to discard a legacy proxy backup without exact ownership")?;
    let published = backup
        .published_proxy_server
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("refusing to discard proxy backup without exact published endpoint")?;
    let published_override = backup
        .published_proxy_override
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("refusing to discard proxy backup without exact published bypass")?;
    let _ = (attempt, published, published_override);
    #[cfg(windows)]
    {
        let current = read_current_proxy_state()?;
        if plan_discard(&current, &backup) == DiscardPlan::NotifyExactOriginal {
            // The registry is already original, but a previous restore may
            // have failed before WinINet observed it. Reuse the normal
            // idempotent path so notification and post-notify revalidation
            // happen before the durable marker is released.
            return restore_owned_publication_locked(&backup, None).map(|_| ());
        }
        anyhow::bail!(
            "refusing to discard recovery backup before the exact saved proxy snapshot is restored; another VPN may later reapply the captured KwikProxy endpoint"
        );
    }
    #[cfg(not(windows))]
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
    fn foreign_endpoint_is_preserved_but_delayed_restore_keeps_ownership() {
        let backup = owned_backup();
        let current = state(1, "http=127.0.0.1:20808", "foreign-bypass");
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::ForeignStatePending
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
    fn confirmed_restore_requires_the_exact_normalized_protocol_map() {
        let published = "socks=127.0.0.1:56800;http=127.0.0.1:56801;https=127.0.0.1:56801";
        let mut backup = owned_backup();
        backup.published_proxy_server = Some(published.into());

        let equivalent = state(
            1,
            " HTTPS = 127.0.0.1:56801 ; SOCKS = 127.0.0.1:56800 ; HTTP = 127.0.0.1:56801 ",
            "foreign-bypass",
        );
        assert!(strict_published_mapping_matches(&equivalent, &backup));

        for rejected in [
            "https=127.42.7.9:56801;socks=127.0.0.1:56800;http=127.0.0.1:56801",
            "https=localhost:56801;socks=127.0.0.1:56800;http=127.0.0.1:56801",
            "https=HTTP://127.0.0.1:56801;socks=127.0.0.1:56800;http=127.0.0.1:56801",
            "https=127.0.0.1:56801;socks=127.0.0.1:56800;ftp=127.0.0.1:56801",
            "https=127.0.0.1:56801;socks=127.0.0.1:56800;http=127.0.0.1:56802",
            "https=127.0.0.1:56801;socks=127.0.0.1:56800",
            "https=127.0.0.1:56801;socks=127.0.0.1:56800;http=127.0.0.1:56801;http=127.0.0.1:56801",
        ] {
            let current = state(1, rejected, "foreign-bypass");
            assert!(points_to_published_endpoint(&current, &backup));
            assert!(!strict_published_mapping_matches(&current, &backup));
        }

        let mut invalid_metadata = backup.clone();
        invalid_metadata.published_proxy_server =
            Some("ftp=127.0.0.1:56800;http=127.0.0.1:56801;https=127.0.0.1:56801".into());
        let current = state(
            1,
            invalid_metadata.published_proxy_server.as_deref().unwrap(),
            "foreign-bypass",
        );
        assert!(!strict_published_mapping_matches(
            &current,
            &invalid_metadata
        ));
    }

    #[test]
    fn manual_restore_challenge_is_stable_then_single_use() {
        let backup = owned_backup();
        let observed = state(1, "http=127.0.0.1:56800", "foreign-bypass");
        let mut slot = RestoreChallengeSlot::default();
        let first = slot.issue("attempt-a", &backup, &observed);
        let repeated = slot.issue("attempt-a", &backup, &observed);
        assert_eq!(first, repeated);
        let issued = slot.take(&first, Some("attempt-a")).unwrap();
        assert_eq!(issued.backup, backup);
        assert_eq!(issued.observed, observed);
        assert!(slot.take(&first, Some("attempt-a")).is_none());
    }

    #[test]
    fn challenge_state_or_token_mismatch_invalidates_it() {
        let backup = owned_backup();
        let observed = state(1, "http=127.0.0.1:56800", "foreign-bypass");
        let changed = state(1, "http=127.0.0.1:56800", "changed-again");
        let mut slot = RestoreChallengeSlot::default();
        let token = slot.issue("attempt-a", &backup, &observed);
        let issued = slot.take(&token, Some("attempt-a")).unwrap();
        assert_ne!(issued.observed, changed);
        assert!(slot.take(&token, Some("attempt-a")).is_none());

        let token = slot.issue("attempt-a", &backup, &observed);
        assert!(slot.take("wrong-token", Some("attempt-a")).is_none());
        assert!(slot.take(&token, Some("attempt-a")).is_none());

        let token = slot.issue("attempt-a", &backup, &observed);
        let mut replaced_backup = backup.clone();
        replaced_backup.proxy_override = Some("different-saved-target".into());
        let issued = slot.take(&token, Some("attempt-a")).unwrap();
        assert_ne!(issued.backup, replaced_backup);
    }

    #[test]
    fn disabled_proxy_with_retained_owned_server_keeps_recovery_marker() {
        let backup = owned_backup();
        let current = state(
            0,
            backup.published_proxy_server.as_deref().unwrap(),
            "foreign-bypass",
        );
        assert!(!points_to_published_endpoint(&current, &backup));
        assert_eq!(
            plan_restore(&current, &backup),
            RestorePlan::ForeignStatePending
        );
        assert_eq!(
            plan_discard(&current, &backup),
            DiscardPlan::RefuseForeignOrDisabled
        );
    }

    #[test]
    fn discard_refuses_any_enabled_broad_owned_endpoint() {
        let backup = owned_backup();
        let changed_bypass = state(1, "http=127.0.0.1:56800", "foreign-bypass");
        assert_eq!(
            plan_discard(&changed_bypass, &backup),
            DiscardPlan::RefuseLiveEndpoint
        );

        let semantic_alias = state(1, "HTTP://127.42.7.9:56800", "foreign-bypass");
        assert_eq!(
            plan_discard(&semantic_alias, &backup),
            DiscardPlan::RefuseLiveEndpoint
        );

        let foreign = state(1, "http=127.0.0.1:20808", "foreign-bypass");
        assert_eq!(
            plan_discard(&foreign, &backup),
            DiscardPlan::RefuseForeignOrDisabled
        );
    }

    #[test]
    fn exact_original_wins_even_if_it_reuses_the_published_port() {
        let mut backup = owned_backup();
        backup.proxy_server = Some("http=127.0.0.1:56800".into());
        let current = state(1, "http=127.0.0.1:56800", "<local>");
        assert!(points_to_published_endpoint(&current, &backup));
        assert_eq!(
            plan_discard(&current, &backup),
            DiscardPlan::NotifyExactOriginal
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
