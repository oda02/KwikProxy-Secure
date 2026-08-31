//! Ownership-safe TUN discovery and orphan cleanup.
//!
//! TUN делает сам движок Mihomo через built-in inbound (tun2proxy spawn
//! давно выпилен). Этот модуль остался только для:
//!
//! Only the reserved `kwikproxy-secure-*` alias is treated as ownership
//! evidence. Generic descriptions, benchmark-range IPs and legacy prefixes
//! are deliberately ignored because another VPN may legitimately use them.
//!
//! `current_tun_interface_index()` finds the active adapter for the
//!    нашего движка для kill-switch'а (13.D step A). Без TUN allow-фильтра
//!    user-трафик идущий через TUN блокируется WFP block-all'ом — allow_app
//!    покрывает только sing-box/mihomo.exe (их собственные шифрованные
//!    пакеты к серверу, НЕ proxied user-трафик).
//! kill-switch. If the owned alias is absent it returns `None`, so the kill
//! switch fails safely without granting another product's adapter access.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

use super::helper_log::log as hlog;
use super::routing;

const TUN_NAME_PREFIX: &str = "kwikproxy-secure-";

/// Опер-статус «адаптер поднят и работает». MIB_IF_ROW2.OperStatus
/// принимает значения IfOperStatusUp=1, Down=2, Testing=3, ... — нам
/// нужна только Up. Значение из MS-документации.
const IF_OPER_STATUS_UP: i32 = 1;

/// Найти индекс активного TUN-адаптера НАШЕГО движка.
///
/// Если `expect_tun=false` (proxy-режим) — single-shot, мгновенный None.
/// Если `expect_tun=true` (TUN-режим) — retry до 5с (адаптер появляется
/// ~500ms-2s после спавна sing-box/mihomo через helper).
pub async fn current_tun_interface_index(
    expect_tun: bool,
    expected_alias: Option<String>,
) -> Result<Option<OwnedTunInterface>> {
    if !expect_tun {
        // Proxy-режим: TUN-адаптера быть не должно. Если от прошлой
        // TUN-сессии остался stale owned adapter (Mihomo умер
        // не успев его почистить, OperStatus всё ещё Up), мы НЕ должны
        // добавлять allow-фильтр для него — kill-switch получится с
        // мёртвым LUID, FwpmFilterAdd0 валит транзакцию целиком.
        // Просто возвращаем None, никакого scan'а.
        hlog("[helper-tun] current_tun_interface_index: proxy-режим, TUN-поиск пропущен");
        return Ok(None);
    }
    let expected_alias =
        expected_alias.ok_or_else(|| anyhow!("TUN mode requires an exact session-owned alias"))?;
    if !expected_alias.starts_with(TUN_NAME_PREFIX) {
        bail!("TUN alias does not use the reserved product prefix");
    }
    hlog("[helper-tun] current_tun_interface_index: TUN-режим, ищем активный адаптер");
    let max_attempts = 50;
    for attempt in 0..max_attempts {
        let alias = expected_alias.clone();
        let found = tokio::task::spawn_blocking(move || find_owned_tun_interface(&alias))
            .await
            .map_err(|error| anyhow!("owned TUN lookup task failed: {error}"))??;
        if let Some(interface) = found {
            hlog(&format!(
                "[helper-tun] TUN-адаптер найден после {}мс retry, ifIndex={}, luid=0x{:016x}",
                attempt * 100,
                interface.if_index,
                interface.luid,
            ));
            return Ok(Some(interface));
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    hlog("[helper-tun] TUN-адаптер не появился за 5с retry — kill-switch без TUN allow!");
    bail!("exact active session-owned TUN adapter did not appear within 5 seconds")
}

/// Кандидат-адаптер: индекс + alias + description (для логов).
#[derive(Debug, Clone)]
struct TunCandidate {
    if_index: u32,
    luid: u64,
    alias: String,
    description: String,
}

/// Synchronous lookup based only on the reserved product alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedTunInterface {
    pub if_index: u32,
    pub luid: u64,
}

fn find_owned_tun_interface(expected_alias: &str) -> Result<Option<OwnedTunInterface>> {
    let candidates = scan_owned_interfaces()?;
    let mut matches = candidates
        .iter()
        .filter(|candidate| candidate.alias == expected_alias);
    let Some(candidate) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        bail!("multiple active interfaces share the exact session-owned TUN alias");
    }
    let converted_luid = routing::luid_from_index(candidate.if_index)?;
    let identity = verify_candidate_identity(candidate, converted_luid)?;
    hlog(&format!(
        "[helper-tun] exact owned adapter found: ifIndex={} alias={:?} desc={:?}",
        candidate.if_index, candidate.alias, candidate.description
    ));
    Ok(Some(identity))
}

fn verify_candidate_identity(
    candidate: &TunCandidate,
    converted_luid: u64,
) -> Result<OwnedTunInterface> {
    if candidate.if_index == 0 || candidate.luid == 0 || converted_luid != candidate.luid {
        bail!(
            "TUN alias/index/LUID identity changed during lookup (ifIndex={}, rowLuid=0x{:016x}, convertedLuid=0x{:016x})",
            candidate.if_index,
            candidate.luid,
            converted_luid,
        );
    }
    Ok(OwnedTunInterface {
        if_index: candidate.if_index,
        luid: candidate.luid,
    })
}

/// Single ownership-safe readiness observation. Unlike
/// `current_tun_interface_index`, this does not hide a five-second retry loop,
/// so the Mihomo lifecycle can interleave adapter checks with child-exit
/// checks and fail immediately when the process terminates.
pub async fn owned_tun_interface_ready(expected_alias: &str) -> bool {
    if !expected_alias.starts_with(TUN_NAME_PREFIX) {
        return false;
    }
    let alias = expected_alias.to_string();
    tokio::task::spawn_blocking(move || find_owned_tun_interface(&alias).is_ok_and(|v| v.is_some()))
        .await
        .unwrap_or(false)
}

/// Enumerate only adapters bearing this fork's reserved alias prefix.
fn scan_owned_interfaces() -> Result<Vec<TunCandidate>> {
    let mut result = Vec::new();
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIfTable2(&mut table_ptr) };
    if ret != NO_ERROR || table_ptr.is_null() {
        hlog(&format!("[helper-tun] GetIfTable2 → код {ret}"));
        bail!("GetIfTable2 failed with code {ret}");
    }

    let table = unsafe { &*table_ptr };
    let entries =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };

    for entry in entries {
        if entry.OperStatus != IF_OPER_STATUS_UP {
            continue;
        }
        let alias = wide_z_to_string(&entry.Alias);
        let description = wide_z_to_string(&entry.Description);

        let alias_match = alias.starts_with(TUN_NAME_PREFIX);
        if alias_match {
            result.push(TunCandidate {
                if_index: entry.InterfaceIndex,
                luid: unsafe { entry.InterfaceLuid.Value },
                alias,
                description,
            });
        }
    }

    hlog(&format!(
        "[helper-tun] scan: owned={} (total interfaces={})",
        result.len(),
        table.NumEntries
    ));
    for c in &result {
        hlog(&format!(
            "  [OWNED kwikproxy-secure-] ifIndex={} alias={:?} desc={:?}",
            c.if_index, c.alias, c.description
        ));
    }

    unsafe { FreeMibTable(table_ptr as *mut _) };
    Ok(result)
}

/// `[u16; N]` с возможным null-terminator → `String`. Обрезает до
/// первого нулевого слова (если есть).
fn wide_z_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

/// Fail-closed startup cleanup of adapters carrying this fork's exact
/// ownership prefix. Legacy aliases and route-only heuristics are
/// intentionally not touched: neither proves product ownership. The helper
/// does not publish its pipe unless command success and all-status absence
/// verification both succeed.
pub async fn cleanup_orphan_resources() -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let still_present = tokio::task::spawn_blocking(owned_prefix_exists)
            .await
            .map_err(|error| anyhow!("owned TUN prefix check task failed: {error}"))??;
        if !still_present {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return cleanup_if_present(
                || Ok(true),
                || {
                    bail!(
                        "owned TUN adapter with the reserved prefix remains after bounded self-removal wait; safe Wintun orphan deletion is unavailable"
                    )
                },
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Remove only the exact adapter name recorded from the accepted Mihomo
/// configuration for the active session. Wildcards are forbidden here.
pub async fn cleanup_owned_device(name: &str) -> Result<()> {
    if !name.starts_with(TUN_NAME_PREFIX)
        || name.len() > 96
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("invalid exact owned TUN device identity");
    }
    // Mihomo/Wintun normally removes its adapter asynchronously while the
    // child is exiting. Give that ownership-safe path a short bounded window
    // before deciding that a real orphan remains.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let alias = name.to_string();
        let still_present = tokio::task::spawn_blocking(move || owned_alias_exists(&alias))
            .await
            .map_err(|error| anyhow!("owned TUN absence check task failed: {error}"))??;
        if !still_present {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return cleanup_if_present(
                || Ok(true),
                || {
                    bail!(
                    "exact owned TUN adapter still exists after bounded self-removal wait; safe Wintun orphan deletion is unavailable"
                )
                },
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Centralized fail-closed policy for an optional orphan-removal backend.
/// Keeping the presence decision explicit makes it impossible to launch a
/// cleanup command on the common clean/absent path.
fn cleanup_if_present<P, F>(presence_check: P, backend: F) -> Result<()>
where
    P: FnOnce() -> Result<bool>,
    F: FnOnce() -> Result<()>,
{
    if presence_check()? {
        backend()
    } else {
        Ok(())
    }
}

/// Exact absence verification scans every operational state. A removed or
/// disabled adapter must not disappear merely because readiness filters only
/// `IfOperStatusUp` entries.
fn owned_alias_exists(expected_alias: &str) -> Result<bool> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIfTable2(&mut table_ptr) };
    if ret != NO_ERROR || table_ptr.is_null() {
        bail!("GetIfTable2 failed with code {ret}");
    }
    let table = unsafe { &*table_ptr };
    let entries =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    let found = entries
        .iter()
        .any(|entry| wide_z_to_string(&entry.Alias) == expected_alias);
    unsafe { FreeMibTable(table_ptr as *mut _) };
    Ok(found)
}

fn owned_prefix_exists() -> Result<bool> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIfTable2(&mut table_ptr) };
    if ret != NO_ERROR || table_ptr.is_null() {
        bail!("GetIfTable2 failed with code {ret}");
    }
    let table = unsafe { &*table_ptr };
    let entries =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    let found = entries
        .iter()
        .any(|entry| wide_z_to_string(&entry.Alias).starts_with(TUN_NAME_PREFIX));
    unsafe { FreeMibTable(table_ptr as *mut _) };
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn wide_z_to_string_handles_null_terminator() {
        let mut buf: Vec<u16> = "kwikproxy-secure-1234".encode_utf16().collect();
        buf.push(0);
        // Дополняем мусором после null — должны его проигнорировать.
        buf.extend_from_slice(&[0xDEAD, 0xBEEF, 0]);
        assert_eq!(wide_z_to_string(&buf), "kwikproxy-secure-1234");
    }

    #[test]
    fn wide_z_to_string_handles_no_null() {
        let buf: Vec<u16> = "no-null".encode_utf16().collect();
        assert_eq!(wide_z_to_string(&buf), "no-null");
    }

    #[test]
    fn alias_prefix_const_is_lowercase_safe() {
        assert_eq!(TUN_NAME_PREFIX, "kwikproxy-secure-");
        assert!(!"kwik-1234".starts_with(TUN_NAME_PREFIX));
        assert!(!"nemefisto-1234".starts_with(TUN_NAME_PREFIX));
    }

    #[test]
    fn exact_cleanup_identity_rejects_wildcards_and_legacy_names() {
        assert!("kwikproxy-secure-owned"
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
        assert!(!"kwikproxy-secure-*"
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
        assert!(!"kwik-old".starts_with(TUN_NAME_PREFIX));
    }

    #[test]
    fn exact_alias_index_luid_gate_rejects_identity_drift() {
        let candidate = TunCandidate {
            if_index: 42,
            luid: 0x1234,
            alias: "kwikproxy-secure-owned".into(),
            description: "Wintun".into(),
        };
        assert_eq!(
            verify_candidate_identity(&candidate, 0x1234).unwrap(),
            OwnedTunInterface {
                if_index: 42,
                luid: 0x1234,
            }
        );
        assert!(verify_candidate_identity(&candidate, 0x9999).is_err());
    }

    #[test]
    fn absent_owned_adapter_never_launches_cleanup_backend() {
        let launched = Cell::new(false);
        let predicate_called = Cell::new(false);
        let result = cleanup_if_present(
            || {
                predicate_called.set(true);
                Ok(false)
            },
            || {
                launched.set(true);
                bail!("backend must not run")
            },
        );
        assert!(result.is_ok());
        assert!(predicate_called.get());
        assert!(!launched.get());
    }

    #[test]
    fn present_owned_adapter_fails_explicitly_without_safe_backend() {
        let launched = Cell::new(false);
        let predicate_called = Cell::new(false);
        let result = cleanup_if_present(
            || {
                predicate_called.set(true);
                Ok(true)
            },
            || {
                launched.set(true);
                bail!("safe Wintun orphan deletion is unavailable")
            },
        );
        assert!(predicate_called.get());
        assert!(launched.get());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("safe Wintun orphan deletion is unavailable"));
    }
}
