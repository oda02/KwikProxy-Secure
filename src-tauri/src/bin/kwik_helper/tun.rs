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

use anyhow::{bail, Result};
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
) -> Option<u32> {
    if !expect_tun {
        // Proxy-режим: TUN-адаптера быть не должно. Если от прошлой
        // TUN-сессии остался stale owned adapter (Mihomo умер
        // не успев его почистить, OperStatus всё ещё Up), мы НЕ должны
        // добавлять allow-фильтр для него — kill-switch получится с
        // мёртвым LUID, FwpmFilterAdd0 валит транзакцию целиком.
        // Просто возвращаем None, никакого scan'а.
        hlog("[helper-tun] current_tun_interface_index: proxy-режим, TUN-поиск пропущен");
        return None;
    }
    let expected_alias = expected_alias?;
    if !expected_alias.starts_with(TUN_NAME_PREFIX) {
        return None;
    }
    hlog("[helper-tun] current_tun_interface_index: TUN-режим, ищем активный адаптер");
    let max_attempts = 50;
    for attempt in 0..max_attempts {
        let alias = expected_alias.clone();
        let res = tokio::task::spawn_blocking(move || find_owned_tun_interface_index(&alias)).await;
        if let Ok(Some(idx)) = res {
            hlog(&format!(
                "[helper-tun] TUN-адаптер найден после {}мс retry, ifIndex={idx}",
                attempt * 100
            ));
            return Some(idx);
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    hlog("[helper-tun] TUN-адаптер не появился за 5с retry — kill-switch без TUN allow!");
    None
}

/// Кандидат-адаптер: индекс + alias + description (для логов).
#[derive(Debug, Clone)]
struct TunCandidate {
    if_index: u32,
    alias: String,
    description: String,
}

/// Synchronous lookup based only on the reserved product alias.
fn find_owned_tun_interface_index(expected_alias: &str) -> Option<u32> {
    let candidates = scan_owned_interfaces();
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.alias == expected_alias)?;
    hlog(&format!(
        "[helper-tun] exact owned adapter found: ifIndex={} alias={:?} desc={:?}",
        candidate.if_index, candidate.alias, candidate.description
    ));
    Some(candidate.if_index)
}

/// Enumerate only adapters bearing this fork's reserved alias prefix.
fn scan_owned_interfaces() -> Vec<TunCandidate> {
    let mut result = Vec::new();
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIfTable2(&mut table_ptr) };
    if ret != NO_ERROR || table_ptr.is_null() {
        hlog(&format!("[helper-tun] GetIfTable2 → код {ret}"));
        return result;
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
    result
}

/// `[u16; N]` с возможным null-terminator → `String`. Обрезает до
/// первого нулевого слова (если есть).
fn wide_z_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

/// Best-effort cleanup of adapters carrying this fork's exact ownership
/// marker. Legacy aliases and route-only heuristics are intentionally not
/// touched: neither proves that a resource belongs to this installation.
pub async fn cleanup_orphan_resources() {
    let wildcard = format!("{TUN_NAME_PREFIX}*");
    if let Err(error) = routing::cleanup_orphan_tun(&wildcard).await {
        eprintln!("[helper-tun] cleanup_orphan_tun({wildcard}) -> {error}");
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
    routing::cleanup_orphan_tun(name).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
