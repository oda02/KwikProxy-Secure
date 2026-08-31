//! Tauri commands, доступные из фронтенда через `invoke`.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use tokio::sync::Mutex as AsyncMutex;

/// Параметры активного kill-switch. Сохраняем при successful connect()
/// чтобы переиспользовать при live-toggle настройки kill-switch без
/// необходимости заново резолвить server_host и собирать app-paths.
#[derive(Clone, Debug)]
pub struct KillSwitchContext {
    pub server_ips: Vec<String>,
    pub allow_lan: bool,
    pub block_dns: bool,
    pub allow_dns_ips: Vec<String>,
    pub strict_mode: bool,
    /// 0.1.3: TUN-режим? Сохраняется чтобы live-toggle re-apply искал
    /// WinTUN-адаптер через retry в helper'е.
    pub expect_tun: bool,
    /// 14.D: блокировать весь IPv6 outbound пока VPN активен. Сохраняем
    /// в контексте для live-toggle (можно включать/выключать без
    /// disconnect/connect через kill_switch_apply).
    pub force_disable_ipv6: bool,
}

/// Tauri-state для контекста активного kill-switch. None = VPN не подключён.
pub struct KillSwitchState(pub AsyncMutex<Option<KillSwitchContext>>);

impl KillSwitchState {
    pub fn new() -> Self {
        Self(AsyncMutex::new(None))
    }
}

use crate::config::mihomo_config::{AntiDpiOptions, AppRule, MuxOptions};
use crate::config::subscription::{fetch_and_parse, SubscriptionMeta};
use crate::config::{mihomo_config, HwidState, ProxyEntry, SubscriptionState};
use crate::platform;
use crate::vpn;
use crate::vpn::{find_free_port, ping_entry, random_high_port, MihomoState};

// ─── Helper-функции для TUN-режима ────────────────────────────────────────────

/// Извлечь хост VPN-сервера из ProxyEntry. Используется для kill-switch
/// (резолв в IP перед включением WFP-фильтров) и для логов.
///
/// Логика повторяет `vpn::ping::extract_target`, возвращает только host
/// (без порта). Для `mihomo-profile` берём первую ноду из `raw["proxies"]`.
fn extract_server_host(entry: &ProxyEntry) -> Option<String> {
    if entry.protocol == "mihomo-profile" {
        return entry
            .raw
            .get("proxies")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|p| {
                    p.get("server")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                })
            });
    }
    if entry.protocol != "xray-json" {
        if entry.server.is_empty() {
            return None;
        }
        return Some(entry.server.clone());
    }
    let outbounds = entry.raw.get("outbounds")?.as_array()?;
    for ob in outbounds {
        let tag = ob.get("tag").and_then(|v| v.as_str()).unwrap_or("");
        if !tag.starts_with("proxy") {
            continue;
        }
        let proto = ob.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
        let settings = ob.get("settings")?;
        let host = match proto {
            "vless" | "vmess" => settings
                .get("vnext")?
                .as_array()?
                .first()?
                .get("address")?
                .as_str()?,
            "trojan" | "shadowsocks" => settings
                .get("servers")?
                .as_array()?
                .first()?
                .get("address")?
                .as_str()?,
            _ => continue,
        };
        return Some(host.to_string());
    }
    None
}

/// Дополнительные хосты VPN-серверов для bypass-route (mihomo-passthrough).
///
/// В full-mihomo подписке проксей бывает 10-20+. Пользователь может на
/// лету переключаться между ними через external-controller, и каждая —
/// отдельный удалённый хост. Если bypass добавлен только на primary
/// (`extract_server_host`), переключение на любую другую ноду сразу
/// заворачивает её исходящий трафик в TUN → петля.
///
/// Возвращает все хосты КРОМЕ primary (того, что вернул
/// Найти путь к sidecar-бинарю по короткому имени (`mihomo`).
/// Используется для kill-switch allow-app-id (этап 13.D) — нам нужно
/// разрешить нашему VPN-движку исходящий трафик.
///
/// Перебирает кандидаты в exe-dir / `binaries` / `resources` / dev
/// `target/{profile}/binaries`. `_app` пока не используется, но
/// зарезервирован под Tauri `app.path()` API.
fn resolve_sidecar_path(_app: &tauri::AppHandle, name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;

    let triplet = format!("{name}-x86_64-pc-windows-msvc.exe");
    let plain = format!("{name}.exe");

    let mut candidates: Vec<PathBuf> = vec![
        exe_dir.join(&triplet),
        exe_dir.join(&plain),
        exe_dir.join("binaries").join(&triplet),
        exe_dir.join("binaries").join(&plain),
        exe_dir.join("resources").join(&triplet),
        exe_dir.join("resources").join(&plain),
    ];
    if let Some(dev_root) = exe_dir.parent().and_then(|p| p.parent()) {
        candidates.push(dev_root.join("binaries").join(&triplet));
        candidates.push(dev_root.join("binaries").join(&plain));
    }

    candidates.into_iter().find(|c| c.is_file())
}

// ─── Результаты команд ────────────────────────────────────────────────────────

/// Возвращается фронтенду после успешного подключения.
///
/// `socks_username` / `socks_password` — заполнены только если включён
/// `auth: password` на SOCKS5 inbound (этап 9.G). Используется в LAN-
/// режиме чтобы UI показал креды для копирования; в TUN-режиме они
/// нужны только внутри движка (built-in TUN inbound движка не лезет
/// через SOCKS5) и пользователю не показываются.
#[derive(Serialize)]
pub struct ConnectResult {
    pub socks_port: u16,
    pub http_port: u16,
    pub server_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_password: Option<String>,
}

// ─── Подписка ─────────────────────────────────────────────────────────────────

/// Результат загрузки подписки: список серверов + опциональные метаданные
/// из стандартных HTTP-заголовков (этап 8.C).
#[derive(Serialize)]
pub struct SubscriptionResult {
    pub servers: Vec<ProxyEntry>,
    pub meta: Option<SubscriptionMeta>,
}

/// Скачать и распарсить подписку без изменения primary runtime state.
///
/// `hwid_override` — explicit advanced override. Otherwise an origin-scoped
/// pseudonym is derived from an app-local random secret; MachineGuid is never
/// read or transmitted.
/// `user_agent` — позволяет переопределить дефолт `clash-verge/v2.0.0`.
/// `send_hwid` — если false, заголовок `x-hwid` не отправляется.
#[tauri::command]
pub async fn fetch_subscription(
    url: String,
    hwid_override: Option<String>,
    user_agent: Option<String>,
    send_hwid: Option<bool>,
    hwid: State<'_, HwidState>,
    mihomo: State<'_, MihomoState>,
) -> Result<SubscriptionResult, String> {
    let send = send_hwid.unwrap_or(false);
    let explicit_hwid = hwid_override
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let effective_hwid = match explicit_hwid {
        Some(value) => value.to_string(),
        None if send => {
            crate::config::hwid::for_subscription(&hwid.0, &url).map_err(|e| e.to_string())?
        }
        None => String::new(),
    };

    let ua = user_agent.unwrap_or_default();

    let trusted_socks_port = mihomo.trusted_subscription_proxy_port();
    let (servers, meta) = fetch_and_parse(&url, &effective_hwid, &ua, send, trusted_socks_port)
        .await
        .map_err(|e| e.to_string())?;
    Ok(SubscriptionResult { servers, meta })
}

/// Вернуть закешированный список серверов без сетевого запроса.
#[tauri::command]
pub fn get_servers(sub: State<'_, SubscriptionState>) -> Vec<ProxyEntry> {
    sub.snapshot().0
}

/// Issue a fresh renderer epoch and invalidate runtime/cache sequences from a
/// previous WebView instance. This must run before hydration or connection.
#[tauri::command]
pub fn begin_subscription_epoch(sub: State<'_, SubscriptionState>) -> Result<String, String> {
    sub.begin_epoch().map_err(|error| error.to_string())
}

/// Заменить runtime-список серверов без сетевого запроса.
///
/// A monotonically increasing generation makes concurrent Tauri invokes
/// deterministic: an older primary can never overwrite a newer selection.
#[tauri::command]
pub fn set_servers(
    session_epoch: String,
    primary_id: String,
    servers: Vec<ProxyEntry>,
    meta: Option<SubscriptionMeta>,
    generation: u64,
    sub: State<'_, SubscriptionState>,
) -> Result<bool, String> {
    sub.commit(&session_epoch, &primary_id, generation, servers, meta)
        .map_err(|e| e.to_string())
}

/// Вернуть закешированные метаданные подписки (трафик, срок).
#[tauri::command]
pub fn get_subscription_meta(sub: State<'_, SubscriptionState>) -> Option<SubscriptionMeta> {
    sub.snapshot().1
}

/// Persist a successfully fetched, still-current subscription only after the
/// frontend generation check. The Rust cache sanitizer runs before DPAPI.
#[tauri::command]
pub fn save_subscription_cache(
    session_epoch: String,
    subscription_id: String,
    source_url: String,
    servers: Vec<ProxyEntry>,
    meta: Option<SubscriptionMeta>,
    generation: u64,
    sub: State<'_, SubscriptionState>,
) -> Result<bool, String> {
    sub.with_cache_generation(&session_epoch, &subscription_id, generation, || {
        crate::config::subscription_cache::save(&subscription_id, &source_url, servers, meta)
    })
    .map(|result| result.is_some())
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn load_subscription_cache(
    session_epoch: String,
    subscription_id: String,
    source_url: String,
    sub: State<'_, SubscriptionState>,
) -> Result<Option<SubscriptionResult>, String> {
    sub.validate_epoch(&session_epoch)
        .map_err(|error| error.to_string())?;
    crate::config::subscription_cache::load(&subscription_id, &source_url)
        .map(|record| {
            record.map(|record| SubscriptionResult {
                servers: record.servers,
                meta: record.meta,
            })
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_subscription_cache(
    session_epoch: String,
    subscription_id: String,
    generation: u64,
    sub: State<'_, SubscriptionState>,
) -> Result<(), String> {
    sub.with_cache_delete_generation(&session_epoch, &subscription_id, generation, || {
        crate::config::subscription_cache::delete(&subscription_id)
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

// ─── Подключение ──────────────────────────────────────────────────────────────

async fn rollback_connect(
    mihomo: &MihomoState,
    mihomo_api: &vpn::MihomoApiState,
    ks_ctx: &KillSwitchState,
    proxy_attempt_id: &str,
    cleanup_helper: bool,
) -> Result<(), String> {
    vpn::diagnostics::record("connect_rollback", "started", "post_spawn_failure");
    let mut errors = Vec::new();
    let mut privileged_cleanup_verified = !cleanup_helper;
    // Each stop is ownership-scoped: the local state owns only our sidecar,
    // and helper MihomoStop is authenticated/session-bound. No foreign VPN
    // process, adapter or proxy executable is selected by name.
    if cleanup_helper {
        privileged_cleanup_verified = true;
        if let Err(error) = platform::helper_client::mihomo_stop().await {
            errors.push(format!("stop protected Mihomo: {error:#}"));
            privileged_cleanup_verified = false;
        }
        if let Err(error) = platform::helper_client::kill_switch_disable().await {
            errors.push(format!("disable kill switch: {error:#}"));
            privileged_cleanup_verified = false;
        }
    }
    if cleanup_helper {
        match platform::helper_client::tunnel_status().await {
            Ok(status) if status.is_clear() => {}
            Ok(status) => {
                errors.push(format!(
                    "protected cleanup remains active after rollback (running={}, cleanup_pending={}, firewall_active={}, device_owned={})",
                    status.running,
                    status.cleanup_pending,
                    status.firewall_active,
                    status.device_owned,
                ));
                privileged_cleanup_verified = false;
            }
            Err(error) => {
                errors.push(format!("verify protected Mihomo stopped: {error:#}"));
                privileged_cleanup_verified = false;
            }
        }
    }
    if !privileged_cleanup_verified {
        // Preserve every visible ownership marker and the local engine/proxy.
        // A retrying disconnect can reconcile the authenticated helper later;
        // reporting stopped here would strand SYSTEM Mihomo or WFP silently.
        mihomo.mark_helper_spawned(true);
        mihomo.mark_privileged_cleanup_uncertain(true);
        vpn::diagnostics::record("connect_rollback", "error", "privileged_state_unknown");
        return Err(errors.join("; "));
    }
    mihomo.mark_privileged_cleanup_uncertain(false);
    mihomo.mark_helper_spawned(false);
    if let Err(error) = mihomo.stop() {
        errors.push(format!("stop local Mihomo: {error}"));
    }
    match platform::proxy::clear_system_proxy_owned(proxy_attempt_id) {
        Ok(true) => mihomo.clear_proxy_attempt(proxy_attempt_id),
        Ok(false) => errors.push("attempt-owned system proxy publication was not found".into()),
        Err(error) => errors.push(format!("restore attempt-owned system proxy: {error:#}")),
    }
    mihomo_api.clear();
    *ks_ctx.0.lock().await = None;
    if errors.is_empty() {
        vpn::diagnostics::record("connect_rollback", "ok", "verified_owned_state_cleared");
        Ok(())
    } else {
        vpn::diagnostics::record("connect_rollback", "error", "cleanup_incomplete");
        Err(errors.join("; "))
    }
}

async fn reconcile_privileged_before_tunnel_start() -> Result<(), String> {
    let before = platform::helper_client::tunnel_status()
        .await
        .map_err(|error| format!("query protected preflight status: {error:#}"))?;
    if before.is_clear() {
        return Ok(());
    }

    let mut errors = Vec::new();
    if let Err(error) = platform::helper_client::mihomo_stop().await {
        errors.push(format!("stop previous protected Mihomo: {error:#}"));
    }
    if let Err(error) = platform::helper_client::kill_switch_disable().await {
        errors.push(format!("disable previous protected kill switch: {error:#}"));
    }
    match platform::helper_client::tunnel_status().await {
        Ok(status) if status.is_clear() => {}
        Ok(status) => errors.push(format!(
            "protected preflight remains non-idle (running={}, cleanup_pending={}, firewall_active={}, device_owned={})",
            status.running,
            status.cleanup_pending,
            status.firewall_active,
            status.device_owned,
        )),
        Err(error) => errors.push(format!("verify protected preflight cleanup: {error:#}")),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn append_rollback_error(primary: String, rollback: Result<(), String>) -> String {
    match rollback {
        Ok(()) => primary,
        Err(cleanup) => format!("{primary}; rollback incomplete: {cleanup}"),
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::append_rollback_error;

    #[test]
    fn cleanup_failures_are_not_reported_as_success() {
        assert_eq!(
            append_rollback_error("connect failed".into(), Ok(())),
            "connect failed"
        );
        let message = append_rollback_error(
            "connect failed".into(),
            Err("protected Mihomo is still running".into()),
        );
        assert!(message.contains("rollback incomplete"));
        assert!(message.contains("still running"));
    }
}

/// Подключиться к серверу с указанным индексом в режиме `mode`.
///
/// `mode` = "proxy" — системный SOCKS5 + HTTP прокси через реестр.
/// `mode` = "tun"   — built-in TUN inbound движка Mihomo через
///                   helper-сервис SYSTEM-spawn. WinTUN-адаптер создаётся
///                   самим движком, отдельный tun2socks не нужен.
/// `allow_lan` — если `Some(true)`, inbound слушает 0.0.0.0 вместо 127.0.0.1.
///
/// Автоматически находит свободные порты начиная с 1080/1087.
#[allow(clippy::too_many_arguments)]
// IPC-команда: Tauri маппит каждый аргумент по имени из фронта — struct сломал бы вызовы
#[tauri::command]
pub async fn connect(
    server_index: usize,
    subscription_epoch: String,
    subscription_id: String,
    subscription_generation: u64,
    mode: String,
    engine: Option<String>,
    allow_lan: Option<bool>,
    anti_dpi: Option<AntiDpiOptions>,
    tun_masking: Option<bool>,
    kill_switch: Option<bool>,
    // 13.D step B: блокировка DNS-leak (UDP/TCP 53 кроме VPN-DNS).
    // По дефолту off — может ломать приложения в proxy-режиме.
    dns_leak_protection: Option<bool>,
    // 13.S strict mode для kill-switch: убирает общий allow-app для xray/mihomo,
    // оставляет только allow на server_ips. Direct outbound xray блокируется.
    kill_switch_strict: Option<bool>,
    // 14.D: принудительно блокировать весь IPv6 outbound пока VPN активен.
    // Защита от утечек на dual-stack ISP. Helper пропускает все v6 allow-фильтры.
    force_disable_ipv6: Option<bool>,
    // Устаревшая опция mux от sing-box-движка. Mihomo её не использует —
    // принимаем для совместимости IPC-контракта и молча игнорируем.
    mux: Option<MuxOptions>,
    // 13.Q: если активного routing-профиля нет — применять встроенный
    // минимальный RU-шаблон (geosite:ru → DIRECT, ads → BLOCK).
    auto_apply_minimal_ru_rules: Option<bool>,
    app_rules: Option<Vec<AppRule>>,
    // #4: разрешить IPv6 в конфиге mihomo (root + dns). По умолчанию false —
    // анти-leak. Не путать с `force_disable_ipv6` (WFP-блокировка v6 на уровне
    // kill-switch): тот режет v6 в файрволе, этот управляет v6 внутри ядра.
    ipv6: Option<bool>,
    // #3: пользовательские DNS-серверы из настроек (DoH-URL или IP). Высший
    // приоритет для `dns.nameserver`. Пусто/None → дефолтная логика.
    custom_dns: Option<Vec<String>>,
    app: tauri::AppHandle,
    mihomo: State<'_, MihomoState>,
    mihomo_api: State<'_, vpn::MihomoApiState>,
    sub: State<'_, SubscriptionState>,
    ks_ctx: State<'_, KillSwitchState>,
    routing_store: State<'_, crate::config::routing_store::RoutingStoreState>,
) -> Result<ConnectResult, String> {
    let _lifecycle = platform::lifecycle::enter().await?;
    vpn::diagnostics::record("connect", "started", "request_received");
    // Долг: TUN 15-секундная задержка первого запроса. Включаем
    // подробное timing-логирование connect-flow чтобы видеть где
    // именно gap. После накопления логов — оптимизируем узкое место
    // (warmup, helper round-trip, tun_start, и т.д.).
    let connect_start = std::time::Instant::now();
    let proxy_attempt_id = uuid::Uuid::new_v4().to_string();
    let stamp = |label: &str| {
        let elapsed = connect_start.elapsed().as_millis();
        eprintln!("[connect-timing][+{elapsed}ms] {label}");
    };
    stamp("start");

    platform::helper_bootstrap::ensure_running()
        .await
        .map_err(|error| format!("helper-сервис недоступен: {error}"))?;
    if mode == "tun" {
        reconcile_privileged_before_tunnel_start().await?;
    } else {
        let status = platform::helper_client::tunnel_status()
            .await
            .map_err(|error| format!("protected runtime status is unknown: {error:#}"))?;
        if status.is_active_or_pending() {
            return Err(format!(
                "protected runtime must be disconnected before proxy connect (running={}, cleanup_pending={}, firewall_active={}, device_owned={})",
                status.running,
                status.cleanup_pending,
                status.firewall_active,
                status.device_owned,
            ));
        }
    }

    // Pre-flight self-healing: если в системе остались наши orphan'ы от
    // упавшей сессии (системный прокси указывает на наш диапазон портов
    // или есть half-default routes), молча чистим перед connect. Иначе
    // следующий xray встретит «сломанную» среду и сам сломается.
    if platform::proxy::has_pending_backup() {
        match platform::proxy::restore_pending_owned_proxy() {
            Ok(true) => {}
            Ok(false) => return Err("previous owned proxy publication disappeared".into()),
            Err(error) => return Err(format!("restore previous proxy publication: {error:#}")),
        }
        stamp("preflight: restored orphan proxy backup");
    }

    // Клонируем ProxyEntry, чтобы сразу освободить lock на список серверов
    let entry = {
        let servers = sub
            .snapshot_for_connect(
                &subscription_epoch,
                &subscription_id,
                subscription_generation,
            )
            .map_err(|error| error.to_string())?;
        servers.get(server_index).cloned().ok_or_else(|| {
            format!(
                "сервер #{server_index} не найден в списке (всего серверов: {}). \
                 обновите подписку и выберите сервер заново",
                servers.len()
            )
        })?
    };

    // Mihomo-only: единственный движок. Параметры `engine` и `mux` из
    // фронта оставлены для совместимости IPC-контракта, но фактически
    // не используются. Проверяем что сервер совместим с mihomo.
    let _ = engine;
    let _ = &mux;
    if !entry.engine_compat.iter().any(|e| e == "mihomo") {
        return Err(format!(
            "сервер «{}» несовместим с движком mihomo; поддерживается: {}",
            entry.name,
            entry.engine_compat.join(", ")
        ));
    }

    // Mihomo built-in TUN теперь работает и для URI/base64-серверов:
    // `mihomo_config::build` синтезирует `tun:` секцию (раньше TUN был
    // только для full mihomo-profile подписок). Ограничения нет —
    // mihomo сам поднимает WinTUN для любого proxy-конфига.

    // 9.H — рандомизация портов inbound. Старт с псевдослучайных значений
    // в диапазоне [30000, 60000) вместо фиксированных 1080/1087, чтобы
    // сторонний процесс на машине не мог дёшево детектнуть VPN-клиент
    // сканированием стандартных портов. См. https://habr.com/ru/news/1020902/.
    // У Mihomo один mixed-port на SOCKS5+HTTP — одно значение на оба "порта".
    let default_socks = find_free_port(random_high_port());
    let lan = allow_lan.unwrap_or(false);
    let listen = if lan { "0.0.0.0" } else { "127.0.0.1" };
    let tun_mode = mode == "tun";

    // 9.G — SOCKS5/HTTP inbound auth. Включаем для TUN-режима всегда
    // (защита от использования прокси посторонними процессами на машине)
    // и для LAN-режима (защита от любого устройства в Wi-Fi сети). В
    // loopback proxy-режиме оставляем noauth — Windows registry для
    // системного прокси не умеет user:pass@host:port, и браузеры будут
    // получать 407 auth challenge на каждый запрос.
    let socks_auth = if tun_mode || lan {
        let pass = uuid::Uuid::new_v4().to_string();
        Some(("kwik".to_string(), pass))
    } else {
        None
    };

    // A globally unique product prefix is the ownership marker used by the
    // privileged helper. Generic/masqueraded names cannot be cleaned up or
    // selected safely because they may belong to another VPN client.
    let _ = tun_masking; // retained in the public API for settings compatibility
    let tun_device: Option<String> = if tun_mode {
        Some(format!(
            "kwikproxy-secure-{}",
            uuid::Uuid::new_v4().simple()
        ))
    } else {
        None
    };

    // Mihomo: YAML с mixed-port; mihomo built-in TUN если подписка пришла
    // как полный mihomo-profile (в URI-режиме TUN запрещён — см. валидацию
    // выше).
    let (socks_port, http_port) = {
        let auth_pair = socks_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        // 8.D: per-process правила. Mihomo получает их через
        // PROCESS-NAME matcher. Xray-ветка ниже их игнорирует —
        // на Windows нет нативной поддержки в Xray (требует kernel-driver,
        // см. план 13.G WFP per-app routing).
        let rules_slice: &[AppRule] = app_rules.as_deref().unwrap_or(&[]);
        // 11.F + 13.Q: активный routing-профиль или встроенный
        // минимальный RU-шаблон (если включён toggle и активного нет).
        let active_profile = routing_store
            .inner
            .lock()
            .ok()
            .and_then(|g| g.active().map(|e| e.profile.clone()))
            .or_else(|| {
                if auto_apply_minimal_ru_rules.unwrap_or(false) {
                    Some(crate::config::routing_profile::RoutingProfile::minimal_ru())
                } else {
                    None
                }
            });
        // 8.F: full-mihomo-passthrough путь. Если в подписке прилетел
        // полный mihomo YAML с proxy-groups — используем его целиком,
        // патчем только наши inbound/auth/external-controller.
        // Иначе — старый путь сборки конфига из ProxyEntry.
        let controller_port = find_free_port(default_socks.saturating_add(1));
        let controller_secret = uuid::Uuid::new_v4().to_string();
        // #4/#3: IPv6-тоггл и пользовательский DNS из настроек.
        let ipv6_enabled = ipv6.unwrap_or(false);
        let custom_dns_slice: Option<&[String]> = custom_dns.as_deref();

        let cfg = if entry.protocol == "mihomo-profile" {
            // raw["yaml"] всегда есть для mihomo-profile (см. subscription.rs)
            let raw_yaml = entry
                .raw
                .get("yaml")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "mihomo-profile без raw.yaml".to_string())?;
            // 13.L: для mihomo-profile в TUN-режиме используем mihomo
            // built-in TUN — он сам управляет адаптером и обходит свой
            // же direct outbound. Без этого петли между half-routes
            // через TUN и mihomo's DIRECT неизбежны.
            //
            // В proxy-режиме (без TUN) — обычный mixed-server на
            // loopback, helper не вовлечён.
            let use_builtin_tun = tun_mode;
            let patch = mihomo_config::FullYamlPatch {
                mixed_port: default_socks,
                listen,
                socks_auth: auth_pair,
                external_controller_port: controller_port,
                external_controller_secret: &controller_secret,
                app_rules: rules_slice,
                anti_dpi: anti_dpi.as_ref(),
                use_builtin_tun,
                tun_device: tun_device.as_deref(),
                routing_profile: active_profile.as_ref(),
                ipv6: ipv6_enabled,
                custom_dns: custom_dns_slice,
            };
            mihomo_config::patch_full_yaml(raw_yaml, &patch)
                .map_err(|e| format!("патч full-mihomo YAML: {e:#}"))?
        } else {
            // URI/base64-сервер: built-in TUN если запрошен TUN-режим
            // (mihomo_config::build синтезирует tun-секцию). Ownership
            // имени адаптера задаётся через app-generated tun_device.
            mihomo_config::build(
                &entry,
                default_socks,
                listen,
                anti_dpi.as_ref(),
                auth_pair,
                rules_slice,
                active_profile.as_ref(),
                tun_mode,
                tun_device.as_deref(),
                ipv6_enabled,
                custom_dns_slice,
                controller_port,
                &controller_secret,
            )
            .map_err(|e| e.to_string())?
        };

        // 13.L: для built-in TUN запускаем mihomo через helper-сервис
        // (он SYSTEM, имеет права на CreateAdapter WinTUN). Tauri-main
        // как user-level не справится. Иначе — старый sidecar-spawn.
        // TUN теперь поддержан и для URI-серверов, поэтому условие —
        // просто tun_mode (а не только mihomo-profile).
        let builtin_tun = tun_mode;
        if builtin_tun {
            // The helper was already reconciled before any engine spawn.
            mihomo
                .stop()
                .map_err(|error| format!("stop previous local Mihomo: {error}"))?;

            if let Err(error) = platform::helper_client::start_tunnel(cfg.yaml.clone(), lan).await {
                vpn::diagnostics::record("tun_readiness", "error", "helper_rejected");
                let rollback =
                    rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, tun_mode)
                        .await;
                return Err(append_rollback_error(
                    format!("helper.start_tunnel: {error}"),
                    rollback,
                ));
            }
            mihomo.mark_helper_spawned(true);
            // mixed_port запоминаем для is_xray_running и др.
            match mihomo.mixed_port.lock() {
                Ok(mut port) => *port = cfg.mixed_port,
                Err(error) => {
                    let message = format!("mutex: {error}");
                    drop(error);
                    let rollback = rollback_connect(
                        &mihomo,
                        &mihomo_api,
                        &ks_ctx,
                        &proxy_attempt_id,
                        tun_mode,
                    )
                    .await;
                    return Err(append_rollback_error(message, rollback));
                }
            }
            vpn::diagnostics::record("tun_readiness", "ok", "helper_ready");
            stamp("mihomo built-in TUN: spawned via helper");
        } else {
            if let Err(error) = mihomo
                .start_with_config(&app, &cfg.yaml, cfg.mixed_port, controller_port)
                .await
            {
                vpn::diagnostics::record("proxy_readiness", "error", "sidecar_not_ready");
                let rollback =
                    rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, false).await;
                return Err(append_rollback_error(error, rollback));
            }
        }

        // 8.F: сохраняем endpoint controller'а — UI достучится через
        // mihomo_proxies / mihomo_select_proxy / mihomo_delay_test.
        mihomo_api.set(vpn::ControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port: controller_port,
            secret: controller_secret,
        });

        (cfg.mixed_port, cfg.mixed_port)
    };

    stamp("vpn engine started");

    match mode.as_str() {
        "proxy" => {
            if let Err(error) =
                mihomo.set_system_proxy_if_running(socks_port, http_port, &proxy_attempt_id)
            {
                vpn::diagnostics::record("system_proxy", "error", "publication_failed");
                let rollback =
                    rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, false).await;
                return Err(append_rollback_error(error, rollback));
            }
            vpn::diagnostics::record("system_proxy", "ok", "published");
            stamp("system proxy set");
        }
        "tun" => {
            // TUN всегда через built-in TUN-inbound Mihomo. Работает и для
            // full mihomo-profile (tun: enable в YAML), и для URI/base64-
            // серверов (tun-секция синтезируется в mihomo_config::build).
            stamp("tun: built-in TUN — движок сам поднимает WinTUN-адаптер");
        }
        other => {
            let rollback =
                rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, tun_mode).await;
            return Err(append_rollback_error(
                format!("неизвестный режим: {other}"),
                rollback,
            ));
        }
    }

    // 13.D — kill switch (настоящий WFP). Поднимаем ПОСЛЕ успешного
    // Xray/TUN — чтобы при ошибке connect не оставить пользователя с
    // заблокированным интернетом.
    if kill_switch.unwrap_or(false) {
        let server_host = extract_server_host(&entry).unwrap_or_else(|| entry.server.clone());

        // Резолвим server_host в IP-адреса ЗДЕСЬ — после включения kill-switch'а
        // DNS уйдёт через VPN-туннель, а его ещё нет (helper-сервис в SYSTEM
        // получит маршруты позже). Если IP в host_str — lookup_host вернёт
        // его как есть.
        let server_ips: Vec<String> = tokio::net::lookup_host(format!("{server_host}:0"))
            .await
            .map(|iter| iter.map(|sa| sa.ip().to_string()).collect())
            .unwrap_or_default();
        if server_ips.is_empty() {
            // Fallback — может быть literal IP без формата host:port.
            // Пробуем парсить напрямую.
            if server_host.parse::<std::net::IpAddr>().is_ok() {
                // ОК
            } else {
                let rollback =
                    rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, tun_mode)
                        .await;
                return Err(append_rollback_error(
                    format!("kill switch: не удалось резолвить server_host={server_host}"),
                    rollback,
                ));
            }
        }
        let server_ips = if server_ips.is_empty() {
            vec![server_host.clone()]
        } else {
            server_ips
        };

        // Гарантируем что helper-сервис запущен (если не активен TUN-режим
        // — у нас не было ensure_running).
        if !tun_mode {
            if let Err(e) = platform::helper_bootstrap::ensure_running().await {
                let rollback =
                    rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, false).await;
                return Err(append_rollback_error(
                    format!("kill switch: helper-сервис недоступен: {e}"),
                    rollback,
                ));
            }
        }
        // 13.D step B: DNS-leak protection. В TUN-режиме разрешаем
        // только VPN-DNS на TUN-gateway (198.18.0.1) — остальной :53
        // блокируется. В proxy-режиме `allow_dns_ips=[]` — пользователь
        // ОЧЕНЬ должен понимать что делает (приложения сломаются если
        // не используют системный прокси для DNS).
        let block_dns = dns_leak_protection.unwrap_or(false);
        let allow_dns_ips: Vec<String> = if block_dns && tun_mode {
            vec!["198.18.0.1".to_string()]
        } else {
            Vec::new()
        };
        let strict = kill_switch_strict.unwrap_or(false);
        let disable_v6 = force_disable_ipv6.unwrap_or(false);

        if let Err(e) = platform::helper_client::kill_switch_enable(
            server_ips.clone(),
            lan,
            block_dns,
            allow_dns_ips.clone(),
            strict,
            tun_mode,
            disable_v6,
        )
        .await
        {
            // При ошибке откатываем всё — интернет НЕ должен оставаться
            // в полу-заблокированном состоянии.
            let rollback =
                rollback_connect(&mihomo, &mihomo_api, &ks_ctx, &proxy_attempt_id, true).await;
            return Err(append_rollback_error(
                format!("kill switch не поднялся: {e}"),
                rollback,
            ));
        }

        // Сохраняем контекст для live-toggle — пользователь может
        // переключать kill-switch в Settings без disconnect/connect.
        // `kill_switch_apply` команда читает это и заново применяет
        // / снимает фильтры с теми же параметрами.
        *ks_ctx.0.lock().await = Some(KillSwitchContext {
            server_ips,
            allow_lan: lan,
            block_dns,
            allow_dns_ips,
            strict_mode: strict,
            expect_tun: tun_mode,
            force_disable_ipv6: disable_v6,
        });
        stamp("kill_switch enabled");
    }

    stamp("connect done");
    vpn::diagnostics::record("connect", "ok", "ready");
    mihomo.set_subscription_proxy_port(if mode == "proxy" && !lan {
        Some(socks_port)
    } else {
        None
    });

    // В UI возвращаем креды только в LAN-режиме — там клиенты должны
    // ввести их вручную. В TUN-режиме они нужны только внутри движка
    // (built-in TUN не использует наш SOCKS5); в proxy-режиме их
    // вообще нет (loopback noauth).
    let (resp_user, resp_pass) = if lan {
        match socks_auth {
            Some((u, p)) => (Some(u), Some(p)),
            None => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(ConnectResult {
        socks_port,
        http_port,
        server_name: entry.name,
        socks_username: resp_user,
        socks_password: resp_pass,
    })
}

/// Отключиться: остановить TUN (если был активен), Xray, сбросить системный
/// прокси, выключить kill switch (если был активен).
///
/// Privileged cleanup is reconciled and verified before local ownership
/// markers are cleared. If helper status is unknown, the command fails while
/// retaining visible state so a later disconnect can retry safely.
#[tauri::command]
pub async fn disconnect(
    mihomo: State<'_, MihomoState>,
    mihomo_api: State<'_, vpn::MihomoApiState>,
    ks_ctx: State<'_, KillSwitchState>,
) -> Result<(), String> {
    let _lifecycle = platform::lifecycle::enter().await?;
    let helper_owned = mihomo.helper_spawned();
    let firewall_owned = ks_ctx.0.lock().await.is_some();
    let mut errors = Vec::new();
    let mut privileged_errors = Vec::new();
    let initial_status = match platform::helper_client::tunnel_status().await {
        Ok(status) => Some(status),
        Err(error) => {
            privileged_errors.push(format!(
                "protected disconnect status was initially unknown: {error:#}"
            ));
            None
        }
    };
    let reconcile_privileged = initial_status
        .as_ref()
        .is_none_or(|status| status.is_active_or_pending())
        || helper_owned
        || firewall_owned
        || mihomo.privileged_cleanup_uncertain();
    let mut privileged_cleanup_verified = initial_status
        .as_ref()
        .is_some_and(|status| status.is_clear());
    if reconcile_privileged {
        privileged_cleanup_verified = false;
        if let Err(error) = platform::helper_client::mihomo_stop().await {
            privileged_errors.push(format!("stop protected Mihomo: {error:#}"));
        }
        if let Err(error) = platform::helper_client::kill_switch_disable().await {
            privileged_errors.push(format!("disable kill switch: {error:#}"));
        }
        match platform::helper_client::tunnel_status().await {
            Ok(status) if status.is_clear() => privileged_cleanup_verified = true,
            Ok(status) => privileged_errors.push(format!(
                "protected cleanup remains active (running={}, cleanup_pending={}, firewall_active={}, device_owned={})",
                status.running,
                status.cleanup_pending,
                status.firewall_active,
                status.device_owned,
            )),
            Err(error) => privileged_errors
                .push(format!("verify protected Mihomo stopped: {error:#}")),
        }
        errors.extend(platform::lifecycle::unresolved_cleanup_errors(
            privileged_cleanup_verified,
            privileged_errors,
        ));
    }

    // Local proxy cleanup is independent from helper reachability. Restore
    // the exact attempt-owned WinINet write-set while its listener is still
    // alive; only then stop the local child. A failed restore deliberately
    // keeps the listener alive instead of creating a dead loopback proxy.
    let mut local_cleanup_verified = true;
    if let Some(attempt_id) = mihomo.proxy_attempt_id() {
        match platform::proxy::clear_system_proxy_owned(&attempt_id) {
            Ok(true) => mihomo.clear_proxy_attempt(&attempt_id),
            Ok(false) => {
                local_cleanup_verified = false;
                errors.push("attempt-owned system proxy publication was not found".into());
            }
            Err(error) => {
                local_cleanup_verified = false;
                errors.push(format!("restore attempt-owned system proxy: {error:#}"));
            }
        }
    }
    if local_cleanup_verified {
        if let Err(error) = mihomo.stop() {
            local_cleanup_verified = false;
            errors.push(format!("stop local Mihomo: {error}"));
        }
    } else {
        errors.push("local Mihomo retained because its system proxy could not be restored".into());
    }

    if privileged_cleanup_verified {
        mihomo.mark_helper_spawned(false);
        mihomo.mark_privileged_cleanup_uncertain(false);
        *ks_ctx.0.lock().await = None;
    } else {
        mihomo.mark_helper_spawned(true);
        mihomo.mark_privileged_cleanup_uncertain(true);
        vpn::diagnostics::record("disconnect", "error", "privileged_state_unknown");
    }
    if privileged_cleanup_verified && local_cleanup_verified {
        mihomo_api.clear();
    }

    if errors.is_empty() {
        vpn::diagnostics::record("disconnect", "ok", "verified_owned_state_cleared");
        Ok(())
    } else {
        vpn::diagnostics::record("disconnect", "error", "cleanup_incomplete");
        Err(format!(
            "disconnect cleanup incomplete: {}",
            errors.join("; ")
        ))
    }
}

/// Запущен ли VPN-движок (Mihomo) прямо сейчас.
///
/// Имя оставлено `is_xray_running` для совместимости с фронтом —
/// возвращает true если движок Mihomo запущен или privileged cleanup ещё
/// pending. Ошибка helper transport/auth возвращается как rejected IPC
/// Result, а не маскируется под `false`.
#[tauri::command]
pub async fn is_xray_running(
    mihomo: State<'_, MihomoState>,
    mihomo_api: State<'_, vpn::MihomoApiState>,
) -> Result<bool, String> {
    if !mihomo.helper_spawned() && mihomo.is_running() {
        // A tracked user-side sidecar needs no privileged round trip.
        return Ok(true);
    }
    match platform::helper_client::tunnel_status().await {
        Ok(status) if status.is_active_or_pending() => {
            // Also adopts a protected child left by a previous UI process:
            // in-memory ownership markers do not survive a UI crash/restart.
            mihomo.mark_helper_spawned(true);
            mihomo.mark_privileged_cleanup_uncertain(status.cleanup_pending);
            vpn::diagnostics::record(
                "tun_child",
                if status.cleanup_pending {
                    "error"
                } else {
                    "ok"
                },
                if status.cleanup_pending {
                    "cleanup_pending"
                } else {
                    "running_reconciled"
                },
            );
            Ok(true)
        }
        Ok(_) => {
            mihomo.mark_helper_spawned(false);
            mihomo.mark_privileged_cleanup_uncertain(false);
            // Clearing the helper domain must not erase a tracked local
            // child or an exact-PID local termination uncertainty. Re-read
            // after dropping the helper marker so `is_running` reflects only
            // the independent local domain.
            if mihomo.is_running() {
                vpn::diagnostics::record("proxy_child", "error", "local_state_retained");
                Ok(true)
            } else {
                mihomo_api.clear();
                vpn::diagnostics::record("tun_child", "error", "not_running");
                Ok(false)
            }
        }
        Err(error) => {
            // A fresh UI has no durable in-process marker. Transport/auth
            // failure therefore remains an explicit unknown error, never a
            // false stopped result that would permit a new connect.
            if mihomo.helper_spawned() || mihomo.privileged_cleanup_uncertain() {
                mihomo.mark_privileged_cleanup_uncertain(true);
            }
            vpn::diagnostics::record("tun_child", "error", "status_unknown");
            Err(format!("protected tunnel status is unknown: {error:#}"))
        }
    }
}

/// Обновить tray-icon под текущий VPN-статус (этап 13.A).
///
/// Фронт вызывает при каждом изменении `vpnStore.status`. Backend
/// меняет текст пункта «Подключить/Отключить» в меню трея и tooltip
/// иконки. Фронт также сообщает имя выбранного сервера и есть ли
/// вообще выбор — по этому решаем enabled-state кнопки.
#[tauri::command]
pub fn tray_set_status(
    status: String,
    server_name: Option<String>,
    has_selection: bool,
    app: tauri::AppHandle,
) -> Result<(), String> {
    platform::tray::set_status(&app, &status, server_name.as_deref(), has_selection)
}

// ─── Kill-switch (13.D) ─────────────────────────────────────────────────────

/// Heartbeat для kill-switch watchdog. Фронт зовёт каждые ~20 сек
/// пока vpn running и kill-switch включён. Helper использует это
/// чтобы понять «main жив» — иначе через 60 сек авто-disable фильтры.
/// Не падает если helper не отвечает — это не критично, при
/// нескольких подряд misses сработает watchdog.
#[tauri::command]
pub async fn kill_switch_heartbeat() -> Result<(), String> {
    platform::helper_client::kill_switch_heartbeat()
        .await
        .map_err(|e| e.to_string())
}

/// Полный network recovery — одной кнопкой починить всё, что мы
/// могли натворить.
///
/// 1. WFP-фильтры (наш provider GUID) — через helper.
/// 2. orphan TUN-адаптеры и half-default routes — через helper.
/// 3. Системный прокси — hardened force-clear через двойной щит.
///
/// Каждый шаг независимый: ошибка одного не отменяет других. Возвращает
/// summary что удалось / не удалось — фронт показывает в toast.
///
/// Безопасно вызывать только когда VPN не активен. UI-кнопку показываем
/// в Settings, активную только в `status === "stopped"`.
#[derive(Serialize)]
pub struct RecoveryReport {
    pub kill_switch_cleaned: bool,
    pub orphan_resources_cleaned: bool,
    pub system_proxy_cleared: bool,
    /// Список ошибок шагов которые не отработали — UI покажет в toast.
    pub errors: Vec<String>,
}

#[tauri::command]
pub async fn recover_network() -> RecoveryReport {
    let mut report = RecoveryReport {
        kill_switch_cleaned: false,
        orphan_resources_cleaned: false,
        system_proxy_cleared: false,
        errors: Vec::new(),
    };
    let _lifecycle = match platform::lifecycle::enter().await {
        Ok(guard) => guard,
        Err(error) => {
            report.errors.push(error);
            return report;
        }
    };

    // Helper нужен для шагов 1+2. Если не доступен — пропускаем их и
    // продолжаем с шагом 3, который независим (registry HKCU).
    let helper_alive = platform::helper_bootstrap::ensure_running().await.is_ok();

    if helper_alive {
        match platform::helper_client::kill_switch_force_cleanup().await {
            Ok(()) => report.kill_switch_cleaned = true,
            Err(e) => report.errors.push(format!("kill switch cleanup: {e}")),
        }
        match platform::helper_client::orphan_cleanup().await {
            Ok(()) => report.orphan_resources_cleaned = true,
            Err(e) => report.errors.push(format!("orphan cleanup: {e}")),
        }
    } else {
        report
            .errors
            .push("helper-сервис недоступен: пропустили WFP/TUN cleanup".to_string());
    }

    match platform::proxy::restore_pending_owned_proxy() {
        Ok(restored) => report.system_proxy_cleared = restored,
        Err(e) => report.errors.push(format!("system proxy: {e}")),
    }

    report
}

/// 14.E — диагностика остатков прошлой сессии для расширенного
/// `CrashRecoveryDialog`. Один вызов на старте app — фронт решает
/// показывать ли диалог.
///
/// Сигналы:
/// - `was_crashed` — lockfile существовал но PID мёртв (значит прошлая
///   сессия не вышла чисто);
/// - `proxy_orphan` — в реестре HKCU прокси указывает на наш паттерн
///   (`127.0.0.1:port` где port в нашем диапазоне);
/// - `proxy_backup_present` — есть `proxy_backup.json` от прошлого
///   `set_system_proxy`, можно сделать restore;
/// - `tun_orphan` — есть адаптер с префиксом `kwikproxy-secure-` (helper
///   обычно их сам чистит при старте, но если helper-сервис не
///   запущен — остаются).
///
/// Если все пять false — фронт диалог не показывает.
///
/// 14.E: добавлено поле `orphan_wfp_filters` — best-effort проверка
/// через helper-сервис. Если helper не запущен или не отвечает —
/// возвращаем false (значит проверить нельзя, лучше не пугать
/// пользователя ложным сигналом).
#[derive(Serialize)]
pub struct RecoveryState {
    pub was_crashed: bool,
    pub proxy_orphan: bool,
    pub proxy_backup_present: bool,
    pub tun_orphan: bool,
    pub orphan_wfp_filters: bool,
}

fn sanitized_proxy_recovery_metadata(backup: &platform::proxy::ProxyBackup) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "has_attempt_token": backup.attempt_id.as_deref().is_some_and(|v| !v.is_empty()),
        "has_exact_publication": backup.published_proxy_server.as_deref().is_some_and(|v| !v.is_empty()),
        "has_exact_bypass": backup.published_proxy_override.as_deref().is_some_and(|v| !v.is_empty()),
        "original_proxy_enabled": backup.proxy_enable == Some(1),
        "original_proxy_server_present": backup.proxy_server.is_some(),
        "original_proxy_override_present": backup.proxy_override.is_some(),
    })
}

#[cfg(test)]
mod diagnostics_privacy_tests {
    use super::*;

    #[test]
    fn proxy_recovery_export_contains_no_raw_registry_values() {
        let backup = platform::proxy::ProxyBackup {
            attempt_id: Some("secret-attempt-token".into()),
            published_proxy_server: Some("http=user:password@127.0.0.1:30000".into()),
            published_proxy_override: Some("internal.corp;<local>".into()),
            proxy_enable: Some(1),
            proxy_server: Some("http=internal-proxy.corp:8080".into()),
            proxy_override: Some("secret.internal".into()),
        };
        let json = sanitized_proxy_recovery_metadata(&backup).to_string();
        for secret in [
            "secret-attempt-token",
            "password",
            "internal.corp",
            "internal-proxy.corp",
            "secret.internal",
        ] {
            assert!(!json.contains(secret));
        }
    }
}

#[tauri::command]
pub async fn get_recovery_state() -> RecoveryState {
    let proxy_orphan = platform::proxy::is_proxy_pointing_to_us();
    let proxy_backup_present = platform::proxy::has_pending_backup();
    let tun_orphan = platform::network::has_orphan_tun_adapters();

    // 14.E: проверка orphan-фильтров через helper. Делаем с timeout и
    // на любые ошибки (helper не отвечает, не установлен) возвращаем
    // false. Pipe внутри helper_client уже имеет 1-секундный retry-loop;
    // дополнительный timeout оборачивать не обязательно, но для
    // надёжности в случае зависшего pipe — да.
    let orphan_wfp_filters = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        platform::helper_client::wfp_query_orphan(),
    )
    .await
    {
        Ok(Ok(has)) => has,
        Ok(Err(_)) | Err(_) => false,
    };

    RecoveryState {
        // session_lock мы вызывали в `lib.rs::setup` — но это уже после
        // того как мы перетёрли lockfile своим PID. Поэтому здесь
        // используем простой proxy для «недавно был краш»: либо backup
        // присутствует, либо прокси указывает на нас. Если ничего из
        // этого нет — was_crashed = false (даже если на самом деле
        // был краш в прошлый раз — нам нечего восстанавливать).
        was_crashed: proxy_backup_present || proxy_orphan || tun_orphan || orphan_wfp_filters,
        proxy_orphan,
        proxy_backup_present,
        tun_orphan,
        orphan_wfp_filters,
    }
}

// ─── Routing table viewer (Settings → диагностика) ──────────────────────────

/// Чтение текущей routing-таблицы Windows для UI-вьюера. Read-only.
/// Возвращает IPv4 + IPv6 маршруты, отсортированные по metric ASC.
///
/// Используется в Settings → диагностика → «таблица маршрутов» — пользователь
/// видит куда уходит трафик (default через TUN, half-default другого VPN,
/// и т.п.). Не делает live-poll'инга — фронт сам дёргает по pull-to-refresh.
#[tauri::command]
pub fn get_routing_table() -> Vec<platform::network::RouteEntry> {
    platform::network::list_routing_table()
}

// ─── Connection ping (Settings → пинг) ──────────────────────────────────────

/// Замерить ping заданным методом (TCP / HTTP-GET / HTTP-HEAD).
///
/// Используется кнопкой «тест соединения» в Settings → пинг. В отличие от
/// `ping_servers` (TCP-ping до VPN-сервера для server-list) этот ping
/// проверяет **активное соединение** через VPN: HTTP-методы идут через
/// SOCKS5 inbound (если VPN активен в proxy-режиме) или через system route
/// (TUN-режим). TCP-метод идёт напрямую к URL.
///
/// `socks_port` — `None` если VPN не активен или в TUN-режиме; `Some(port)`
/// в proxy-режиме когда хотим прогнать запрос через туннель.
#[tauri::command]
pub async fn connection_ping(
    method: String,
    url: String,
    socks_port: Option<u16>,
    timeout_secs: u32,
) -> vpn::connection_ping::PingResult {
    use vpn::connection_ping::{ping, PingMethod};
    let m = match method.as_str() {
        "tcp" => PingMethod::Tcp,
        "http-get" => PingMethod::HttpGet,
        "http-head" => PingMethod::HttpHead,
        other => {
            return vpn::connection_ping::PingResult {
                latency_ms: None,
                status: None,
                error: Some(format!("неизвестный метод ping'а: {other}")),
                via_proxy: socks_port.is_some(),
            };
        }
    };
    ping(m, &url, socks_port, timeout_secs).await
}

/// Live-toggle kill-switch без disconnect/connect.
///
/// Фронт зовёт когда пользователь меняет переключатель в Settings во
/// время активного VPN. Параметры (server_ips, app-paths, dns) берутся
/// из контекста, сохранённого при connect — пересборка не нужна.
///
/// `enabled=true` без активного контекста (VPN не подключён) — no-op,
/// `false` без контекста — best-effort disable (на случай orphan
/// фильтров от прошлой сессии).
///
/// `strict` опционально обновляет сохранённый strict_mode перед re-apply.
/// Используется при live-toggle 13.S strict-mode и 14.D force_disable_ipv6
/// toggle'ов в Settings — без disconnect/connect.
#[tauri::command]
pub async fn kill_switch_apply(
    enabled: bool,
    strict: Option<bool>,
    force_disable_ipv6: Option<bool>,
    ks_ctx: State<'_, KillSwitchState>,
) -> Result<(), String> {
    let _lifecycle = platform::lifecycle::enter().await?;
    // Обновляем поля в контексте если фронт прислал новые значения.
    {
        let mut g = ks_ctx.0.lock().await;
        if let Some(ctx) = g.as_mut() {
            if let Some(new_strict) = strict {
                ctx.strict_mode = new_strict;
            }
            if let Some(new_v6) = force_disable_ipv6 {
                ctx.force_disable_ipv6 = new_v6;
            }
        }
    }

    let ctx_opt = ks_ctx.0.lock().await.clone();

    if !enabled {
        // disable — безопасно вызвать всегда, helper-side идемпотентно.
        return platform::helper_client::kill_switch_disable()
            .await
            .map_err(|e| e.to_string());
    }

    let Some(ctx) = ctx_opt else {
        // VPN не подключён — нечего применять. Не ошибка: пользователь
        // мог включить переключатель «впрок» до connect.
        return Ok(());
    };

    // Helper должен быть жив — kill_switch_enable требует pipe.
    if let Err(e) = platform::helper_bootstrap::ensure_running().await {
        return Err(format!("helper-сервис недоступен: {e}"));
    }
    platform::helper_client::kill_switch_enable(
        ctx.server_ips,
        ctx.allow_lan,
        ctx.block_dns,
        ctx.allow_dns_ips,
        ctx.strict_mode,
        ctx.expect_tun,
        ctx.force_disable_ipv6,
    )
    .await
    .map_err(|e| e.to_string())
}

// ─── Leak-test (13.B + 13.H) ────────────────────────────────────────────────

/// Проверка утечек IP/DNS. Делает два HTTP-запроса параллельно:
/// ipapi.co для public IP/GeoIP и DoH к Cloudflare для DNS-резолвера.
///
/// `socks_port` — наш локальный SOCKS5 inbound (proxy-mode). В tun-mode
/// фронт передаёт `None` и трафик идёт через system route.
///
/// Команда не падает при сетевой ошибке — возвращает структуру с
/// частично заполненными полями, фронт показывает «—» где данных нет.
#[tauri::command]
pub async fn leak_test(
    socks_port: Option<u16>,
) -> Result<crate::vpn::leak_test::LeakTestResult, String> {
    crate::vpn::leak_test::run(socks_port)
        .await
        .map_err(|e| e.to_string())
}

// ─── Floating window (13.O) ─────────────────────────────────────────────────

/// Показать плавающее окно со статусом и скоростью передачи данных.
/// Окно создаётся в `lib.rs` setup всегда, но скрытым; команда лишь
/// делает его видимым. Идемпотентна: повторный вызов на видимом окне —
/// просто .show() (no-op) + setFocus.
#[tauri::command]
pub fn show_floating_window(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    let win = app
        .get_webview_window("floating")
        .ok_or_else(|| "floating-окно не зарегистрировано".to_string())?;
    win.show().map_err(|e| e.to_string())?;
    Ok(())
}

/// Скрыть плавающее окно. Окно остаётся в памяти, повторный
/// `show_floating_window` мгновенный (нет переинициализации webview).
#[tauri::command]
pub fn hide_floating_window(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    let win = app
        .get_webview_window("floating")
        .ok_or_else(|| "floating-окно не зарегистрировано".to_string())?;
    win.hide().map_err(|e| e.to_string())?;
    Ok(())
}

// ─── Crash recovery (9.D) ─────────────────────────────────────────────────────

/// Восстановить системный прокси из backup-файла (после краша приложения
/// в режиме proxy). Удаляет backup-файл после успеха.
#[tauri::command]
pub async fn restore_proxy_backup() -> Result<(), String> {
    let _lifecycle = platform::lifecycle::enter().await?;
    platform::proxy::restore_pending_owned_proxy()
        .and_then(|restored| {
            if restored {
                Ok(())
            } else {
                anyhow::bail!("owned proxy publication was not restored")
            }
        })
        .map_err(|e| e.to_string())
}

/// Отбросить backup без применения (пользователь в диалоге выбрал
/// «не восстанавливать»). Текущее состояние реестра остаётся как есть.
#[tauri::command]
pub async fn discard_proxy_backup() -> Result<(), String> {
    let _lifecycle = platform::lifecycle::enter().await?;
    platform::proxy::discard_backup().map_err(|error| error.to_string())
}

// ─── Secure storage (6.A — Credential Manager) ────────────────────────────────

/// Прочитать значение из Windows Credential Manager. Возвращает пустую
/// строку если ключа нет — фронту так удобнее обрабатывать.
#[tauri::command]
pub fn secure_storage_get(key: String) -> Result<String, String> {
    platform::secure_storage::get(&key)
        .map(|v| v.unwrap_or_default())
        .map_err(|e| e.to_string())
}

/// Записать значение в Windows Credential Manager.
#[tauri::command]
pub fn secure_storage_set(key: String, value: String) -> Result<(), String> {
    platform::secure_storage::set(&key, &value).map_err(|e| e.to_string())
}

/// Удалить значение из Windows Credential Manager.
#[tauri::command]
pub fn secure_storage_delete(key: String) -> Result<(), String> {
    platform::secure_storage::delete(&key).map_err(|e| e.to_string())
}

// ─── Autostart (6.B) ──────────────────────────────────────────────────────────

/// Зарегистрирован ли task автозапуска в Windows Task Scheduler.
///
/// 0.1.1 / Bug 4: команда async — `schtasks.exe` блокирует поток до
/// 15 секунд, и старая sync-версия зависала весь UI на это время.
#[tauri::command]
pub async fn autostart_is_enabled() -> bool {
    platform::autostart::is_enabled().await
}

/// Включить автозапуск приложения с системой (создаёт task ONLOGON).
#[tauri::command]
pub async fn autostart_enable() -> Result<(), String> {
    platform::autostart::enable()
        .await
        .map_err(|e| e.to_string())
}

/// Выключить автозапуск (удаляет task).
#[tauri::command]
pub async fn autostart_disable() -> Result<(), String> {
    platform::autostart::disable()
        .await
        .map_err(|e| e.to_string())
}

/// Return only the pseudonym for the supplied subscription origin.  The
/// app-local master secret never crosses into the WebView.
#[tauri::command]
pub fn get_hwid(url: Option<String>, hwid: State<'_, HwidState>) -> Result<String, String> {
    let Some(url) = url.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) else {
        return Ok(String::new());
    };
    crate::config::hwid::for_subscription(&hwid.0, &url).map_err(|e| e.to_string())
}

/// Read bounded credential-free lifecycle diagnostics. Protected service
/// diagnostics cross the authenticated helper pipe; this user process never
/// opens or guesses a flat ProgramData path.
///
/// Имя `read_xray_log` оставлено для совместимости с фронтом (UI
/// `LogsBlock`). Содержимое — логи Mihomo.
#[tauri::command]
pub async fn read_xray_log() -> Result<String, String> {
    let app_log = vpn::diagnostics::recent().unwrap_or_default();
    let helper_log = platform::helper_client::read_diagnostics()
        .await
        .unwrap_or_default();
    let mut sections = Vec::new();
    if !app_log.is_empty() {
        sections.push(format!("=== application lifecycle ===\n{app_log}"));
    }
    if !helper_log.is_empty() {
        sections.push(format!("=== protected helper lifecycle ===\n{helper_log}"));
    }
    Ok(sections.join("\n"))
}

/// Пинговать все серверы из текущей подписки параллельно (TCP-connect).
///
/// Возвращает массив той же длины и порядка что `get_servers`. Для каждого
/// сервера: время отклика в мс или `None`, если адрес не извлекается /
/// сервер не ответил за 2.5 секунды.
#[tauri::command]
pub async fn ping_servers(sub: State<'_, SubscriptionState>) -> Result<Vec<Option<u32>>, String> {
    let entries = sub.snapshot().0;

    let futures = entries.iter().map(ping_entry);
    let results = futures::future::join_all(futures).await;
    Ok(results)
}

/// Нода mihomo-профиля для pre-connect TCP-пинга.
#[derive(serde::Deserialize)]
pub struct MihomoNodePing {
    pub name: String,
    pub server: String,
    pub port: u16,
}

/// Ping нод mihomo-профиля ДО подключения. Для full-mihomo подписки
/// `state.servers` содержит одну синтетическую запись «профиль», поэтому
/// обычный `ping_servers` не годится — ноды передаём из UI (имя + server +
/// port из `raw.proxies`). Пингуем параллельно, возвращаем `[имя, мс|null]`.
#[tauri::command]
pub async fn ping_mihomo_nodes(nodes: Vec<MihomoNodePing>) -> Vec<(String, Option<u32>)> {
    let futures = nodes.into_iter().map(|n| async move {
        let latency = ping_node(&n.server, n.port).await;
        (n.name, latency)
    });
    futures::future::join_all(futures).await
}

/// Универсальный pre-connect ping одной ноды.
///
/// 1. **TCP-connect** к `server:port` — подтверждает живой TCP-сервис
///    (vless / vmess / trojan / ss поверх TCP), даёт RTT до порта.
/// 2. **Fallback ICMP-echo** к хосту — для UDP-протоколов
///    (hysteria2 / tuic / wireguard), которые не слушают TCP, и когда
///    TCP закрыт фаерволом. ICMP даёт network-RTT независимо от протокола
///    (если сервер отвечает на эхо).
async fn ping_node(server: &str, port: u16) -> Option<u32> {
    // Без порта (старый кеш до добавления поля `port`) не пингуем: иначе
    // весь список ушёл бы в ICMP, а ICMP к CDN-фронтед хостам отвечает
    // за ~1мс (ближайший anycast-edge) → «1 ms везде». Пусть UI покажет
    // «—», пока подписка не обновлена (refresh заполнит порты).
    if server.is_empty() || port == 0 {
        return None;
    }
    // TCP-connect к реальному серверу ноды — честный RTT для TCP-протоколов
    // (vless/vmess/trojan/ss).
    if let Some(ms) = vpn::ping::tcp_ping(server, port).await {
        return Some(ms);
    }
    // TCP молчит → нода на UDP (hysteria2/tuic/wireguard) или TCP закрыт
    // фаерволом. Fallback ICMP-echo к хосту.
    let ip = resolve_ipv4(server, port).await?;
    tokio::task::spawn_blocking(move || platform::icmp::icmp_echo_ipv4(ip, 2500))
        .await
        .ok()
        .flatten()
}

/// Резолв хоста в IPv4 (host уже IP — возвращаем как есть, иначе DNS-lookup).
async fn resolve_ipv4(host: &str, port: u16) -> Option<std::net::Ipv4Addr> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some(ip);
    }
    let p = if port == 0 { 443 } else { port };
    tokio::net::lookup_host((host, p))
        .await
        .ok()?
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
}

// ─── 14.F — export logs для саппорта ──────────────────────────────────────────

/// Собирает диагностический zip-пакет с локальной информацией для саппорта.
/// Без телеметрии — файл сохраняется на диск пользователя, он сам решает
/// кому отправить.
///
/// Содержимое:
/// - `app-info.txt` — версия клиента, OS, CARGO_PKG_VERSION;
/// - `connection-lifecycle.log` — bounded credential-free app/helper stages;
/// - `competing-vpns.txt` — список найденных параллельных VPN-клиентов;
/// - `recovery-state.json` — текущее состояние orphan-ресурсов;
/// - `proxy-recovery-metadata.json` — только безопасные признаки наличия
///   attempt-owned backup, без исходных proxy/bypass значений и token.
///
/// Сохраняется в `%USERPROFILE%\Documents\kwikproxy-secure-diagnostics-<timestamp>.zip`.
/// Возвращает абсолютный путь — UI показывает в toast с кнопкой
/// «открыть папку» через `tauri-plugin-opener::reveal_item_in_dir`.
#[tauri::command]
pub async fn export_diagnostics() -> Result<String, String> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::SimpleFileOptions;

    let docs = std::env::var_os("USERPROFILE")
        .map(|h| std::path::PathBuf::from(h).join("Documents"))
        .ok_or_else(|| "не удалось определить путь к Documents".to_string())?;
    if !docs.exists() {
        std::fs::create_dir_all(&docs).map_err(|e| e.to_string())?;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let zip_path = docs.join(format!("kwikproxy-secure-diagnostics-{ts}.zip"));

    let app_lifecycle = vpn::diagnostics::recent().unwrap_or_default();
    let helper_lifecycle = platform::helper_client::read_diagnostics()
        .await
        .unwrap_or_default();

    let file = std::fs::File::create(&zip_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    // 1. app-info.txt
    let info = format!(
        "kwik version: {}\n\
         OS family: {}\n\
         arch: {}\n\
         timestamp (unix): {}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        ts,
    );
    zip.start_file("app-info.txt", opts)
        .map_err(|e| e.to_string())?;
    zip.write_all(info.as_bytes()).map_err(|e| e.to_string())?;

    // 2. Safe structured lifecycle diagnostics. Raw engine output is not
    // exported because it can contain subscription hosts, provider URLs or
    // other user configuration.
    let lifecycle = format!(
        "=== application lifecycle ===\n{}\n=== protected helper lifecycle ===\n{}\n",
        app_lifecycle, helper_lifecycle,
    );
    zip.start_file("connection-lifecycle.log", opts)
        .map_err(|e| e.to_string())?;
    zip.write_all(lifecycle.as_bytes())
        .map_err(|e| e.to_string())?;

    // 3. competing-vpns.txt
    let competing = platform::processes::detect_competing_vpns();
    let competing_text = if competing.is_empty() {
        "(никаких сторонних VPN-процессов не найдено)\n".to_string()
    } else {
        competing.join("\n") + "\n"
    };
    let _ = zip.start_file("competing-vpns.txt", opts);
    let _ = zip.write_all(competing_text.as_bytes());

    // 4. recovery-state.json (без orphan_wfp_filters — оно требует
    // helper round-trip, не нужно в синхронном export-flow)
    let state = RecoveryState {
        proxy_orphan: platform::proxy::is_proxy_pointing_to_us(),
        proxy_backup_present: platform::proxy::has_pending_backup(),
        tun_orphan: platform::network::has_orphan_tun_adapters(),
        orphan_wfp_filters: false,
        was_crashed: false,
    };
    if let Ok(json) = serde_json::to_string_pretty(&state) {
        let _ = zip.start_file("recovery-state.json", opts);
        let _ = zip.write_all(json.as_bytes());
    }

    // 5. Proxy recovery metadata only. Original proxy/bypass strings can
    // contain internal hosts or credential-like material and are omitted.
    if let Some(backup) = platform::proxy::read_backup() {
        let safe = sanitized_proxy_recovery_metadata(&backup);
        if let Ok(json) = serde_json::to_string_pretty(&safe) {
            let _ = zip.start_file("proxy-recovery-metadata.json", opts);
            let _ = zip.write_all(json.as_bytes());
        }
    }

    // 6. 14.C: crash-dump'ы за последние 7 дней. Кладём в zip как
    // crashes/<filename>.txt чтобы саппорт сразу видел стек-трейсы.
    if let Some(dir) = platform::crash_dumps::crashes_dir() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let week_ago = std::time::SystemTime::now()
                .checked_sub(std::time::Duration::from_secs(7 * 86400))
                .unwrap_or(std::time::UNIX_EPOCH);
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("txt") {
                    continue;
                }
                let modified = entry.metadata().and_then(|m| m.modified()).ok();
                if let Some(t) = modified {
                    if t < week_ago {
                        continue;
                    }
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if let Ok(content) = std::fs::read(&path) {
                    let _ = zip.start_file(format!("crashes/{name}"), opts);
                    let _ = zip.write_all(&content);
                }
            }
        }
    }

    zip.finish().map_err(|e| e.to_string())?;
    Ok(zip_path.to_string_lossy().into_owned())
}

/// 14.C: количество свежих crash-dump'ов (за неделю). UI на старте
/// показывает toast «обнаружены прошлые крахи, нажмите выгрузить
/// диагностику чтобы поделиться» если > 0.
#[tauri::command]
pub fn count_recent_crashes() -> usize {
    platform::crash_dumps::count_recent_crashes()
}

// ─── 8.F — Mihomo controller API (proxy-groups UI) ───────────────────────────

/// `GET /proxies` через mihomo external-controller. Возвращает список
/// всех нод и групп с `now`/`all`/`history`/`type`.
///
/// Доступно только когда mihomo жив И мы знаем endpoint (заполняется
/// в `connect()` для full-mihomo-профилей). Иначе — ошибка.
#[tauri::command]
pub async fn mihomo_proxies(
    state: State<'_, vpn::MihomoApiState>,
) -> Result<vpn::mihomo_api::ProxiesSnapshot, String> {
    let ep = state
        .get()
        .ok_or_else(|| "mihomo controller не активен".to_string())?;
    vpn::mihomo_api::fetch_proxies(&ep)
        .await
        .map_err(|e| e.to_string())
}

/// `PUT /proxies/:group` — выбрать ноду в select-группе. UI вызывает
/// при клике на ноду; mihomo переключает activeNode без рестарта.
///
/// Сразу после успешного select зовём `DELETE /connections` — это
/// форсит закрытие всех TCP-сессий через старый outbound. Без этого
/// браузер держит keep-alive со старой нодой и трафик продолжает идти
/// через неё, пока сессии не истекут (могут жить минутами). С close-
/// connections новый запрос сразу пойдёт через свежий outbound, как
/// FlClash/Clash Verge.
///
/// Ошибка `close_connections` не блокирует — селект уже применён,
/// просто браузер чуть позже сам подхватит. Логируем и идём дальше.
#[tauri::command]
pub async fn mihomo_select_proxy(
    group: String,
    name: String,
    state: State<'_, vpn::MihomoApiState>,
) -> Result<(), String> {
    let ep = state
        .get()
        .ok_or_else(|| "mihomo controller не активен".to_string())?;
    vpn::mihomo_api::select_proxy(&ep, &group, &name)
        .await
        .map_err(|e| e.to_string())?;
    if let Err(e) = vpn::mihomo_api::close_all_connections(&ep).await {
        eprintln!("[mihomo] close_connections after select failed: {e:#}");
    }
    Ok(())
}

/// `GET /proxies/:name/delay` — измерить latency. Используется в
/// ProxiesPanel для кнопок «test now». URL и timeout берутся
/// разумные дефолты.
#[tauri::command]
pub async fn mihomo_delay_test(
    name: String,
    state: State<'_, vpn::MihomoApiState>,
) -> Result<Option<u32>, String> {
    let ep = state
        .get()
        .ok_or_else(|| "mihomo controller не активен".to_string())?;
    // cdn-cgi/trace — лёгкий 200 OK от Cloudflare, не подвержен
    // throttle'у других сервисов; 5s timeout ловит только реально
    // живые узлы.
    vpn::mihomo_api::delay_test(&ep, &name, "https://cp.cloudflare.com/generate_204", 5000)
        .await
        .map_err(|e| e.to_string())
}

/// #3 per-app UX: список запущенных процессов (имя + полный путь) для
/// пикера app-rules. Без admin-прав, наши/системные exe отфильтрованы.
#[tauri::command]
pub fn list_processes() -> Vec<platform::processes::ProcessEntry> {
    platform::processes::list_processes()
}

/// #4 per-app UX: агрегированный трафик по процессам через mihomo
/// `/connections`. Доступно когда mihomo жив. Процессы определяются при
/// `find-process-mode: always` (включается с app-rules).
#[tauri::command]
pub async fn app_traffic_stats(
    state: State<'_, vpn::MihomoApiState>,
) -> Result<Vec<vpn::mihomo_api::AppTraffic>, String> {
    let ep = state
        .get()
        .ok_or_else(|| "mihomo controller не активен".to_string())?;
    vpn::mihomo_api::fetch_app_traffic(&ep)
        .await
        .map_err(|e| e.to_string())
}

// ─── 12.D — backup/restore настроек ─────────────────────────────────────────

const MAX_SETTINGS_BACKUP_BYTES: usize = 1024 * 1024;

fn validate_settings_backup_json(json: &str) -> Result<(), String> {
    let byte_len = json.len();
    if byte_len == 0 {
        return Err("backup JSON is empty".to_string());
    }
    if byte_len > MAX_SETTINGS_BACKUP_BYTES {
        return Err(format!(
            "backup JSON exceeds the {} byte limit",
            MAX_SETTINGS_BACKUP_BYTES
        ));
    }

    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid backup JSON: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "backup JSON must be an object".to_string())?;
    if object.get("schema_version").and_then(|v| v.as_u64()) != Some(1) {
        return Err("unsupported or missing backup schema_version".to_string());
    }
    Ok(())
}

/// Записать backup-JSON в `%USERPROFILE%\Documents\kwikproxy-secure-backup-<ts>.json`.
///
/// Frontend сам собирает JSON (с whitelist'ом полей и `schema_version`),
/// а Rust-сторона проверяет максимальный размер, JSON-object и schema-v1
/// перед записью. Возвращаем абсолютный путь, который UI показывает в toast.
///
/// Безопасность: frontend по умолчанию не включает URL/token
/// подписки и никогда не включает HWID. После явного UI opt-in URL/token
/// может присутствовать в JSON; Rust не логирует и не интерпретирует его.
#[tauri::command]
pub fn export_settings_to_documents(json: String) -> Result<String, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    validate_settings_backup_json(&json)?;

    let docs = std::env::var_os("USERPROFILE")
        .map(|h| std::path::PathBuf::from(h).join("Documents"))
        .ok_or_else(|| "не удалось определить путь к Documents".to_string())?;
    if !docs.exists() {
        std::fs::create_dir_all(&docs).map_err(|e| e.to_string())?;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = docs.join(format!("kwikproxy-secure-backup-{ts}.json"));
    std::fs::write(&path, json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod backup_export_tests {
    use super::*;

    #[test]
    fn backup_json_must_be_bounded_schema_v1_object() {
        assert!(validate_settings_backup_json("").is_err());
        assert!(validate_settings_backup_json("[]").is_err());
        assert!(validate_settings_backup_json(r#"{"schema_version":2}"#).is_err());
        assert!(validate_settings_backup_json(r#"{"schema_version":1}"#).is_ok());

        let oversized = format!(
            r#"{{"schema_version":1,"padding":"{}"}}"#,
            "x".repeat(MAX_SETTINGS_BACKUP_BYTES)
        );
        assert!(validate_settings_backup_json(&oversized).is_err());
    }
}

// ─── 11.C/D/E — управление routing-профилями ──────────────────────────────────

use crate::config::routing_profile::{parse_profile_input, ProfileSource};
use crate::config::routing_store::{
    canonicalize_github_blob, fetch_profile_from_url, RoutingStoreSnapshot, RoutingStoreState,
};

/// Получить snapshot всех профилей и id активного. Один вызов на UI-mount.
#[tauri::command]
pub fn routing_list(state: State<'_, RoutingStoreState>) -> RoutingStoreSnapshot {
    state.inner.lock().map(|g| g.snapshot()).unwrap_or_default()
}

/// Добавить статический профиль из base64/JSON-строки. Возвращает id.
#[tauri::command]
pub fn routing_add_static(
    payload: String,
    state: State<'_, RoutingStoreState>,
) -> Result<String, String> {
    let profile = parse_profile_input(&payload).map_err(|e| e.to_string())?;
    let id = state
        .inner
        .lock()
        .map_err(|e| e.to_string())?
        .add(profile, ProfileSource::Static)
        .map_err(|e| e.to_string())?;
    state.wake.notify_one();
    Ok(id)
}

/// Скачать профиль по URL **один раз** и сохранить как статический
/// (`Static`) — без авто-обновления и без autorouting-метки в UI.
/// Для deep-link `kwikproxy-secure://routing/add/{url}`, где URL — разовый
/// источник, а не подписка на обновления.
#[tauri::command]
pub async fn routing_add_static_from_url(
    url: String,
    state: State<'_, RoutingStoreState>,
) -> Result<String, String> {
    let profile = fetch_profile_from_url(&url)
        .await
        .map_err(|e| e.to_string())?;
    let id = state
        .inner
        .lock()
        .map_err(|e| e.to_string())?
        .add(profile, ProfileSource::Static)
        .map_err(|e| e.to_string())?;
    state.wake.notify_one();
    Ok(id)
}

/// Скачать профиль по URL и добавить как autorouting (с авто-обновлением
/// каждые `interval_hours`). При первом скачивании сразу применяется.
#[tauri::command]
pub async fn routing_add_url(
    url: String,
    interval_hours: u32,
    state: State<'_, RoutingStoreState>,
) -> Result<String, String> {
    let profile = fetch_profile_from_url(&url)
        .await
        .map_err(|e| e.to_string())?;
    let canonical = canonicalize_github_blob(&url);
    let id = {
        let mut g = state.inner.lock().map_err(|e| e.to_string())?;
        g.add(
            profile,
            ProfileSource::Autorouting {
                url: canonical,
                interval_hours: interval_hours.clamp(1, 720),
            },
        )
        .map_err(|e| e.to_string())?
    };
    state.wake.notify_one();
    Ok(id)
}

/// Удалить профиль. Если он был активным — активный сбрасывается.
#[tauri::command]
pub fn routing_remove(id: String, state: State<'_, RoutingStoreState>) -> Result<(), String> {
    state
        .inner
        .lock()
        .map_err(|e| e.to_string())?
        .remove(&id)
        .map_err(|e| e.to_string())
}

/// Сделать профиль активным (или сбросить активный если `id=None`).
#[tauri::command]
pub fn routing_set_active(
    id: Option<String>,
    state: State<'_, RoutingStoreState>,
) -> Result<(), String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.set_active(id.as_deref()).map_err(|e| e.to_string())?;
    drop(g);
    state.wake.notify_one();
    Ok(())
}

/// Принудительно обновить autorouting-профиль (не дожидаясь scheduler-tick).
/// Для статического профиля — no-op.
#[tauri::command]
pub async fn routing_refresh(
    id: String,
    state: State<'_, RoutingStoreState>,
) -> Result<(), String> {
    let entry = {
        let g = state.inner.lock().map_err(|e| e.to_string())?;
        g.snapshot().entries.into_iter().find(|e| e.id == id)
    };
    let Some(entry) = entry else {
        return Err(format!("профиль {id} не найден"));
    };
    match entry.source {
        ProfileSource::Static => Ok(()),
        ProfileSource::Autorouting { url, .. } => {
            let profile = fetch_profile_from_url(&url)
                .await
                .map_err(|e| e.to_string())?;
            state
                .inner
                .lock()
                .map_err(|e| e.to_string())?
                .update_profile(&id, profile)
                .map_err(|e| e.to_string())?;
            state.wake.notify_one();
            Ok(())
        }
    }
}

/// Принудительное обновление geofiles (.dat-файлов) — для UI-кнопки в
/// разделе routing. Возвращает report что обновилось / что пропустилось
/// по unchanged sha256 / какие были errors.
#[tauri::command]
pub async fn geofiles_refresh(
    state: State<'_, RoutingStoreState>,
) -> Result<crate::config::geofiles::UpdateReport, String> {
    let active = state
        .inner
        .lock()
        .map_err(|e| e.to_string())?
        .active()
        .map(|e| (e.profile.geoip_url.clone(), e.profile.geosite_url.clone()));
    let (geoip, geosite) = active.unwrap_or_default();
    Ok(crate::config::geofiles::update_geofiles_if_changed(&geoip, &geosite).await)
}

/// Текущее состояние geofiles: какие файлы есть, размер, sha256.
#[tauri::command]
pub fn geofiles_status() -> crate::config::geofiles::GeofilesStatus {
    crate::config::geofiles::status()
}

// ─── 9.B / 9.C — детект конфликтов с другими VPN ──────────────────────────────

/// 9.C — Список интерфейсов с активными default- или half-default-маршрутами,
/// принадлежащих **не нам** (NextHop ≠ 198.18.0.1) и **не штатному** physic-
/// default'у. Признак того, что параллельно работает другой VPN.
///
/// Возвращает aliases интерфейсов (например `["Wintun Userspace Tunnel"]`).
/// Frontend перед connect показывает toast и не запускает VPN.
#[tauri::command]
pub fn check_routing_conflicts() -> Vec<String> {
    platform::network::detect_routing_conflicts()
}
