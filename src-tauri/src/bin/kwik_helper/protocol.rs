//! JSON-RPC протокол между helper-сервисом и Tauri-приложением.
//!
//! Каждое сообщение — одна строка JSON, заканчивается `\n`. Helper читает
//! строку, парсит как `Request`, выполняет, отвечает `Response` (тоже одна
//! строка JSON + `\n`). Одно соединение принимает ровно один ограниченный
//! по размеру запрос.

use serde::{Deserialize, Serialize};

/// Version 15 makes privileged runtime status resource-aware. The UI must not
/// collapse a stopped child into a clean state while exact TUN-device or WFP
/// cleanup is still pending. Client and helper require an exact version match;
/// upgrades are performed only by the per-machine installer.
pub const PROTOCOL_VERSION: u32 = 15;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Request {
    /// Health-check. Helper отвечает `Response::Pong`.
    Ping,
    /// Версия helper-а.
    Version,
    /// Включить kill switch (этап 13.D — настоящий WFP).
    ///
    /// `server_ips` — список IP-адресов VPN-сервера (Tauri-main делает
    /// DNS-резолв перед вызовом, потому что после включения kill-switch'а
    /// DNS-запросы вне VPN заблокированы).
    ///
    /// `allow_lan` — пускать ли локальную сеть (10/8, 172.16/12,
    /// 192.168/16, 169.254/16, fe80::/10, ff00::/8).
    ///
    KillSwitchEnable {
        #[serde(default)]
        server_ips: Vec<String>,
        #[serde(default)]
        allow_lan: bool,
        /// DNS leak protection (этап 13.D step B): блокировать весь
        /// :53/UDP+TCP трафик кроме явно разрешённых IP.
        #[serde(default)]
        block_dns: bool,
        /// IPv4 адреса VPN-DNS которые остаются разрешены при `block_dns`.
        /// В TUN-mode обычно [`198.18.0.1`] (наш TUN gateway).
        #[serde(default)]
        allow_dns_ips: Vec<String>,
        /// 13.S strict mode: НЕ давать общий allow_app для движка mihomo.
        /// Он сможет соединяться только на server_ips (через
        /// add_filter_allow_v4_addr_port_proto, который добавляется в
        /// любом случае). Direct outbound по `geosite:ru` будет
        /// блокирован — это и есть смысл strict mode.
        #[serde(default)]
        strict_mode: bool,
        /// 0.1.3 kill-switch fix: нужен ли retry-поиск активного
        /// WinTUN-адаптера для TUN allow-фильтра. `true` в TUN-режиме
        /// (sing-box/mihomo built-in TUN), `false` в proxy-режиме —
        /// чтобы не задерживать `enable()` на 5с впустую.
        #[serde(default)]
        expect_tun: bool,
        /// 14.D — принудительно блокировать весь IPv6-трафик пока
        /// VPN активен. Защита от утечек на dual-stack ISP, где часть
        /// трафика идёт по нативному v6 минуя v4-туннель. Если `true`,
        /// helper пропускает все v6 allow-фильтры (LAN, server, app,
        /// TUN-interface), оставляя только базовый block-all v6.
        /// Loopback `::1` остаётся разрешён — он не уходит в сеть.
        #[serde(default)]
        force_disable_ipv6: bool,
    },
    /// Выключить kill switch — drop'ает WFP DYNAMIC engine,
    /// все наши фильтры удаляются автоматически.
    KillSwitchDisable,
    /// Heartbeat для kill-switch watchdog (этап 13.D).
    /// Tauri-main шлёт каждые ~20 сек пока активен kill-switch. Если
    /// helper не получит heartbeat 60+ секунд — фильтры автоматически
    /// снимаются (страховка от зависания main-процесса).
    KillSwitchHeartbeat,
    /// Emergency cleanup всех WFP-фильтров с нашим provider GUID.
    /// Используется UI-кнопкой «аварийный сброс» — даже если main
    /// сейчас не имеет активного kill-switch state, удалит всё что
    /// потенциально зависло от прошлых сессий.
    KillSwitchForceCleanup,
    /// Cleanup orphan TUN adapters bearing the reserved
    /// `kwikproxy-secure-*` ownership marker. Используется UI-кнопкой
    /// «восстановить сеть» когда видимо, что что-то осталось от
    /// упавшей сессии. Безопасно вызывать только когда VPN не активен.
    OrphanCleanup,
    /// 14.E: read-only проверка остатков WFP-фильтров от прошлой
    /// сессии. Возвращает `Response::WfpOrphan { has_orphan }` —
    /// фронт показывает в crash-recovery диалоге если true.
    /// Не destructive: только читает существование sublayer'а с
    /// нашим GUID.
    WfpQueryOrphan,
    /// Read a bounded, credential-free tail from the protected helper
    /// lifecycle log. The pipe authentication boundary is required even
    /// though this operation is read-only.
    ReadDiagnostics,
    /// Read-only liveness for the helper-owned Mihomo child. This lets the UI
    /// discard stale local state after an unexpected engine exit.
    TunnelStatus,
    /// Start the fixed, installer-owned Mihomo binary. The unprivileged UI
    /// supplies configuration bytes, never filesystem/executable paths.
    StartTunnel {
        config_yaml: String,
        allow_lan: bool,
    },
    /// 13.L: остановить SYSTEM-spawned mihomo. Идемпотентно: если
    /// helper не запускал mihomo — no-op.
    MihomoStop,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong,
    Version {
        version: String,
        /// `PROTOCOL_VERSION` помощника. Если поле отсутствует в JSON
        /// (старый helper до 0.1.2) — десериализуется в 0, и
        /// Tauri-main триггерит reinstall.
        #[serde(default)]
        protocol_version: u32,
    },
    /// Успешный результат операции без полезной нагрузки.
    Ok,
    /// 14.E: ответ на `WfpQueryOrphan`. `has_orphan` — есть ли
    /// sublayer с нашим GUID в persistent WFP-store.
    WfpOrphan {
        has_orphan: bool,
    },
    Diagnostics {
        text: String,
    },
    TunnelStatus {
        running: bool,
        cleanup_pending: bool,
        firewall_active: bool,
        device_owned: bool,
    },
    /// Ошибка с описанием.
    Error {
        message: String,
    },
}

impl Response {
    pub fn err(msg: impl Into<String>) -> Self {
        Self::Error {
            message: msg.into(),
        }
    }
}

pub const PIPE_NAME: &str = r"\\.\pipe\KwikProxySecure.Helper.v15";
pub const SERVICE_NAME: &str = "KwikProxySecureHelper";
pub const SERVICE_DISPLAY_NAME: &str = "KwikProxy Secure Helper";
pub const SERVICE_DESCRIPTION: &str = "Protected TUN and kill-switch broker for KwikProxy Secure.";

#[cfg(test)]
mod tests {
    use super::*;

    /// 14.E: проверка JSON-формата `WfpQueryOrphan` request — должен быть
    /// `{"cmd":"wfp_query_orphan"}`. Если случайно изменить tag/rename_all
    /// на helper-стороне — тест поймает.
    #[test]
    fn wfp_query_orphan_request_serializes() {
        let req = Request::WfpQueryOrphan;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"cmd":"wfp_query_orphan"}"#);
    }

    /// 14.E: `WfpOrphan` response с `has_orphan: true`.
    #[test]
    fn wfp_orphan_response_serializes() {
        let resp = Response::WfpOrphan { has_orphan: true };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"result":"wfp_orphan","has_orphan":true}"#);
    }

    /// Roundtrip: Request → JSON → Request. Если serde-теги совпадают,
    /// десериализация должна вернуть тот же variant.
    #[test]
    fn wfp_query_orphan_roundtrip() {
        let req = Request::WfpQueryOrphan;
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Request::WfpQueryOrphan));
    }

    #[test]
    fn diagnostics_request_contains_no_path() {
        let json = serde_json::to_string(&Request::ReadDiagnostics).unwrap();
        assert_eq!(json, r#"{"cmd":"read_diagnostics"}"#);
        assert!(!json.contains("path"));
    }

    #[test]
    fn tunnel_status_wire_shape_is_path_free() {
        assert_eq!(
            serde_json::to_string(&Request::TunnelStatus).unwrap(),
            r#"{"cmd":"tunnel_status"}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::TunnelStatus {
                running: false,
                cleanup_pending: true,
                firewall_active: true,
                device_owned: false,
            })
            .unwrap(),
            r#"{"result":"tunnel_status","running":false,"cleanup_pending":true,"firewall_active":true,"device_owned":false}"#
        );
    }

    #[test]
    fn start_tunnel_contains_no_paths() {
        let json = serde_json::to_string(&Request::StartTunnel {
            config_yaml: "mixed-port: 7890".into(),
            allow_lan: false,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"cmd":"start_tunnel","config_yaml":"mixed-port: 7890","allow_lan":false}"#
        );
        assert!(!json.contains("path"));
    }

    #[test]
    fn legacy_path_injection_request_is_rejected() {
        let legacy = r#"{"cmd":"mihomo_start","config_path":"C:\\\\evil.yml","mihomo_exe_path":"C:\\\\evil.exe","data_dir":"C:\\\\"}"#;
        assert!(serde_json::from_str::<Request>(legacy).is_err());
    }
}
