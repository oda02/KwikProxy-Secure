//! RPC-клиент для подключения к helper-сервису через named pipe.
//!
//! Помещает каждое JSON-сообщение строкой с `\n`-терминатором, как в pipe.rs
//! на стороне сервиса. Каждый вызов открывает свежее подключение, шлёт один
//! request и закрывает. Helper-pipe.rs умеет много клиентов — каждый
//! обработчик в отдельной задаче.
//!
//! ВАЖНО: типы должны точно совпадать с тегами в
//! `src/bin/kwik_helper/protocol.rs`.

use std::os::windows::io::AsRawHandle;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

const PIPE_NAME: &str = r"\\.\pipe\KwikProxySecure.Helper.v15";
const SERVICE_NAME: &str = "KwikProxySecureHelper";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONFIG_BYTES: usize = 1400 * 1024;
const MAX_REQUEST_BYTES: usize = 1536 * 1024;
// StartTunnel readiness is bounded at 10 seconds and may perform a further
// bounded child cleanup before replying. Keep the outer transport deadline
// comfortably beyond that complete request transaction.
const IO_TIMEOUT: Duration = Duration::from_secs(20);
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum HelperRequest {
    Ping,
    Version,
    /// Включить kill switch (этап 13.D — настоящий WFP).
    /// `server_ips` — массив IP уже резолвленный в Tauri-main.
    /// `allow_lan` — пускать ли локальную сеть.
    KillSwitchEnable {
        #[serde(default)]
        server_ips: Vec<String>,
        #[serde(default)]
        allow_lan: bool,
        /// DNS leak protection (13.D step B). См. protocol.rs.
        #[serde(default)]
        block_dns: bool,
        #[serde(default)]
        allow_dns_ips: Vec<String>,
        /// 13.S strict mode — без общего allow_app для xray/mihomo.
        #[serde(default)]
        strict_mode: bool,
        /// 0.1.3 kill-switch fix: TUN-режим? Helper ретраит поиск
        /// WinTUN-адаптера до 5с если true; в proxy-режиме single-shot
        /// (быстро возвращает None).
        #[serde(default)]
        expect_tun: bool,
        /// 14.D — принудительно блокировать весь IPv6 пока VPN активен.
        /// При `true` все v6 allow-фильтры пропускаются → весь IPv6
        /// outbound упирается в base block-all v6.
        #[serde(default)]
        force_disable_ipv6: bool,
    },
    KillSwitchDisable,
    /// Heartbeat для watchdog: главный шлёт каждые ~20 сек, иначе
    /// helper через 60+ сек снимет фильтры сам. См. firewall.rs.
    KillSwitchHeartbeat,
    /// Emergency cleanup — снять любые наши WFP-фильтры (для UI-кнопки
    /// «аварийный сброс»).
    KillSwitchForceCleanup,
    /// Cleanup orphan TUN adapters bearing the reserved
    /// `kwikproxy-secure-*` ownership marker.
    OrphanCleanup,
    /// 14.E: read-only проверка остатков WFP-фильтров от прошлой
    /// сессии. Helper смотрит существование sublayer с нашим GUID.
    WfpQueryOrphan,
    ReadDiagnostics,
    TunnelStatus,
    /// Start the fixed protected Mihomo binary with config bytes only.
    StartTunnel {
        config_yaml: String,
        allow_lan: bool,
    },
    /// 13.L: остановить SYSTEM-spawned mihomo. Идемпотентно.
    MihomoStop,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum HelperResponse {
    Pong,
    Version {
        version: String,
        /// 0.1.2: версия wire-протокола helper'а. Старые helper'ы
        /// (v0.1.1 и раньше) не возвращают это поле — десериализуем
        /// в 0, что триггерит auto-reinstall в `helper_bootstrap`.
        #[serde(default)]
        protocol_version: u32,
    },
    Ok,
    /// 14.E: ответ на `WfpQueryOrphan`.
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
    Error {
        message: String,
    },
}

/// Минимально-поддерживаемая версия протокола. Если helper отвечает
/// меньшей — `helper_bootstrap` форсит uninstall+install. Бампается
/// синхронно с константой в `kwik_helper::protocol`.
pub const HELPER_PROTOCOL_VERSION: u32 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelStatus {
    pub running: bool,
    pub cleanup_pending: bool,
    pub firewall_active: bool,
    pub device_owned: bool,
}

impl TunnelStatus {
    pub fn is_clear(self) -> bool {
        !self.running && !self.cleanup_pending && !self.firewall_active && !self.device_owned
    }

    pub fn is_active_or_pending(self) -> bool {
        !self.is_clear()
    }
}

/// Открыть pipe с retry — сервис может быть busy сразу после старта или
/// перезапуска. Возвращает первый успешный клиент за 1 секунду или ошибку.
async fn open_pipe() -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..10 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(client) => return Ok(client),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    let err = last_err
        .map(|e| format!("{e}"))
        .unwrap_or_else(|| "не удалось открыть pipe".into());
    bail!("helper-сервис недоступен ({PIPE_NAME}): {err}")
}

fn validate_service_binding(
    pipe_pid: u32,
    service_state: ServiceState,
    service_pid: Option<u32>,
) -> Result<()> {
    if pipe_pid == 0 {
        bail!("named-pipe server returned an invalid process id");
    }
    if service_state != ServiceState::Running {
        bail!("protected helper service is not running");
    }
    let service_pid = service_pid
        .filter(|pid| *pid != 0)
        .context("running protected helper service did not report a process id")?;
    if service_pid != pipe_pid {
        bail!("named-pipe server is not the registered protected helper service");
    }
    Ok(())
}

fn authenticate_pipe_server(
    client: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> Result<()> {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) } == 0
        || pid == 0
    {
        bail!("GetNamedPipeServerProcessId failed");
    }
    // Bind the connected pipe instance to the protected SCM registration.
    // Directly opening the SYSTEM process/token is both unnecessary and
    // denied to the intended non-elevated UI. SERVICE_QUERY_STATUS exposes
    // only state/PID; service control and reconfiguration remain admin-only.
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open Service Control Manager for helper authentication")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .context("open registered protected helper service for status query")?;
    let status = service
        .query_status()
        .context("query registered protected helper service status")?;
    validate_service_binding(pid, status.current_state, status.process_id)
}

/// Низкоуровневый round-trip: отправить request, получить response.
pub async fn send(req: HelperRequest) -> Result<HelperResponse> {
    let client = open_pipe().await?;
    authenticate_pipe_server(&client)?;
    let (read_half, mut write_half) = tokio::io::split(client);
    let reader = BufReader::new(read_half);

    let mut payload = serde_json::to_vec(&req)?;
    payload.push(b'\n');
    if payload.len() > MAX_REQUEST_BYTES {
        bail!("helper request exceeds {MAX_REQUEST_BYTES} bytes after JSON encoding");
    }
    tokio::time::timeout(IO_TIMEOUT, write_half.write_all(&payload))
        .await
        .context("таймаут записи в pipe")??;
    tokio::time::timeout(IO_TIMEOUT, write_half.flush())
        .await
        .context("таймаут flush pipe")??;

    let mut response = Vec::new();
    let mut limited = reader.take((MAX_RESPONSE_BYTES + 1) as u64);
    let n = tokio::time::timeout(IO_TIMEOUT, limited.read_to_end(&mut response))
        .await
        .context("таймаут чтения из pipe")??;
    if n == 0 {
        bail!("helper закрыл соединение без ответа");
    }
    if response.len() > MAX_RESPONSE_BYTES || response.last() != Some(&b'\n') {
        bail!("helper вернул слишком большой или незавершённый ответ");
    }
    response.pop();
    let resp: HelperResponse =
        serde_json::from_slice(&response).context("невалидный JSON-ответ helper")?;
    Ok(resp)
}

/// Health-check. Bool на успех / Result для UI «статус helper-а».
pub async fn ping() -> Result<()> {
    match send(HelperRequest::Ping).await? {
        HelperResponse::Pong => Ok(()),
        HelperResponse::Error { message } => bail!("helper: {message}"),
        other => bail!("ожидали Pong, получили {other:?}"),
    }
}

/// Получить версию helper-сервиса. Используется `helper_bootstrap` для
/// проверки точной совместимости wire-протокола installer-managed helper-а.
pub async fn version() -> Result<(String, u32)> {
    match send(HelperRequest::Version).await? {
        HelperResponse::Version {
            version,
            protocol_version,
        } => Ok((version, protocol_version)),
        HelperResponse::Error { message } => bail!("helper: {message}"),
        other => bail!("ожидали Version, получили {other:?}"),
    }
}

/// Включить kill switch — WFP-фильтры на уровне ядра блокируют весь
/// outbound кроме allowlist'а (этап 13.D).
///
/// - `server_ips` — IP-адреса VPN-сервера, уже резолвленные;
/// - `allow_lan` — пускать ли локальную сеть;
/// - `block_dns` — DNS-leak protection: блокировать весь :53 кроме
///   `allow_dns_ips` (13.D step B);
/// - `allow_dns_ips` — IPv4 адреса разрешённых DNS-серверов (когда
///   `block_dns=true`);
/// - `strict_mode` — 13.S, без общего allow_app для VPN-движков;
/// - `expect_tun` — TUN-режим? Helper ретраит поиск WinTUN-адаптера
///   до 5с если true (нужен для allow-фильтра user-трафика идущего
///   через TUN). В proxy-режиме `false` чтобы не задерживать enable.
/// - `force_disable_ipv6` — 14.D, блокировать весь IPv6 outbound пока
///   VPN активен. Helper пропустит все v6 allow-фильтры.
#[allow(clippy::too_many_arguments)] // аргументы зеркалят поля wire-протокола/конфига — структура здесь не упростит вызовы
pub async fn kill_switch_enable(
    server_ips: Vec<String>,
    allow_lan: bool,
    block_dns: bool,
    allow_dns_ips: Vec<String>,
    strict_mode: bool,
    expect_tun: bool,
    force_disable_ipv6: bool,
) -> Result<()> {
    let resp = send(HelperRequest::KillSwitchEnable {
        server_ips,
        allow_lan,
        block_dns,
        allow_dns_ips,
        strict_mode,
        expect_tun,
        force_disable_ipv6,
    })
    .await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// Выключить kill switch (восстановить default-allow). Идемпотентно.
pub async fn kill_switch_disable() -> Result<()> {
    let resp = send(HelperRequest::KillSwitchDisable).await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// Heartbeat для kill-switch watchdog. Зовётся каждые ~20 сек пока
/// VPN активен. Если helper не получит ping 60+ сек — он автоматически
/// снимет фильтры (страховка от зависания main).
pub async fn kill_switch_heartbeat() -> Result<()> {
    let resp = send(HelperRequest::KillSwitchHeartbeat).await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// Аварийный сброс — удалить все WFP-фильтры с нашим provider GUID.
/// Используется UI-кнопкой когда что-то пошло не так и интернет
/// заблокирован. Идемпотентно: если ничего нет — просто Ok.
pub async fn kill_switch_force_cleanup() -> Result<()> {
    let resp = send(HelperRequest::KillSwitchForceCleanup).await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// 13.L: spawn mihomo как SYSTEM-процесс через helper. Используется
/// в built-in TUN-режиме где требуются админ-права на CreateAdapter.
pub async fn start_tunnel(config_yaml: String, allow_lan: bool) -> Result<()> {
    if config_yaml.len() > MAX_CONFIG_BYTES {
        bail!("mihomo config exceeds {MAX_CONFIG_BYTES} bytes");
    }
    let resp = send(HelperRequest::StartTunnel {
        config_yaml,
        allow_lan,
    })
    .await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// 13.L: остановить SYSTEM-spawned mihomo. Идемпотентно — если helper
/// не запускал mihomo, вернёт Ok сразу.
pub async fn mihomo_stop() -> Result<()> {
    let resp = send(HelperRequest::MihomoStop).await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// Cleanup orphan TUN resources carrying the reserved product marker.
/// «восстановить сеть». Безопасно вызывать только когда VPN не активен
/// (иначе порвёт активный туннель).
pub async fn orphan_cleanup() -> Result<()> {
    let resp = send(HelperRequest::OrphanCleanup).await?;
    match resp {
        HelperResponse::Ok => Ok(()),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// 14.E: проверка остатков WFP-фильтров от прошлой сессии. Best-effort,
/// без побочных эффектов. Возвращает `Ok(true)` если sublayer с нашим
/// GUID существует в persistent WFP store. Используется для UI-сигнала
/// в crash-recovery диалоге.
pub async fn wfp_query_orphan() -> Result<bool> {
    let resp = send(HelperRequest::WfpQueryOrphan).await?;
    match resp {
        HelperResponse::WfpOrphan { has_orphan } => Ok(has_orphan),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// Read a bounded sanitized lifecycle log through the authenticated helper
/// pipe. The unprivileged process never opens ProgramData directly.
pub async fn read_diagnostics() -> Result<String> {
    match send(HelperRequest::ReadDiagnostics).await? {
        HelperResponse::Diagnostics { text } => Ok(text),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

/// Query liveness of the service-owned Mihomo child over the authenticated
/// pipe. A transport error is deliberately distinct from `running=false` so
/// callers can choose a fail-closed UI state.
pub async fn tunnel_status() -> Result<TunnelStatus> {
    match send(HelperRequest::TunnelStatus).await? {
        HelperResponse::TunnelStatus {
            running,
            cleanup_pending,
            firewall_active,
            device_owned,
        } => Ok(TunnelStatus {
            running,
            cleanup_pending,
            firewall_active,
            device_owned,
        }),
        HelperResponse::Error { message } => bail!("{message}"),
        other => bail!("неожиданный ответ helper: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_is_exact_and_path_free() {
        assert_eq!(HELPER_PROTOCOL_VERSION, 15);
        let json = serde_json::to_string(&HelperRequest::StartTunnel {
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
    fn pipe_deadline_covers_privileged_readiness_and_cleanup() {
        assert!(IO_TIMEOUT > Duration::from_secs(10 + 3));
    }

    #[test]
    fn cleanup_pending_status_is_not_clear() {
        let status = TunnelStatus {
            running: false,
            cleanup_pending: true,
            firewall_active: false,
            device_owned: true,
        };
        assert!(status.is_active_or_pending());
        assert!(!status.is_clear());
    }

    #[test]
    fn resource_status_wire_shape_contains_no_identity() {
        let json = r#"{"result":"tunnel_status","running":false,"cleanup_pending":true,"firewall_active":false,"device_owned":true}"#;
        let response: HelperResponse = serde_json::from_str(json).unwrap();
        assert!(matches!(
            response,
            HelperResponse::TunnelStatus {
                running: false,
                cleanup_pending: true,
                firewall_active: false,
                device_owned: true,
            }
        ));
        assert!(!json.contains("path"));
        assert!(!json.contains("alias"));
        assert!(!json.contains("pid"));
    }

    #[test]
    fn accepts_only_running_service_with_exact_pipe_pid() {
        assert!(validate_service_binding(1234, ServiceState::Running, Some(1234)).is_ok());
    }

    #[test]
    fn rejects_non_running_missing_and_mismatched_service_pids() {
        assert!(validate_service_binding(1234, ServiceState::Stopped, Some(1234)).is_err());
        assert!(validate_service_binding(1234, ServiceState::Running, None).is_err());
        assert!(validate_service_binding(1234, ServiceState::Running, Some(0)).is_err());
        assert!(validate_service_binding(1234, ServiceState::Running, Some(4321)).is_err());
        assert!(validate_service_binding(0, ServiceState::Running, Some(0)).is_err());
    }
}
