//! Session-scoped privileged RPC dispatch.
//!
//! All state-changing requests are serialized. Once a tunnel or WFP state is
//! active, only the authenticated interactive session that created it may
//! mutate or clean it up. A same-session UI restart is intentionally allowed;
//! a different session must restart the service for controlled recovery.

use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::Mutex;

use super::firewall;
use super::helper_log::log as hlog;
use super::mihomo;
use super::protocol::{Request, Response, PROTOCOL_VERSION};
use super::security::{AuthenticatedClient, Installation};
use super::wfp;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
struct ActiveOwner {
    generation: String,
    session_id: u32,
    last_pid: u32,
    tunnel_active: bool,
    firewall_active: bool,
    tun_device: Option<String>,
    tunnel_pid: Option<u32>,
    tunnel_instance_id: Option<String>,
}

impl ActiveOwner {
    fn matches(&self, generation: &str, session_id: u32) -> bool {
        self.session_id == session_id && self.generation == generation
    }
}

#[derive(Default)]
struct BrokerState {
    owner: Option<ActiveOwner>,
}

impl BrokerState {
    fn bind_or_verify(
        &mut self,
        installation: &Installation,
        session_id: u32,
        pid: u32,
    ) -> Result<()> {
        match self.owner.as_mut() {
            Some(owner) if !owner.matches(&installation.generation, session_id) => {
                bail!("privileged state belongs to another session or install generation")
            }
            Some(owner) => {
                // Same-session process restart is controlled recovery, not a
                // cross-session ownership transfer.
                owner.last_pid = pid;
                Ok(())
            }
            None => {
                self.owner = Some(ActiveOwner {
                    generation: installation.generation.clone(),
                    session_id,
                    last_pid: pid,
                    tunnel_active: false,
                    firewall_active: false,
                    tun_device: None,
                    tunnel_pid: None,
                    tunnel_instance_id: None,
                });
                Ok(())
            }
        }
    }

    fn verify_if_active(&self, installation: &Installation, session_id: u32) -> Result<()> {
        if let Some(owner) = self.owner.as_ref() {
            if !owner.matches(&installation.generation, session_id) {
                bail!("privileged state belongs to another session or install generation");
            }
        }
        Ok(())
    }

    fn release_if_idle(&mut self) {
        if self.owner.as_ref().is_some_and(|owner| {
            !owner.tunnel_active && !owner.firewall_active && owner.tun_device.is_none()
        }) {
            self.owner = None;
        }
    }

    fn any_active(&self) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.tunnel_active || owner.firewall_active || owner.tun_device.is_some()
        })
    }

    fn note_tunnel_exit(
        &mut self,
        generation: &str,
        session_id: u32,
        pid: u32,
        instance_id: &str,
    ) -> bool {
        let Some(owner) = self.owner.as_mut() else {
            return false;
        };
        if !owner.matches(generation, session_id)
            || owner.tunnel_pid != Some(pid)
            || owner.tunnel_instance_id.as_deref() != Some(instance_id)
        {
            return false;
        }
        owner.tunnel_active = false;
        owner.tunnel_pid = None;
        owner.tunnel_instance_id = None;
        true
    }

    fn runtime_status(&self, running: bool) -> (bool, bool, bool) {
        let firewall_active = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.firewall_active);
        let device_owned = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.tun_device.is_some());
        let tunnel_marked = self.owner.as_ref().is_some_and(|owner| owner.tunnel_active);
        let cleanup_pending = !running && (tunnel_marked || firewall_active || device_owned);
        (cleanup_pending, firewall_active, device_owned)
    }
}

fn broker() -> &'static Mutex<BrokerState> {
    static BROKER: OnceLock<Mutex<BrokerState>> = OnceLock::new();
    BROKER.get_or_init(|| Mutex::new(BrokerState::default()))
}

pub async fn handle(
    req: Request,
    installation: &Installation,
    client: &AuthenticatedClient,
) -> Response {
    match req {
        Request::Ping => Response::Pong,
        Request::Version => Response::Version {
            version: HELPER_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
        },
        Request::WfpQueryOrphan => match wfp::has_orphan_filters() {
            Ok(has_orphan) => Response::WfpOrphan { has_orphan },
            Err(error) => Response::err(format!("wfp_query_orphan: {error:#}")),
        },
        Request::ReadDiagnostics => Response::Diagnostics {
            text: super::helper_log::recent_structured(16 * 1024).unwrap_or_default(),
        },
        Request::TunnelStatus => {
            let running = mihomo::is_running().await;
            let state = broker().lock().await;
            if let Err(error) = state.verify_if_active(installation, client.session_id) {
                return Response::err(error.to_string());
            }
            let (cleanup_pending, firewall_active, device_owned) = state.runtime_status(running);
            Response::TunnelStatus {
                running,
                cleanup_pending,
                firewall_active,
                device_owned,
            }
        }
        request => {
            let mut state = broker().lock().await;
            handle_mutating(request, installation, client, &mut state).await
        }
    }
}

async fn handle_mutating(
    req: Request,
    installation: &Installation,
    client: &AuthenticatedClient,
    state: &mut BrokerState,
) -> Response {
    let result: Result<()> = match req {
        Request::KillSwitchEnable {
            server_ips,
            allow_lan,
            block_dns,
            allow_dns_ips,
            strict_mode,
            expect_tun,
            force_disable_ipv6,
        } => {
            if server_ips.len() > 128 || allow_dns_ips.len() > 16 {
                return Response::err("kill-switch address list exceeds safety limit");
            }
            if server_ips
                .iter()
                .chain(allow_dns_ips.iter())
                .any(|value| value.parse::<std::net::IpAddr>().is_err())
            {
                return Response::err("kill-switch accepts literal IP addresses only");
            }
            if let Err(error) = state.bind_or_verify(installation, client.session_id, client.pid) {
                return Response::err(error.to_string());
            }
            let expected_device = if expect_tun {
                match state
                    .owner
                    .as_ref()
                    .and_then(|owner| owner.tun_device.clone())
                {
                    Some(device) => Some(device),
                    None => {
                        state.release_if_idle();
                        return Response::err(
                            "TUN kill-switch requires a tunnel owned by this session",
                        );
                    }
                }
            } else {
                None
            };
            let tun_if =
                match super::tun::current_tun_interface_index(expect_tun, expected_device).await {
                    Ok(interface) => interface,
                    Err(error) => {
                        state.release_if_idle();
                        return Response::err(format!(
                            "TUN kill-switch ownership gate failed: {error:#}"
                        ));
                    }
                };
            firewall::enable(
                server_ips,
                allow_lan,
                installation.trusted_app_paths(),
                block_dns,
                allow_dns_ips,
                tun_if,
                strict_mode,
                force_disable_ipv6,
            )
            .await
            .map(|()| {
                if let Some(owner) = state.owner.as_mut() {
                    owner.firewall_active = true;
                }
            })
        }
        Request::KillSwitchDisable | Request::KillSwitchForceCleanup => {
            if let Err(error) = state.verify_if_active(installation, client.session_id) {
                return Response::err(error.to_string());
            }
            firewall::disable().await.map(|()| {
                if let Some(owner) = state.owner.as_mut() {
                    owner.firewall_active = false;
                }
                state.release_if_idle();
            })
        }
        Request::KillSwitchHeartbeat => {
            if let Err(error) = state.verify_if_active(installation, client.session_id) {
                return Response::err(error.to_string());
            }
            if !state
                .owner
                .as_ref()
                .is_some_and(|owner| owner.firewall_active)
            {
                Err(anyhow!("no session-owned kill-switch is active"))
            } else {
                firewall::heartbeat();
                Ok(())
            }
        }
        Request::OrphanCleanup => {
            if state.any_active() {
                Err(anyhow!(
                    "orphan cleanup is disabled while privileged state is active"
                ))
            } else {
                super::tun::cleanup_orphan_resources().await
            }
        }
        Request::StartTunnel {
            config_yaml,
            allow_lan,
        } => {
            if let Err(error) = state.bind_or_verify(installation, client.session_id, client.pid) {
                return Response::err(error.to_string());
            }
            if state.any_active() {
                return Response::err(
                    "privileged tunnel/device/firewall state must be fully reconciled before start",
                );
            }
            let exact_device = match mihomo::validated_tun_device(&config_yaml, allow_lan) {
                Ok(device) => device,
                Err(error) => {
                    state.release_if_idle();
                    return Response::err(format!("privileged config rejected: {error:#}"));
                }
            };
            if let Some(owner) = state.owner.as_mut() {
                // Record the cleanup obligation before spawn. Any failure is
                // reconciled against this exact reserved alias.
                owner.tun_device = Some(exact_device.clone());
            }
            match mihomo::start(&config_yaml, allow_lan, installation, client.session_id).await {
                Ok(started) => {
                    debug_assert_eq!(started.tun_device, exact_device);
                    if let Some(owner) = state.owner.as_mut() {
                        owner.tunnel_active = true;
                        owner.tun_device = Some(started.tun_device);
                        owner.tunnel_pid = Some(started.pid);
                        owner.tunnel_instance_id = Some(started.instance_id);
                    }
                    Ok(())
                }
                Err(start_error) => match super::tun::cleanup_owned_device(&exact_device).await {
                    Ok(()) => {
                        if let Some(owner) = state.owner.as_mut() {
                            owner.tun_device = None;
                        }
                        state.release_if_idle();
                        Err(start_error)
                    }
                    Err(cleanup_error) => Err(anyhow!(
                        "tunnel start failed ({start_error:#}); exact device cleanup remains pending ({cleanup_error:#})"
                    )),
                },
            }
        }
        Request::MihomoStop => {
            if let Err(error) = state.verify_if_active(installation, client.session_id) {
                return Response::err(error.to_string());
            }
            let device = state
                .owner
                .as_ref()
                .and_then(|owner| owner.tun_device.clone());
            match mihomo::stop_owned(client.session_id, &installation.generation).await {
                Ok(()) => {
                    if let Some(owner) = state.owner.as_mut() {
                        owner.tunnel_active = false;
                        owner.tunnel_pid = None;
                        owner.tunnel_instance_id = None;
                    }
                    if let Some(device) = device.as_deref() {
                        if let Err(error) = super::tun::cleanup_owned_device(device).await {
                            return Response::err(format!("owned TUN cleanup: {error:#}"));
                        }
                    }
                    if let Some(owner) = state.owner.as_mut() {
                        owner.tun_device = None;
                    }
                    state.release_if_idle();
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        Request::Ping
        | Request::Version
        | Request::WfpQueryOrphan
        | Request::ReadDiagnostics
        | Request::TunnelStatus => {
            unreachable!()
        }
    };
    if result.is_err() {
        state.release_if_idle();
    }
    match result {
        Ok(()) => Response::Ok,
        Err(error) => Response::err(format!("privileged request rejected: {error:#}")),
    }
}

/// Reconcile broker/WFP ownership after the monitored SYSTEM Mihomo child
/// exits without an explicit stop request. Matching is exact, so a delayed
/// monitor from an older process cannot clear a replacement session.
pub async fn on_tunnel_process_exit(
    session_id: u32,
    generation: &str,
    pid: u32,
    instance_id: &str,
) {
    let mut state = broker().lock().await;
    if !state.note_tunnel_exit(generation, session_id, pid, instance_id) {
        return;
    }
    let device = state
        .owner
        .as_ref()
        .and_then(|owner| owner.tun_device.clone());
    if let Some(device) = device.as_deref() {
        match super::tun::cleanup_owned_device(device).await {
            Ok(()) => {
                if let Some(owner) = state.owner.as_mut() {
                    owner.tun_device = None;
                }
            }
            Err(_) => hlog(
                "[helper-dispatch] stage=child_exit_device_cleanup outcome=error code=cleanup_failed",
            ),
        }
    }
    let firewall_active = state
        .owner
        .as_ref()
        .is_some_and(|owner| owner.firewall_active);
    if firewall_active {
        match firewall::disable().await {
            Ok(()) => {
                if let Some(owner) = state.owner.as_mut() {
                    owner.firewall_active = false;
                }
            }
            Err(_) => hlog(
                "[helper-dispatch] stage=child_exit_wfp_cleanup outcome=error code=disable_failed",
            ),
        }
    }
    state.release_if_idle();
}

/// Service-only shutdown transaction. Pipe acceptance has already stopped and
/// all request workers have drained before this is called.
pub async fn shutdown_cleanup() -> Result<()> {
    let mut state = broker().lock().await;
    let device = state
        .owner
        .as_ref()
        .and_then(|owner| owner.tun_device.clone());
    let mihomo_result = mihomo::stop().await;
    if mihomo_result.is_ok() {
        if let Some(owner) = state.owner.as_mut() {
            owner.tunnel_active = false;
            owner.tunnel_pid = None;
            owner.tunnel_instance_id = None;
        }
    }
    let firewall_result = firewall::disable().await;
    if firewall_result.is_ok() {
        if let Some(owner) = state.owner.as_mut() {
            owner.firewall_active = false;
        }
    }
    let device_result = if mihomo_result.is_ok() {
        match device.as_deref() {
            Some(device) => super::tun::cleanup_owned_device(device).await,
            None => Ok(()),
        }
    } else {
        Err(anyhow!(
            "device cleanup blocked because Mihomo stop was not verified"
        ))
    };
    if device_result.is_ok() {
        if let Some(owner) = state.owner.as_mut() {
            owner.tun_device = None;
        }
    }
    state.release_if_idle();
    mihomo_result.context("stop Mihomo during service shutdown")?;
    firewall_result.context("disable WFP during service shutdown")?;
    device_result.context("remove owned TUN during service shutdown")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> BrokerState {
        BrokerState {
            owner: Some(ActiveOwner {
                generation: "generation-a".into(),
                session_id: 7,
                last_pid: 700,
                tunnel_active: true,
                firewall_active: false,
                tun_device: Some("kwikproxy-secure-owned".into()),
                tunnel_pid: Some(701),
                tunnel_instance_id: Some("instance-a".into()),
            }),
        }
    }

    #[test]
    fn active_owner_records_session_generation_and_exact_device() {
        let state = state();
        let owner = state.owner.as_ref().unwrap();
        assert_eq!(owner.session_id, 7);
        assert_eq!(owner.last_pid, 700);
        assert_eq!(owner.generation, "generation-a");
        assert_eq!(owner.tun_device.as_deref(), Some("kwikproxy-secure-owned"));
        assert!(owner.matches("generation-a", 7));
        assert!(!owner.matches("generation-a", 8));
        assert!(!owner.matches("generation-b", 7));
        assert!(state.any_active());
    }

    #[test]
    fn owner_is_released_only_after_both_resources_stop() {
        let mut state = state();
        state.release_if_idle();
        assert!(state.owner.is_some());
        state.owner.as_mut().unwrap().tunnel_active = false;
        state.release_if_idle();
        assert!(state.owner.is_some());
        state.owner.as_mut().unwrap().tun_device = None;
        state.release_if_idle();
        assert!(state.owner.is_none());
    }

    #[test]
    fn spontaneous_exit_clears_only_matching_tunnel_owner() {
        let mut state = state();
        assert!(!state.note_tunnel_exit("generation-b", 7, 701, "instance-a"));
        assert!(state.owner.as_ref().unwrap().tunnel_active);
        assert!(state.note_tunnel_exit("generation-a", 7, 701, "instance-a"));
        assert!(!state.owner.as_ref().unwrap().tunnel_active);
        assert_eq!(
            state.owner.as_ref().unwrap().tun_device.as_deref(),
            Some("kwikproxy-secure-owned")
        );
        let (cleanup_pending, firewall_active, device_owned) = state.runtime_status(false);
        assert!(cleanup_pending);
        assert!(!firewall_active);
        assert!(device_owned);
        state.release_if_idle();
        assert!(state.owner.is_some());
    }

    #[test]
    fn stale_same_session_monitor_cannot_clear_replacement() {
        let mut state = state();
        assert!(!state.note_tunnel_exit("generation-a", 7, 700, "instance-old"));
        assert!(state.owner.as_ref().unwrap().tunnel_active);
        assert!(state.owner.as_ref().unwrap().firewall_active == false);
    }
}
