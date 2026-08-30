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
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| !owner.tunnel_active && !owner.firewall_active)
        {
            self.owner = None;
        }
    }

    fn any_active(&self) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| owner.tunnel_active || owner.firewall_active)
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
            let tun_if = super::tun::current_tun_interface_index(expect_tun, expected_device).await;
            if expect_tun && tun_if.is_none() {
                hlog("[helper-dispatch] exact session-owned TUN adapter was not found");
            }
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
                super::tun::cleanup_orphan_resources().await;
                Ok(())
            }
        }
        Request::StartTunnel {
            config_yaml,
            allow_lan,
        } => {
            if let Err(error) = state.bind_or_verify(installation, client.session_id, client.pid) {
                return Response::err(error.to_string());
            }
            mihomo::start(&config_yaml, allow_lan, installation, client.session_id)
                .await
                .map(|tun_device| {
                    if let Some(owner) = state.owner.as_mut() {
                        owner.tunnel_active = true;
                        owner.tun_device = Some(tun_device);
                    }
                })
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
                    if let Some(device) = device.as_deref() {
                        if let Err(error) = super::tun::cleanup_owned_device(device).await {
                            return Response::err(format!("owned TUN cleanup: {error:#}"));
                        }
                    }
                    if let Some(owner) = state.owner.as_mut() {
                        owner.tunnel_active = false;
                        owner.tun_device = None;
                    }
                    state.release_if_idle();
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        Request::Ping | Request::Version | Request::WfpQueryOrphan => unreachable!(),
    };
    if result.is_err() {
        state.release_if_idle();
    }
    match result {
        Ok(()) => Response::Ok,
        Err(error) => Response::err(format!("privileged request rejected: {error:#}")),
    }
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
    let firewall_result = firewall::disable().await;
    if let Some(device) = device.as_deref() {
        super::tun::cleanup_owned_device(device).await?;
    }
    state.owner = None;
    mihomo_result.context("stop Mihomo during service shutdown")?;
    firewall_result.context("disable WFP during service shutdown")?;
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
        assert!(state.owner.is_none());
    }
}
