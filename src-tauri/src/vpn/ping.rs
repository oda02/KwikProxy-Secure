//! TCP-connect ping для оценки задержки до сервера.
//!
//! Не использует ICMP (требует raw socket / прав администратора). Вместо
//! этого замеряет время установления TCP-соединения к `host:port` сервера,
//! что даёт практически релевантную метрику для VPN-подключения.

use std::time::{Duration, Instant};

use serde_json::Value;
use std::net::{IpAddr, SocketAddr};

use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

use crate::config::ProxyEntry;

const PING_TIMEOUT_MS: u64 = 2500;

/// TCP-connect-ping. Возвращает время в миллисекундах или `None`, если
/// сервер не отвечает в течение `PING_TIMEOUT_MS`.
pub async fn tcp_ping(host: &str, port: u16) -> Option<u32> {
    let start = Instant::now();
    timeout(Duration::from_millis(PING_TIMEOUT_MS), async {
        // Resolve explicitly before connecting.  A concurrently running VPN
        // may answer DNS with a fake-IP (most commonly 198.18.0.0/15) and
        // accept the TCP socket in its local TUN stack in 1-4 ms.  Measuring
        // that local interception as the remote node's latency is actively
        // misleading, so never probe non-public/fake addresses.
        let addrs = lookup_host((host, port)).await.ok()?;
        for addr in addrs {
            if !is_public_probe_addr(addr) {
                continue;
            }
            if TcpStream::connect(addr).await.is_ok() {
                return Some(start.elapsed().as_millis() as u32);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

fn is_public_probe_addr(addr: SocketAddr) -> bool {
    is_public_probe_ip(addr.ip())
}

/// Whether an address can represent a real Internet endpoint for latency
/// probing.  Shared with the ICMP fallback so a fake-IP rejected by the TCP
/// path cannot come back as a bogus 1 ms ICMP result.
pub(crate) fn is_public_probe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            !ip.is_unspecified()
                && !ip.is_loopback()
                && (first & 0xfe00) != 0xfc00 // fc00::/7 unique-local
                && (first & 0xffc0) != 0xfe80 // fe80::/10 link-local
                && (first & 0xff00) != 0xff00 // ff00::/8 multicast
                && !is_documentation_v6(ip)
        }
    }
}

fn is_documentation_v6(ip: std::net::Ipv6Addr) -> bool {
    // 2001:db8::/32.  Keep this separate to make the intended prefix clear.
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

/// Извлечь host/port из ProxyEntry для пинга.
///
/// Для обычных серверов берётся `entry.server` / `entry.port`.
/// Для `xray-json` ищется первый outbound с тегом, начинающимся на `proxy`,
/// и берётся адрес из его настроек (vnext для VLESS/VMess, servers для Trojan/SS).
pub fn extract_target(entry: &ProxyEntry) -> Option<(String, u16)> {
    if entry.protocol != "xray-json" {
        if entry.server.is_empty() || entry.port == 0 {
            return None;
        }
        return Some((entry.server.clone(), entry.port));
    }

    let outbounds = entry.raw.get("outbounds")?.as_array()?;
    for ob in outbounds {
        let tag = ob.get("tag").and_then(Value::as_str).unwrap_or("");
        if !tag.starts_with("proxy") {
            continue;
        }
        let proto = ob.get("protocol").and_then(Value::as_str).unwrap_or("");
        let settings = ob.get("settings")?;

        let target = match proto {
            "vless" | "vmess" => {
                let first = settings.get("vnext")?.as_array()?.first()?;
                let host = first.get("address")?.as_str()?;
                let port = first.get("port")?.as_u64()? as u16;
                Some((host.to_string(), port))
            }
            "trojan" | "shadowsocks" => {
                let first = settings.get("servers")?.as_array()?.first()?;
                let host = first.get("address")?.as_str()?;
                let port = first.get("port")?.as_u64()? as u16;
                Some((host.to_string(), port))
            }
            _ => None,
        };
        if target.is_some() {
            return target;
        }
    }
    None
}

/// Пингует один ProxyEntry. Возвращает None если адрес не извлекается
/// или если сервер не ответил в timeout.
pub async fn ping_entry(entry: &ProxyEntry) -> Option<u32> {
    let (host, port) = extract_target(entry)?;
    tcp_ping(&host, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn socket(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 443)
    }

    #[test]
    fn rejects_fake_ip_and_non_public_probe_targets() {
        for ip in [
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 19, 255, 254),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(203, 0, 113, 1),
        ] {
            assert!(!is_public_probe_addr(socket(IpAddr::V4(ip))), "{ip}");
        }
        for ip in [
            Ipv6Addr::LOCALHOST,
            "fc00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ] {
            assert!(!is_public_probe_addr(socket(IpAddr::V6(ip))), "{ip}");
        }
    }

    #[test]
    fn accepts_public_probe_targets() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
        ] {
            assert!(is_public_probe_addr(socket(ip)), "{ip}");
        }
    }
}
