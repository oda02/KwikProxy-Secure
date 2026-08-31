//! TCP-connect ping для оценки задержки до сервера.
//!
//! Не использует ICMP (требует raw socket / прав администратора). Вместо
//! этого замеряет время установления TCP-соединения к `host:port` сервера,
//! что даёт практически релевантную метрику для VPN-подключения.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use serde_json::Value;

use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

use crate::config::ProxyEntry;
use crate::platform;

const PING_TIMEOUT_MS: u64 = 2500;
/// One wall-clock budget for the mihomo-node probe, including DNS, TCP and
/// the optional ICMP fallback. TCP gets at most the first half so an
/// UDP-only node still has a chance to answer ICMP inside the same deadline.
const NODE_PING_TOTAL_TIMEOUT_MS: u64 = 5000;

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
        let addrs = resolve_public_probe_addrs(host, port).await?;
        if tcp_connect_first(&addrs).await {
            Some(elapsed_ms(start))
        } else {
            None
        }
    })
    .await
    .ok()
    .flatten()
}

/// Pre-connect probe for a Mihomo profile node. DNS is resolved exactly once;
/// the same filtered addresses feed TCP and the IPv4 ICMP fallback. An
/// IPv6-only UDP node intentionally returns `None` (UI: `—`) because this
/// process has no safe user-mode ICMPv6 implementation; fabricating an IPv4
/// or TCP result would be misleading.
pub(crate) async fn ping_node(host: &str, port: u16) -> Option<u32> {
    if host.is_empty() || port == 0 {
        return None;
    }

    let total = Duration::from_millis(NODE_PING_TOTAL_TIMEOUT_MS);
    timeout(total, async {
        let started = Instant::now();
        let addrs = resolve_public_probe_addrs(host, port).await?;

        let remaining = total.checked_sub(started.elapsed())?;
        let tcp_budget = remaining.min(Duration::from_millis(PING_TIMEOUT_MS));
        if timeout(tcp_budget, tcp_connect_first(&addrs))
            .await
            .unwrap_or(false)
        {
            return Some(elapsed_ms(started));
        }

        let ipv4 = addrs.iter().find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })?;
        let remaining = total.checked_sub(started.elapsed())?;
        let icmp_timeout_ms = remaining.as_millis().clamp(1, u32::MAX as u128) as u32;
        tokio::task::spawn_blocking(move || platform::icmp::icmp_echo_ipv4(ipv4, icmp_timeout_ms))
            .await
            .ok()
            .flatten()
    })
    .await
    .ok()
    .flatten()
}

async fn resolve_public_probe_addrs(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let addrs: Vec<_> = if let Ok(ip) = host.parse::<IpAddr>() {
        std::iter::once(SocketAddr::new(ip, port))
            .filter(|addr| is_public_probe_addr(*addr))
            .collect()
    } else {
        lookup_host((host, port))
            .await
            .ok()?
            .filter(|addr| is_public_probe_addr(*addr))
            .filter(|addr| seen.insert(*addr))
            .collect()
    };
    (!addrs.is_empty()).then_some(addrs)
}

async fn tcp_connect_first(addrs: &[SocketAddr]) -> bool {
    for &addr in addrs {
        // Defense in depth for future callers: never trust that a resolved
        // address was filtered earlier in the pipeline.
        if is_public_probe_addr(addr) && TcpStream::connect(addr).await.is_ok() {
            return true;
        }
    }
    false
}

fn elapsed_ms(started: Instant) -> u32 {
    started.elapsed().as_millis().min(u32::MAX as u128) as u32
}

fn is_public_probe_addr(addr: SocketAddr) -> bool {
    is_public_probe_ip(addr.ip())
}

/// Whether an address can represent a real Internet endpoint for latency
/// probing.  Shared with the ICMP fallback so a fake-IP rejected by the TCP
/// path cannot come back as a bogus 1 ms ICMP result.
pub(crate) fn is_public_probe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_probe_ipv4(ip),
        IpAddr::V6(ip) => is_public_probe_ipv6(ip),
    }
}

fn is_public_probe_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();

    // IANA assigns two globally reachable anycast services inside the
    // otherwise special 192.0.0.0/24 block.
    if (a, b, c) == (192, 0, 0) {
        return d == 9 || d == 10;
    }

    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_probe_ipv6(ip: Ipv6Addr) -> bool {
    // Normalize both IPv4-compatible (::a.b.c.d) and IPv4-mapped
    // (::ffff:a.b.c.d) forms through the exact same IPv4 policy. Otherwise
    // mapped loopback/RFC1918/fake-IP addresses bypass an IPv6 denylist.
    if let Some(ipv4) = embedded_ipv4(ip) {
        return is_public_probe_ipv4(ipv4);
    }

    let segments = ip.segments();
    // Conservatively probe only today's global-unicast 2000::/3 space.
    // Within it, exclude IANA special-purpose blocks which are not ordinary
    // remotely routable endpoints. This intentionally favors `—` over a
    // misleading or internal probe when allocation semantics are unclear.
    (segments[0] & 0xe000) == 0x2000
        && !ipv6_prefix_matches(&segments, &[0x2001, 0x0000], 23) // IETF protocol assignments
        && !ipv6_prefix_matches(&segments, &[0x2001, 0x0db8], 32) // documentation
        && !ipv6_prefix_matches(&segments, &[0x2002], 16) // deprecated 6to4 transition
        && !ipv6_prefix_matches(&segments, &[0x3ffe], 16) // returned 6bone space
        && !ipv6_prefix_matches(&segments, &[0x3fff, 0x0000], 20) // documentation
}

fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    let compatible = octets[..12].iter().all(|byte| *byte == 0);
    let mapped =
        octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff;
    (compatible || mapped).then(|| Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
}

fn ipv6_prefix_matches(segments: &[u16; 8], prefix: &[u16], bits: u8) -> bool {
    let full_segments = (bits / 16) as usize;
    if segments[..full_segments] != prefix[..full_segments] {
        return false;
    }
    let remaining = bits % 16;
    if remaining == 0 {
        return true;
    }
    let mask = u16::MAX << (16 - remaining);
    segments[full_segments] & mask == prefix[full_segments] & mask
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

    fn socket(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 443)
    }

    #[test]
    fn ipv4_special_range_boundaries_are_table_driven() {
        let cases = [
            ("0.255.255.255", false),
            ("1.0.0.1", true),
            ("10.255.255.255", false),
            ("11.0.0.0", true),
            ("100.63.255.255", true),
            ("100.64.0.0", false),
            ("100.127.255.255", false),
            ("100.128.0.0", true),
            ("172.15.255.255", true),
            ("172.16.0.0", false),
            ("172.31.255.255", false),
            ("172.32.0.0", true),
            ("192.0.0.8", false),
            ("192.0.0.9", true),
            ("192.0.0.10", true),
            ("192.0.0.11", false),
            ("192.0.2.1", false),
            ("192.88.99.1", false),
            ("192.168.255.255", false),
            ("198.17.255.255", true),
            ("198.18.0.0", false),
            ("198.19.255.255", false),
            ("198.20.0.0", true),
            ("198.51.100.1", false),
            ("203.0.113.1", false),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
        ];
        for (raw, expected) in cases {
            let ip: IpAddr = raw.parse().unwrap();
            assert_eq!(is_public_probe_addr(socket(ip)), expected, "{raw}");
        }
    }

    #[test]
    fn mapped_and_compatible_ipv4_use_the_ipv4_classifier() {
        let cases = [
            ("::ffff:127.0.0.1", false),
            ("::ffff:10.0.0.1", false),
            ("::ffff:192.168.1.1", false),
            ("::ffff:198.18.0.1", false),
            ("::127.0.0.1", false),
            ("::10.0.0.1", false),
            ("::198.18.0.1", false),
            ("::ffff:8.8.8.8", true),
            ("::8.8.8.8", true),
        ];
        for (raw, expected) in cases {
            let ip: IpAddr = raw.parse().unwrap();
            assert_eq!(is_public_probe_addr(socket(ip)), expected, "{raw}");
        }
    }

    #[test]
    fn ipv6_probe_policy_is_conservative_and_boundary_checked() {
        let cases = [
            ("::", false),
            ("::1", false),
            ("64:ff9b::808:808", false),
            ("100::1", false),
            ("2001:1ff:ffff::1", false),
            ("2001:200::1", true),
            ("2001:db8::1", false),
            ("2002:808:808::1", false),
            ("2606:4700:4700::1111", true),
            ("3ffd:ffff::1", true),
            ("3ffe::1", false),
            ("3fff::1", false),
            ("4000::1", false),
            ("fc00::1", false),
            ("fec0::1", false),
            ("fe80::1", false),
            ("ff02::1", false),
        ];
        for (raw, expected) in cases {
            let ip: IpAddr = raw.parse().unwrap();
            assert_eq!(is_public_probe_addr(socket(ip)), expected, "{raw}");
        }
    }
}
