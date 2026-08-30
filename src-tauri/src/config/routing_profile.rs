//! 11.A — Модель routing-профиля для split-routing конфигурации.
//!
//! Совместима с типовыми панелями (Marzban-style): GlobalProxy /
//! DomainStrategy / Direct/Proxy/BlockSites/Ip / Geoipurl/Geositeurl и др.
//! Парсится через `serde` из JSON; PascalCase поля переименовываются в
//! snake_case Rust-стороны через `#[serde(rename = "...")]`.
//!
//! Один профиль либо «статический» (вшит в base64 deep-link / в подписке),
//! либо «autorouting» (URL-источник с авто-обновлением). Различие хранится
//! в `RoutingStore` (см. routing_store.rs), здесь — только сам формат.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Стратегия резолва доменов для матчинга по IP-правилам.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[derive(Default)]
pub enum DomainStrategy {
    /// Не резолвить, матчить только домены.
    AsIs,
    /// Резолвить если домен не сматчился ни одному правилу — потом матчить IP.
    #[serde(rename = "IPIfNonMatch")]
    #[default]
    IpIfNonMatch,
    /// Всегда резолвить домен в IP перед матчингом.
    #[serde(rename = "IPOnDemand")]
    IpOnDemand,
}


/// Routing-профиль — единая декларация split-routing правил.
///
/// Поля имеют PascalCase для совместимости с Marzban / 3x-ui / sing-box
/// дампами, которые пользователи обычно копируют как есть.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingProfile {
    /// Человеко-читаемое имя профиля.
    #[serde(rename = "Name")]
    pub name: String,

    /// Если `true` — весь трафик через прокси кроме явных Direct-правил.
    /// Если `false` — только то что в ProxySites/ProxyIp.
    #[serde(rename = "GlobalProxy")]
    pub global_proxy: BoolString,

    /// Unix-timestamp последнего обновления (от автора профиля).
    #[serde(rename = "LastUpdated")]
    pub last_updated: String,

    /// Стратегия резолва доменов (см. enum).
    ///
    /// В mihomo поведение «домен → IP при необходимости» задаётся per-rule
    /// (`no-resolve` на IP-правилах = `IPIfNonMatch`, наш дефолт). Отдельного
    /// глобального knob'а нет, поэтому `AsIs`/`IPOnDemand` к точному режиму
    /// mihomo не транслируются — поле сохраняется для round-trip формата.
    #[serde(rename = "DomainStrategy")]
    pub domain_strategy: DomainStrategy,

    // ── DNS ────────────────────────────────────────────────────────────────
    // 11.E: применяются в `mihomo_config::build_dns` (URI-путь — полностью:
    // remote/domestic/hosts/fake-ip) и `merge_profile_dns` (full-profile —
    // аддитивно hosts + domestic nameserver-policy).
    #[serde(rename = "RemoteDNSType")]
    pub remote_dns_type: String,
    #[serde(rename = "RemoteDNSDomain")]
    pub remote_dns_domain: String,
    #[serde(rename = "RemoteDNSIP")]
    pub remote_dns_ip: String,
    #[serde(rename = "DomesticDNSType")]
    pub domestic_dns_type: String,
    #[serde(rename = "DomesticDNSDomain")]
    pub domestic_dns_domain: String,
    #[serde(rename = "DomesticDNSIP")]
    pub domestic_dns_ip: String,

    /// Статические DNS-hosts (в обход всех резолверов).
    #[serde(rename = "DnsHosts")]
    pub dns_hosts: std::collections::BTreeMap<String, String>,

    /// FakeDNS — виртуальные IP для доменов (Mihomo only).
    #[serde(rename = "FakeDNS")]
    pub fake_dns: BoolString,

    // ── Правила маршрутизации ──────────────────────────────────────────────
    /// Сайты которые идут direct (например `geosite:ru`).
    #[serde(rename = "DirectSites")]
    pub direct_sites: Vec<String>,
    /// IP/CIDR direct (`geoip:ru`, `10.0.0.0/8`).
    #[serde(rename = "DirectIp")]
    pub direct_ip: Vec<String>,
    /// Сайты только через прокси.
    #[serde(rename = "ProxySites")]
    pub proxy_sites: Vec<String>,
    /// IP/CIDR только через прокси.
    #[serde(rename = "ProxyIp")]
    pub proxy_ip: Vec<String>,
    /// Сайты заблокировать.
    #[serde(rename = "BlockSites")]
    pub block_sites: Vec<String>,
    /// IP/CIDR заблокировать.
    #[serde(rename = "BlockIp")]
    pub block_ip: Vec<String>,

    // ── Geofiles ───────────────────────────────────────────────────────────
    #[serde(rename = "Geoipurl")]
    pub geoip_url: String,
    #[serde(rename = "Geositeurl")]
    pub geosite_url: String,

    /// Использовать chunked-файлы (только мобильные, на десктопе игнорим).
    #[serde(rename = "useChunkFiles")]
    pub use_chunk_files: bool,
}

/// Helper-обёртка над bool для совместимости с JSON где бы значение
/// могло быть строкой (`"true"`/`"false"`) ИЛИ натуральным bool. Marzban
/// и подобные часто пишут строкой.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoolString(pub bool);

impl Serialize for BoolString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(if self.0 { "true" } else { "false" })
    }
}

impl<'de> Deserialize<'de> for BoolString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Bool(b) => Ok(BoolString(b)),
            serde_json::Value::String(s) => match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(BoolString(true)),
                "false" | "0" | "no" | "" => Ok(BoolString(false)),
                _ => Err(D::Error::custom(format!("ожидался bool, получено: {s:?}"))),
            },
            serde_json::Value::Number(n) => Ok(BoolString(n.as_i64().unwrap_or(0) != 0)),
            other => Err(D::Error::custom(format!("ожидался bool, получено: {other:?}"))),
        }
    }
}

impl RoutingProfile {
    /// Распарсить JSON-строку в RoutingProfile с базовой валидацией.
    pub fn parse_json(s: &str) -> Result<Self> {
        let p: Self = serde_json::from_str(s).context("невалидный routing JSON")?;
        p.validate()?;
        Ok(p)
    }

    /// Базовая валидация формата правил. Проверяем что URL'ы — это URL,
    /// IP/CIDR — корректные, geosite/geoip — известные префиксы.
    pub fn validate(&self) -> Result<()> {
        if self.name.len() > 256 || self.name.chars().any(char::is_control) {
            bail!("Name слишком длинное или содержит управляющие символы");
        }
        if !self.geoip_url.is_empty() && !is_https_remote_url(&self.geoip_url) {
            bail!("Geoipurl не валидный URL: {}", self.geoip_url);
        }
        if !self.geosite_url.is_empty() && !is_https_remote_url(&self.geosite_url) {
            bail!("Geositeurl не валидный URL: {}", self.geosite_url);
        }
        for (label, value) in [
            ("RemoteDNSDomain", &self.remote_dns_domain),
            ("RemoteDNSIP", &self.remote_dns_ip),
            ("DomesticDNSDomain", &self.domestic_dns_domain),
            ("DomesticDNSIP", &self.domestic_dns_ip),
        ] {
            if !value.is_empty() && !is_valid_dns_endpoint(value) {
                bail!("{label}: небезопасный DNS endpoint");
            }
        }
        for (label, value) in [
            ("RemoteDNSType", &self.remote_dns_type),
            ("DomesticDNSType", &self.domestic_dns_type),
        ] {
            let value = value.trim().to_ascii_lowercase();
            if value.len() > 16
                || !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                bail!("{label}: невалидный тип DNS");
            }
        }
        if self.dns_hosts.len() > 4096 {
            bail!("DnsHosts: слишком много записей");
        }
        for (host, address) in &self.dns_hosts {
            if !is_valid_host_pattern(host) || address.parse::<std::net::IpAddr>().is_err() {
                bail!("DnsHosts: невалидная запись `{host}`");
            }
        }
        let all_lists = [
            &self.direct_sites,
            &self.proxy_sites,
            &self.block_sites,
            &self.direct_ip,
            &self.proxy_ip,
            &self.block_ip,
        ];
        let total_rules: usize = all_lists.iter().map(|list| list.len()).sum();
        if total_rules > 100_000 {
            bail!("слишком много routing rules");
        }
        for entry in all_lists.into_iter().flatten() {
            if entry.is_empty()
                || entry.len() > 4096
                || entry.contains(',')
                || entry.chars().any(char::is_control)
            {
                bail!("routing rule содержит небезопасные символы или слишком длинное");
            }
        }
        for (label, list) in [
            ("DirectIp", &self.direct_ip),
            ("ProxyIp", &self.proxy_ip),
            ("BlockIp", &self.block_ip),
        ] {
            for entry in list {
                if entry.starts_with("geoip:") {
                    continue;
                }
                if !is_ip_or_cidr(entry) {
                    bail!("{label}: невалидный IP/CIDR `{entry}`");
                }
            }
        }
        Ok(())
    }

    /// Удобный builder для встроенного «минимального RU» шаблона (13.Q).
    pub fn minimal_ru() -> Self {
        Self {
            name: "минимальный RU".to_string(),
            global_proxy: BoolString(true),
            domain_strategy: DomainStrategy::IpIfNonMatch,
            direct_sites: vec!["geosite:ru".to_string()],
            direct_ip: vec![
                "geoip:ru".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            block_sites: vec!["geosite:category-ads-all".to_string()],
            geoip_url:
                "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
                    .to_string(),
            geosite_url:
                "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
                    .to_string(),
            ..Default::default()
        }
    }
}

pub(crate) fn is_https_remote_url(s: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(s) else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_public_ip(ip);
    }
    true
}

pub(crate) fn is_valid_dns_endpoint(raw: &str) -> bool {
    let value = raw.trim();
    if value.len() > 2048 || value.chars().any(char::is_control) {
        return false;
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return is_public_ip(ip);
    }
    if value.starts_with("https://") {
        return is_https_remote_url(value);
    }
    for scheme in ["tls://", "quic://"] {
        if let Some(authority) = value.strip_prefix(scheme) {
            if authority.is_empty()
                || authority
                    .chars()
                    .any(|c| matches!(c, '/' | '?' | '#' | '@'))
            {
                return false;
            }
            let host = if let Some(bracketed) = authority.strip_prefix('[') {
                let Some((host, suffix)) = bracketed.split_once(']') else {
                    return false;
                };
                if !suffix.is_empty()
                    && (!suffix.starts_with(':')
                        || suffix[1..].parse::<u16>().is_err())
                {
                    return false;
                }
                host
            } else {
                if authority.matches(':').count() > 1 {
                    return false; // IPv6 authorities must be bracketed.
                }
                let (host, port) = authority
                    .split_once(':')
                    .map_or((authority, None), |(host, port)| (host, Some(port)));
                if port.is_some_and(|port| port.parse::<u16>().is_err()) {
                    return false;
                }
                host
            };
            let normalized = host.trim_end_matches('.').to_ascii_lowercase();
            if normalized == "localhost"
                || normalized.ends_with(".localhost")
                || normalized.ends_with(".local")
                || normalized.ends_with(".internal")
            {
                return false;
            }
            if let Ok(ip) = normalized.parse::<std::net::IpAddr>() {
                return is_public_ip(ip);
            }
            return !normalized.is_empty()
                && normalized
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
        }
    }
    false
}

pub(crate) fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            let special = octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                || octets[0] >= 240;
            !special
                && !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                return is_public_ip(std::net::IpAddr::V4(v4));
            }
            !v6.is_loopback()
                && !v6.is_unique_local()
                && !v6.is_unicast_link_local()
                && !v6.is_unspecified()
                && !v6.is_multicast()
        }
    }
}

fn is_valid_host_pattern(host: &str) -> bool {
    let host = host.trim();
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '+'))
}

fn is_ip_or_cidr(s: &str) -> bool {
    let core = s.split('/').next().unwrap_or(s);
    let Ok(ip) = core.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    s.split('/')
        .nth(1)
        .map(|p| p.parse::<u8>().map(|n| n <= max).unwrap_or(false))
        .unwrap_or(true)
}

/// Источник профиля — критично для UX отображения и автообновления.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileSource {
    /// Статический — JSON прислан по deep-link (base64) или вручную.
    Static,
    /// Autorouting — скачан с URL и обновляется по интервалу часов.
    Autorouting { url: String, interval_hours: u32 },
}

/// Запись в `RoutingStore` — профиль + метаданные источника.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingProfileEntry {
    /// Уникальный id (UUIDv4) — генерируется при добавлении.
    pub id: String,
    /// Сам профиль с правилами.
    pub profile: RoutingProfile,
    /// Откуда он взялся (для UI и scheduler'а).
    pub source: ProfileSource,
    /// Когда последний раз обновили (unix-ts). 0 если ещё ни разу.
    pub last_fetched_at: u64,
}

impl RoutingProfileEntry {
    /// Создать новую запись со свежим UUID.
    pub fn new(profile: RoutingProfile, source: ProfileSource) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            profile,
            source,
            last_fetched_at: 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.id).context("routing entry id is not a UUID")?;
        self.profile.validate()?;
        if let ProfileSource::Autorouting {
            url,
            interval_hours,
        } = &self.source
        {
            if !is_https_remote_url(url) {
                bail!("autorouting source must be a public HTTPS URL");
            }
            if !(1..=720).contains(interval_hours) {
                bail!("autorouting interval must be between 1 and 720 hours");
            }
        }
        Ok(())
    }
}

/// Helper для парсинга: принимает либо JSON-строку, либо base64-encoded
/// JSON. Удобно для deep-link где JSON всегда base64.
pub fn parse_profile_input(input: &str) -> Result<RoutingProfile> {
    const MAX_ROUTING_INPUT_BYTES: usize = 1536 * 1024;
    const MAX_ROUTING_JSON_BYTES: usize = 1024 * 1024;
    if input.len() > MAX_ROUTING_INPUT_BYTES {
        bail!("routing profile input is too large");
    }
    let trimmed = input.trim();
    // Если начинается с `{` — это уже JSON.
    if trimmed.starts_with('{') {
        if trimmed.len() > MAX_ROUTING_JSON_BYTES {
            bail!("routing profile JSON is too large");
        }
        return RoutingProfile::parse_json(trimmed);
    }
    // Иначе пробуем как base64.
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|e| anyhow!("не base64 и не JSON: {e}"))?;
    if decoded.len() > MAX_ROUTING_JSON_BYTES {
        bail!("decoded routing profile is too large");
    }
    let s = String::from_utf8(decoded).context("base64 содержимое — не UTF-8")?;
    RoutingProfile::parse_json(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_marzban_style_json() {
        let json = r#"{
            "Name": "Test",
            "GlobalProxy": "true",
            "DomainStrategy": "IPIfNonMatch",
            "DirectSites": ["geosite:ru"],
            "DirectIp": ["10.0.0.0/8"],
            "Geoipurl": "https://example.com/geoip.dat",
            "Geositeurl": "https://example.com/geosite.dat"
        }"#;
        let p = RoutingProfile::parse_json(json).unwrap();
        assert_eq!(p.name, "Test");
        assert!(p.global_proxy.0);
        assert_eq!(p.direct_sites.len(), 1);
        assert_eq!(p.direct_sites[0], "geosite:ru");
    }

    #[test]
    fn bool_string_accepts_native_bool() {
        let json = r#"{"Name":"X","GlobalProxy":true}"#;
        let p = RoutingProfile::parse_json(json).unwrap();
        assert!(p.global_proxy.0);
    }

    #[test]
    fn rejects_invalid_cidr() {
        let json = r#"{
            "Name": "Bad",
            "DirectIp": ["999.0.0.0/8"]
        }"#;
        assert!(RoutingProfile::parse_json(json).is_err());
    }

    #[test]
    fn allows_geoip_prefix_in_ip_list() {
        let json = r#"{"Name":"X","DirectIp":["geoip:ru","10.0.0.0/8"]}"#;
        let p = RoutingProfile::parse_json(json).unwrap();
        assert_eq!(p.direct_ip.len(), 2);
    }

    #[test]
    fn minimal_ru_template_is_valid() {
        RoutingProfile::minimal_ru().validate().unwrap();
    }

    #[test]
    fn rejects_http_geofile_and_rule_injection() {
        let http = r#"{"Name":"Bad","Geoipurl":"http://example.com/geo.dat"}"#;
        assert!(RoutingProfile::parse_json(http).is_err());

        let injected = r#"{"Name":"Bad","DirectSites":["example.com,DIRECT\nMATCH,PROXY"]}"#;
        assert!(RoutingProfile::parse_json(injected).is_err());
    }

    #[test]
    fn validates_dns_hosts_and_endpoints() {
        let valid = r#"{
            "Name":"DNS",
            "RemoteDNSDomain":"https://dns.example/dns-query",
            "DomesticDNSIP":"1.1.1.1",
            "DnsHosts":{"example.com":"203.0.113.10"}
        }"#;
        RoutingProfile::parse_json(valid).unwrap();

        let bad_host = r#"{"Name":"Bad","DnsHosts":{"evil.com,INJECT":"not-an-ip"}}"#;
        assert!(RoutingProfile::parse_json(bad_host).is_err());
        let bad_dns = r#"{"Name":"Bad","RemoteDNSDomain":"file:///windows/win.ini"}"#;
        assert!(RoutingProfile::parse_json(bad_dns).is_err());
        let local_dns = r#"{"Name":"Bad","RemoteDNSIP":"127.0.0.1"}"#;
        assert!(RoutingProfile::parse_json(local_dns).is_err());
        let local_dot = r#"{"Name":"Bad","RemoteDNSDomain":"tls://localhost:853"}"#;
        assert!(RoutingProfile::parse_json(local_dot).is_err());
    }
}
