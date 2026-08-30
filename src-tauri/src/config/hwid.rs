//! Optional subscription pseudonyms.
//!
//! Never expose Windows `MachineGuid`: it is a stable cross-application
//! identifier.  We keep a random app-local secret and derive a different
//! deterministic pseudonym for each subscription origin.  Sending remains
//! opt-in at the UI/IPC boundary.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use uuid::Uuid;

/// Неизменяемый HWID, доступный через AppState.
pub struct HwidState(pub String);

fn hwid_path() -> Result<PathBuf> {
    let base = std::env::var("LOCALAPPDATA")
        .context("переменная LOCALAPPDATA не установлена")?;
    Ok(PathBuf::from(base).join("KwikProxy Secure").join("hwid.txt"))
}

/// Load or create the app-local random secret.  It is deliberately unrelated
/// to OS/hardware identifiers.
pub fn load_or_create() -> Result<String> {
    let path = hwid_path()?;

    let existing_is_bounded = fs::metadata(&path)
        .map(|metadata| metadata.len() <= 128)
        .unwrap_or(false);
    if existing_is_bounded {
        if let Ok(existing) = fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if Uuid::parse_str(trimmed).is_ok() {
                return Ok(trimmed.to_string());
            }
        }
    }

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).context("не удалось создать директорию для HWID")?;
    }
    let hwid = Uuid::new_v4().to_string();
    fs::write(&path, &hwid).context("не удалось сохранить HWID")?;
    Ok(hwid)
}

/// Derive a stable, unlinkable pseudonym for one normalized HTTPS
/// subscription record. Path/query are included so two subscriptions hosted
/// on the same panel do not share an identifier; fragments are excluded
/// because they are not sent to the server.
pub fn for_subscription(master_secret: &str, subscription_url: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(subscription_url).context("invalid subscription URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("subscription HWID is available only for HTTPS URLs");
    }
    url.host_str().context("subscription URL has no host")?;
    url.set_fragment(None);
    let normalized_record = url.to_string();
    let mut message = b"kwikproxy-secure-subscription-pseudonym-v1\0".to_vec();
    message.extend_from_slice(normalized_record.as_bytes());
    let digest = hmac_sha256(master_secret.as_bytes(), &message);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Minimal RFC 2104 HMAC-SHA-256 using the already-audited `sha2` crate.
/// Keeping the install secret as the HMAC key avoids the length-extension
/// weakness of a raw `SHA256(secret || url)` construction.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_known_vector() {
        let digest = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn pseudonym_is_subscription_scoped_and_ignores_fragments() {
        let master = "random-install-secret";
        let a = for_subscription(master, "https://example.com/sub?token=one").unwrap();
        let b = for_subscription(master, "https://example.com/sub?token=one#ui").unwrap();
        let c = for_subscription(master, "https://other.example/sub").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let other_record = for_subscription(master, "https://example.com/sub?token=two").unwrap();
        assert_ne!(a, other_record);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn pseudonym_rejects_plain_http() {
        assert!(for_subscription("secret", "http://example.com/sub").is_err());
    }
}
