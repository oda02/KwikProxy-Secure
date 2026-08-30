//! Current-user encrypted offline subscription cache.
//!
//! Subscription entries contain bearer credentials and, for full profiles,
//! complete Mihomo YAML.  They must never be stored in WebView localStorage.
//! On Windows the serialized record is protected with DPAPI for the current
//! user and written atomically under the fork-specific application directory.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::mihomo_config::{self, FullYamlPatch};
use super::server::ProxyEntry;
use super::subscription::SubscriptionMeta;

const CACHE_VERSION: u32 = 1;
const MAX_CACHE_PLAINTEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CACHE_CIPHERTEXT_BYTES: u64 = MAX_CACHE_PLAINTEXT_BYTES as u64 + 64 * 1024;
const MAX_CACHE_SERVERS: usize = 4096;
const DPAPI_ENTROPY: &[u8] = b"io.github.oda02.kwikproxy-secure/subscription-cache/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSubscription {
    version: u32,
    subscription_id: String,
    source_url: String,
    pub servers: Vec<ProxyEntry>,
    pub meta: Option<SubscriptionMeta>,
}

fn validate_subscription_id(id: &str) -> Result<()> {
    if id.len() < 8 || id.len() > 80 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("invalid subscription id");
    }
    Ok(())
}

fn cache_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?;
    Ok(PathBuf::from(base)
        .join("KwikProxy Secure")
        .join("subscription-cache"))
}

fn cache_path(id: &str) -> Result<PathBuf> {
    validate_subscription_id(id)?;
    Ok(cache_dir()?.join(format!("{id}.dpapi")))
}

fn reject_reparse_point(path: &std::path::Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect subscription cache path"),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("subscription cache path must not be a reparse point");
        }
    }
    #[cfg(not(windows))]
    if metadata.file_type().is_symlink() {
        bail!("subscription cache path must not be a symlink");
    }
    Ok(())
}

fn ensure_cache_dir() -> Result<PathBuf> {
    let dir = cache_dir()?;
    let app_dir = dir.parent().context("cache directory has no parent")?;
    for path in [app_dir, dir.as_path()] {
        reject_reparse_point(path)?;
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create subscription cache directory"),
        }
        // Close the create/check race before using the directory.
        reject_reparse_point(path)?;
        if !fs::metadata(path)
            .context("stat subscription cache directory")?
            .is_dir()
        {
            bail!("subscription cache path is not a directory");
        }
    }
    Ok(dir)
}

#[cfg(windows)]
fn atomic_replace(temp: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    reject_reparse_point(destination)?;
    let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        bail!("MoveFileExW failed: {}", unsafe { GetLastError() });
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(temp: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    reject_reparse_point(destination)?;
    fs::rename(temp, destination).context("atomically replace subscription cache")
}

fn validate_source_url(raw: &str) -> Result<String> {
    let mut parsed = reqwest::Url::parse(raw).context("invalid subscription URL")?;
    if !super::routing_profile::is_https_remote_url(parsed.as_str()) {
        bail!("subscription cache requires a credential-free HTTPS URL");
    }
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// Validate every entry at a config-generation sink and strip dangerous
/// full-profile surface before it can reach persistent storage.
fn sanitize_servers_for_cache(mut servers: Vec<ProxyEntry>) -> Result<Vec<ProxyEntry>> {
    if servers.len() > MAX_CACHE_SERVERS {
        bail!("too many cached subscription entries");
    }

    for entry in &mut servers {
        if entry.protocol == "mihomo-profile" {
            let raw_yaml = entry
                .raw
                .get("yaml")
                .and_then(serde_json::Value::as_str)
                .context("mihomo profile is missing raw YAML")?;
            let patch = FullYamlPatch {
                mixed_port: 31_000,
                listen: "127.0.0.1",
                socks_auth: None,
                external_controller_port: 31_001,
                external_controller_secret: "offline-cache-placeholder",
                app_rules: &[],
                anti_dpi: None,
                use_builtin_tun: false,
                tun_device: None,
                routing_profile: None,
                ipv6: false,
                custom_dns: None,
            };
            let sanitized = mihomo_config::patch_full_yaml(raw_yaml, &patch)
                .context("unsafe full profile cannot be cached")?;
            let raw = entry
                .raw
                .as_object_mut()
                .context("mihomo profile raw data must be an object")?;
            raw.insert("yaml".into(), sanitized.yaml.into());
        } else {
            // This discards no credentials, but proves the entry is one of the
            // protocols accepted by the final Mihomo config builder.
            mihomo_config::build(
                entry,
                31_000,
                "127.0.0.1",
                None,
                None,
                &[],
                None,
                false,
                None,
                false,
                None,
                31_001,
                "offline-cache-placeholder",
            )
            .context("unsafe proxy entry cannot be cached")?;
        }
    }
    Ok(servers)
}

pub fn save(
    subscription_id: &str,
    source_url: &str,
    servers: Vec<ProxyEntry>,
    meta: Option<SubscriptionMeta>,
) -> Result<()> {
    let dir = ensure_cache_dir()?;
    save_in_dir(&dir, subscription_id, source_url, servers, meta)
}

fn save_in_dir(
    dir: &std::path::Path,
    subscription_id: &str,
    source_url: &str,
    servers: Vec<ProxyEntry>,
    meta: Option<SubscriptionMeta>,
) -> Result<()> {
    validate_subscription_id(subscription_id)?;
    let source_url = validate_source_url(source_url)?;
    let servers = sanitize_servers_for_cache(servers)?;
    let record = CachedSubscription {
        version: CACHE_VERSION,
        subscription_id: subscription_id.to_string(),
        source_url,
        servers,
        meta,
    };
    let plaintext = serde_json::to_vec(&record).context("serialize subscription cache")?;
    if plaintext.len() > MAX_CACHE_PLAINTEXT_BYTES {
        bail!("subscription cache is too large");
    }
    let ciphertext = protect_current_user(&plaintext)?;
    if ciphertext.len() as u64 > MAX_CACHE_CIPHERTEXT_BYTES {
        bail!("encrypted subscription cache is too large");
    }

    let path = dir.join(format!("{subscription_id}.dpapi"));
    let temp = dir.join(format!(
        ".{subscription_id}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .context("create temporary subscription cache")?;
        file.write_all(&ciphertext)
            .context("write encrypted subscription cache")?;
        file.sync_all()
            .context("flush encrypted subscription cache")?;
        atomic_replace(&temp, &path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result?;
    Ok(())
}

pub fn load(
    subscription_id: &str,
    expected_source_url: &str,
) -> Result<Option<CachedSubscription>> {
    let path = cache_path(subscription_id)?;
    reject_reparse_point(path.parent().context("cache path has no parent")?)?;
    reject_reparse_point(&path)?;
    load_from_path(&path, subscription_id, expected_source_url)
}

fn load_from_path(
    path: &std::path::Path,
    subscription_id: &str,
    expected_source_url: &str,
) -> Result<Option<CachedSubscription>> {
    let expected_source_url = validate_source_url(expected_source_url)?;
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("stat subscription cache"),
    };
    if !metadata.is_file() || metadata.len() > MAX_CACHE_CIPHERTEXT_BYTES {
        bail!("encrypted subscription cache has an invalid size");
    }
    let mut ciphertext = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&path)
        .context("open subscription cache")?
        .take(MAX_CACHE_CIPHERTEXT_BYTES + 1)
        .read_to_end(&mut ciphertext)
        .context("read subscription cache")?;
    if ciphertext.is_empty() || ciphertext.len() as u64 > MAX_CACHE_CIPHERTEXT_BYTES {
        bail!("encrypted subscription cache has an invalid size");
    }
    let plaintext = unprotect_current_user(&ciphertext)?;
    if plaintext.len() > MAX_CACHE_PLAINTEXT_BYTES {
        bail!("decrypted subscription cache is too large");
    }
    let mut record: CachedSubscription =
        serde_json::from_slice(&plaintext).context("parse subscription cache")?;
    if record.version != CACHE_VERSION
        || record.subscription_id != subscription_id
        || record.source_url != expected_source_url
    {
        bail!("subscription cache identity mismatch");
    }
    record.servers = sanitize_servers_for_cache(record.servers)?;
    Ok(Some(record))
}

pub fn delete(subscription_id: &str) -> Result<()> {
    validate_subscription_id(subscription_id)?;
    let path = cache_path(subscription_id)?;
    reject_reparse_point(path.parent().context("cache path has no parent")?)?;
    reject_reparse_point(&path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("delete subscription cache"),
    }?;
    Ok(())
}

#[cfg(windows)]
fn protect_current_user(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
        bail!("invalid DPAPI plaintext size");
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        bail!("CryptProtectData failed: {}", unsafe { GetLastError() });
    }
    if output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as u64 > MAX_CACHE_CIPHERTEXT_BYTES
    {
        if !output.pbData.is_null() {
            unsafe { LocalFree(output.pbData as _) };
        }
        bail!("CryptProtectData returned an invalid output size");
    }
    let encrypted = unsafe {
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as _);
        bytes
    };
    Ok(encrypted)
}

#[cfg(windows)]
fn unprotect_current_user(ciphertext: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if ciphertext.is_empty() || ciphertext.len() > u32::MAX as usize {
        bail!("invalid DPAPI ciphertext size");
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        bail!("CryptUnprotectData failed: {}", unsafe { GetLastError() });
    }
    if output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > MAX_CACHE_PLAINTEXT_BYTES
    {
        if !output.pbData.is_null() {
            unsafe { LocalFree(output.pbData as _) };
        }
        bail!("CryptUnprotectData returned an invalid output size");
    }
    let plaintext = unsafe {
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as _);
        bytes
    };
    Ok(plaintext)
}

#[cfg(not(windows))]
fn protect_current_user(_plaintext: &[u8]) -> Result<Vec<u8>> {
    bail!("encrypted subscription cache is only available on Windows")
}

#[cfg(not(windows))]
fn unprotect_current_user(_ciphertext: &[u8]) -> Result<Vec<u8>> {
    bail!("encrypted subscription cache is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_ids_cannot_escape_the_fork_directory() {
        for bad in ["../escape", "a/b", "a\\b", ".", "short"] {
            assert!(validate_subscription_id(bad).is_err(), "accepted {bad}");
        }
        assert!(validate_subscription_id("12345678-abcd-4321").is_ok());
    }

    #[test]
    fn source_identity_is_https_and_fragment_free() {
        assert!(validate_source_url("https://example.com/sub?id=secret").is_ok());
        assert!(validate_source_url("http://example.com/sub").is_err());
        assert!(validate_source_url("https://user@example.com/sub").is_err());
        assert_eq!(
            validate_source_url("https://example.com/sub#other").unwrap(),
            "https://example.com/sub"
        );
    }

    #[test]
    fn hostile_full_profile_is_sanitized_before_persistence() {
        let mut raw = serde_json::Map::new();
        raw.insert(
            "yaml".into(),
            "listeners: [{name: evil, type: tun, port: 1}]\nss-config: C:\\\\evil.yaml\nproxies: []\nrules: ['MATCH,DIRECT']\n"
                .into(),
        );
        let entries = sanitize_servers_for_cache(vec![ProxyEntry {
            name: "profile".into(),
            protocol: "mihomo-profile".into(),
            server: "<mihomo>".into(),
            port: 0,
            raw: serde_json::Value::Object(raw),
            engine_compat: vec!["mihomo".into()],
        }])
        .unwrap();
        let yaml = entries[0].raw["yaml"].as_str().unwrap();
        assert!(!yaml.contains("listeners:"));
        assert!(!yaml.contains("ss-config:"));
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_uses_current_user_context() {
        let plaintext = b"kwikproxy-secure-dpapi-test";
        let ciphertext = protect_current_user(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(unprotect_current_user(&ciphertext).unwrap(), plaintext);
    }

    #[cfg(windows)]
    #[test]
    fn repeated_save_atomically_replaces_existing_cache() {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let url = "https://example.com/subscription?id=secret";
        let dir = std::env::temp_dir().join(format!(
            "kwikproxy-secure-cache-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&dir).unwrap();
        save_in_dir(&dir, &id, url, Vec::new(), None).unwrap();
        save_in_dir(&dir, &id, url, Vec::new(), None).unwrap();
        let path = dir.join(format!("{id}.dpapi"));
        let loaded = load_from_path(&path, &id, url)
            .unwrap()
            .expect("cache exists");
        assert_eq!(loaded.subscription_id, id);
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
