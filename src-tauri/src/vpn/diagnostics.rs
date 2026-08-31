//! Bounded, credential-free connection lifecycle diagnostics.
//!
//! Callers can only record compile-time stage/code labels. Raw errors, YAML,
//! subscription URLs, server hosts and bearer credentials never reach this
//! file. Detailed errors still travel through the immediate Tauri command
//! result, while this log is safe to expose later from the diagnostics UI.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_NAME: &str = "connection-events.log";
const MAX_LOG_BYTES: u64 = 64 * 1024;
const MAX_READ_BYTES: usize = 32 * 1024;

fn log_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(|base| PathBuf::from(base).join("KwikProxy Secure").join(LOG_NAME))
}

/// Record only static, reviewed labels. This signature deliberately makes it
/// impossible to accidentally pass a dynamic host, URL, token or YAML value.
pub fn record(stage: &'static str, outcome: &'static str, code: &'static str) {
    let Some(path) = log_path() else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let replace = path
        .metadata()
        .is_ok_and(|meta| meta.len() >= MAX_LOG_BYTES);
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if replace {
        options.truncate(true);
    } else {
        options.append(true);
    }
    let Ok(mut file) = options.open(path) else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let _ = writeln!(file, "ts={ts} stage={stage} outcome={outcome} code={code}");
}

pub fn recent() -> Option<String> {
    let path = log_path()?;
    let mut file = File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let start = length.saturating_sub(MAX_READ_BYTES as u64);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::with_capacity((length - start) as usize);
    file.take(MAX_READ_BYTES as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_api_accepts_static_labels_only() {
        let record_fn: fn(&'static str, &'static str, &'static str) = record;
        let _ = record_fn;
        assert!(MAX_READ_BYTES as u64 <= MAX_LOG_BYTES);
        assert!(!LOG_NAME.contains("yaml"));
    }
}
