//! Append-only log in the installer-protected runtime directory.
//!
//! Helper работает как Windows service — его stdout/stderr куда-то теряются
//! (SCM не сохраняет их по умолчанию). Чтобы пользователь и разработчик
//! могли видеть что происходит внутри (особенно kill-switch decisions),
//! ключевые сообщения дублируем сюда.
//!
//! Best-effort: ошибки записи игнорируются (не валим helper если файл не
//! доступен). Файл переоткрывается на каждое сообщение — медленно, но
//! kill-switch enable случается раз в connect-сессию, не критично.

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use super::security::Installation;

static LOG_INITIALIZED: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
static VERIFIED_INSTALLATION: std::sync::Mutex<Option<Installation>> = std::sync::Mutex::new(None);

/// Дописать строку в helper.log с timestamp'ом + продублировать в stderr
/// (на случай если helper запущен не как сервис, а через `debug`-режим).
///
/// Не возвращает Result — если запись не удалась, helper продолжает
/// работать.
pub fn log(msg: &str) {
    eprintln!("{msg}");

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let installation = {
        let Ok(mut cached) = VERIFIED_INSTALLATION.lock() else {
            return;
        };
        if cached.is_none() {
            let Ok(verified) = Installation::load() else {
                return;
            };
            *cached = Some(verified);
        }
        cached.as_ref().unwrap().clone()
    };
    let Ok(mut initialized) = LOG_INITIALIZED.lock() else {
        return;
    };
    let file = if *initialized {
        installation.open_runtime_log("helper.log")
    } else {
        installation.replace_runtime_file("helper.log")
    };
    if let Ok(mut f) = file {
        *initialized = true;
        let _ = f.seek(SeekFrom::End(0));
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

/// Read a bounded tail of the protected service log so the elevated installer
/// process can surface an early startup failure before its safe rollback
/// removes the per-install runtime directory.
pub fn recent(max_bytes: usize) -> Option<String> {
    if max_bytes == 0 {
        return None;
    }
    let installation = Installation::load().ok()?;
    let mut file = installation.open_runtime_log("helper.log").ok()?;
    let length = file.metadata().ok()?.len();
    let start = length.saturating_sub(max_bytes as u64);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::with_capacity((length - start) as usize);
    file.take(max_bytes as u64).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    (!text.is_empty()).then_some(text)
}
