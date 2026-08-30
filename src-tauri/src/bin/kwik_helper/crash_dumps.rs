//! 14.C — crash-dump hook для helper-сервиса.
//!
//! Dumps are written only below the installer-protected runtime directory;
//! environment-controlled/user-writable paths are never used by SYSTEM.

use std::backtrace::Backtrace;
use std::io::Write;
use std::panic;
use std::time::{SystemTime, UNIX_EPOCH};

use super::security::Installation;

pub fn install_panic_hook() {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        prev(info);
        if let Err(e) = write_crash_dump(info) {
            eprintln!("[crash-dump] не удалось записать: {e}");
        }
    }));
}

fn write_crash_dump(info: &panic::PanicHookInfo<'_>) -> std::io::Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let installation = Installation::load().map_err(std::io::Error::other)?;
    let mut f = installation
        .replace_runtime_file(&format!("crash-{ts}-kwik-helper.txt"))
        .map_err(std::io::Error::other)?;

    writeln!(f, "Kwik helper crash dump")?;
    writeln!(f, "----------------------")?;
    writeln!(f, "component: kwik-helper")?;
    writeln!(f, "version:   {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(f, "timestamp: {ts}")?;
    writeln!(f, "os:        {}", std::env::consts::OS)?;
    writeln!(f, "arch:      {}", std::env::consts::ARCH)?;
    if let Some(loc) = info.location() {
        writeln!(f, "location:  {loc}")?;
    }
    writeln!(f)?;
    writeln!(f, "panic info:")?;
    writeln!(f, "{info}")?;
    writeln!(f)?;
    let bt = Backtrace::force_capture();
    writeln!(f, "backtrace:")?;
    writeln!(f, "{bt}")?;

    Ok(())
}
