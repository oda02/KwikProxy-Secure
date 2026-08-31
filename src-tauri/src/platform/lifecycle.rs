//! Process-wide serialization and shutdown seal for network mutations.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tokio::sync::{Mutex, MutexGuard};

static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

fn lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub struct Guard {
    _guard: MutexGuard<'static, ()>,
}

pub async fn enter() -> Result<Guard, String> {
    let guard = lock().lock().await;
    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        return Err("application shutdown is already sealed".into());
    }
    Ok(Guard { _guard: guard })
}

pub async fn begin_shutdown() -> Result<Guard, String> {
    let guard = lock().lock().await;
    if SHUTTING_DOWN.swap(true, Ordering::SeqCst) {
        return Err("application shutdown is already in progress".into());
    }
    Ok(Guard { _guard: guard })
}

pub fn cancel_shutdown() {
    SHUTTING_DOWN.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_seal_is_fail_closed_until_explicit_cancel() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            cancel_shutdown();
            let shutdown = begin_shutdown().await.unwrap();
            drop(shutdown);
            assert!(enter().await.is_err());
            cancel_shutdown();
            assert!(enter().await.is_ok());
        });
    }
}
