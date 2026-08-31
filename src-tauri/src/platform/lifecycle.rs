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

/// An early helper RPC failure is an observation, not proof cleanup failed.
/// A later authenticated clear status is authoritative and supersedes it;
/// otherwise retain the full chain for a truthful user-visible error.
pub fn unresolved_cleanup_errors(verified_clear: bool, errors: Vec<String>) -> Vec<String> {
    if verified_clear {
        Vec::new()
    } else {
        errors
    }
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

    #[test]
    fn authoritative_final_status_controls_cleanup_error() {
        let observations = vec!["initial status unavailable".to_string()];
        assert!(unresolved_cleanup_errors(true, observations.clone()).is_empty());
        assert_eq!(
            unresolved_cleanup_errors(false, observations.clone()),
            observations
        );
    }
}
