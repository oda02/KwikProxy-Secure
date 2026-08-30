//! Kwik VPN Helper — Windows-сервис, выполняющий привилегированные
//! операции от имени SYSTEM: SYSTEM-spawn VPN-движка Mihomo, настройка
//! WFP-фильтров для kill-switch, очистка orphan-ресурсов. Built-in TUN
//! inbound движка создаёт WinTUN-адаптер изнутри SYSTEM-процесса
//! (CreateAdapter требует админа).
//!
//! User-mode Tauri-приложение общается с этим helper-ом через named pipe
//! `\\.\pipe\KwikProxySecure.Helper.v13` bounded JSON-RPC протоколом.
//!
//! CLI:
//!   kwik-helper install      — установить и запустить сервис (нужен UAC)
//!   kwik-helper uninstall    — остановить и удалить сервис (нужен UAC)
//!   kwik-helper service      — точка входа SCM, не вызывать руками

#[cfg(windows)]
mod kwik_helper {
    pub mod crash_dumps;
    pub mod dispatch;
    pub mod firewall;
    pub mod helper_log;
    pub mod mihomo;
    pub mod pipe;
    pub mod protocol;
    pub mod routing;
    pub mod security;
    pub mod service;
    pub mod tun;
    pub mod wfp;
}

#[cfg(windows)]
fn main() {
    // 14.C: panic-hook первой строкой — даже если service::install
    // паникует, мы это запишем в файл.
    kwik_helper::crash_dumps::install_panic_hook();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    let result: anyhow::Result<()> = match cmd {
        "install" => kwik_helper::service::install(),
        "uninstall" => kwik_helper::service::uninstall(),
        "service" => kwik_helper::service::run_as_service(),
        "debug" => run_debug_foreground(),
        // 13.D EMERGENCY: восстанавливает интернет если kill-switch
        // фильтры остались висеть (helper не убрал их при crash, или
        // DYNAMIC не сработал). Не требует запущенного сервиса —
        // открывает свой WFP-engine, удаляет наш provider+sublayer
        // каскадно (вместе со всеми filter'ами).
        // Запускать ОТ АДМИНА:
        //   & "C:\path\to\kwik-helper.exe" killswitch-cleanup
        "killswitch-cleanup" => match kwik_helper::wfp::cleanup_provider() {
            Ok(()) => {
                println!("✓ WFP kill-switch фильтры удалены, интернет восстановлен");
                Ok(())
            }
            Err(e) => Err(e),
        },
        _ => {
            print_usage();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("ошибка: {e:#}");
        std::process::exit(1);
    }
}

/// Foreground-режим: pipe-сервер крутится прямо в этой консоли без
/// регистрации Windows-сервиса. Нужны admin-права (для CreateAdapter
/// WinTUN внутри mihomo и для WFP kill-switch фильтров).
/// Ctrl+C — корректное завершение через shutdown-флаг.
#[cfg(windows)]
fn run_debug_foreground() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_for_handler = shutdown.clone();
    ctrlc_or_warn(move || {
        eprintln!("\n[helper-debug] получен Ctrl+C, выход…");
        shutdown_for_handler.store(true, Ordering::SeqCst);
    });

    eprintln!("[helper-debug] foreground-режим (нет регистрации сервиса)");
    eprintln!("[helper-debug] Ctrl+C для выхода");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        // 13.D: то же что в service.rs — cleanup orphan-фильтров
        // на старте debug-режима (для тестов вручную).
        if let Err(err) = kwik_helper::firewall::cleanup_on_startup().await {
            eprintln!("[helper-debug] startup cleanup error: {err}");
        }
        kwik_helper::pipe::run_pipe_server(shutdown).await
    })?;
    Ok(())
}

/// Простейший Ctrl+C handler через windows-sys — без новой зависимости.
#[cfg(windows)]
fn ctrlc_or_warn<F: FnMut() + Send + 'static>(handler: F) {
    use std::sync::Mutex;
    static HANDLER: Mutex<Option<Box<dyn FnMut() + Send>>> = Mutex::new(None);
    // lock(): poisoning невозможен по построению (handler ставится один
    // раз до регистрации ctrl-handler'а), но на всякий случай recovery.
    *HANDLER.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(handler));

    unsafe extern "system" fn ctrl_handler(_: u32) -> i32 {
        if let Ok(mut g) = HANDLER.lock() {
            if let Some(h) = g.as_mut() {
                h();
            }
        }
        1 // TRUE — обработали
    }

    unsafe {
        let _ = windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

#[cfg(windows)]
fn print_usage() {
    eprintln!("kwik-helper — Windows-сервис для управления TUN-режимом");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  kwik-helper install     установить и запустить сервис");
    eprintln!("  kwik-helper uninstall   остановить и удалить сервис");
    eprintln!("  kwik-helper service     (внутренняя — вызывается SCM)");
    eprintln!("  kwik-helper debug       foreground-режим для отладки");
    eprintln!(
        "  kwik-helper killswitch-cleanup  EMERGENCY: убрать WFP-фильтры если \
         kill-switch завис и интернет заблокирован"
    );
}

#[cfg(not(windows))]
fn main() {
    eprintln!("kwik-helper поддерживается только на Windows");
    std::process::exit(1);
}
