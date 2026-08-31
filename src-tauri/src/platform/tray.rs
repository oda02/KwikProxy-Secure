//! Системный трей (этап 13.A).
//!
//! Tauri 2 имеет встроенный API для трея — `tauri::tray::TrayIconBuilder`.
//! Создаём tray один раз на старте; при смене VPN-статуса фронт зовёт
//! `tray_set_status`, мы пересобираем меню целиком (Tauri 2 не даёт
//! достать существующее меню из TrayIcon, только `set_menu` целиком —
//! это дешёвая операция, делается раз в секунду максимум).
//!
//! UX-модель:
//! - закрытие главного окна → сворачиваем в трей (без cleanup);
//! - левый клик по иконке → toggle visibility главного окна;
//! - правый клик → меню с действиями;
//! - выход из приложения возможен **только** через пункт «выйти»
//!   в меню трея — там же делаем full cleanup (Xray/Mihomo/proxy).

use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime, Wry};
use tauri_plugin_notification::NotificationExt;

use std::sync::atomic::{AtomicBool, Ordering};

use crate::platform;
use crate::vpn::MihomoState;

/// Идентификатор tray-icon. Используется потом в `tray_set_status` для
/// `app.tray_by_id`. Один трей на приложение.
pub const TRAY_ID: &str = "main";

const MENU_ID_TOGGLE: &str = "tray:toggle";
const MENU_ID_VPN: &str = "tray:vpn";
const MENU_ID_QUIT: &str = "tray:quit";
static QUIT_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

fn surface_quit_error(app: &AppHandle, error: &str) {
    eprintln!("[tray-quit] cleanup refused exit: {error}");
    let bounded: String = error.chars().take(600).collect();
    let _ = app.emit("tray-quit-error", bounded.clone());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    if let Err(notification_error) = app
        .notification()
        .builder()
        .title("KwikProxy Secure: выход отменён")
        .body(format!(
            "Не удалось безопасно завершить VPN. Окно оставлено открытым: {bounded}"
        ))
        .show()
    {
        eprintln!("[tray-quit] could not show cleanup notification: {notification_error}");
    }
}

/// Собрать меню под заданное состояние. Текст VPN-кнопки и
/// её enabled-state зависят от status/has_selection.
fn build_menu<R: Runtime>(
    app: &AppHandle<R>,
    status: &str,
    has_selection: bool,
) -> tauri::Result<Menu<R>> {
    let toggle = MenuItemBuilder::with_id(MENU_ID_TOGGLE, "Открыть Kwik").build(app)?;
    let (vpn_label, vpn_enabled) = match status {
        "running" => ("Отключить", true),
        "starting" | "stopping" => ("…", false),
        _ => ("Подключить", has_selection),
    };
    let vpn = MenuItemBuilder::with_id(MENU_ID_VPN, vpn_label)
        .enabled(vpn_enabled)
        .build(app)?;
    let quit = MenuItemBuilder::with_id(MENU_ID_QUIT, "Выйти").build(app)?;

    MenuBuilder::new(app)
        .item(&toggle)
        .separator()
        .item(&vpn)
        .separator()
        .item(&quit)
        .build()
}

/// Создать tray-icon и зарегистрировать в приложении.
///
/// Меню:
/// - **Открыть / Свернуть Kwik** — toggle главного окна;
/// - separator;
/// - **Подключить / Отключить** — invoke в фронт через event
///   `tray-action`; фронт сам вызовет `connect`/`disconnect` (логика
///   там уже есть, чтобы не дублировать на бэкенде);
/// - separator;
/// - **Выйти** — gracefully останавливаем движок, чистим прокси,
///   exit(0).
pub fn init(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let menu = build_menu(app, "stopped", false)?;

    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or_else(|| tauri::Error::AssetNotFound("default window icon".into()))?;

    let _tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("KwikProxy Secure — отключено")
        .menu(&menu)
        // По умолчанию left-click открывает меню. Перехватываем чтобы
        // вместо этого делать toggle главного окна (одинарный клик —
        // тогглит, как у большинства Windows-tray-приложений).
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            MENU_ID_TOGGLE => toggle_main_window(app),
            MENU_ID_VPN => {
                // Делегируем фронту — у него вся логика connect/disconnect
                // (выбор движка, проверка engine_compat, anti-DPI, и т.д.).
                let _ = app.emit("tray-action", "toggle-vpn");
            }
            MENU_ID_QUIT => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

/// Открыть главное окно если оно скрыто, иначе свернуть в трей.
fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        match window.is_visible() {
            Ok(true) => {
                let _ = window.hide();
            }
            _ => {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }
    }
}

/// Полный shutdown: гасим VPN и закрываем приложение. Вызывается из
/// пункта «Выйти» в меню трея — обычное закрытие окна (X) приложение
/// не закрывает, только сворачивает в трей.
pub fn quit_app(app: &AppHandle) {
    if QUIT_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _lifecycle = match platform::lifecycle::begin_shutdown().await {
            Ok(guard) => guard,
            Err(error) => {
                surface_quit_error(&app, &error);
                QUIT_IN_PROGRESS.store(false, Ordering::SeqCst);
                return;
            }
        };
        let result: Result<(), String> = async {
            let mut errors = Vec::new();
            let mut privileged_errors = Vec::new();
            if let Err(error) = platform::helper_client::tunnel_status().await {
                privileged_errors.push(format!(
                    "protected shutdown status was initially unknown: {error:#}"
                ));
            }
            if let Err(error) = platform::helper_client::mihomo_stop().await {
                privileged_errors.push(format!("stop protected Mihomo: {error:#}"));
            }
            if let Err(error) = platform::helper_client::kill_switch_disable().await {
                privileged_errors.push(format!("disable protected kill switch: {error:#}"));
            }
            let mut privileged_cleanup_verified = false;
            match platform::helper_client::tunnel_status().await {
                Ok(status) if status.is_clear() => privileged_cleanup_verified = true,
                Ok(status) => privileged_errors.push(format!(
                    "protected cleanup remains active (running={}, cleanup_pending={}, firewall_active={}, device_owned={})",
                    status.running,
                    status.cleanup_pending,
                    status.firewall_active,
                    status.device_owned,
                )),
                Err(error) => {
                    privileged_errors
                        .push(format!("verify protected shutdown cleanup: {error:#}"))
                }
            }
            errors.extend(platform::lifecycle::unresolved_cleanup_errors(
                privileged_cleanup_verified,
                privileged_errors,
            ));

            // Restore the exact attempt-owned proxy while its local listener
            // is still alive. A failed restore aborts exit instead of leaving
            // clients cached on a dead loopback endpoint.
            let mihomo = app.state::<MihomoState>();
            let mut local_cleanup_verified = true;
            if let Some(attempt_id) = mihomo.proxy_attempt_id() {
                match platform::proxy::clear_system_proxy_owned(&attempt_id) {
                    Ok(true) => mihomo.clear_proxy_attempt(&attempt_id),
                    Ok(false) => {
                        local_cleanup_verified = false;
                        errors.push("attempt-owned system proxy publication is missing".into());
                    }
                    Err(error) => {
                        local_cleanup_verified = false;
                        errors.push(format!("restore attempt-owned system proxy: {error:#}"));
                    }
                }
            } else if platform::proxy::has_pending_backup() {
                match platform::proxy::restore_pending_owned_proxy() {
                    Ok(true) => {}
                    Ok(false) => {
                        local_cleanup_verified = false;
                        errors.push("pending owned system proxy disappeared".into());
                    }
                    Err(error) => {
                        local_cleanup_verified = false;
                        errors.push(format!("restore pending owned system proxy: {error:#}"));
                    }
                }
            }
            if local_cleanup_verified {
                if let Err(error) = mihomo.stop() {
                    errors.push(format!("stop local Mihomo: {error}"));
                }
            } else {
                errors
                    .push("local Mihomo retained because its system proxy is not restored".into());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(format!("shutdown cleanup incomplete: {}", errors.join("; ")))
            }
        }
        .await;

        match result {
            Ok(()) => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                app.exit(0);
            }
            Err(error) => {
                surface_quit_error(&app, &error);
                platform::lifecycle::cancel_shutdown();
                QUIT_IN_PROGRESS.store(false, Ordering::SeqCst);
            }
        }
    });
}

/// Обновить tray под текущий VPN-статус — пересобираем меню целиком
/// и обновляем tooltip.
///
/// `status` — один из: `"stopped"`, `"starting"`, `"running"`,
/// `"stopping"`, `"error"`. `server_name` — опциональное имя текущего
/// сервера (показываем в tooltip когда подключены).
/// `has_selection` — выбран ли сервер. Если нет — кнопка connect
/// disabled с подсказкой.
pub fn set_status(
    app: &AppHandle,
    status: &str,
    server_name: Option<&str>,
    has_selection: bool,
) -> Result<(), String> {
    let tray = app
        .tray_by_id(TRAY_ID)
        .ok_or_else(|| "tray не зарегистрирован".to_string())?;

    // Tooltip — короткая строка, видна при hover в системном трее.
    let tooltip = match status {
        "running" => match server_name {
            Some(name) => format!("KwikProxy Secure — {name}"),
            None => "KwikProxy Secure — подключено".to_string(),
        },
        "starting" => "KwikProxy Secure — подключаем…".to_string(),
        "stopping" => "KwikProxy Secure — отключаем…".to_string(),
        "error" => "KwikProxy Secure — ошибка".to_string(),
        _ => "KwikProxy Secure — отключено".to_string(),
    };
    tray.set_tooltip(Some(tooltip)).map_err(|e| e.to_string())?;

    // Tauri 2 не отдаёт mutable ref на существующее меню — пересобираем
    // целиком. Дёшево, делается раз в N секунд (на каждое vpnStore.set).
    let menu = build_menu(app, status, has_selection).map_err(|e| e.to_string())?;
    tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;

    Ok(())
}
