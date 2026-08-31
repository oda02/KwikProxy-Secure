//! Управление процессом Mihomo (Clash Meta) sidecar — этап 8.B.
//!
//! Симметричен `xray.rs`: принимает готовый YAML-конфиг, пишет в файл
//! `%TEMP%\KwikProxy Secure\mihomo-config.yaml` и запускает sidecar
//! `mihomo` (target-suffixed source installed by Tauri as `mihomo.exe`). Логи stderr —
//! в `%TEMP%\KwikProxy Secure\mihomo-stderr.log`.
//!
//! Один движок на сессию (Xray ИЛИ Mihomo), что выбран — определяется в
//! `commands.rs::connect()`. Mihomo используется когда сервер из подписки
//! имеет `engine_compat = ["mihomo"]` (TUIC / AnyTLS / Mieru) либо когда
//! пользователь явно выбрал Mihomo через Settings.
//!
//! У Mihomo один объединённый порт `mixed-port` для SOCKS5+HTTP, поэтому
//! `MihomoState` хранит только один порт (в отличие от `XrayState` с двумя).

use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{AppHandle, Manager};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tokio::net::TcpStream;

const READINESS_TIMEOUT: Duration = Duration::from_secs(8);
const READINESS_POLL: Duration = Duration::from_millis(100);
const READINESS_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

/// Глобальный state Mihomo sidecar.
///
/// `current_pid` нужен для защиты от race: при быстром перезапуске старый
/// listener Terminated не должен затереть state нового процесса.
///
/// `helper_spawned` — 13.L флаг для built-in TUN-режима. Когда `true`,
/// mihomo запущен helper-сервисом (SYSTEM), не через Tauri sidecar.
/// `child` в этом случае пуст (Tauri процессом не владеет), но
/// `is_running()` всё равно возвращает true — UI/connect-checks
/// должны видеть состояние корректно.
pub struct MihomoState {
    child: Mutex<Option<CommandChild>>,
    current_pid: Mutex<Option<u32>>,
    /// `mixed-port` Mihomo: один сокет на SOCKS5 и HTTP одновременно
    /// (стандартная фича clash-style ядра, не требует двух inbound'ов).
    pub mixed_port: Mutex<u16>,
    /// Explicitly trusted no-auth loopback SOCKS port for subscription
    /// refreshes. Set only after a successful proxy-mode/non-LAN connect.
    subscription_proxy_port: Mutex<Option<u16>>,
    /// Connect-attempt identity that owns the currently published WinINet
    /// proxy backup. The process monitor may restore only this exact marker.
    proxy_attempt_id: Mutex<Option<String>>,
    /// 13.L: mihomo запущен helper'ом (built-in TUN). Set/cleared в
    /// connect/disconnect, влияет только на `is_running()`.
    helper_spawned: AtomicBool,
    /// A failed helper round-trip means SYSTEM Mihomo or WFP state may still
    /// exist. Keep the lifecycle visibly active until a later authenticated
    /// reconciliation proves both resources stopped.
    privileged_cleanup_uncertain: AtomicBool,
}

impl MihomoState {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
            current_pid: Mutex::new(None),
            mixed_port: Mutex::new(7890),
            subscription_proxy_port: Mutex::new(None),
            proxy_attempt_id: Mutex::new(None),
            helper_spawned: AtomicBool::new(false),
            privileged_cleanup_uncertain: AtomicBool::new(false),
        }
    }

    /// 13.L: пометить что mihomo сейчас запущен helper-сервисом
    /// (built-in TUN-режим). На Tauri-стороне Child нет, но `is_running`
    /// должен возвращать true.
    pub fn mark_helper_spawned(&self, on: bool) {
        self.helper_spawned.store(on, Ordering::SeqCst);
    }

    pub fn helper_spawned(&self) -> bool {
        self.helper_spawned.load(Ordering::SeqCst)
    }

    pub fn mark_privileged_cleanup_uncertain(&self, on: bool) {
        self.privileged_cleanup_uncertain
            .store(on, Ordering::SeqCst);
    }

    pub fn privileged_cleanup_uncertain(&self) -> bool {
        self.privileged_cleanup_uncertain.load(Ordering::SeqCst)
    }

    pub fn set_subscription_proxy_port(&self, port: Option<u16>) {
        if let Ok(mut current) = self.subscription_proxy_port.lock() {
            *current = port.filter(|value| (30_000..60_000).contains(value));
        }
    }

    pub fn trusted_subscription_proxy_port(&self) -> Option<u16> {
        if !self.is_running() {
            return None;
        }
        self.subscription_proxy_port
            .lock()
            .ok()
            .and_then(|port| *port)
    }

    /// Запустить Mihomo с указанным YAML-конфигом.
    ///
    /// Если уже запущен — останавливает перед перезапуском. Конфиг
    /// сохраняется в `%TEMP%\KwikProxy Secure\mihomo-config.yaml`.
    pub async fn start_with_config(
        &self,
        app: &AppHandle,
        config_yaml: &str,
        mixed_port: u16,
        controller_port: u16,
    ) -> Result<(), String> {
        self.stop()?;
        super::diagnostics::record("proxy_spawn", "started", "pending_readiness");

        let tmp_dir = std::env::temp_dir().join("KwikProxy Secure");
        std::fs::create_dir_all(&tmp_dir)
            .map_err(|e| format!("не удалось создать %TEMP%\\KwikProxy Secure: {e}"))?;
        let config_path = tmp_dir.join("mihomo-config.yaml");
        std::fs::write(&config_path, config_yaml)
            .map_err(|e| format!("запись mihomo-конфига: {e}"))?;

        let config_path_str = config_path
            .to_str()
            .ok_or_else(|| "путь к mihomo-конфигу содержит не-UTF-8 символы".to_string())?;

        // Mihomo требует «директорию данных» где хранятся geoip/geosite и cache.db.
        // Используем тот же %TEMP%\KwikProxy Secure — Mihomo создаст при необходимости.
        // 11.B: кладём geo `.dat` (user-скачанные приоритетнее бандла) в data-dir,
        // иначе правила GEOSITE:/GEOIP: профиля ломают старт mihomo.
        crate::config::geofiles::provision_into(&tmp_dir);
        let data_dir_str = tmp_dir
            .to_str()
            .ok_or_else(|| "путь к data-dir содержит не-UTF-8 символы".to_string())?;

        let stderr_log_path = tmp_dir.join("mihomo-stderr.log");
        let stderr_log: Arc<Mutex<File>> = Arc::new(Mutex::new(
            File::create(&stderr_log_path)
                .map_err(|e| format!("создание mihomo stderr-лога: {e}"))?,
        ));

        let (mut rx, child) = app
            .shell()
            .sidecar("mihomo")
            .map_err(|e| format!("sidecar mihomo не зарегистрирован: {e}"))?
            .args(["-f", config_path_str, "-d", data_dir_str])
            .spawn()
            .map_err(|e| format!("не удалось запустить mihomo: {e}"))?;

        let my_pid = child.pid();
        eprintln!("[mihomo] запущен pid={my_pid}, stderr-лог: {stderr_log_path:?}");

        let readiness = wait_for_readiness(
            &mut rx,
            mixed_port,
            controller_port,
            &stderr_log,
            READINESS_TIMEOUT,
        )
        .await;
        if let Err(error) = readiness {
            super::diagnostics::record("proxy_readiness", "error", "not_ready");
            let _ = child.kill();
            return Err(error);
        }
        super::diagnostics::record("proxy_readiness", "ok", "listeners_ready");

        {
            let mut g = self.child.lock().map_err(|e| format!("mutex: {e}"))?;
            *g = Some(child);
        }
        *self.current_pid.lock().map_err(|e| format!("mutex: {e}"))? = Some(my_pid);
        *self.mixed_port.lock().map_err(|e| format!("mutex: {e}"))? = mixed_port;

        let app_handle = app.clone();
        let stderr_log_clone = stderr_log.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    // Mihomo (Go logrus) пишет ВСЁ в stdout — info, warning,
                    // error. Чтобы пользователь мог открыть mihomo-stderr.log
                    // и увидеть «provider download failed / config parse
                    // error», складываем оба stream'а в один файл с
                    // префиксом. Без этого `out`-канал терялся в eprintln.
                    CommandEvent::Stdout(line) => {
                        let s = String::from_utf8_lossy(&line);
                        eprintln!("[mihomo:out] {s}");
                        if let Ok(mut f) = stderr_log_clone.lock() {
                            let _ = writeln!(f, "{s}");
                            let _ = f.flush();
                        }
                    }
                    CommandEvent::Stderr(line) => {
                        let s = String::from_utf8_lossy(&line);
                        eprintln!("[mihomo:err] {s}");
                        if let Ok(mut f) = stderr_log_clone.lock() {
                            let _ = writeln!(f, "{s}");
                            let _ = f.flush();
                        }
                    }
                    CommandEvent::Terminated(payload) => {
                        eprintln!(
                            "[mihomo] завершён pid={my_pid}: code={:?}, signal={:?}",
                            payload.code, payload.signal
                        );
                        if let Ok(mut f) = stderr_log_clone.lock() {
                            let _ = writeln!(
                                f,
                                "--- terminated code={:?} signal={:?} ---",
                                payload.code, payload.signal
                            );
                            let _ = f.flush();
                        }
                        let state = app_handle.state::<MihomoState>();
                        let mut proxy_attempt = state.proxy_attempt_id.lock().ok();
                        let is_current = state
                            .current_pid
                            .lock()
                            .map(|g| *g == Some(my_pid))
                            .unwrap_or(false);
                        if is_current {
                            if let Ok(mut g) = state.child.lock() {
                                *g = None;
                            }
                            if let Ok(mut g) = state.current_pid.lock() {
                                *g = None;
                            }
                            app_handle.state::<super::MihomoApiState>().clear();
                            super::diagnostics::record("proxy_child", "error", "unexpected_exit");
                            if let Some(attempt_id) =
                                proxy_attempt.as_mut().and_then(|attempt| attempt.take())
                            {
                                if !matches!(
                                    crate::platform::proxy::clear_system_proxy_owned(&attempt_id),
                                    Ok(true)
                                ) {
                                    if let Some(current) = proxy_attempt.as_mut() {
                                        **current = Some(attempt_id);
                                    }
                                    super::diagnostics::record(
                                        "system_proxy",
                                        "error",
                                        "monitor_restore_failed",
                                    );
                                }
                            }
                        } else {
                            eprintln!(
                                "[mihomo] pid={my_pid} устаревший — не трогаем state нового процесса"
                            );
                        }
                        break;
                    }
                    CommandEvent::Error(err) => {
                        eprintln!("[mihomo:error] {err}");
                        break;
                    }
                    _ => {}
                }
            }
            // A closed/erroring event stream means child liveness is no
            // longer observable. Fail closed: terminate only the exact child
            // currently associated with this monitor, then clear published
            // controller/proxy state. Normal termination and explicit stop
            // clear current_pid first, making this block a no-op.
            let state = app_handle.state::<MihomoState>();
            let mut proxy_attempt = state.proxy_attempt_id.lock().ok();
            let is_current = state
                .current_pid
                .lock()
                .map(|current| *current == Some(my_pid))
                .unwrap_or(false);
            if is_current {
                let child = state.child.lock().ok().and_then(|mut child| child.take());
                if let Ok(mut current) = state.current_pid.lock() {
                    *current = None;
                }
                if let Some(child) = child {
                    let _ = child.kill();
                }
                app_handle.state::<super::MihomoApiState>().clear();
                super::diagnostics::record("proxy_monitor", "error", "event_stream_lost");
                if let Some(attempt_id) = proxy_attempt.as_mut().and_then(|attempt| attempt.take())
                {
                    if !matches!(
                        crate::platform::proxy::clear_system_proxy_owned(&attempt_id),
                        Ok(true)
                    ) {
                        if let Some(current) = proxy_attempt.as_mut() {
                            **current = Some(attempt_id);
                        }
                        super::diagnostics::record(
                            "system_proxy",
                            "error",
                            "monitor_restore_failed",
                        );
                    }
                }
            }
        });

        Ok(())
    }

    /// Publish the system proxy while holding the same state lock used by the
    /// Terminated handler. If Mihomo died after readiness, publication fails;
    /// if it dies immediately afterwards, the handler clears the proxy after
    /// this method releases the lock.
    pub fn set_system_proxy_if_running(
        &self,
        socks_port: u16,
        http_port: u16,
        attempt_id: &str,
    ) -> Result<(), String> {
        let mut proxy_attempt = self
            .proxy_attempt_id
            .lock()
            .map_err(|e| format!("mutex: {e}"))?;
        let child = self.child.lock().map_err(|e| format!("mutex: {e}"))?;
        if child.is_none() {
            return Err("Mihomo exited before system proxy publication".to_string());
        }
        crate::platform::proxy::set_system_proxy_owned(socks_port, http_port, attempt_id)
            .map_err(|error| error.to_string())?;
        *proxy_attempt = Some(attempt_id.to_string());
        Ok(())
    }

    pub fn clear_proxy_attempt(&self, attempt_id: &str) {
        if let Ok(mut current) = self.proxy_attempt_id.lock() {
            if current.as_deref() == Some(attempt_id) {
                *current = None;
            }
        }
    }

    pub fn proxy_attempt_id(&self) -> Option<String> {
        self.proxy_attempt_id
            .lock()
            .ok()
            .and_then(|current| current.clone())
    }

    /// Остановить Mihomo. Если не запущен — no-op.
    pub fn stop(&self) -> Result<(), String> {
        self.set_subscription_proxy_port(None);
        let mut g = self.child.lock().map_err(|e| format!("mutex: {e}"))?;
        if let Some(child) = g.take() {
            let pid = child.pid();
            eprintln!("[mihomo] kill pid={pid} (явный stop)");
            child.kill().map_err(|e| format!("kill mihomo: {e}"))?;
        }
        if let Ok(mut g) = self.current_pid.lock() {
            *g = None;
        }
        Ok(())
    }

    /// Запущен ли Mihomo прямо сейчас (как Tauri-sidecar ИЛИ через helper).
    pub fn is_running(&self) -> bool {
        if self.helper_spawned.load(Ordering::SeqCst) {
            return true;
        }
        self.child.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

async fn loopback_listener_ready(port: u16) -> bool {
    tokio::time::timeout(
        READINESS_CONNECT_TIMEOUT,
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn wait_for_readiness(
    events: &mut tauri::async_runtime::Receiver<CommandEvent>,
    mixed_port: u16,
    controller_port: u16,
    log: &Arc<Mutex<File>>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if loopback_listener_ready(mixed_port).await
            && loopback_listener_ready(controller_port).await
        {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "Mihomo did not open its loopback listeners within {timeout:?}"
            ));
        }
        let wait = READINESS_POLL.min(deadline - now);
        tokio::select! {
            event = events.recv() => match event {
                Some(CommandEvent::Stdout(line)) | Some(CommandEvent::Stderr(line)) => {
                    if let Ok(mut file) = log.lock() {
                        let _ = writeln!(file, "{}", String::from_utf8_lossy(&line));
                        let _ = file.flush();
                    }
                }
                Some(CommandEvent::Terminated(payload)) => {
                    if let Ok(mut file) = log.lock() {
                        let _ = writeln!(
                            file,
                            "--- terminated during readiness code={:?} signal={:?} ---",
                            payload.code,
                            payload.signal,
                        );
                        let _ = file.flush();
                    }
                    return Err(format!(
                        "Mihomo exited before readiness (code={:?}, signal={:?})",
                        payload.code, payload.signal
                    ));
                }
                Some(CommandEvent::Error(_)) => {
                    return Err("Mihomo process monitor failed during readiness".to_string());
                }
                None => return Err("Mihomo process event stream closed before readiness".to_string()),
                _ => {}
            },
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn unused_loopback_port_is_not_ready() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(!loopback_listener_ready(port).await);
    }

    #[test]
    fn uncertain_privileged_cleanup_remains_visible() {
        let state = MihomoState::new();
        state.mark_helper_spawned(true);
        state.mark_privileged_cleanup_uncertain(true);
        assert!(state.is_running());
        assert!(state.privileged_cleanup_uncertain());
        state.mark_privileged_cleanup_uncertain(false);
        state.mark_helper_spawned(false);
        assert!(!state.is_running());
    }

    fn temporary_log() -> (std::path::PathBuf, Arc<Mutex<File>>) {
        let path = std::env::temp_dir().join(format!(
            "kwikproxy-readiness-test-{}-{}.log",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let file = File::create(&path).unwrap();
        (path, Arc::new(Mutex::new(file)))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn immediate_termination_event_fails_readiness() {
        let (sender, mut receiver) = tauri::async_runtime::channel(1);
        sender
            .send(CommandEvent::Terminated(
                tauri_plugin_shell::process::TerminatedPayload {
                    code: Some(23),
                    signal: None,
                },
            ))
            .await
            .unwrap();
        let (path, log) = temporary_log();
        let error = wait_for_readiness(
            &mut receiver,
            unused_port(),
            unused_port(),
            &log,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        drop(log);
        let _ = std::fs::remove_file(path);
        assert!(error.contains("exited before readiness"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_readiness_timeout_is_bounded() {
        let (_sender, mut receiver) = tauri::async_runtime::channel(1);
        let (path, log) = temporary_log();
        let error = wait_for_readiness(
            &mut receiver,
            unused_port(),
            unused_port(),
            &log,
            Duration::from_millis(250),
        )
        .await
        .unwrap_err();
        drop(log);
        let _ = std::fs::remove_file(path);
        assert!(error.contains("did not open"));
    }

    fn unused_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }
}
