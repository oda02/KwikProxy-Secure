//! Проверка доступности привилегированного helper-сервиса.
//!
//! Установка, обновление и удаление сервиса являются исключительно
//! обязанностью per-machine installer-а. User-mode приложение никогда не
//! ищет helper рядом с собой, не запускает его через `runas` и не меняет SCM.
//! Это не позволяет подменённому файлу из user-writable каталога стать
//! SYSTEM-сервисом через обычный runtime-путь приложения.

use anyhow::{bail, Context, Result};

use super::helper_client;

/// Проверить, что installer-managed helper доступен и совместим.
///
/// Эта функция намеренно read-only. Несовместимый или отсутствующий helper
/// исправляется только повторным запуском подписанного per-machine installer-а.
pub async fn ensure_running() -> Result<()> {
    helper_client::ping()
        .await
        .context("защищённый helper-сервис недоступен; восстановите установку KwikProxy Secure")?;

    let (version, protocol) = helper_client::version()
        .await
        .context("helper-сервис не сообщил версию протокола")?;

    if !is_compatible(protocol) {
        bail!(
            "helper версии {version} использует protocol={protocol}, требуется protocol={}; \
             закройте приложение и восстановите установку KwikProxy Secure",
            helper_client::HELPER_PROTOCOL_VERSION
        );
    }

    Ok(())
}

fn is_compatible(protocol: u32) -> bool {
    protocol == helper_client::HELPER_PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_older_protocols() {
        assert!(!super::is_compatible(
            super::helper_client::HELPER_PROTOCOL_VERSION - 1
        ));
        assert!(super::is_compatible(
            super::helper_client::HELPER_PROTOCOL_VERSION
        ));
        assert!(!super::is_compatible(
            super::helper_client::HELPER_PROTOCOL_VERSION + 1
        ));
    }
}
