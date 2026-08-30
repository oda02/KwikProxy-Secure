import { openUrl } from "@tauri-apps/plugin-opener";
import { useSubscriptionStore } from "../stores/subscriptionStore";

function trustedHttpsUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host.endsWith(".internal") ||
      /^(127\.|10\.|192\.168\.|169\.254\.)/.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      host === "::1"
    ) {
      return null;
    }
    return url.toString();
  } catch {
    return null;
  }
}

/** Открыть личный кабинет подписки.
 *
 *  ВАЖНО (изменение поведения): URL берётся ТОЛЬКО из заголовка
 *  `profile-web-page-url`, который провайдер подписки прислал в HTTP-
 *  ответе. Если заголовка нет — функция ничего не делает (no-op).
 *
 *  Захардкоженный fallback (`web.kwik.online`) убран:
 *   - универсальный клиент не должен рекламировать конкретного
 *     провайдера;
 *   - для пользователей сторонних подписок ссылка на наш сайт не
 *     релевантна;
 *   - UI должен скрывать кнопку когда `useHasDashboardUrl() === false`. */
export function openDashboard() {
  const url = trustedHttpsUrl(
    useSubscriptionStore.getState().meta?.webPageUrl
  );
  if (!url) return;
  void openUrl(url);
}

/** Hook для условного рендера кнопки «личный кабинет».
 *  Возвращает `true` только если подписка прислала
 *  `profile-web-page-url`. */
export function useHasDashboardUrl(): boolean {
  return useSubscriptionStore(
    (s) => trustedHttpsUrl(s.meta?.webPageUrl) !== null
  );
}

/** Открыть страницу поддержки.
 *
 *  URL берётся ТОЛЬКО из заголовка `support-url` подписки. Захардкоженный
 *  fallback убран: универсальный клиент не привязан к конкретному
 *  провайдеру, поддержку задаёт сама подписка. Если заголовка нет —
 *  no-op, а UI должен скрывать кнопку (`useHasSupportUrl() === false`). */
export function openSupport() {
  const url = trustedHttpsUrl(useSubscriptionStore.getState().meta?.supportUrl);
  if (!url) return;
  void openUrl(url);
}

/** Hook для условного рендера кнопки «поддержка».
 *  Возвращает `true` только если подписка прислала `support-url`. */
export function useHasSupportUrl(): boolean {
  return useSubscriptionStore(
    (s) => trustedHttpsUrl(s.meta?.supportUrl) !== null
  );
}
