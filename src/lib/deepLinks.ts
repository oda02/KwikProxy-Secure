import { onOpenUrl, getCurrent } from "@tauri-apps/plugin-deep-link";
import { getCurrentWindow } from "@tauri-apps/api/window";
import i18n from "../i18n";
import { showToast } from "../stores/toastStore";
import {
  parseBackup,
  useBackupModalStore,
} from "./backup";

/**
 * Поддерживаемые deep-link-ссылки:
 *
 *  Управление VPN:
 *   kwikproxy-secure://connect | open     запросить действие в UI
 *   kwikproxy-secure://status             вынести окно вперёд
 *
 *  Импорт подписки (поддерживается оба синтаксиса):
 *   kwikproxy-secure://add?url=<encoded-url> — только показывает
 *   предупреждение; импорт не сохраняется и не запускается автоматически.
 *
 *  Auto-detect для path-формы import: если значение начинается с
 *  http(s):// — это URL подписки. Иначе пробуем base64-декод и
 *  проверяем на http(s):// внутри.
 */

/** Декодирует строку: сначала URL-decode, затем если не похоже на URL —
 *  пробуем base64. Возвращает первое валидное http(s):// или null. */
function detectSubscriptionUrl(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 8192) return null;
  // 1. Уже URL (после URL-decode)
  let candidate = trimmed;
  try {
    candidate = decodeURIComponent(trimmed);
  } catch {
    // не получилось декодировать — пробуем как есть
  }
  if (/^https:\/\//i.test(candidate)) return candidate;
  // 2. base64 → URL
  try {
    const decoded = atob(candidate.replace(/-/g, "+").replace(/_/g, "/"));
    if (/^https:\/\//i.test(decoded)) return decoded.trim();
  } catch {
    // не base64 — игнорируем
  }
  return null;
}

async function focusMainWindow() {
  try {
    const w = getCurrentWindow();
    await w.show();
    await w.unminimize();
    await w.setFocus();
  } catch (e) {
    console.warn("[deep-link] не удалось вынести окно вперёд:", e);
  }
}

export function handleDeepLink(rawUrl: string) {
  if (rawUrl.length > 1024 * 1024) {
    console.warn("[deep-link] payload too large");
    return;
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    console.warn("[deep-link] невалидный URL");
    return;
  }

  if (parsed.protocol !== "kwikproxy-secure:") {
    console.warn("[deep-link] чужая схема:", parsed.protocol);
    return;
  }

  // host у kwikproxy-secure://action — пустой на одних платформах, заполнен на
  // других. Action всегда первый сегмент: либо host, либо первая часть
  // pathname. payload (если есть) — остальное pathname (для path-формы)
  // или ?url=/?data= параметры.
  const segments = parsed.pathname.split("/").filter((s) => s.length > 0);
  const action = (parsed.host || segments.shift() || "").toLowerCase();
  const pathPayload = segments.join("/"); // для import/onadd
  const queryUrl = parsed.searchParams.get("url");
  const queryData = parsed.searchParams.get("data");

  switch (action) {
    case "add":
    case "import":
    case "onadd": {
      const raw = pathPayload || queryUrl || queryData;
      if (!raw) {
        console.warn("[deep-link] import без payload");
        return;
      }
      const url = detectSubscriptionUrl(raw);
      if (!url) {
        console.warn("[deep-link] не удалось извлечь безопасный URL подписки");
        return;
      }
      // Do not persist even the URL: cold-start logic must not mistake an
      // attacker-controlled deep-link for a user-confirmed subscription.
      void url;
      showToast({
        kind: "warning",
        title: i18n.t("deepLink.pending.title"),
        message: i18n.t("deepLink.pending.subscription"),
        durationMs: 8000,
      });
      void focusMainWindow();
      break;
    }
    case "connect":
    case "open":
    case "disconnect":
    case "close":
    case "toggle": {
      showToast({
        kind: "warning",
        title: i18n.t("deepLink.pending.title"),
        message: i18n.t("deepLink.pending.vpnAction"),
        durationMs: 8000,
      });
      void focusMainWindow();
      break;
    }
    case "status": {
      // Просто вынести приложение на передний план. Полезно для интеграций
      // (виджет/скрипт хочет «открой клиент»).
      void focusMainWindow();
      break;
    }
    case "export": {
      showToast({
        kind: "warning",
        title: i18n.t("deepLink.pending.title"),
        message: i18n.t("deepLink.pending.export"),
        durationMs: 8000,
      });
      void focusMainWindow();
      break;
    }
    case "import-from-url": {
      // `kwikproxy-secure://import-from-url/<url>` is intentionally disabled.
      // открыть preview-модалку. payload — URL, может быть в pathPayload
      // или ?url=.
      const raw = pathPayload || queryUrl || "";
      const url = decodeUriOrPassthrough(raw);
      if (!/^https:\/\//i.test(url)) {
        showToast({
          kind: "error",
          title: i18n.t("deepLink.importFromUrl.title"),
          message: i18n.t("deepLink.importFromUrl.expectedHttpUrl"),
        });
        return;
      }
      showToast({
        kind: "warning",
        title: i18n.t("deepLink.pending.title"),
        message: i18n.t("deepLink.pending.remoteImport"),
        durationMs: 8000,
      });
      void focusMainWindow();
      break;
    }
    case "import-settings": {
      // `kwikproxy-secure://import-settings?...` parses only into an in-memory
      // preview modal; applying still requires an explicit UI action.
      // из inline payload. Имя выбрано чтобы не конфликтовать с
      // существующим `import` который импортирует подписку.
      const raw = pathPayload || queryData || queryUrl || "";
      if (raw.length > 1024 * 1024) {
        showToast({
          kind: "error",
          title: i18n.t("deepLink.importSettings.title"),
          message: i18n.t("deepLink.importSettings.notBase64OrJson"),
        });
        return;
      }
      let json = "";
      try {
        json = decodeURIComponent(raw);
      } catch {
        json = raw;
      }
      // Если не похоже на JSON — пробуем base64-decode.
      if (!json.trim().startsWith("{")) {
        try {
          json = atob(json.replace(/-/g, "+").replace(/_/g, "/"));
        } catch {
          showToast({
            kind: "error",
            title: i18n.t("deepLink.importSettings.title"),
            message: i18n.t("deepLink.importSettings.notBase64OrJson"),
          });
          return;
        }
      }
      try {
        const backup = parseBackup(json);
        useBackupModalStore.getState().show(backup);
      } catch (e) {
        showToast({
          kind: "error",
          title: i18n.t("deepLink.importSettings.title"),
          message: String(e),
        });
      }
      void focusMainWindow();
      break;
    }
    case "routing":
    case "autorouting": {
      // 11.D расширенные deep-links для routing-профилей. Формат:
      //   kwikproxy-secure://routing/{add|onadd}/{base64|url}
      //   kwikproxy-secure://autorouting/{add|onadd}/{url}
      // segments тут — [verb, ...payload]. queryUrl/queryData как
      // альтернативные источники payload (для длинных base64).
      const verb = (segments.shift() || "").toLowerCase();
      if (verb !== "add" && verb !== "onadd") {
        console.warn("[deep-link] routing: неизвестный verb:", verb);
        return;
      }
      const raw = segments.join("/") || queryData || queryUrl || "";
      const decodedRaw = decodeUriOrPassthrough(raw);
      // Parsing establishes that this is a well-formed request, but applying
      // or downloading a routing profile remains a manual Settings action.
      if (decodedRaw) {
        showToast({
          kind: "warning",
          title: i18n.t("deepLink.pending.title"),
          message: i18n.t("deepLink.pending.routing"),
          durationMs: 8000,
        });
      }
      void focusMainWindow();
      break;
    }
    default:
      console.warn("[deep-link] неизвестное действие:", action);
  }
}

function decodeUriOrPassthrough(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * 11.D — обработчик routing/autorouting deep-links.
 *
 * - `routing/add/{base64-or-url}` — добавить статический профиль
 *   (без активации). Если payload — URL, скачиваем JSON один раз и
 *   сохраняем как Static.
 * - `routing/onadd/{base64-or-url}` — то же + сразу активируем.
 * - `autorouting/add/{url}` — добавить URL-источник с авто-обновлением
 *   (default 24ч). Без активации.
 * - `autorouting/onadd/{url}` — то же + активируем.
 */
/**
 * Регистрирует подписку на deep-link события и обрабатывает «холодный»
 * запуск (когда приложение запустили кликом по kwikproxy-secure://...).
 */
export async function initDeepLinks(): Promise<() => void> {
  // Cold start: процесс был запущен с deep-link-ом в args
  try {
    const initial = await getCurrent();
    if (initial && initial.length > 0) {
      for (const url of initial) handleDeepLink(url);
    }
  } catch {
    // на платформах без cold-start API getCurrent кидает — игнорируем
  }

  // Warm: пока приложение запущено, ОС вызывает onOpenUrl
  const unlisten = await onOpenUrl((urls) => {
    for (const url of urls) handleDeepLink(url);
  });
  return unlisten;
}
