import { useTranslation } from "react-i18next";
import { useToastStore } from "../stores/toastStore";

/**
 * Контейнер для тостов — монтируется один раз в App.tsx, рендерит
 * стек активных уведомлений в правом нижнем углу. Тосты добавляются
 * через `showToast()` (см. toastStore.ts), уходят сами через
 * `durationMs` или по клику.
 */
export function Toaster() {
  const { t } = useTranslation();
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);

  if (toasts.length === 0) return null;

  return (
    <div className="toaster" role="region" aria-label={t("toaster.regionLabel")}>
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`toast toast-${toast.kind}`}
          role={toast.kind === "error" ? "alert" : "status"}
        >
          <div className="toast-content">
            {toast.title && <div className="toast-title">{toast.title}</div>}
            <div className="toast-message">
              {toast.message.split("\n").map((line, i) => (
                <div key={i}>{line}</div>
              ))}
            </div>
          </div>
          <button
            type="button"
            className="toast-dismiss"
            onClick={() => dismiss(toast.id)}
            title={t("toaster.dismissTitle")}
            aria-label={t("toaster.dismissTitle")}
          >
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
      ))}
    </div>
  );
}
