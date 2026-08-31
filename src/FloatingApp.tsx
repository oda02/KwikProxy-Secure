import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { emit, listen } from "@tauri-apps/api/event";
import { getAllWindows } from "@tauri-apps/api/window";
import {
  applyExternalVpnStatus,
  useVpnStore,
  type VpnStatus,
} from "./stores/vpnStore";
import "./FloatingApp.css";

/**
 * Плавающее мини-окно (этап 13.O). Запускается во втором Tauri-окне
 * с label `"floating"`, рендерится из того же entrypoint что и
 * главное приложение (см. `main.tsx`).
 *
 * Содержимое:
 * - **status-dot** — клик toggle'ит VPN (connect/disconnect);
 * - **имя сервера** — truncate если длинное;
 * - **скорость** — ↑ uplink / ↓ downlink в KB/s или MB/s,
 *   обновляется раз в секунду через `bandwidth-tick` event.
 *
 * Двойной клик в любую область — открывает главное окно.
 *
 * Окно полупрозрачное, alwaysOnTop, decorationless. Перетаскивается
 * за корневой div через `data-tauri-drag-region`.
 */
export function FloatingApp() {
  const { t } = useTranslation();
  const status = useVpnStore((s) => s.status);
  const refresh = useVpnStore((s) => s.refresh);

  const [bw, setBw] = useState<{ up: number; down: number }>({ up: 0, down: 0 });

  // Скоуп CSS: ставим класс на <html> чтобы правила из FloatingApp.css
  // (`html.is-floating { background: transparent }` и т.д.) применялись
  // только в этом окне. Vite бандлит CSS обоих окон в один файл, без
  // скоупа правила убивали бы темы главного окна.
  useEffect(() => {
    document.documentElement.classList.add("is-floating");
    return () => {
      document.documentElement.classList.remove("is-floating");
    };
  }, []);

  // Floating не публикует subscription runtime: это отдельный WebView со
  // своей generation sequence, которая могла обогнать receipt главного окна.
  // Статус читаем из backend, выбор и имя придут broadcast'ом от main.
  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void listen<{ up_bps: number; down_bps: number }>(
      "bandwidth-tick",
      (event) => {
        setBw({ up: event.payload.up_bps, down: event.payload.down_bps });
      }
    ).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  // Слушаем смены VPN-статуса из главного окна. Tauri broadcast'ит
  // emit-ы во все окна, но vpnStore состояние локально per-window —
  // здесь мы просто refresh'имся при любых служебных событиях.
  useEffect(() => {
    let unlistens: Array<() => void> = [];
    const onAny = () => void refresh();
    Promise.all([
      listen("vpn-status-changed", onAny),
      listen("tray-action", onAny),
    ]).then((fns) => {
      unlistens = fns;
    });
    return () => {
      unlistens.forEach((u) => u());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 0.1.1 / Bug 1: main-окно emit-ит `vpn-state-broadcast` при любом
  // изменении состояния (status / selectedIndex / имя сервера). У
  // floating-окна свой store, и selectedIndex живёт отдельно — без
  // этого события floating всегда показывал «нет сервера», даже
  // когда VPN активно работал. Bandwidth и status_dot работали через
  // отдельные events, имя — нет.
  const [broadcastName, setBroadcastName] = useState<string | null>(null);
  const [hasSelection, setHasSelection] = useState(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void listen<{
      status: VpnStatus;
      selectedName: string | null;
      hasSelection: boolean;
    }>(
      "vpn-state-broadcast",
      (event) => {
        setBroadcastName(event.payload.selectedName);
        setHasSelection(event.payload.hasSelection);
        if (
          ["stopped", "starting", "running", "stopping", "error"].includes(
            event.payload.status
          )
        ) {
          applyExternalVpnStatus(event.payload.status);
        }
      }
    ).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  const isRunning = status === "running";
  const isBusy = status === "starting" || status === "stopping";
  const isError = status === "error";
  const selectedName = broadcastName;

  const onDotClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (isBusy) return;
    if (isRunning || hasSelection) {
      // Main is the sole owner of subscription receipts and connect state.
      void emit("floating-toggle-vpn");
    }
  };

  const onDoubleClick = async () => {
    try {
      const wins = await getAllWindows();
      const main = wins.find((w) => w.label === "main");
      if (main) {
        await main.show();
        await main.unminimize();
        await main.setFocus();
      }
    } catch {
      // ignore
    }
  };

  const dotClass = isError
    ? "is-error"
    : isBusy
    ? "is-busy"
    : isRunning
    ? "is-running"
    : "";

  return (
    <div
      className="floating-shell"
      data-tauri-drag-region
      onDoubleClick={onDoubleClick}
    >
      <button
        type="button"
        className={`floating-dot ${dotClass}`}
        onClick={onDotClick}
        title={
          isRunning
            ? t("floating.vpnOn")
            : hasSelection
            ? t("floating.vpnOff")
            : t("floating.pickServer")
        }
      />
      <div className="floating-name" data-tauri-drag-region>
        {selectedName ?? t("floating.noServer")}
      </div>
      <div className="floating-bw" data-tauri-drag-region>
        <span>↑ {formatRate(bw.up)}</span>
        <span>↓ {formatRate(bw.down)}</span>
      </div>
    </div>
  );
}

/**
 * Форматирует bytes/sec в читаемый вид:
 *   - <1 KB/s — `0 B/s` (нулевая активность, не захламляем);
 *   - <1 MB/s — `123 KB/s` (целое число);
 *   - >=1 MB/s — `4.2 MB/s` (одна цифра после запятой).
 */
function formatRate(bps: number): string {
  if (bps < 1024) return "0 B/s";
  if (bps < 1024 * 1024) {
    return `${Math.round(bps / 1024)} KB/s`;
  }
  return `${(bps / (1024 * 1024)).toFixed(1)} MB/s`;
}
