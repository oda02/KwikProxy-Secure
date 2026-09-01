import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTranslation } from "react-i18next";
import {
  extractProxyRestoreChallenge,
  isUnsafeAutomaticProxyRestore,
  PROXY_RESTORE_FOREIGN_STATE_PENDING,
  PROXY_RESTORE_MANUAL_INTERVENTION_REQUIRED,
  proxyRestoreConfirmationArgs,
  recoveryDialogOutcome,
  shouldKeepRecoveryDialogOpen,
  type ProxyRecoveryDisposition,
} from "../lib/proxyRestore";

/**
 * 14.E — Расширенный crash-recovery диалог.
 *
 * При старте app вызываем `get_recovery_state` — он проверяет четыре
 * сигнала остатков от прошлой сессии:
 *  - `proxy_orphan` — реестр HKCU указывает на наш SOCKS5/HTTP прокси,
 *    но xray не запущен → браузер «сломан»;
 *  - `proxy_backup_present` — есть `proxy_backup.json` от прошлого
 *    `set_system_proxy`, можно сделать восстановление оригинала;
 *  - `tun_orphan` — в системе остался адаптер `kwikproxy-secure-*`;
 *  - `was_crashed` — общий флаг что хоть что-то найдено.
 *
 * Если все четыре false — диалог не показываем.
 *
 * Кнопки:
 *  - **«починить всё»** → `recover_network` (kill_switch_force_cleanup +
 *    orphan_cleanup + force_clear_system_proxy);
 *  - **«восстановить прокси»** → `restore_proxy_backup` (только если
 *    `proxy_backup_present`); откатывает реестр на оригинальные значения;
 *  - **«оставить как есть»** → закрыть диалог, сохранив durable backup.
 */
type RecoveryState = {
  was_crashed: boolean;
  proxy_orphan: boolean;
  proxy_backup_present: boolean;
  tun_orphan: boolean;
  /** 14.E: остатки WFP-фильтров от прошлой сессии (best-effort через
   *  helper). Если helper не отвечает — false (не пугаем зря). */
  orphan_wfp_filters: boolean;
  proxy_recovery_disposition: ProxyRecoveryDisposition;
};

type RecoveryReport = {
  kill_switch_cleaned: boolean;
  orphan_resources_cleaned: boolean;
  system_proxy_cleared: boolean;
  errors: string[];
};

export function CrashRecoveryDialog() {
  const { t } = useTranslation();
  const [state, setState] = useState<RecoveryState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proxyRestoreChallenge, setProxyRestoreChallenge] = useState<
    string | null
  >(null);

  useEffect(() => {
    void (async () => {
      try {
        const s = await invoke<RecoveryState>("get_recovery_state");
        if (s.was_crashed) setState(s);
      } catch {
        // не критично
      }
    })();
  }, []);

  if (!state) return null;

  const close = () => setState(null);

  const captureRestoreChallenge = (value: unknown): boolean => {
    const challenge = extractProxyRestoreChallenge(value);
    if (!challenge) return false;
    setProxyRestoreChallenge(challenge);
    return true;
  };

  const refreshStateOrClose = async () => {
    const refreshed = await invoke<RecoveryState>("get_recovery_state");
    if (shouldKeepRecoveryDialogOpen(refreshed)) setState(refreshed);
    else close();
  };

  const visibleProxyError = (value: unknown): string => {
    const message = String(value);
    if (message.includes(PROXY_RESTORE_MANUAL_INTERVENTION_REQUIRED)) {
      return t("modal.crashRecovery.manualIntervention");
    }
    if (message.includes(PROXY_RESTORE_FOREIGN_STATE_PENDING)) {
      return t("modal.crashRecovery.foreignProxyPending");
    }
    return message;
  };

  const onFixAll = async () => {
    setBusy(true);
    setError(null);
    try {
      const report = await invoke<RecoveryReport>("recover_network");
      const challengeError = report.errors.find((item) =>
        extractProxyRestoreChallenge(item)
      );
      if (challengeError) captureRestoreChallenge(challengeError);
      const visibleErrors = report.errors
        .filter((item) => !extractProxyRestoreChallenge(item))
        .map((item) => {
          if (item.includes(PROXY_RESTORE_MANUAL_INTERVENTION_REQUIRED)) {
            return t("modal.crashRecovery.manualIntervention");
          }
          if (item.includes(PROXY_RESTORE_FOREIGN_STATE_PENDING)) {
            return t("modal.crashRecovery.foreignProxyPending");
          }
          return item;
        });
      try {
        // Even a partial cleanup can remove some proxy/TUN/WFP findings.
        // Never keep rendering the pre-action snapshot merely because the
        // report also contains an error.
        const refreshed = await invoke<RecoveryState>("get_recovery_state");
        const outcome = recoveryDialogOutcome(refreshed, visibleErrors);
        setError(outcome.error);
        if (outcome.keepOpen) setState(refreshed);
        else close();
      } catch (refreshError) {
        setError([...visibleErrors, String(refreshError)].join("; "));
      }
      setBusy(false);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  const onRestoreBackup = async () => {
    setBusy(true);
    setError(null);
    try {
      await invoke("restore_proxy_backup");
      await refreshStateOrClose();
      setBusy(false);
    } catch (e) {
      if (!captureRestoreChallenge(e)) {
        setError(visibleProxyError(e));
      }
      setBusy(false);
    }
  };

  const onConfirmRestoreBackup = async () => {
    if (!proxyRestoreChallenge) return;
    setBusy(true);
    setError(null);
    try {
      await invoke("restore_proxy_backup_confirmed", {
        ...proxyRestoreConfirmationArgs(proxyRestoreChallenge),
      });
      setProxyRestoreChallenge(null);
      await refreshStateOrClose();
      setBusy(false);
    } catch (e) {
      // A challenge is single-use even on mismatch/failure. Require another
      // ordinary restore request to observe and bind the new registry state.
      setProxyRestoreChallenge(null);
      setError(visibleProxyError(e));
      setBusy(false);
    }
  };

  const onLeaveAsIs = async () => {
    setBusy(true);
    try {
      // Keep the durable marker. Deleting it while Windows still references
      // the dead local endpoint would destroy the only exact recovery target.
      close();
    } finally {
      setBusy(false);
    }
  };

  // Считаем сколько orphan'ов нашли — для текста в шапке.
  const findings: { key: string; label: string }[] = [];
  if (state.proxy_orphan)
    findings.push({ key: "proxy", label: t("modal.crashRecovery.findings.proxy") });
  if (state.proxy_backup_present)
    findings.push({
      key: "backup",
      label: t("modal.crashRecovery.findings.backup"),
    });
  if (state.tun_orphan)
    findings.push({ key: "tun", label: t("modal.crashRecovery.findings.tun") });
  if (state.orphan_wfp_filters)
    findings.push({
      key: "wfp",
      label: t("modal.crashRecovery.findings.wfp"),
    });

  return (
    <div className="recovery-overlay" role="dialog" aria-modal="true">
      <div className="recovery-dialog">
        <div className="recovery-title">{t("modal.crashRecovery.title")}</div>
        <div className="recovery-text">
          {t("modal.crashRecovery.intro")}
        </div>
        <ul className="recovery-list">
          {findings.map((f) => (
            <li key={f.key}>{f.label}</li>
          ))}
        </ul>
        <div className="recovery-text">
          {t("modal.crashRecovery.explainBase")}
          {state.proxy_backup_present && (
            <>
              {" "}
              {t("modal.crashRecovery.explainRestoreProxy")}
            </>
          )}
        </div>
        {state.proxy_recovery_disposition ===
          "manual_intervention_required" && (
          <div className="recovery-error">
            {t("modal.crashRecovery.manualIntervention")}
          </div>
        )}
        {state.proxy_recovery_disposition === "foreign_state_pending" && (
          <div className="recovery-error">
            {t("modal.crashRecovery.foreignProxyPending")}
          </div>
        )}
        {state.proxy_recovery_disposition === "unreadable" && (
          <div className="recovery-error">
            {t("modal.crashRecovery.unreadableProxyBackup")}
          </div>
        )}
        {proxyRestoreChallenge && (
          <div className="recovery-error">
            {t("modal.crashRecovery.confirmRestoreWarning")}
          </div>
        )}
        {error && <pre className="recovery-error">{error}</pre>}
        <div className="recovery-actions">
          {proxyRestoreChallenge ? (
            <>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setProxyRestoreChallenge(null)}
                disabled={busy}
              >
                {t("modal.crashRecovery.cancelRestore")}
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={onConfirmRestoreBackup}
                disabled={busy}
              >
                {busy
                  ? "…"
                  : t("modal.crashRecovery.confirmRestoreSnapshot")}
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                className="btn-ghost"
                onClick={onLeaveAsIs}
                disabled={busy}
              >
                {t("modal.crashRecovery.leaveAsIs")}
              </button>
              {state.proxy_backup_present &&
                !isUnsafeAutomaticProxyRestore(
                  state.proxy_recovery_disposition
                ) && (
                  <button
                    type="button"
                    className="btn-ghost"
                    onClick={onRestoreBackup}
                    disabled={busy}
                  >
                    {t("modal.crashRecovery.restoreProxy")}
                  </button>
                )}
              <button
                type="button"
                className="btn-primary"
                onClick={onFixAll}
                disabled={busy}
              >
                {busy ? "…" : t("modal.crashRecovery.fixAll")}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
