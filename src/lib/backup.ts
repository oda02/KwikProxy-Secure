import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import i18n from "../i18n";
import { useSettingsStore, type Settings, type AppRule } from "../stores/settingsStore";
import { useSubscriptionStore } from "../stores/subscriptionStore";
import { APP_VERSION } from "./constants";

/**
 * 12.D — backup/restore настроек.
 *
 * Сериализуем подмножество Settings + appRules в JSON. URL подписки
 * часто содержит bearer-token, поэтому по умолчанию поле в backup
 * вообще не попадает. Его можно добавить только явным opt-in в UI.
 *
 * Whitelist намеренно не включает HWID-override, opt-in отправки
 * HWID, dismissed-set объявлений и localStorage tutorial-флаги: это
 * machine-specific / consent / UX-state, которые нельзя незаметно
 * переносить между устройствами.
 *
 * Импорт проходит `parseBackup()` и `sanitizeImportedSettings()`:
 * неожиданные типы и не-whitelist поля отбрасываются.
 */

export type BackupSchema = {
  schema_version: 1;
  app_version: string;
  exported_at: number; // unix-ms
  settings: Partial<Settings>;
  /** Secret-bearing field, absent from normal exports. Kept optional so
   *  schema-v1 backups made by older releases remain importable. */
  subscription_url?: string;
  app_rules: AppRule[];
};

/** Shared frontend bound for local files, deep-link payloads and IPC export. */
export const MAX_BACKUP_BYTES = 1024 * 1024;
const MAX_BACKUP_STRING_BYTES = 4096;
const MAX_BACKUP_ARRAY_ITEMS = 256;
const MAX_BACKUP_APP_RULES = 4096;

const backupByteLength = (value: string): number =>
  new TextEncoder().encode(value).byteLength;

const assertBackupSize = (value: string): void => {
  if (backupByteLength(value) > MAX_BACKUP_BYTES) {
    throw new Error(i18n.t("backup.tooLarge", { maxMiB: 1 }));
  }
};

/** Поля Settings которые мы сохраняем при экспорте/импорте.
 *
 *  Не вошли:
 *   - все touched-флаги (восстанавливаем из значений сами);
 *   - `sendHwid` (это consent-state, на новом устройстве нужен новый opt-in);
 *   - machine-specific, updater и dismissed UX-state. */
const SETTINGS_WHITELIST: Array<keyof Settings> = [
  "autoRefresh",
  "autoRefreshHours",
  "refreshOnOpen",
  "pingOnOpen",
  "connectOnOpen",
  "userAgent",
  "sort",
  "allowLan",
  "theme",
  "antiDpiFragmentation",
  "antiDpiFragmentationPackets",
  "antiDpiFragmentationLength",
  "antiDpiFragmentationInterval",
  "antiDpiNoises",
  "antiDpiNoisesType",
  "antiDpiNoisesPacket",
  "antiDpiNoisesDelay",
  "antiDpiServerResolve",
  "antiDpiResolveDoH",
  "antiDpiResolveBootstrap",
  "tunMasking",
  "tunOnlyStrict",
  "killSwitch",
  "killSwitchStrict",
  "autoApplyMinimalRuRules",
  "defaultTraffic",
  "dnsLeakProtection",
  "forceDisableIpv6",
  "ipv6",
  "customDns",
  "pingMethod",
  "pingUrl",
  "pingTimeoutSec",
  "showMemoryMonitor",
  "mux",
  "muxProtocol",
  "muxMaxStreams",
  "engine",
  "shortcutToggleVpn",
  "shortcutShowHide",
  "shortcutSwitchMode",
  "floatingWindow",
  "autoLeakTest",
  "trustedSsids",
  "trustedSsidAction",
  "autoConnectOnLeave",
];

/** Собрать backup-объект из текущих store'ов.
 *
 * `includeSubscriptionSecret` намеренно явный и default-false:
 * callsite не может случайно выгрузить URL/token. */
export function collectBackup(includeSubscriptionSecret = false): BackupSchema {
  const s = useSettingsStore.getState();
  const sub = useSubscriptionStore.getState();
  const settings: Partial<Settings> = {};
  for (const key of SETTINGS_WHITELIST) {
    // Type-assertion необходима — TS не выводит общий тип Settings[K]
    // через цикл по разнотипным ключам.
    (settings as Record<string, unknown>)[key as string] = s[key];
  }
  const backup: BackupSchema = {
    schema_version: 1,
    app_version: APP_VERSION,
    exported_at: Date.now(),
    settings,
    app_rules: s.appRules,
  };
  if (includeSubscriptionSecret && sub.url.trim()) {
    backup.subscription_url = sub.url.trim();
  }
  return backup;
}

/** Сохранить backup-файл в `~/Documents/`. Возвращает путь. */
export async function exportBackupToDocuments(
  includeSubscriptionSecret = false
): Promise<string> {
  const backup = collectBackup(includeSubscriptionSecret);
  const json = JSON.stringify(backup, null, 2);
  assertBackupSize(json);
  return await invoke<string>("export_settings_to_documents", { json });
}

/** Прочитать локальный File через FileReader (для file-input). */
export function readBackupFile(file: File): Promise<string> {
  if (file.size > MAX_BACKUP_BYTES) {
    return Promise.reject(new Error(i18n.t("backup.tooLarge", { maxMiB: 1 })));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
    reader.onload = () => {
      const value = String(reader.result ?? "");
      try {
        assertBackupSize(value);
        resolve(value);
      } catch (error) {
        reject(error);
      }
    };
    reader.readAsText(file);
  });
}

/** Отфильтровать импортируемые настройки по типам.
 *
 *  Backup приходит в т.ч. из deep-link (`kwikproxy-secure://import-settings`) —
 *  недоверенный источник. Принимаем только значения whitelist-полей,
 *  тип которых совпадает с текущим в сторе (boolean/number/string или
 *  массив строк). Это перекрывает класс «инъекция чужого типа» (объект
 *  вместо строки, NaN/Infinity вместо числа) — соответствует
 *  whitelist-принципу проекта. Enum-строки доп. санитизируются в
 *  settingsStore.set/load (напр. theme мигрирует невалидное значение). */
function sanitizeImportedSettings(raw: unknown): Partial<Settings> {
  if (!raw || typeof raw !== "object") return {};
  const incoming = raw as Record<string, unknown>;
  const cur = useSettingsStore.getState();
  const out: Record<string, unknown> = {};
  for (const key of SETTINGS_WHITELIST) {
    const v = incoming[key as string];
    if (v === undefined) continue;
    const ref = cur[key];
    if (Array.isArray(ref)) {
      // Все массивы в whitelist — string[] (trustedSsids).
      if (
        Array.isArray(v) &&
        v.length <= MAX_BACKUP_ARRAY_ITEMS &&
        v.every(
          (x) =>
            typeof x === "string" &&
            backupByteLength(x) <= MAX_BACKUP_STRING_BYTES
        )
      ) {
        out[key as string] = v;
      }
    } else if (typeof v === "number") {
      if (typeof ref === "number" && Number.isFinite(v)) out[key as string] = v;
    } else if (typeof v === "boolean" || typeof v === "string") {
      if (
        typeof ref === typeof v &&
        (typeof v !== "string" || backupByteLength(v) <= MAX_BACKUP_STRING_BYTES)
      ) {
        out[key as string] = v;
      }
    }
    // объекты/функции/null — молча отбрасываем.
  }
  return out as Partial<Settings>;
}

const isSafeImportedAppRule = (
  raw: unknown
): raw is { exe: string; action: AppRule["action"]; comment?: string } => {
  if (!raw || typeof raw !== "object") return false;
  const rule = raw as Record<string, unknown>;
  if (typeof rule.exe !== "string") return false;
  const exe = rule.exe.trim();
  if (
    exe.length === 0 ||
    backupByteLength(exe) > 1024 ||
    exe.split("").some(
      (char) => char === "," || /\p{Cc}/u.test(char)
    )
  ) {
    return false;
  }
  return (
    rule.action === "proxy" ||
    rule.action === "direct" ||
    rule.action === "block"
  );
};

/** Безопасный парсер JSON-payload в `BackupSchema` или ошибка. */
export function parseBackup(raw: string): BackupSchema {
  assertBackupSize(raw);
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    throw new Error(i18n.t("backup.parseError", { error: String(e) }));
  }
  if (!obj || typeof obj !== "object") {
    throw new Error(i18n.t("backup.expectedJson"));
  }
  const o = obj as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new Error(
      i18n.t("backup.unsupportedSchema", { version: String(o.schema_version) })
    );
  }
  const settings = o.settings;
  const sub = typeof o.subscription_url === "string" ? o.subscription_url.trim() : "";
  if (sub) {
    if (backupByteLength(sub) > MAX_BACKUP_STRING_BYTES) {
      throw new Error(i18n.t("backup.expectedJson"));
    }
    let parsedSubscription: URL;
    try {
      parsedSubscription = new URL(sub);
    } catch {
      throw new Error(i18n.t("backup.expectedJson"));
    }
    if (
      parsedSubscription.protocol !== "https:" ||
      parsedSubscription.username !== "" ||
      parsedSubscription.password !== ""
    ) {
      throw new Error(i18n.t("backup.expectedJson"));
    }
  }
  const rulesRaw = Array.isArray(o.app_rules) ? o.app_rules : [];
  if (rulesRaw.length > MAX_BACKUP_APP_RULES) {
    throw new Error(i18n.t("backup.expectedJson"));
  }
  const rules: AppRule[] = rulesRaw
    .filter(isSafeImportedAppRule)
    .map((r) => ({
      exe: r.exe.trim(),
      action: r.action,
      comment:
        typeof r.comment === "string" &&
        backupByteLength(r.comment) <= MAX_BACKUP_STRING_BYTES
          ? r.comment
          : undefined,
    }));

  const backup: BackupSchema = {
    schema_version: 1,
    app_version:
      typeof o.app_version === "string" &&
      backupByteLength(o.app_version) <= 256
        ? o.app_version
        : "?",
    exported_at:
      typeof o.exported_at === "number" && Number.isFinite(o.exported_at)
        ? o.exported_at
        : 0,
    settings: sanitizeImportedSettings(settings),
    app_rules: rules,
  };
  if (sub) backup.subscription_url = sub;
  return backup;
}

/** Применить backup к store'ам. Touched-флаги выставляем там где должно
 *  «прилипнуть» (engine/theme/etc) — иначе server-driven заголовки тут
 *  же перебьют импортируемое значение, и пользователь не получит то
 *  что ожидал. */
export function applyBackup(backup: BackupSchema): void {
  const s = useSettingsStore.getState();
  for (const key of SETTINGS_WHITELIST) {
    const incoming = (backup.settings as Record<string, unknown>)[key as string];
    if (incoming === undefined) continue;
    // set() сам пробрасывает touched-флаги для themeTouched / engineTouched
    // и т.п. — переиспользуем эту логику.
    s.set(key, incoming as never);
  }
  // appRules — отдельный setter (не один из ключей выше).
  useSettingsStore.getState().set("appRules", backup.app_rules);

  if (backup.subscription_url?.trim()) {
    useSubscriptionStore.getState().setUrl(backup.subscription_url.trim());
  }
}

/** Diff между текущим store и импортируемым backup'ом. Возвращает список
 *  «ключ: текущее → импортируемое» — для preview-modal'а. */
export type BackupDiffEntry = {
  key: string;
  current: string;
  incoming: string;
};

export function diffBackup(backup: BackupSchema): BackupDiffEntry[] {
  const s = useSettingsStore.getState();
  const sub = useSubscriptionStore.getState();
  const out: BackupDiffEntry[] = [];

  const fmt = (v: unknown): string => {
    if (v === null || v === undefined) return i18n.t("backup.values.dash");
    if (typeof v === "boolean")
      return v ? i18n.t("backup.values.on") : i18n.t("backup.values.off");
    if (Array.isArray(v))
      return v.length === 0
        ? i18n.t("backup.values.empty")
        : i18n.t("backup.values.itemsCount", { count: v.length });
    return String(v);
  };

  for (const key of SETTINGS_WHITELIST) {
    const incoming = (backup.settings as Record<string, unknown>)[key as string];
    if (incoming === undefined) continue;
    const current = s[key];
    // Простое сравнение строкой через JSON для массивов и enum'ов.
    if (JSON.stringify(current) !== JSON.stringify(incoming)) {
      out.push({ key: String(key), current: fmt(current), incoming: fmt(incoming) });
    }
  }

  if (
    backup.subscription_url?.trim() &&
    backup.subscription_url.trim() !== sub.url.trim()
  ) {
    out.push({
      key: i18n.t("backup.fieldLabels.subscriptionUrl"),
      // Never echo token-bearing URLs into the preview (screenshots and
      // support recordings are much easier to leak than the backup itself).
      current: sub.url
        ? i18n.t("backup.values.secretPresent")
        : i18n.t("backup.values.dash"),
      incoming: i18n.t("backup.values.secretPresent"),
    });
  }

  // appRules сравниваем отдельно — только количество / наличие.
  if (JSON.stringify(s.appRules) !== JSON.stringify(backup.app_rules)) {
    out.push({
      key: i18n.t("backup.fieldLabels.appRules"),
      current: i18n.t("backup.values.itemsCount", { count: s.appRules.length }),
      incoming: i18n.t("backup.values.itemsCount", {
        count: backup.app_rules.length,
      }),
    });
  }

  return out;
}

/** Глобальный store для backup-preview модалки. App.tsx рендерит
 *  `<BackupPreviewModal>` если `pending != null`. */
type BackupModalStore = {
  pending: BackupSchema | null;
  show: (b: BackupSchema) => void;
  close: () => void;
};

export const useBackupModalStore = create<BackupModalStore>((set) => ({
  pending: null,
  show: (b) => set({ pending: b }),
  close: () => set({ pending: null }),
}));
