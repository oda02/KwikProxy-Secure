import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { effectiveUserAgent, useSettingsStore, type Engine } from "./settingsStore";
import { findSelectedIndexByName, useVpnStore } from "./vpnStore";
import i18n from "../i18n";
import { showToast } from "./toastStore";
import {
  AsyncMutex,
  MutationFence,
  choosePersistedById,
  deleteWithRollback,
  optionalValueOrThrow,
  publishAfterCommit,
  publishRequiredTombstone,
  readOptional,
  type OptionalRead,
  withAsyncRollback,
} from "../lib/asyncControl";

export type ProxyEntry = {
  name: string;
  protocol: string;
  server: string;
  port: number;
  raw: Record<string, unknown>;
  /** Список движков, способных поднять этот сервер.
   *  Возможные значения: "xray", "mihomo".
   *  Если поле пустое (старый кеш до 8.A) — считаем совместимым с обоими. */
  engine_compat?: string[];
  /** 0.3.0 multi-subscription: id подписки-источника. Заполняется
   *  frontend'ом при сохранении в state.servers (Rust возвращает entries
   *  без этого поля). Используется в drawer'е для group-by-source и в
   *  vpn_connect для выбора правильного engine через
   *  `getEffectiveEngine(subscriptionId)`. */
  subscriptionId?: string;
};

/** Метаданные подписки из HTTP-заголовков.
 *
 *  Стандартные (де-факто индустрии — 3x-ui / Marzban / x-ui / sing-box):
 *  - used/total: байты, total=0 → безлимит;
 *  - expireAt: unix-timestamp в секундах, null → бессрочно;
 *  - title: имя подписки (`profile-title`);
 *  - webPageUrl: URL личного кабинета (`profile-web-page-url`);
 *  - supportUrl: URL поддержки (`support-url`);
 *  - updateIntervalHours: интервал автообновления в часах
 *    (`profile-update-interval`);
 *  - announce / announceUrl: текст и опциональная ссылка для объявления
 *    от провайдера;
 *  - premiumUrl: URL премиум-страницы.
 *
 *  X-Kwik-* (наше расширение, server-driven UX, 8.C):
 *  - theme / mode / engine — задают
 *    дефолты; применяются только если пользователь не менял эти
 *    настройки вручную (override-логика).
 *
 *  Все enum-значения валидируются на бэкенде по whitelist; неизвестные
 *  становятся null. */
export type SubscriptionMeta = {
  used: number;
  total: number;
  expireAt: number | null;
  title: string | null;
  webPageUrl: string | null;
  supportUrl: string | null;
  updateIntervalHours: number | null;
  announce: string | null;
  announceUrl: string | null;
  premiumUrl: string | null;
  theme: string | null;
  mode: string | null;
  engine: string | null;
  // Anti-DPI (этап 10)
  fragmentationEnable: boolean | null;
  fragmentationPackets: string | null;
  fragmentationLength: string | null;
  fragmentationInterval: string | null;
  noisesEnable: boolean | null;
  noisesType: string | null;
  noisesPacket: string | null;
  noisesDelay: string | null;
  serverResolveEnable: boolean | null;
  serverResolveDoH: string | null;
  serverResolveBootstrap: string | null;
  // 11.E: routing-директивы из спец-строк подписки. UI применяет
  // через invoke routing_add_url / routing_add_static + опционально
  // routing_set_active.
  routingAutorouting: [string, boolean] | null;
  routingStatic: [string, boolean] | null;
};

/** Сырой ответ команды fetch_subscription — Rust возвращает snake_case. */
type SubscriptionMetaRaw = {
  used: number;
  total: number;
  expire_at: number | null;
  title: string | null;
  web_page_url: string | null;
  support_url: string | null;
  update_interval_hours: number | null;
  announce: string | null;
  announce_url: string | null;
  premium_url: string | null;
  theme: string | null;
  mode: string | null;
  engine: string | null;
  fragmentation_enable: boolean | null;
  fragmentation_packets: string | null;
  fragmentation_length: string | null;
  fragmentation_interval: string | null;
  noises_enable: boolean | null;
  noises_type: string | null;
  noises_packet: string | null;
  noises_delay: string | null;
  server_resolve_enable: boolean | null;
  server_resolve_doh: string | null;
  server_resolve_bootstrap: string | null;
  routing_autorouting: [string, boolean] | null;
  routing_static: [string, boolean] | null;
};
type FetchSubscriptionRaw = {
  servers: ProxyEntry[];
  meta: SubscriptionMetaRaw | null;
};

export type SubscriptionRuntimeReceipt = {
  sessionEpoch: string;
  primaryId: string;
  generation: number;
};

/** 0.3.0 (multi-subscription): описание одной подписки. До 0.3.0 был
 *  один URL/HWID/meta в singleton-полях; теперь — массив `subscriptions`,
 *  каждая со своими данными. Legacy-поля (url/hwid/meta/...) остаются для
 *  backward compat: они sync'ятся с **primary** подпиской (subscriptions[0]
 *  по умолчанию). UI постепенно переезжает на чтение `subscriptions`. */
export type Subscription = {
  /** uuid v4. Используется как суффикс keyring-ключей и subscriptionId
   *  у `ProxyEntry` (для group-by-source в drawer). */
  id: string;
  url: string;
  hwid: string;
  /** Метаданные одной подписки (трафик, срок, заголовки X-Kwik-*).
   *  null если ещё ни разу не fetch'или или провайдер не прислал. */
  meta: SubscriptionMeta | null;
  /** Unix-ms времени последнего успешного fetch для этой подписки. */
  lastFetchedAt: number | null;
  loading: boolean;
  error: string | null;
  /** Per-subscription engine override через ⋯ меню карточки.
   *  Mihomo-only: фактически всегда mihomo. Поле сохранено для
   *  совместимости persisted-структуры. */
  engineOverride: Engine | null;
  /** 0.3.0 multi-server-list: серверы этой подписки. Tagged
   *  с subscriptionId для group-by-source. */
  servers: ProxyEntry[];
  /** Пинги по индексам servers (parallel array). */
  pings: (number | null)[];
};

type SubscriptionStore = {
  // ─── Multi-subscription API (0.3.0+) ─────────────────────────────────
  /** Все подписки. Первая = primary (для legacy совместимости). */
  subscriptions: Subscription[];
  /** id текущей primary подписки. null когда subscriptions пустой. */
  primaryId: string | null;
  /** Добавить новую подписку с заданным URL. Создаёт uuid, сохраняет URL
   *  в keyring под `subscription_url:${id}`, делает fetch, возвращает id. */
  addSubscription: (url: string) => Promise<string>;
  /** Удалить подписку (по id). Если удаляем primary — следующая в списке
   *  становится primary. Чистит keyring entries и связанные servers. */
  removeSubscription: (id: string) => Promise<void>;
  /** Назначить primary (обычно UI-переключатель в Welcome / Settings). */
  setPrimaryId: (id: string) => Promise<boolean>;
  /** Publish and verify the exact current primary snapshot before connect. */
  ensurePrimaryRuntimeReady: () => Promise<SubscriptionRuntimeReceipt | null>;
  /** Keep the exact receipt current until its backend consumer completes. */
  withPrimaryRuntimeReady: <T>(
    consume: (receipt: SubscriptionRuntimeReceipt) => Promise<T>
  ) => Promise<T | null>;
  /** Set engineOverride для подписки (через ⋯ меню → radio выбор). */
  setEngineOverride: (id: string, engine: Engine | null) => void;
  /** Получить effective engine для подписки. Mihomo-only — всегда "mihomo". */
  getEffectiveEngine: (id: string) => Engine;
  /** Fetch конкретной подписки. Если эта подписка primary, синхронизирует
    *  legacy state.servers/meta для backward compat. Если не primary —
    *  обновляет только sub.servers/meta. Rust runtime принимает только
    *  generation-guarded snapshot актуальной primary подписки. */
  fetchSubscriptionById: (id: string) => Promise<void>;
  /** Пинги серверов конкретной подписки. */
  pingAllOf: (id: string) => Promise<void>;

  // ─── Legacy API (sync'ится с primary, остаётся для обратной совместимости)
  servers: ProxyEntry[];
  /** Метаданные подписки или null если сервер их не прислал. */
  meta: SubscriptionMeta | null;
  /** Unix-ms времени последнего успешного fetchSubscription. null —
   *  ни разу не обновлялась за всю жизнь приложения (например, серверы
   *  пришли только из кеша при старте). 12.B */
  lastFetchedAt: number | null;
  /** Пинги по индексам серверов: ms или null если offline / timeout. */
  pings: (number | null)[];
  pingsLoading: boolean;
  loading: boolean;
  error: string | null;
  url: string;
  /** Origin-scoped subscription pseudonym. Auto, read-only, never MachineGuid. */
  deviceHwid: string;
  /** Опциональный override HWID для разработки / переноса с другого клиента. */
  hwid: string;
  setUrl: (url: string) => void;
  setHwid: (hwid: string) => void;
  loadDeviceHwid: () => Promise<void>;
  /** Прочитать URL/HWID из Windows Credential Manager и current-user DPAPI
    *  cache серверов. Raw credentials/YAML не читаются из localStorage. */
  loadSecureCreds: () => Promise<void>;
  fetchSubscription: () => Promise<void>;
  loadCached: () => Promise<void>;
  pingAll: () => Promise<void>;
  /** Полная очистка подписки: URL/HWID из keyring, кеш серверов в Rust,
   *  meta + lastFetched + pings в памяти, persisted selectedIndex name.
   *  После вызова экран возвращается к Welcome. Эквивалент
   *  removeSubscription(primaryId), оставлен для существующих callsites. */
  deleteSubscription: () => Promise<void>;
};

/** Конверсия snake_case ответа Rust → camelCase TS. */
const normalizeMeta = (
  raw: SubscriptionMetaRaw | null
): SubscriptionMeta | null =>
  raw
    ? {
        used: raw.used,
        total: raw.total,
        expireAt: raw.expire_at,
        title: raw.title,
        webPageUrl: raw.web_page_url,
        supportUrl: raw.support_url,
        updateIntervalHours: raw.update_interval_hours,
        announce: raw.announce,
        announceUrl: raw.announce_url,
        premiumUrl: raw.premium_url,
        theme: raw.theme,
        mode: raw.mode,
        engine: raw.engine,
        fragmentationEnable: raw.fragmentation_enable,
        fragmentationPackets: raw.fragmentation_packets,
        fragmentationLength: raw.fragmentation_length,
        fragmentationInterval: raw.fragmentation_interval,
        noisesEnable: raw.noises_enable,
        noisesType: raw.noises_type,
        noisesPacket: raw.noises_packet,
        noisesDelay: raw.noises_delay,
        serverResolveEnable: raw.server_resolve_enable,
        serverResolveDoH: raw.server_resolve_doh,
        serverResolveBootstrap: raw.server_resolve_bootstrap,
        routingAutorouting: raw.routing_autorouting,
        routingStatic: raw.routing_static,
      }
    : null;

const serializeMeta = (
  meta: SubscriptionMeta | null
): SubscriptionMetaRaw | null =>
  meta
    ? {
        used: meta.used,
        total: meta.total,
        expire_at: meta.expireAt,
        title: meta.title,
        web_page_url: meta.webPageUrl,
        support_url: meta.supportUrl,
        update_interval_hours: meta.updateIntervalHours,
        announce: meta.announce,
        announce_url: meta.announceUrl,
        premium_url: meta.premiumUrl,
        theme: meta.theme,
        mode: meta.mode,
        engine: meta.engine,
        fragmentation_enable: meta.fragmentationEnable,
        fragmentation_packets: meta.fragmentationPackets,
        fragmentation_length: meta.fragmentationLength,
        fragmentation_interval: meta.fragmentationInterval,
        noises_enable: meta.noisesEnable,
        noises_type: meta.noisesType,
        noises_packet: meta.noisesPacket,
        noises_delay: meta.noisesDelay,
        server_resolve_enable: meta.serverResolveEnable,
        server_resolve_doh: meta.serverResolveDoH,
        server_resolve_bootstrap: meta.serverResolveBootstrap,
        routing_autorouting: meta.routingAutorouting,
        routing_static: meta.routingStatic,
      }
    : null;

/** Ключи в Windows Credential Manager (этап 6.A). Чувствительные данные
 *  переехали из localStorage в защищённое хранилище ОС. localStorage
 *  ключи остаются как fallback на время миграции. */
const URL_KEYRING = "subscription_url";
const HWID_KEYRING = "hwid_override";

const URL_KEY = "kwikproxy-secure.subscription.url";
const LAST_FETCH_KEY = "kwikproxy-secure.subscription.lastFetchedAt";
const KEYRING_MIGRATION_KEY = "kwikproxy-secure.migrated.keyring.v1";
// Версионируем ключ override-HWID: при апгрейде клиента старое значение
// (когда мы вручную подсовывали Happ-овский HWID для отладки) автоматически
// перестаёт читаться. Override — теперь advanced-only, по умолчанию используется
// origin-scoped pseudonym через get_hwid.
const HWID_KEY = "kwikproxy-secure.subscription.hwid.v2";
const HWID_KEY_LEGACY = "kwikproxy-secure.subscription.hwid";
const MIGRATION_KEY = "kwikproxy-secure.migrated.v2";
const credentialMutationMutex = new AsyncMutex();
const credentialMutationFence = new MutationFence();

const loadFromStorage = (key: string): string => {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
};

const saveToStorage = (key: string, value: string) => {
  try {
    localStorage.setItem(key, value);
  } catch {
    // приватный режим/квота — не критично
  }
};

/** Записать значение в Windows Credential Manager. Возвращает true при
 *  успехе. Ошибки не критичны — на платформах без keyring (или приватных
 *  пользователях) тихо проваливаемся. */
const keyringSetRaw = async (key: string, value: string): Promise<void> => {
  await invoke("secure_storage_set", { key, value });
};

const keyringGetRaw = async (key: string): Promise<string> => {
  return await invoke<string>("secure_storage_get", { key });
};

const keyringDeleteRaw = async (key: string): Promise<void> => {
  await invoke("secure_storage_delete", { key });
};

const keyringSet = (key: string, value: string): Promise<boolean> => {
  const epoch = credentialMutationFence.snapshot();
  if (epoch === null) return Promise.resolve(false);
  return credentialMutationMutex.runExclusive(async () => {
    if (!credentialMutationFence.allows(epoch)) return false;
    await keyringSetRaw(key, value);
    return true;
  });
};

const keyringRead = (key: string): Promise<OptionalRead<string>> => {
  const epoch = credentialMutationFence.snapshot();
  if (epoch === null) {
    return Promise.resolve({
      kind: "error",
      error: new Error("credential deletion is active"),
    });
  }
  return credentialMutationMutex.runExclusive(async () => {
    if (!credentialMutationFence.allows(epoch)) {
      return {
        kind: "error",
        error: new Error("credential read was cancelled by deletion"),
      };
    }
    return await readOptional(
      () => keyringGetRaw(key),
      (value) => value.length === 0
    );
  });
};

const keyringGet = async (key: string): Promise<string> => {
  const result = await keyringRead(key);
  return result.kind === "value" ? result.value : "";
};

const keyringDelete = (key: string): Promise<void> => {
  const epoch = credentialMutationFence.snapshot();
  if (epoch === null) return Promise.resolve();
  return credentialMutationMutex.runExclusive(async () => {
    if (!credentialMutationFence.allows(epoch)) return;
    await keyringDeleteRaw(key);
  });
};

const queueCredentialMutation = (mutation: Promise<unknown>): void => {
  void mutation.catch((error) => {
    console.warn("[subscription] credential mutation failed:", error);
    showToast({
      kind: "error",
      title: "Credential storage update failed",
      message: String(error),
      durationMs: 8000,
    });
  });
};

type CredentialRecord = { key: string; value: string };
type CredentialValue = { key: string; value: string | null };

const snapshotCredentials = async (
  keys: readonly string[]
): Promise<CredentialRecord[]> => {
  const entries: CredentialRecord[] = [];
  for (const key of keys) {
    const value = await keyringGetRaw(key);
    if (value) entries.push({ key, value });
  }
  return entries;
};

const deleteCredentialsTransactional = (
  entries: readonly CredentialRecord[]
): Promise<void> =>
  deleteWithRollback(
    entries,
    (entry) => keyringDeleteRaw(entry.key),
    (entry) => keyringSetRaw(entry.key, entry.value)
  );

const deleteCredentialKeysTransactional = (
  keys: readonly string[]
): Promise<CredentialRecord[]> =>
  credentialMutationMutex.runExclusive(async () => {
    const entries = await snapshotCredentials(keys);
    await deleteCredentialsTransactional(entries);
    return entries;
  });

const restoreCredentialRecords = (
  entries: readonly CredentialRecord[]
): Promise<void> =>
  credentialMutationMutex.runExclusive(async () => {
    for (const entry of entries) {
      await keyringSetRaw(entry.key, entry.value);
    }
  });

const replaceCredentialsTransactional = (
  updates: readonly CredentialValue[]
): Promise<CredentialValue[]> =>
  credentialMutationMutex.runExclusive(async () => {
    const previous: CredentialValue[] = [];
    for (const update of updates) {
      const value = await keyringGetRaw(update.key);
      previous.push({ key: update.key, value: value || null });
    }
    try {
      for (const update of updates) {
        if (update.value === null) await keyringDeleteRaw(update.key);
        else await keyringSetRaw(update.key, update.value);
      }
    } catch (error) {
      const rollbackErrors: unknown[] = [];
      for (const entry of previous) {
        try {
          if (entry.value === null) await keyringDeleteRaw(entry.key);
          else await keyringSetRaw(entry.key, entry.value);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }
      if (rollbackErrors.length > 0) {
        throw new Error(
          `${String(error)}; credential replace rollback failed: ${rollbackErrors
            .map(String)
            .join("; ")}`
        );
      }
      throw error;
    }
    return previous;
  });

const restoreCredentialValues = (
  entries: readonly CredentialValue[]
): Promise<void> =>
  credentialMutationMutex.runExclusive(async () => {
    for (const entry of entries) {
      if (entry.value === null) await keyringDeleteRaw(entry.key);
      else await keyringSetRaw(entry.key, entry.value);
    }
  });

// Чистим устаревший ключ override-HWID. Версионирование выше уже отрезает
// его от чтения, но удаляем для гигиены localStorage.
const runMigrations = () => {
  try {
    if (!localStorage.getItem(MIGRATION_KEY)) {
      localStorage.removeItem(HWID_KEY_LEGACY);
      localStorage.setItem(MIGRATION_KEY, "1");
    }
  } catch {
    // приватный режим — пропускаем
  }
};
runMigrations();

/** Прочитать unix-ms из localStorage. Возвращает null если ключа нет
 *  или значение некорректное. */
const loadTimestamp = (key: string): number | null => {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
};

/** localStorage key для списка ID-всех-подписок (multi-subscription
 *  state). Каждый id — uuid v4. Соответствующие URL/HWID хранятся в
 *  Windows Credential Manager под ключами `subscription_url:${id}` и
 *  `hwid_override:${id}`. На init читаем этот список → подгружаем по
 *  каждому id креды из keyring. */
const SUBS_INDEX_KEY = "kwikproxy-secure.subscriptions.index.v1";
const PRIMARY_ID_KEY = "kwikproxy-secure.subscriptions.primary.v1";

const loadSubsIndex = (): string[] => {
  try {
    const raw = localStorage.getItem(SUBS_INDEX_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
};

const saveSubsIndexStrict = (ids: string[]): void => {
  localStorage.setItem(SUBS_INDEX_KEY, JSON.stringify(ids));
};

const loadPrimaryId = (): string | null => {
  try {
    return localStorage.getItem(PRIMARY_ID_KEY);
  } catch {
    return null;
  }
};

const savePrimaryIdStrict = (id: string): void => {
  localStorage.setItem(PRIMARY_ID_KEY, id);
};

const loadPrimaryIdStrict = (): string | null =>
  localStorage.getItem(PRIMARY_ID_KEY);

const restorePrimaryIdStrict = (id: string | null): void => {
  if (id === null) localStorage.removeItem(PRIMARY_ID_KEY);
  else localStorage.setItem(PRIMARY_ID_KEY, id);
};

const saveBootstrapIdentityStrict = (id: string): void => {
  const previousIndex = localStorage.getItem(SUBS_INDEX_KEY);
  const previousPrimary = localStorage.getItem(PRIMARY_ID_KEY);
  try {
    saveSubsIndexStrict([id]);
    savePrimaryIdStrict(id);
  } catch (error) {
    try {
      if (previousIndex === null) localStorage.removeItem(SUBS_INDEX_KEY);
      else localStorage.setItem(SUBS_INDEX_KEY, previousIndex);
      restorePrimaryIdStrict(previousPrimary);
    } catch (rollbackError) {
      throw new Error(
        `${String(error)}; bootstrap identity rollback failed: ${String(
          rollbackError
        )}`
      );
    }
    throw error;
  }
};

/** Legacy fork-local plaintext cache key. Raw server credentials are never
 * written here; loadSecureCreds removes it before DPAPI hydration. */
const SERVERS_CACHE_KEY = "kwikproxy-secure.servers.cache.v1";

const removeLegacyPlaintextCache = () => {
  try {
    localStorage.removeItem(SERVERS_CACHE_KEY);
  } catch {
    // Storage unavailable is equivalent to an already absent cache.
  }
};

let nextFetchGeneration = 0;
let nextRuntimeGeneration = 0;
const primaryRuntimeMutex = new AsyncMutex();
const subscriptionMutationMutex = new AsyncMutex();
const subscriptionSourceFence = new MutationFence();
const fetchGenerations = new Map<string, number>();
let runtimeEpochPromise: Promise<string> | null = null;

const ensureRuntimeEpoch = (): Promise<string> => {
  if (!runtimeEpochPromise) {
    runtimeEpochPromise = invoke<string>("begin_subscription_epoch").catch(
      (error) => {
        runtimeEpochPromise = null;
        throw error;
      }
    );
  }
  return runtimeEpochPromise;
};

const runSubscriptionMutation = <T>(task: () => Promise<T>): Promise<T> =>
  subscriptionMutationMutex.runExclusive(async () => {
    const fence = subscriptionSourceFence.beginExclusive();
    try {
      return await task();
    } finally {
      subscriptionSourceFence.endExclusive(fence);
    }
  });

const beginFetch = (id: string): number => {
  const generation = ++nextFetchGeneration;
  fetchGenerations.set(id, generation);
  return generation;
};

const invalidateFetch = (id: string): number => {
  const generation = ++nextFetchGeneration;
  fetchGenerations.set(id, generation);
  return generation;
};

const isCurrentFetch = (id: string, url: string, generation: number): boolean => {
  const state = useSubscriptionStore.getState();
  const subscription = state.subscriptions.find((item) => item.id === id);
  return (
    fetchGenerations.get(id) === generation &&
    subscription?.url === url
  );
};

const saveEncryptedCache = async (
  id: string,
  url: string,
  result: FetchSubscriptionRaw,
  generation: number
): Promise<void> => {
  if (!isCurrentFetch(id, url, generation)) return;
  try {
    const sessionEpoch = await ensureRuntimeEpoch();
    if (!isCurrentFetch(id, url, generation)) return;
    await invoke("save_subscription_cache", {
      sessionEpoch,
      subscriptionId: id,
      sourceUrl: url,
      servers: result.servers,
      meta: result.meta,
      generation,
    });
  } catch (error) {
    console.warn("[subscription] encrypted cache save failed:", error);
  }
};

const deleteEncryptedCache = async (id: string): Promise<void> => {
  const generation = invalidateFetch(id);
  try {
    const sessionEpoch = await ensureRuntimeEpoch();
    await invoke("delete_subscription_cache", {
      sessionEpoch,
      subscriptionId: id,
      generation,
    });
  } catch (error) {
    console.warn("[subscription] encrypted cache delete failed:", error);
    showToast({
      kind: "error",
      title: "Encrypted cache cleanup failed",
      message: String(error),
      durationMs: 8000,
    });
    throw error;
  }
};

/** Commit the primary snapshot with an app-global monotonic generation.
 * Rust rejects late invokes, so a previous primary cannot win a race. */
const writeRuntimeSnapshot = async (
  id: string,
  servers: ProxyEntry[],
  meta: SubscriptionMeta | null
): Promise<SubscriptionRuntimeReceipt | null> => {
  const generation = ++nextRuntimeGeneration;
  const sessionEpoch = await ensureRuntimeEpoch();
  const committed = await invoke<boolean>("set_servers", {
    sessionEpoch,
    primaryId: id,
    servers,
    meta: serializeMeta(meta),
    generation,
  });
  return committed ? { sessionEpoch, primaryId: id, generation } : null;
};

const commitPrimaryToRust = async (
  id: string,
  url: string,
  servers: ProxyEntry[],
  meta: SubscriptionMeta | null
): Promise<SubscriptionRuntimeReceipt | null> => {
  const state = useSubscriptionStore.getState();
  const current = state.subscriptions.find((item) => item.id === id);
  if (state.primaryId !== id || current?.url !== url) return null;
  const beforeCommit = useSubscriptionStore.getState();
  const beforePrimary = beforeCommit.subscriptions.find((item) => item.id === id);
  if (beforeCommit.primaryId !== id || beforePrimary?.url !== url) return null;
  const receipt = await writeRuntimeSnapshot(id, servers, meta);
  if (!receipt) return null;
  const afterCommit = useSubscriptionStore.getState();
  const afterPrimary = afterCommit.subscriptions.find((item) => item.id === id);
  if (afterCommit.primaryId !== id || afterPrimary?.url !== url) return null;
  return receipt;
};

const pushPrimaryToRust = (
  id: string,
  url: string,
  servers: ProxyEntry[],
  meta: SubscriptionMeta | null
): Promise<SubscriptionRuntimeReceipt | null> =>
  primaryRuntimeMutex.runExclusive(async () => {
    try {
      return await commitPrimaryToRust(id, url, servers, meta);
    } catch (error) {
      console.warn("[subscription] set_servers failed:", error);
      return null;
    }
  });

const clearRustRuntimeUnlocked = async (primaryId: string): Promise<void> => {
  const committed = await writeRuntimeSnapshot(primaryId, [], null);
  if (!committed) {
    throw new Error(
      `set_servers rejected runtime tombstone for subscription ${primaryId}`
    );
  }
};

const restoreVpnSelectionWhenStable = (selectedIndex: number): void => {
  const status = useVpnStore.getState().status;
  if (status === "starting" || status === "stopping") return;
  useVpnStore.setState({ selectedIndex });
};

const requireVpnStopped = (operation: string): void => {
  const vpn = useVpnStore.getState();
  if (vpn.status === "stopped") return;
  throw new Error(
    vpn.errorMessage || `VPN cleanup did not finish before ${operation}`
  );
};

const requireVpnTransitionStable = (operation: string): void => {
  const status = useVpnStore.getState().status;
  if (status !== "starting" && status !== "stopping") return;
  throw new Error(`Cannot ${operation} while the VPN connection is changing`);
};

const requireCredentialMutationAllowed = (operation: string): void => {
  if (!credentialMutationFence.isBlocked()) return;
  throw new Error(`Cannot ${operation} while subscription deletion is active`);
};

const genId = (): string => {
  // Безопасный uuid v4 без external crypto.randomUUID для старых runtime'ов.
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return "sub-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
};

const newSubscription = (url: string, hwid: string): Subscription => ({
  id: genId(),
  url,
  hwid,
  meta: null,
  lastFetchedAt: null,
  loading: false,
  error: null,
  engineOverride: null,
  servers: [],
  pings: [],
});

export const useSubscriptionStore = create<SubscriptionStore>((set, get) => {
  const setPrimaryIdUnlocked = async (id: string): Promise<boolean> => {
    if (useVpnStore.getState().status !== "stopped") return false;
    const before = get();
    const target = before.subscriptions.find((s) => s.id === id);
    if (!target) return false;
    const persistedPrimaryBefore = loadPrimaryIdStrict();

    const receipt = await primaryRuntimeMutex.runExclusive(async () => {
      let latestTarget: Subscription | null = null;
      let committedTarget: Subscription | null = null;
      let rollbackTarget: Subscription | null = null;
      return await publishAfterCommit(
        async () => {
          if (useVpnStore.getState().status !== "stopped") return null;
          const currentState = get();
          const currentTarget = currentState.subscriptions.find(
            (s) => s.id === id
          );
          if (!currentTarget || currentTarget.url !== target.url) return null;
          committedTarget = currentTarget;
          rollbackTarget =
            currentState.subscriptions.find(
              (s) => s.id === currentState.primaryId
            ) ?? null;

          let committed: SubscriptionRuntimeReceipt | null;
          try {
            committed = await writeRuntimeSnapshot(
              id,
              currentTarget.servers,
              currentTarget.meta
            );
          } catch (error) {
            try {
              const rollback = rollbackTarget
                ? await writeRuntimeSnapshot(
                    rollbackTarget.id,
                    rollbackTarget.servers,
                    rollbackTarget.meta
                  )
                : await writeRuntimeSnapshot(id, [], null);
              if (!rollback) throw new Error("backend rejected primary rollback");
            } catch (rollbackError) {
              throw new Error(
                `${String(error)}; backend rollback failed: ${String(rollbackError)}`
              );
            }
            throw error;
          }
          if (!committed) return null;

          latestTarget =
            get().subscriptions.find((s) => s.id === id) ?? null;
          if (
            !latestTarget ||
            latestTarget.url !== target.url ||
            latestTarget !== committedTarget ||
            useVpnStore.getState().status !== "stopped"
          ) {
            const rollback = rollbackTarget
              ? await writeRuntimeSnapshot(
                  rollbackTarget.id,
                  rollbackTarget.servers,
                  rollbackTarget.meta
                )
              : await writeRuntimeSnapshot(id, [], null);
            if (!rollback) throw new Error("backend rejected primary rollback");
            latestTarget = null;
            return null;
          }

          // Persist legacy credentials + explicit primary before publishing
          // locally. Any failure restores both persistence layers and backend.
          let previousLegacy: CredentialValue[] | null = null;
          try {
            previousLegacy = await replaceCredentialsTransactional([
              { key: URL_KEYRING, value: latestTarget.url },
              {
                key: HWID_KEYRING,
                value: latestTarget.hwid.trim() ? latestTarget.hwid : null,
              },
            ]);
            savePrimaryIdStrict(id);
          } catch (error) {
            const persistenceRollbackErrors: unknown[] = [];
            if (previousLegacy) {
              try {
                await restoreCredentialValues(previousLegacy);
              } catch (rollbackError) {
                persistenceRollbackErrors.push(rollbackError);
              }
            }
            try {
              restorePrimaryIdStrict(persistedPrimaryBefore);
            } catch (rollbackError) {
              persistenceRollbackErrors.push(rollbackError);
            }
            const rollback = rollbackTarget
              ? await writeRuntimeSnapshot(
                  rollbackTarget.id,
                  rollbackTarget.servers,
                  rollbackTarget.meta
                )
              : await writeRuntimeSnapshot(id, [], null);
            if (!rollback) {
              persistenceRollbackErrors.push(
                new Error("backend rejected primary persistence rollback")
              );
            }
            latestTarget = null;
            if (persistenceRollbackErrors.length > 0) {
              throw new Error(
                `${String(error)}; primary persistence rollback failed: ${persistenceRollbackErrors
                  .map(String)
                  .join("; ")}`
              );
            }
            throw error;
          }
          return committed;
        },
        () => {
          if (!latestTarget) return;
          set({
            primaryId: id,
            url: latestTarget.url,
            hwid: latestTarget.hwid,
            meta: latestTarget.meta,
            servers: latestTarget.servers,
            pings: latestTarget.pings ?? [],
            lastFetchedAt: latestTarget.lastFetchedAt,
            deviceHwid: "",
          });
          useVpnStore.setState({ selectedIndex: null });
        }
      );
    });
    if (!receipt) return false;
    const published = get().subscriptions.find((s) => s.id === id) ?? target;
    void invoke<string>("get_hwid", { url: published.url })
      .then((derived) => {
        if (get().primaryId === id && get().url === published.url) {
          set({ deviceHwid: derived });
        }
      })
      .catch(() => {});
    return true;
  };

  const deleteSubscriptionUnlocked = async (): Promise<void> => {
    requireCredentialMutationAllowed("delete subscriptions");
    const vpn = useVpnStore.getState();
    if (vpn.status !== "stopped") {
      await vpn.disconnect();
      requireVpnStopped("subscription deletion");
    }

    const deletionFence = credentialMutationFence.beginExclusive();
    try {
      await primaryRuntimeMutex.runExclusive(async () => {
        // connect() publishes `starting` before it can enter this same runtime
        // mutex. Recheck here so a connect that overtook the initial stop
        // check cannot coexist with tombstone/credential destruction.
        requireVpnStopped("subscription deletion finalization");
        const runtimePrimaryId = get().primaryId;
        const subscriptionsToDelete = [...get().subscriptions];
        await publishRequiredTombstone(
          runtimePrimaryId,
          clearRustRuntimeUnlocked
        );

        // Cache deletion is fallible and irreversible. Run it before deleting
        // Credential Manager source-of-truth so a cache error leaves enough
        // persisted state for retry/recovery.
        await Promise.all(
          subscriptionsToDelete.map((s) => deleteEncryptedCache(s.id))
        );

        const credentialKeys = [
          URL_KEYRING,
          HWID_KEYRING,
          ...subscriptionsToDelete.flatMap((s) => [
            `${URL_KEYRING}:${s.id}`,
            `${HWID_KEYRING}:${s.id}`,
          ]),
        ];
        const deletedCredentials = await deleteCredentialKeysTransactional(
          credentialKeys
        );

        const localKeys = [
          LAST_FETCH_KEY,
          "kwikproxy-secure.selectedServerName.v1",
          SUBS_INDEX_KEY,
          PRIMARY_ID_KEY,
          SERVERS_CACHE_KEY,
        ];
        const previousLocal = new Map<string, string | null>();
        try {
          for (const key of localKeys) {
            previousLocal.set(key, localStorage.getItem(key));
          }
          for (const key of localKeys) localStorage.removeItem(key);
        } catch (error) {
          const rollbackErrors: unknown[] = [];
          try {
            for (const [key, value] of previousLocal) {
              if (value === null) localStorage.removeItem(key);
              else localStorage.setItem(key, value);
            }
          } catch (rollbackError) {
            rollbackErrors.push(rollbackError);
          }
          try {
            await restoreCredentialRecords(deletedCredentials);
          } catch (rollbackError) {
            rollbackErrors.push(rollbackError);
          }
          if (rollbackErrors.length > 0) {
            throw new Error(
              `${String(error)}; deletion persistence rollback failed: ${rollbackErrors
                .map(String)
                .join("; ")}`
            );
          }
          throw error;
        }

        set({
          subscriptions: [],
          primaryId: null,
          servers: [],
          meta: null,
          pings: [],
          lastFetchedAt: null,
          url: "",
          hwid: "",
          error: null,
        });
        useVpnStore.setState({ selectedIndex: null });
      });
    } finally {
      credentialMutationFence.endExclusive(deletionFence);
    }

    showToast({
      kind: "success",
      title: i18n.t("toast.subscriptionDeleted.title"),
      message: i18n.t("toast.subscriptionDeleted.message"),
      durationMs: 4000,
    });
  };

  return ({
  // Multi-subscription (0.3.0+) — populated from `loadSecureCreds`.
  subscriptions: [],
  primaryId: null,

  servers: [],
  meta: null,
  lastFetchedAt: loadTimestamp(LAST_FETCH_KEY),
  pings: [],
  pingsLoading: false,
  loading: false,
  error: null,
  url: loadFromStorage(URL_KEY),
  deviceHwid: "",
  hwid: loadFromStorage(HWID_KEY),

  // ─── Multi-subscription methods (0.3.0+) ─────────────────────────────

  async addSubscription(url) {
    return await runSubscriptionMutation(async () => {
      requireCredentialMutationAllowed("add a subscription");
      requireVpnTransitionStable("add a subscription");
      const trimmed = url.trim();
      if (!trimmed) throw new Error("empty URL");

      const initial = get();
      const dup = initial.subscriptions.find((s) => s.url === trimmed);
      if (dup) {
        showToast({
          kind: "warning",
          title: i18n.t("toast.subscriptionDuplicate.title"),
          message: i18n.t("toast.subscriptionDuplicate.message"),
          durationMs: 4000,
        });
        return dup.id;
      }
      if (initial.url === trimmed && initial.subscriptions.length === 0) {
        showToast({
          kind: "warning",
          title: i18n.t("toast.subscriptionDuplicate.title"),
          message: i18n.t("toast.subscriptionDuplicate.message"),
          durationMs: 4000,
        });
        return "__legacy_dup__";
      }

      let existing = initial.subscriptions;
      const credentialUpdates: CredentialValue[] = [];
      if (existing.length === 0 && initial.url.trim()) {
        const legacyId = genId();
        const legacySub: Subscription = {
          id: legacyId,
          url: initial.url,
          hwid: initial.hwid,
          meta: initial.meta,
          lastFetchedAt: initial.lastFetchedAt,
          loading: false,
          error: null,
          engineOverride: null,
          servers: [],
          pings: [],
        };
        existing = [legacySub];
        credentialUpdates.push(
          { key: `${URL_KEYRING}:${legacyId}`, value: legacySub.url },
          {
            key: `${HWID_KEYRING}:${legacyId}`,
            value: legacySub.hwid.trim() ? legacySub.hwid : null,
          }
        );
      }

      const id = genId();
      const sub = { ...newSubscription(trimmed, ""), id };
      credentialUpdates.push({ key: `${URL_KEYRING}:${id}`, value: trimmed });
      const next = [...existing, sub];
      const nextPrimaryId = initial.primaryId ?? existing[0]?.id ?? id;
      if (existing.length === 0) {
        credentialUpdates.push({ key: URL_KEYRING, value: trimmed });
      }

      const previousIndex = localStorage.getItem(SUBS_INDEX_KEY);
      const previousPrimary = localStorage.getItem(PRIMARY_ID_KEY);
      const previousCredentials = await replaceCredentialsTransactional(
        credentialUpdates
      );
      try {
        saveSubsIndexStrict(next.map((s) => s.id));
        savePrimaryIdStrict(nextPrimaryId);
      } catch (error) {
        const rollbackErrors: unknown[] = [];
        try {
          await restoreCredentialValues(previousCredentials);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
        try {
          if (previousIndex === null) localStorage.removeItem(SUBS_INDEX_KEY);
          else localStorage.setItem(SUBS_INDEX_KEY, previousIndex);
          restorePrimaryIdStrict(previousPrimary);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
        if (rollbackErrors.length > 0) {
          throw new Error(
            `${String(error)}; subscription add rollback failed: ${rollbackErrors
              .map(String)
              .join("; ")}`
          );
        }
        throw error;
      }

      set({
        subscriptions: next,
        ...(initial.subscriptions.length === 0
          ? {
              primaryId: nextPrimaryId,
              url: existing.length === 0 ? trimmed : initial.url,
            }
          : {}),
      });
      if (get().primaryId === id) await get().fetchSubscription();
      else await get().fetchSubscriptionById(id);
      return id;
    });
  },

  async removeSubscription(id) {
    return await runSubscriptionMutation(async () => {
      requireCredentialMutationAllowed("remove a subscription");
      const initial = get();
      const sub = initial.subscriptions.find((s) => s.id === id);
      if (!sub) return;
      const wasPrimary = initial.primaryId === id;
      const vpn = useVpnStore.getState();
      const previousSelectedIndex = vpn.selectedIndex;
      if (!wasPrimary) requireVpnTransitionStable("remove a subscription");
      if (wasPrimary && vpn.status !== "stopped") {
        await vpn.disconnect();
        requireVpnStopped("subscription removal");
      }

      const current = get();
      if (!current.subscriptions.some((s) => s.id === id)) return;
      const remaining = current.subscriptions.filter((s) => s.id !== id);
      if (wasPrimary && remaining.length === 0) {
        await deleteSubscriptionUnlocked();
        return;
      }

      let primarySwitched = false;
      if (wasPrimary) {
        const switched = await setPrimaryIdUnlocked(remaining[0].id);
        if (!switched) {
          throw new Error(
            "backend rejected the replacement primary subscription"
          );
        }
        primarySwitched = true;
      }

      const finalizeRemoval = async (): Promise<string | null> => {
        // Irreversible/fallible cache cleanup precedes source-of-truth secrets.
        await deleteEncryptedCache(id);
        const deletedCredentials = await deleteCredentialKeysTransactional([
          `${URL_KEYRING}:${id}`,
          `${HWID_KEYRING}:${id}`,
        ]);

        const latestRemaining = get().subscriptions.filter((s) => s.id !== id);
        try {
          saveSubsIndexStrict(latestRemaining.map((s) => s.id));
        } catch (error) {
          try {
            await restoreCredentialRecords(deletedCredentials);
          } catch (rollbackError) {
            throw new Error(
              `${String(error)}; subscription removal rollback failed: ${String(
                rollbackError
              )}`
            );
          }
          throw error;
        }
        set({ subscriptions: latestRemaining });
        if (wasPrimary) {
          const next = latestRemaining[0];
          return next.servers.length === 0 ? next.id : null;
        }
        return null;
      };
      const rollbackPrimary = async (): Promise<void> => {
        const rollbackVpn = useVpnStore.getState();
        if (rollbackVpn.status !== "stopped") {
          await rollbackVpn.disconnect();
          requireVpnStopped("primary subscription rollback");
        }
        const restored = await setPrimaryIdUnlocked(id);
        if (!restored) {
          throw new Error("backend rejected primary subscription rollback");
        }
        useVpnStore.setState({ selectedIndex: previousSelectedIndex });
      };

      const nextToFetchId = primarySwitched
        ? await withAsyncRollback(
          finalizeRemoval,
          rollbackPrimary,
          "primary subscription"
        )
        : await finalizeRemoval();
      if (nextToFetchId) await get().fetchSubscriptionById(nextToFetchId);
    });
  },

  async setPrimaryId(id) {
    return await runSubscriptionMutation(() => setPrimaryIdUnlocked(id));
  },

  async ensurePrimaryRuntimeReady() {
    const state = get();
    const id = state.primaryId;
    if (!id) return null;
    const sub = state.subscriptions.find((item) => item.id === id);
    if (!sub) return null;
    return await pushPrimaryToRust(id, sub.url, sub.servers, sub.meta);
  },

  async withPrimaryRuntimeReady(consume) {
    return await primaryRuntimeMutex.runExclusive(async () => {
      const state = get();
      const id = state.primaryId;
      if (!id) return null;
      const sub = state.subscriptions.find((item) => item.id === id);
      if (!sub) return null;
      const receipt = await commitPrimaryToRust(
        id,
        sub.url,
        sub.servers,
        sub.meta
      );
      if (!receipt) return null;
      return await consume(receipt);
    });
  },

  setEngineOverride(id, engine) {
    set({
      subscriptions: get().subscriptions.map((s) =>
        s.id === id ? { ...s, engineOverride: engine } : s
      ),
    });
  },

  getEffectiveEngine(_id) {
    // Mihomo-only (миграция 2026-05): движок всегда Mihomo. sing-box
    // выпиливается, поэтому per-subscription override и header
    // X-Kwik-Engine больше не влияют — подписка всегда запрашивается
    // с clash-verge UA и подключается через Mihomo. Сигнатура сохранена
    // для совместимости вызовов (fetch UA + vpn_connect).
    return "mihomo";
  },

  async fetchSubscriptionById(id) {
    const sub = get().subscriptions.find((s) => s.id === id);
    if (!sub) return;
    if (!sub.url.trim()) return;
    const requestUrl = sub.url;
    const generation = beginFetch(id);
    const wasPrimary = get().primaryId === id;
    // Помечаем sub как loading для UI.
    set({
      subscriptions: get().subscriptions.map((s) =>
        s.id === id ? { ...s, loading: true, error: null } : s
      ),
      ...(wasPrimary ? { loading: true, error: null } : {}),
    });
    const settings = useSettingsStore.getState();
    const ua = effectiveUserAgent(
      get().getEffectiveEngine(id),
      settings.userAgent,
      settings.userAgentTouched
    );
    try {
      const result = await invoke<FetchSubscriptionRaw>("fetch_subscription", {
        url: requestUrl,
        hwidOverride: sub.hwid.trim() || null,
        userAgent: ua.trim() || null,
        sendHwid: settings.sendHwid,
      });
      if (!isCurrentFetch(id, requestUrl, generation)) return;
      const now = Date.now();
      const normalized = normalizeMeta(result.meta);
      // Tag servers с subscriptionId.
      const tagged = result.servers.map((s) => ({ ...s, subscriptionId: id }));
      // Update этой sub's data.
      set({
        subscriptions: get().subscriptions.map((s) =>
          s.id === id
            ? {
                ...s,
                meta: normalized,
                lastFetchedAt: now,
                servers: tagged,
                pings: [],
                loading: false,
                error: null,
              }
            : s
        ),
      });
      // Persist only after the request-id/URL generation check. Rust applies
      // the full-profile sanitizer before current-user DPAPI encryption.
      void saveEncryptedCache(id, requestUrl, result, generation);
      // Если primary — синхронизируем legacy state для backward compat
      // (компоненты вроде vpnStore.connect и старого ServerSelector).
      if (
        get().primaryId === id &&
        isCurrentFetch(id, requestUrl, generation)
      ) {
        saveToStorage(LAST_FETCH_KEY, String(now));
        set({
          servers: tagged,
          meta: normalized,
          pings: [],
          lastFetchedAt: now,
          loading: false,
        });
        // Rust runtime-state получает серверы primary — connect-by-index
        // работает без re-fetch'а.
        const receipt = await pushPrimaryToRust(
          id,
          requestUrl,
          tagged,
          normalized
        );
        if (!receipt) return;
        if (
          get().primaryId !== id ||
          !isCurrentFetch(id, requestUrl, generation)
        ) {
          return;
        }
        // Restore selectedIndex по сохранённому имени (как и в legacy fetch).
        const restoredIndex = findSelectedIndexByName(tagged);
        if (restoredIndex >= 0) {
          restoreVpnSelectionWhenStable(restoredIndex);
        } else if (tagged.length === 1) {
          // Auto-select единственной записи (full-mihomo «профиль») —
          // без него сетка локаций не отрисуется после смены подписки.
          restoreVpnSelectionWhenStable(0);
        }
      }
      // Авто-пинг для этой sub.
      void get().pingAllOf(id);

      if (normalized?.routingAutorouting || normalized?.routingStatic) {
        showToast({
          kind: "warning",
          title: i18n.t("toast.routingDirectivePending.title"),
          message: i18n.t("toast.routingDirectivePending.message"),
          durationMs: 8000,
        });
      }
    } catch (e) {
      if (!isCurrentFetch(id, requestUrl, generation)) return;
      set({
        subscriptions: get().subscriptions.map((s) =>
          s.id === id ? { ...s, loading: false, error: String(e) } : s
        ),
        ...(get().primaryId === id
          ? { loading: false, error: String(e) }
          : {}),
      });
    }
  },

  async pingAllOf(id) {
    const sub = get().subscriptions.find((s) => s.id === id);
    if (!sub || sub.servers.length === 0) return;
    // Rust ping_servers intentionally sees only the generation-guarded
    // primary snapshot. Secondary refreshes never replace it.
    if (get().primaryId !== id) return;
    set({ pingsLoading: true });
    try {
      const result = await invoke<(number | null)[]>("ping_servers");
      set({ pings: result, pingsLoading: false });
      set({
        subscriptions: get().subscriptions.map((s) =>
          s.id === id ? { ...s, pings: result } : s
        ),
      });
    } catch {
      set({ pingsLoading: false });
    }
  },

  // ─── Legacy API (sync'ится с primary subscription) ───────────────────

  setUrl: (url) => {
    if (
      credentialMutationFence.isBlocked() ||
      subscriptionSourceFence.isBlocked()
    ) return;
    set({
      url,
      deviceHwid: "",
      servers: [],
      meta: null,
      pings: [],
      loading: false,
      error: null,
    });
    const normalizedInput = url.trim();
    if (/^https:\/\//i.test(normalizedInput)) {
      void invoke<string>("get_hwid", { url: normalizedInput })
        .then((id) => {
          // Ignore stale async results while the user is still editing.
          if (get().url.trim() === normalizedInput) set({ deviceHwid: id });
        })
        .catch(() => {});
    }
    // 0.3.0: обновляем primary subscription тоже (sync legacy ↔ multi).
    const primaryId = get().primaryId;
    if (primaryId) {
      set({
        subscriptions: get().subscriptions.map((s) =>
          s.id === primaryId
            ? {
                ...s,
                url,
                servers: [],
                meta: null,
                pings: [],
                loading: false,
                error: null,
              }
            : s
        ),
      });
      void deleteEncryptedCache(primaryId).catch(() => {
        // Error is already surfaced by deleteEncryptedCache.
      });
      void pushPrimaryToRust(primaryId, url, [], null);
      queueCredentialMutation(keyringSet(`${URL_KEYRING}:${primaryId}`, url));
    }
    // Чувствительные значения пишем в Windows Credential Manager.
    // localStorage больше НЕ используется как источник правды — оставляем
    // пустым, чтобы старые версии приложения не подсунули устаревший URL.
    saveToStorage(URL_KEY, "");
    queueCredentialMutation(keyringSet(URL_KEYRING, url));
  },
  setHwid: (hwid) => {
    if (
      credentialMutationFence.isBlocked() ||
      subscriptionSourceFence.isBlocked()
    ) return;
    set({ hwid });
    // 0.3.0: sync с primary subscription тоже.
    const primaryId = get().primaryId;
    if (primaryId) {
      set({
        subscriptions: get().subscriptions.map((s) =>
          s.id === primaryId ? { ...s, hwid } : s
        ),
      });
      if (hwid.trim()) {
        queueCredentialMutation(
          keyringSet(`${HWID_KEYRING}:${primaryId}`, hwid)
        );
      } else {
        queueCredentialMutation(keyringDelete(`${HWID_KEYRING}:${primaryId}`));
      }
    }
    saveToStorage(HWID_KEY, "");
    if (hwid.trim()) {
      queueCredentialMutation(keyringSet(HWID_KEYRING, hwid));
    } else {
      queueCredentialMutation(keyringDelete(HWID_KEYRING));
    }
  },

  async loadDeviceHwid() {
    try {
      const url = get().url.trim();
      const id = await invoke<string>("get_hwid", { url: url || null });
      set({ deviceHwid: id });
    } catch {
      // не критично — UI покажет пустую строку
    }
  },

  async loadSecureCreds() {
    return await runSubscriptionMutation(async () => {
    // Rotate the backend-issued epoch before reading any runtime/cache state.
    // Renderer reloads therefore cannot reuse sequence numbers or complete
    // delayed mutations from the previous WebView instance.
    await ensureRuntimeEpoch();
    // Этап 6.A: читаем URL/HWID из Windows Credential Manager. Если в
    // keyring пусто, но в localStorage есть — мигрируем (один раз) и
    // зачищаем localStorage. Маркер миграции защищает от повторного
    // запуска (если вдруг пользователь вернёт старую версию и оставит
    // там URL — на следующем апгрейде не будем перезатирать keyring).
    let migrated = false;
    try {
      migrated = !!localStorage.getItem(KEYRING_MIGRATION_KEY);
    } catch {
      // приватный режим — мигрируем каждый раз, не критично
    }

    let urlFromKeyring = await keyringGet(URL_KEYRING);
    let hwidFromKeyring = await keyringGet(HWID_KEYRING);

    if (!migrated) {
      const legacyUrl = loadFromStorage(URL_KEY);
      const legacyHwid = loadFromStorage(HWID_KEY);
      if (!urlFromKeyring && legacyUrl) {
        await keyringSet(URL_KEYRING, legacyUrl);
        urlFromKeyring = legacyUrl;
      }
      if (!hwidFromKeyring && legacyHwid) {
        await keyringSet(HWID_KEYRING, legacyHwid);
        hwidFromKeyring = legacyHwid;
      }
      saveToStorage(URL_KEY, "");
      saveToStorage(HWID_KEY, "");
      try {
        localStorage.setItem(KEYRING_MIGRATION_KEY, "1");
      } catch {
        // ignore
      }
    }

    if (urlFromKeyring) {
      set({ url: urlFromKeyring });
    }
    if (hwidFromKeyring) {
      set({ hwid: hwidFromKeyring });
    }

    // 0.3.0 multi-subscription bootstrap. Сценарии:
    //   A) localStorage SUBS_INDEX_KEY есть → читаем все по списку из
    //      keyring `subscription_url:${id}` / `hwid_override:${id}`.
    //   B) Списка нет (или Scenario A не нашёл ни одной живой записи),
    //      но legacy URL_KEYRING есть → создаём subscriptions[0] из
    //      этого URL, сохраняем его и в новые per-id ключи (миграция).
    //   C) Всё пусто → subscriptions = [], primaryId = null. Welcome.
    const ids = loadSubsIndex();
    const persistedPrimary = loadPrimaryId();
    let scenarioASucceeded = false;
    if (ids.length > 0) {
      // Сценарий A
      const subs: Subscription[] = [];
      let allReadEmpty = true;
      for (const id of ids) {
        const primaryRead = id === persistedPrimary;
        const u = optionalValueOrThrow(
          await keyringRead(`${URL_KEYRING}:${id}`),
          primaryRead
        );
        const h = optionalValueOrThrow(
          await keyringRead(`${HWID_KEYRING}:${id}`),
          primaryRead
        );
        if (!u) {
          // 0.3.3 fix: НЕ удаляем ID из индекса. Транзиентная ошибка
          // Credential Manager на старте app (race с инициализацией
          // SCM, или CredRead returns NoEntry до того как закончилась
          // подгрузка credentials profile) приводила к permanent
          // data loss — мы покарали индекс, на следующем старте
          // нечего восстановить. Лучше показать Welcome (если ВСЕ
          // прочитались пустыми) и retry'нуть на следующем запуске.
          continue;
        }
        allReadEmpty = false;
        subs.push({
          id,
          url: u,
          hwid: h ?? "",
          meta: null,
          lastFetchedAt: null,
          loading: false,
          error: null,
          engineOverride: null,
          servers: [],
          pings: [],
        });
      }
      if (subs.length > 0) {
        const primary = choosePersistedById(subs, persistedPrimary)!;
        set({ subscriptions: subs, primaryId: primary.id });
        // Legacy fields синхронизируются с primary (для callsites,
        // которые ещё читают `url`/`hwid`/`meta`).
        set({ url: primary.url, hwid: primary.hwid });
        scenarioASucceeded = true;
        // Index НЕ переписываем — даже если из 5 ids только 3
        // прочитались (2 транзиентно фейлят), на следующем запуске
        // те 2 могут восстановиться. Permanent purge — это решение
        // юзера через removeSubscription, не наше.
      } else if (allReadEmpty) {
        // Все ids вернули пустой keyring. **Не трогаем индекс** —
        // оставляем для retry на следующем запуске. Падаем в
        // Сценарий B ниже как fallback.
        console.warn(
          `[subscription] все ${ids.length} ID вернули пустой keyring — индекс и primary сохранены для retry`
        );
      }
    }
    if (!scenarioASucceeded && ids.length === 0 && urlFromKeyring) {
      // Сценарий B — миграция legacy single-sub в multi
      // только когда multi-index действительно отсутствует. Если indexed
      // reads были временно пустыми, индекс нельзя заменять новым ID.
      const id = genId();
      const sub: Subscription = {
        id,
        url: urlFromKeyring,
        hwid: hwidFromKeyring || "",
        meta: null,
        lastFetchedAt: get().lastFetchedAt,
        loading: false,
        error: null,
        engineOverride: null,
        servers: [],
        pings: [],
      };
      // 0.3.3 fix: keyring-write СНАЧАЛА (await), потом index. Если
      // keyring write упал — index не обновляется → нет phantom id
      // которые попадут в next-start scenario A с пустым keyring.
      const previous = await replaceCredentialsTransactional([
        { key: `${URL_KEYRING}:${id}`, value: urlFromKeyring },
        {
          key: `${HWID_KEYRING}:${id}`,
          value: hwidFromKeyring || null,
        },
      ]);
      try {
        saveBootstrapIdentityStrict(id);
      } catch (error) {
        await restoreCredentialValues(previous);
        throw error;
      }
      set({ subscriptions: [sub], primaryId: id });
    }

    removeLegacyPlaintextCache();

    // Hydrate each URL-bound record from the current-user DPAPI cache. A
    // corrupt, foreign-user or URL-mismatched record fails closed and is
    // treated as a cache miss; credentials never pass through localStorage.
    {
      const subscriptions = get().subscriptions;
      const cached = await Promise.all(
        subscriptions.map(async (subscription) => {
          try {
            const result = await invoke<FetchSubscriptionRaw | null>(
              "load_subscription_cache",
              {
                sessionEpoch: await ensureRuntimeEpoch(),
                subscriptionId: subscription.id,
                sourceUrl: subscription.url,
              }
            );
            return { id: subscription.id, url: subscription.url, result };
          } catch (error) {
            console.warn("[subscription] encrypted cache load failed:", error);
            return { id: subscription.id, url: subscription.url, result: null };
          }
        })
      );
      const byId = new Map(cached.map((entry) => [entry.id, entry]));
      const current = get().subscriptions;
      const hydrated = current.map((subscription) => {
        const entry = byId.get(subscription.id);
        if (
          !entry?.result ||
          entry.url !== subscription.url ||
          entry.result.servers.length === 0
        ) {
          return subscription;
        }
        const servers = entry.result.servers.map((server) => ({
          ...server,
          subscriptionId: subscription.id,
        }));
        return {
          ...subscription,
          servers,
          meta: normalizeMeta(entry.result.meta),
          pings: [],
        };
      });
      set({ subscriptions: hydrated });
      const currentPrimaryId = get().primaryId;
      const primary = hydrated.find(
        (subscription) => subscription.id === currentPrimaryId
      );
      if (primary && primary.servers.length > 0) {
        set({
          servers: primary.servers,
          meta: primary.meta,
          pings: [],
        });
        const receipt = await pushPrimaryToRust(
          primary.id,
          primary.url,
          primary.servers,
          primary.meta
        );
        if (!receipt) return;
        const restoredIndex = findSelectedIndexByName(primary.servers);
        useVpnStore.setState({
          selectedIndex:
            restoredIndex >= 0
              ? restoredIndex
              : primary.servers.length === 1
                ? 0
                : null,
        });
      }
    }
    });
  },

  async fetchSubscription() {
    const initial = get();
    if (!initial.url.trim() && initial.subscriptions.length === 0) return;

    // 0.3.0 auto-bootstrap: если subscriptions[] пуст, создаём primary
    // из текущего legacy URL ДО fetch'а. Иначе после fetch'а subscriptions[]
    // останется пустым (т.к. fetchSubscription не дёргает addSubscription),
    // и UI карточек подписок не покажется. Это случай:
    // - Welcome → setUrl(url) → fetchSubscription() (старый flow)
    // - юзер запустил app до миграции (legacy single-sub)
    // - keyring пуст, но Rust state имеет cached servers
    if (get().subscriptions.length === 0) {
      await runSubscriptionMutation(async () => {
      if (get().subscriptions.length > 0) return;
      const { url, hwid } = get();
      if (!url.trim()) return;
      const bootstrapId = genId();
      const bootstrapSub: Subscription = {
        id: bootstrapId,
        url,
        hwid,
        meta: get().meta,
        lastFetchedAt: get().lastFetchedAt,
        loading: false,
        error: null,
        engineOverride: null,
        servers: [],
        pings: [],
      };
      // 0.3.3 fix: keyring СНАЧАЛА (await), потом state + index. Если
      // keyring write упал — index не обновляется → нет phantom id
      // в индексе который покараем на следующем старте. До 0.3.3 был
      // обратный порядок: saveSubsIndex → keyringSet, что при тихом
      // failure'е keyring (наш wrapper глотает ошибки) приводил к
      // permanent data loss.
      const previous = await replaceCredentialsTransactional([
        { key: `${URL_KEYRING}:${bootstrapId}`, value: url },
        {
          key: `${HWID_KEYRING}:${bootstrapId}`,
          value: hwid.trim() ? hwid : null,
        },
      ]);
      try {
        saveBootstrapIdentityStrict(bootstrapId);
      } catch (error) {
        await restoreCredentialValues(previous);
        throw error;
      }
      set({ subscriptions: [bootstrapSub], primaryId: bootstrapId });
      });
    }

    const primaryId = get().primaryId;
    if (primaryId) await get().fetchSubscriptionById(primaryId);
  },

  async loadCached() {
    return await runSubscriptionMutation(async () => {
    try {
      await ensureRuntimeEpoch();
      const servers = await invoke<ProxyEntry[]>("get_servers");
      if (servers.length > 0) {
        // 0.3.0 auto-bootstrap: если subscriptions[] пуст НО Rust имеет
        // cached servers — создаём fallback subscription из legacy URL.
        // Это покрывает случаи когда loadSecureCreds B-сценарий не
        // отработал (URL_KEYRING пуст), но юзер всё ещё имеет servers
        // в Rust runtime state.
        let primaryId = get().primaryId;
        if (!primaryId && get().subscriptions.length === 0) {
          const url = get().url;
          if (url.trim()) {
            const id = genId();
            const sub: Subscription = {
              id,
              url,
              hwid: get().hwid,
              meta: get().meta,
              lastFetchedAt: get().lastFetchedAt,
              loading: false,
              error: null,
              engineOverride: null,
              servers: [],
              pings: [],
            };
            const previous = await replaceCredentialsTransactional([
              { key: `${URL_KEYRING}:${id}`, value: url },
              {
                key: `${HWID_KEYRING}:${id}`,
                value: sub.hwid.trim() ? sub.hwid : null,
              },
            ]);
            try {
              saveBootstrapIdentityStrict(id);
            } catch (error) {
              await restoreCredentialValues(previous);
              throw error;
            }
            set({ subscriptions: [sub], primaryId: id });
            primaryId = id;
          } else {
            // URL пуст и subscriptions[] пуст — Rust state хранит orphan
            // servers от предыдущего runtime'а (например после полного
            // deleteSubscription в прошлой сессии). Юзер не может ими
            // управлять (нет URL для refresh, нет ⋯ меню). Очищаем —
            // App.tsx покажет Welcome с возможностью ввести новый URL.
            set({ servers: [], meta: null, pings: [] });
            return;
          }
        }
        const tagged = primaryId
          ? servers.map((s) => ({ ...s, subscriptionId: primaryId! }))
          : servers;
        set({ servers: tagged });
        if (primaryId) {
          set({
            subscriptions: get().subscriptions.map((s) =>
              s.id === primaryId ? { ...s, servers: tagged } : s
            ),
          });
        }
        // 0.2.4: на старте app vpnStore.selectedIndex = null (он
        // живёт только в памяти), так что восстанавливаем по имени из
        // localStorage. Auto-select 0 для одиночного сервера —
        // важно для mihomo-passthrough.
        const restoredIndex = findSelectedIndexByName(servers);
        if (restoredIndex >= 0) {
          restoreVpnSelectionWhenStable(restoredIndex);
        } else if (servers.length === 1) {
          restoreVpnSelectionWhenStable(0);
        }
        // Метаданные кешируются параллельно — могут отсутствовать если
        // сервер их не присылал.
        try {
          const rawMeta = await invoke<SubscriptionMetaRaw | null>(
            "get_subscription_meta"
          );
          set({ meta: normalizeMeta(rawMeta) });
        } catch {
          // не критично
        }
        void get().pingAll();
      }
    } catch {
      // кеш пустой — не ошибка
    }
    });
  },

  async pingAll() {
    if (get().servers.length === 0) return;
    set({ pingsLoading: true });
    try {
      const result = await invoke<(number | null)[]>("ping_servers");
      set({ pings: result, pingsLoading: false });
    } catch {
      set({ pingsLoading: false });
    }
  },

  async deleteSubscription() {
    return await runSubscriptionMutation(deleteSubscriptionUnlocked);
  },
  });
});
