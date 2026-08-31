import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { effectiveUserAgent, useSettingsStore, type Engine } from "./settingsStore";
import { findSelectedIndexByName, useVpnStore } from "./vpnStore";
import i18n from "../i18n";
import { showToast } from "./toastStore";
import {
  AsyncMutex,
  publishRequiredTombstone,
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
const keyringSet = async (key: string, value: string): Promise<boolean> => {
  try {
    await invoke("secure_storage_set", { key, value });
    return true;
  } catch {
    return false;
  }
};

const keyringGet = async (key: string): Promise<string> => {
  try {
    return await invoke<string>("secure_storage_get", { key });
  } catch {
    return "";
  }
};

const keyringDelete = async (key: string): Promise<void> => {
  try {
    await invoke("secure_storage_delete", { key });
  } catch {
    // ignore
  }
};

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

const saveSubsIndex = (ids: string[]) => {
  try {
    localStorage.setItem(SUBS_INDEX_KEY, JSON.stringify(ids));
  } catch {
    // приватный режим — не критично
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
const commitPrimaryToRust = async (
  id: string,
  url: string,
  servers: ProxyEntry[],
  meta: SubscriptionMeta | null
): Promise<SubscriptionRuntimeReceipt | null> => {
  const state = useSubscriptionStore.getState();
  const current = state.subscriptions.find((item) => item.id === id);
  if (state.primaryId !== id || current?.url !== url) return null;
  const generation = ++nextRuntimeGeneration;
  const sessionEpoch = await ensureRuntimeEpoch();
  const beforeCommit = useSubscriptionStore.getState();
  const beforePrimary = beforeCommit.subscriptions.find((item) => item.id === id);
  if (beforeCommit.primaryId !== id || beforePrimary?.url !== url) return null;
  const committed = await invoke<boolean>("set_servers", {
    sessionEpoch,
    primaryId: id,
    servers,
    meta: serializeMeta(meta),
    generation,
  });
  if (!committed) return null;
  const afterCommit = useSubscriptionStore.getState();
  const afterPrimary = afterCommit.subscriptions.find((item) => item.id === id);
  if (afterCommit.primaryId !== id || afterPrimary?.url !== url) return null;
  return { sessionEpoch, primaryId: id, generation };
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

const clearRustRuntime = (primaryId: string): Promise<void> =>
  primaryRuntimeMutex.runExclusive(async () => {
    const generation = ++nextRuntimeGeneration;
    const sessionEpoch = await ensureRuntimeEpoch();
    const committed = await invoke<boolean>("set_servers", {
      sessionEpoch,
      primaryId,
      servers: [],
      meta: null,
      generation,
    });
    if (!committed) {
      throw new Error(
        `set_servers rejected runtime tombstone for subscription ${primaryId}`
      );
    }
  });

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

export const useSubscriptionStore = create<SubscriptionStore>((set, get) => ({
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
    requireVpnTransitionStable("add a subscription");
    const trimmed = url.trim();
    if (!trimmed) throw new Error("empty URL");

    // 0.3.0: проверка дубликатов — сравниваем полный URL точно.
    // Если уже есть такая же подписка, ничего не добавляем и показываем
    // юзеру toast (возвращаем id существующей для callsite).
    const dup = get().subscriptions.find((s) => s.url === trimmed);
    if (dup) {
      showToast({
        kind: "warning",
        title: i18n.t("toast.subscriptionDuplicate.title"),
        message: i18n.t("toast.subscriptionDuplicate.message"),
        durationMs: 4000,
      });
      return dup.id;
    }
    // Также проверяем legacy URL (на случай если subscriptions[] ещё не
    // мигрирован — юзер пытается добавить тот же URL что в legacy).
    if (get().url === trimmed && get().subscriptions.length === 0) {
      showToast({
        kind: "warning",
        title: i18n.t("toast.subscriptionDuplicate.title"),
        message: i18n.t("toast.subscriptionDuplicate.message"),
        durationMs: 4000,
      });
      // Возвращаем placeholder id; при следующем fetchSubscription
      // legacy замигрируется в subscriptions[0] и duplicate-check
      // сработает в обычном виде.
      return "__legacy_dup__";
    }

    // 0.3.0: если subscriptions пусты, но legacy URL уже есть (юзер
    // ещё не делал hard-reload после миграции 0.3.0), сначала
    // мигрируем legacy в subscriptions[0]. Без этого новая подписка
    // становится primary и legacy URL «теряется» (его нет в массиве).
    let existing = get().subscriptions;
    if (existing.length === 0) {
      const legacyUrl = get().url;
      const legacyHwid = get().hwid;
      if (legacyUrl.trim()) {
        const legacyId = genId();
        const legacySub: Subscription = {
          id: legacyId,
          url: legacyUrl,
          hwid: legacyHwid,
          meta: get().meta,
          lastFetchedAt: get().lastFetchedAt,
          loading: false,
          error: null,
          engineOverride: null,
          servers: [],
          pings: [],
        };
        await keyringSet(`${URL_KEYRING}:${legacyId}`, legacyUrl);
        if (legacyHwid.trim()) {
          await keyringSet(`${HWID_KEYRING}:${legacyId}`, legacyHwid);
        }
        existing = [legacySub];
        set({ subscriptions: existing, primaryId: legacyId });
        saveSubsIndex([legacyId]);
      }
    }

    const id = genId();
    const sub = newSubscription(trimmed, "");
    sub.id = id;
    await keyringSet(`${URL_KEYRING}:${id}`, trimmed);
    const next = [...existing, sub];
    set({ subscriptions: next });
    // Если это вообще первая подписка (и legacy URL не было) —
    // становится primary и legacy url синхронизируется.
    if (existing.length === 0) {
      set({ primaryId: id, url: trimmed });
      await keyringSet(URL_KEYRING, trimmed);
    }
    saveSubsIndex(next.map((s) => s.id));
    // 0.3.0 Этап 6: fetch для любой подписки. Primary использует legacy
    // fetchSubscription (синкнутся state.servers/meta для backward compat),
    // non-primary — fetchSubscriptionById (хранит результаты только в
    // sub'а; legacy state не трогается).
    if (get().primaryId === id) {
      await get().fetchSubscription();
    } else {
      await get().fetchSubscriptionById(id);
    }
    return id;
  },

  async removeSubscription(id) {
    const subs = get().subscriptions;
    const sub = subs.find((s) => s.id === id);
    if (!sub) return;
    const wasPrimary = get().primaryId === id;
    const vpn = useVpnStore.getState();
    if (!wasPrimary) {
      requireVpnTransitionStable("remove a subscription");
    }
    if (wasPrimary && vpn.status !== "stopped") {
      await vpn.disconnect();
      requireVpnStopped("subscription removal");
    }

    // Удаляем keyring entries (и legacy keys если был primary).
    await Promise.all([
      keyringDelete(`${URL_KEYRING}:${id}`),
      keyringDelete(`${HWID_KEYRING}:${id}`),
      deleteEncryptedCache(id),
    ]);

    const remaining = subs.filter((s) => s.id !== id);
    set({ subscriptions: remaining });
    saveSubsIndex(remaining.map((s) => s.id));
    if (wasPrimary) {
      // Promote first remaining to primary, или если пусто — полная очистка.
      if (remaining.length > 0) {
        const next = remaining[0];
        await get().setPrimaryId(next.id);
        if (next.servers.length === 0) {
          await get().fetchSubscriptionById(next.id);
        }
      } else {
        // Это была последняя подписка — выкидываем все legacy данные.
        await get().deleteSubscription();
      }
    }
  },

  async setPrimaryId(id) {
    const vpnStatus = useVpnStore.getState().status;
    if (vpnStatus === "starting" || vpnStatus === "stopping") return false;
    const sub = get().subscriptions.find((s) => s.id === id);
    if (!sub) return false;
    set({
      primaryId: id,
      url: sub.url,
      hwid: sub.hwid,
      meta: sub.meta,
      servers: sub.servers,
      pings: sub.pings ?? [],
      lastFetchedAt: sub.lastFetchedAt,
      deviceHwid: "",
    });
    // This synchronous selection change always publishes a newer runtime
    // generation, including an empty list, so the previous primary cannot be
    // connected while the new one is still loading.
    const receipt = await pushPrimaryToRust(id, sub.url, sub.servers, sub.meta);
    void invoke<string>("get_hwid", { url: sub.url })
      .then((derived) => {
        if (get().primaryId === id && get().url === sub.url) {
          set({ deviceHwid: derived });
        }
      })
      .catch(() => {});
    // Sync legacy keyring keys на новый primary.
    void keyringSet(URL_KEYRING, sub.url);
    if (sub.hwid.trim()) void keyringSet(HWID_KEYRING, sub.hwid);
    else void keyringDelete(HWID_KEYRING);
    return receipt !== null;
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
      void keyringSet(`${URL_KEYRING}:${primaryId}`, url);
    }
    // Чувствительные значения пишем в Windows Credential Manager.
    // localStorage больше НЕ используется как источник правды — оставляем
    // пустым, чтобы старые версии приложения не подсунули устаревший URL.
    saveToStorage(URL_KEY, "");
    void keyringSet(URL_KEYRING, url);
  },
  setHwid: (hwid) => {
    set({ hwid });
    // 0.3.0: sync с primary subscription тоже.
    const primaryId = get().primaryId;
    if (primaryId) {
      set({
        subscriptions: get().subscriptions.map((s) =>
          s.id === primaryId ? { ...s, hwid } : s
        ),
      });
      if (hwid.trim()) void keyringSet(`${HWID_KEYRING}:${primaryId}`, hwid);
      else void keyringDelete(`${HWID_KEYRING}:${primaryId}`);
    }
    saveToStorage(HWID_KEY, "");
    if (hwid.trim()) {
      void keyringSet(HWID_KEYRING, hwid);
    } else {
      void keyringDelete(HWID_KEYRING);
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
    let scenarioASucceeded = false;
    if (ids.length > 0) {
      // Сценарий A
      const subs: Subscription[] = [];
      let allReadEmpty = true;
      for (const id of ids) {
        const u = await keyringGet(`${URL_KEYRING}:${id}`);
        const h = await keyringGet(`${HWID_KEYRING}:${id}`);
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
          hwid: h,
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
        set({ subscriptions: subs, primaryId: subs[0].id });
        // Legacy fields синхронизируются с primary (для callsites,
        // которые ещё читают `url`/`hwid`/`meta`).
        set({ url: subs[0].url, hwid: subs[0].hwid });
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
          `[subscription] все ${ids.length} ID вернули пустой keyring — индекс сохранён для retry, fallback на legacy URL_KEYRING`
        );
      }
    }
    if (!scenarioASucceeded && urlFromKeyring) {
      // Сценарий B — миграция legacy single-sub в multi
      // ИЛИ recovery после транзиентной ошибки Scenario A.
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
      const ok = await keyringSet(`${URL_KEYRING}:${id}`, urlFromKeyring);
      if (ok) {
        if (hwidFromKeyring) {
          await keyringSet(`${HWID_KEYRING}:${id}`, hwidFromKeyring);
        }
        set({ subscriptions: [sub], primaryId: id });
        // Если Scenario A создал устаревший индекс с мертвыми ids —
        // здесь его перезапишем валидным. Если index был пуст — тоже
        // OK, пишем новый.
        saveSubsIndex([id]);
      } else {
        // Keyring write упал — оставляем все state как есть, юзеру
        // придётся ввести URL заново. Это лучше чем сломать индекс.
        console.warn(
          "[subscription] Scenario B keyring write failed — Welcome будет показан, юзер введёт URL вручную"
        );
      }
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
  },

  async fetchSubscription() {
    const { url, hwid } = get();
    if (!url.trim()) return;

    // 0.3.0 auto-bootstrap: если subscriptions[] пуст, создаём primary
    // из текущего legacy URL ДО fetch'а. Иначе после fetch'а subscriptions[]
    // останется пустым (т.к. fetchSubscription не дёргает addSubscription),
    // и UI карточек подписок не покажется. Это случай:
    // - Welcome → setUrl(url) → fetchSubscription() (старый flow)
    // - юзер запустил app до миграции (legacy single-sub)
    // - keyring пуст, но Rust state имеет cached servers
    if (get().subscriptions.length === 0) {
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
      const urlOk = await keyringSet(`${URL_KEYRING}:${bootstrapId}`, url);
      if (urlOk) {
        if (hwid.trim()) {
          await keyringSet(`${HWID_KEYRING}:${bootstrapId}`, hwid);
        }
        set({ subscriptions: [bootstrapSub], primaryId: bootstrapId });
        saveSubsIndex([bootstrapId]);
      } else {
        // Keyring недоступен — ставим только in-memory state без
        // index'а. На след. старте Welcome заново; индекс не сломан.
        set({ subscriptions: [bootstrapSub], primaryId: bootstrapId });
        console.warn(
          "[subscription] bootstrap keyring write failed — index НЕ обновлён, данные не переживут restart"
        );
      }
    }

    const primaryId = get().primaryId;
    if (primaryId) await get().fetchSubscriptionById(primaryId);
  },

  async loadCached() {
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
            set({ subscriptions: [sub], primaryId: id });
            saveSubsIndex([id]);
            await keyringSet(`${URL_KEYRING}:${id}`, url);
            if (sub.hwid.trim()) {
              await keyringSet(`${HWID_KEYRING}:${id}`, sub.hwid);
            }
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
    // Capture the backend identity before any await. The mutex may be held by
    // an in-flight connect; reading primaryId inside that mutex would see null
    // after local reset and silently skip the required tombstone.
    const runtimePrimaryId = get().primaryId;
    // 0.2.4: полное удаление подписки. Если VPN активен — сначала
    // тушим (без него выбранный сервер «висит» в ядре, но в UI его
    // уже нет). После очистки экран должен вернуться к Welcome.
    const vpn = useVpnStore.getState();
    if (vpn.status !== "stopped") {
      await vpn.disconnect();
      requireVpnStopped("subscription deletion");
    }

    // Runtime snapshot живёт в памяти; per-subscription offline cache ниже
    // удаляется отдельными DPAPI-командами вместе с keyring credentials.
    // Publish and await the empty generation before clearing primaryId or
    // credentials. A failure aborts local deletion with the exact IPC error.
    await publishRequiredTombstone(runtimePrimaryId, clearRustRuntime);

    // 1. Удаляем URL и override-HWID из keyring (legacy + per-id для
     //    каждой подписки в multi-state).
    await Promise.all([
      keyringDelete(URL_KEYRING),
      keyringDelete(HWID_KEYRING),
      ...get().subscriptions.flatMap((s) => [
        keyringDelete(`${URL_KEYRING}:${s.id}`),
        keyringDelete(`${HWID_KEYRING}:${s.id}`),
        deleteEncryptedCache(s.id),
      ]),
    ]);

    // 2. Чистим persisted selectedIndex, last-fetched timestamp и
     //    multi-subscription index.
    try {
      localStorage.removeItem(LAST_FETCH_KEY);
      localStorage.removeItem("kwikproxy-secure.selectedServerName.v1");
      localStorage.removeItem(SUBS_INDEX_KEY);
      localStorage.removeItem(SERVERS_CACHE_KEY);
    } catch {
      // приватный режим — игнорируем
    }
    // 3. Сбрасываем in-memory state (multi + legacy) и selectedIndex в vpnStore.
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

    showToast({
      kind: "success",
      title: i18n.t("toast.subscriptionDeleted.title"),
      message: i18n.t("toast.subscriptionDeleted.message"),
      durationMs: 4000,
    });
  },
}));
