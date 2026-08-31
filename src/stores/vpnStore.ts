import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import i18n from "../i18n";
import { useSettingsStore } from "./settingsStore";
import { useSubscriptionStore } from "./subscriptionStore";
import { showToast } from "./toastStore";
import {
  AsyncMutex,
  AsyncSingleFlight,
  AttemptEpoch,
  isSameConnectionSelection,
  stopAndReconcile,
  type BackendStopResult,
} from "../lib/asyncControl";

/** Anti-DPI опции в формате camelCase, который Rust десериализует через
 *  serde(rename_all = "camelCase") в struct AntiDpiOptions. */
type AntiDpiPayload = {
  fragmentation: boolean;
  fragmentationPackets: string;
  fragmentationLength: string;
  fragmentationInterval: string;
  noises: boolean;
  noisesType: string;
  noisesPacket: string;
  noisesDelay: string;
  serverResolve: boolean;
  serverResolveDoH: string;
  serverResolveBootstrap: string;
};

/** Effective anti-DPI с учётом override-логики 8.C: если пользователь
 *  не трогал, используются значения из заголовков подписки. Возвращает
 *  null если все три механизма выключены — connect передаст None. */
function buildEffectiveAntiDpi(): AntiDpiPayload | null {
  const s = useSettingsStore.getState();
  const meta = useSubscriptionStore.getState().meta;
  const touched = s.antiDpiTouched;

  // Boolean: from header if untouched и заголовок прислал значение,
  // иначе from settings.
  const pickBool = (
    metaVal: boolean | null | undefined,
    settingVal: boolean
  ): boolean =>
    !touched && metaVal != null ? metaVal : settingVal;
  const pickStr = (
    metaVal: string | null | undefined,
    settingVal: string
  ): string => (!touched && metaVal ? metaVal : settingVal);

  const result: AntiDpiPayload = {
    fragmentation: pickBool(meta?.fragmentationEnable, s.antiDpiFragmentation),
    fragmentationPackets: pickStr(
      meta?.fragmentationPackets,
      s.antiDpiFragmentationPackets
    ),
    fragmentationLength: pickStr(
      meta?.fragmentationLength,
      s.antiDpiFragmentationLength
    ),
    fragmentationInterval: pickStr(
      meta?.fragmentationInterval,
      s.antiDpiFragmentationInterval
    ),
    noises: pickBool(meta?.noisesEnable, s.antiDpiNoises),
    noisesType: pickStr(meta?.noisesType, s.antiDpiNoisesType),
    noisesPacket: pickStr(meta?.noisesPacket, s.antiDpiNoisesPacket),
    noisesDelay: pickStr(meta?.noisesDelay, s.antiDpiNoisesDelay),
    serverResolve: pickBool(
      meta?.serverResolveEnable,
      s.antiDpiServerResolve
    ),
    serverResolveDoH: pickStr(meta?.serverResolveDoH, s.antiDpiResolveDoH),
    serverResolveBootstrap: pickStr(
      meta?.serverResolveBootstrap,
      s.antiDpiResolveBootstrap
    ),
  };

  // Если ни один механизм не включён — не платим за лишний JSON-сериализатор
  // в Rust, передаём null (anti_dpi: None).
  if (!result.fragmentation && !result.noises && !result.serverResolve) {
    return null;
  }
  return result;
}

export type VpnStatus =
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "error";

export type VpnMode = "proxy" | "tun";

type ConnectResult = {
  socks_port: number;
  http_port: number;
  server_name: string;
  /** SOCKS5 username/password для LAN-режима (этап 9.G).
   *  Заполнено только когда LAN активен; UI показывает их с copy-кнопкой. */
  socks_username?: string | null;
  socks_password?: string | null;
};

type VpnState = {
  status: VpnStatus;
  errorMessage: string | null;
  mode: VpnMode;
  selectedIndex: number | null;
  socksPort: number | null;
  httpPort: number | null;
  /** SOCKS5 креды показываемые в LAN-режиме (этап 9.G).
   *  null когда LAN выключен или connect ещё не выполнялся. */
  socksUsername: string | null;
  socksPassword: string | null;
  /** Unix-ms момента успешного connect — для таймера сессии в дашборде.
   *  null когда не подключён. После рефреша «живого» соединения без
   *  известного старта подставляем текущее время (best-effort). */
  connectedAt: number | null;

  setMode: (mode: VpnMode) => void;
  selectServer: (index: number) => void;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  refresh: () => Promise<void>;
};

/** Persist выбранного сервера: сохраняем `(subscriptionId, name)` пару.
 *  - serverName — устойчиво к смене порядка серверов в подписке (refetch
 *    пересоздаёт массив, индексы сбиваются)
 *  - subscriptionId — устойчиво к multi-subscription (две подписки
 *    могут содержать сервер с одинаковым именем «Germany», без id
 *    мы бы выбирали не тот)
 *  Сохраняется при `selectServer()`. Восстанавливается через
 *  findSelectedIndexByName в subscriptionStore (loadCached / fetchSubscription). */
const SELECTED_NAME_KEY = "kwikproxy-secure.selectedServerName.v1";
const SELECTED_SUB_KEY = "kwikproxy-secure.selectedSubscriptionId.v1";

/** Нормализация имени для сравнения: trim + collapse повторных пробелов
 *  + lowercase. Нужно потому что разные парсеры формируют одно и то же
 *  имя по-разному: например mihomo пишет «🇪🇺  Fastest» с двумя
 *  пробелами, sing-box — «🇪🇺 Fastest» с одним. Без нормализации
 *  findSelectedIndexByName промахивается при смене engine. */
const normalizeName = (name: string): string =>
  name.trim().replace(/\s+/g, " ").toLowerCase();

const saveSelectedName = (name: string | null, subId: string | null) => {
  try {
    if (name) localStorage.setItem(SELECTED_NAME_KEY, name);
    else localStorage.removeItem(SELECTED_NAME_KEY);
    if (subId) localStorage.setItem(SELECTED_SUB_KEY, subId);
    else localStorage.removeItem(SELECTED_SUB_KEY);
  } catch {
    // приватный режим — игнорируем
  }
};

export const loadSelectedName = (): string | null => {
  try {
    return localStorage.getItem(SELECTED_NAME_KEY);
  } catch {
    return null;
  }
};

export const loadSelectedSubId = (): string | null => {
  try {
    return localStorage.getItem(SELECTED_SUB_KEY);
  } catch {
    return null;
  }
};

/** Найти индекс сохранённого сервера в новом массиве. Логика поиска:
 *   1. Если saved subscriptionId есть — ищем сначала точный match по
 *      (name + subscriptionId). Это правильное поведение для multi-sub:
 *      «Germany» из подписки A не выберется при выбранной из B.
 *   2. Fallback на просто name (для legacy single-sub state, где
 *      subscriptionId ещё не tag'ался).
 *  Сравнение имён через normalizeName (trim + collapse spaces + lowercase). */
export const findSelectedIndexByName = (
  servers: { name: string; subscriptionId?: string }[]
): number => {
  const saved = loadSelectedName();
  if (!saved) return -1;
  const target = normalizeName(saved);
  const savedSubId = loadSelectedSubId();
  if (savedSubId) {
    const exact = servers.findIndex(
      (s) =>
        s.subscriptionId === savedSubId && normalizeName(s.name) === target
    );
    if (exact >= 0) return exact;
  }
  // Fallback: поиск только по имени.
  return servers.findIndex((s) => normalizeName(s.name) === target);
};

/** Идёт ли уже цепочка авто-переподключения при смене сервера. Защищает
 *  от гонки: быстрые клики по разным серверам не должны запускать
 *  несколько параллельных disconnect→connect. Module-level (а не в state)
 *  — это чисто внутренний мьютекс, перерисовка UI на него не нужна. */
let switchingServer = false;
const connectSingleFlight = new AsyncSingleFlight();
const connectionLifecycle = new AsyncMutex();
const connectionAttempts = new AttemptEpoch();

class ConnectFailure extends Error {
  constructor(
    message: string,
    readonly toastTitle: string,
    readonly toastKind: "warning" | "error" = "error"
  ) {
    super(message);
    this.name = "ConnectFailure";
  }
}

class ConnectCancelled extends Error {
  constructor() {
    super("Connection attempt was cancelled");
    this.name = "ConnectCancelled";
  }
}

class BackendCleanupFailure extends Error {
  constructor(
    message: string,
    readonly cleanupError: unknown,
    readonly observedRunning: boolean | null,
    readonly connectedResult: ConnectResult | null = null
  ) {
    super(`${message}: ${String(cleanupError)}`);
    this.name = "BackendCleanupFailure";
  }
}

const cleanupBackendConnection = (): Promise<BackendStopResult> =>
  stopAndReconcile(
    () => invoke("disconnect"),
    () => invoke<boolean>("is_xray_running")
  );

export const useVpnStore = create<VpnState>((set, get) => ({
  status: "stopped",
  errorMessage: null,
  mode: "proxy",
  selectedIndex: null,
  socksPort: null,
  httpPort: null,
  socksUsername: null,
  socksPassword: null,
  connectedAt: null,

  setMode: (mode) => {
    if (["starting", "stopping"].includes(get().status)) return;
    set({ mode });
  },
  selectServer: (index) => {
    if (["starting", "stopping"].includes(get().status)) return;
    const prev = get().selectedIndex;
    set({ selectedIndex: index });
    // Persist (subscriptionId, name) пары для восстановления после
    // refetch / restart app. 0.3.0: subscriptionId различает серверы
    // с одинаковыми именами из разных подписок.
    const servers = useSubscriptionStore.getState().servers;
    const sel = servers[index];
    saveSelectedName(sel?.name ?? null, sel?.subscriptionId ?? null);
    // 0.1.1 / Bug 6: авто-reconnect при смене сервера. Раньше после
    // выбора другого сервера пользователь должен был вручную
    // disconnect → connect — счёт-фактура «два клика на смену сервера»
    // была неудобной.
    //
    // Теперь: если VPN активен и индекс реально сменился, мы атомарно
    // переподключаемся к новому серверу. Если был только что error /
    // stopping / starting — не трогаем (пусть пользователь дождётся
    // финального состояния).
    if (prev !== null && prev !== index && get().status === "running") {
      // Если цепочка переподключения уже идёт — не плодим вторую.
      // selectedIndex уже обновлён выше, и do-while ниже подхватит
      // самый свежий выбор (подключимся к последнему, что ты выбрал).
      if (switchingServer) return;
      void (async () => {
        switchingServer = true;
        try {
          showToast({
            kind: "info",
            title: i18n.t("vpnStore.switching.title"),
            message: i18n.t("vpnStore.switching.message"),
            durationMs: 3000,
          });
          // disconnect → пауза 200мс на снятие WFP/маршрутов → connect.
          // Без паузы новый коннект может не дождаться очистки и увидеть
          // «old proxy still active». Цикл повторяется, если за время
          // переподключения пользователь выбрал ещё другой сервер.
          let target: number | null;
          do {
            target = get().selectedIndex;
            await get().disconnect();
            await new Promise((r) => setTimeout(r, 200));
            await get().connect();
          } while (get().selectedIndex !== target);
        } catch (error) {
          console.warn("[vpn] server switch stopped:", error);
        } finally {
          switchingServer = false;
        }
      })();
    }
  },

  async refresh() {
    const observedStatus = get().status;
    if (observedStatus === "starting" || observedStatus === "stopping") return;
    const observedAttempt = connectionAttempts.current();
    try {
      await connectionLifecycle.runExclusive(async () => {
        const running = await invoke<boolean>("is_xray_running");
        if (!connectionAttempts.isCurrent(observedAttempt)) return;
        set((s) => ({
          status: running ? "running" : "stopped",
          errorMessage: null,
          socksPort: running ? s.socksPort : null,
          httpPort: running ? s.httpPort : null,
          // Живое соединение без известного connectedAt (рестарт app при
          // активном VPN) — стартуем таймер с текущего момента.
          connectedAt: running ? s.connectedAt ?? Date.now() : null,
        }));
      });
    } catch (e) {
      if (!connectionAttempts.isCurrent(observedAttempt)) return;
      set({ status: "error", errorMessage: String(e) });
    }
  },

  connect() {
    return connectSingleFlight.run(async () => {
      const attempt = connectionAttempts.begin();
      let backendStarted = false;
      let backendCleaned = false;
      const { selectedIndex, mode } = get();
      set({ status: "starting", errorMessage: null });

      try {
        if (selectedIndex === null) {
          throw new ConnectFailure(
            i18n.t("vpnStore.connectError.noSelection"),
            i18n.t("vpnStore.staleSelection.title"),
            "warning"
          );
        }
        // Защита от устаревшего индекса: после смены/удаления подписки
        // selectedIndex мог остаться от прежнего (более длинного) списка.
        // Без проверки в Rust ушёл бы out-of-range / чужой сервер.
        const servers = useSubscriptionStore.getState().servers;
        if (selectedIndex < 0 || selectedIndex >= servers.length) {
          set({ selectedIndex: null });
          throw new ConnectFailure(
            i18n.t("vpnStore.staleSelection.message"),
            i18n.t("vpnStore.staleSelection.title"),
            "warning"
          );
        }

        // 9.C: проверяем routing-таблицу на чужие default/half-default
        // маршруты до запуска connect. Если такие есть — это другой
        // активный VPN, и наш TUN/прокси конфликтует с ним. Не запускаем.
        let conflicts: string[] = [];
        try {
          conflicts = await invoke<string[]>("check_routing_conflicts");
        } catch {
          // Best-effort preflight: a Win32 inspection failure must not block
          // a connection whose backend still performs its own validation.
        }
        if (Array.isArray(conflicts) && conflicts.length > 0) {
          const list = conflicts.join(", ");
          throw new ConnectFailure(
            i18n.t("vpnStore.vpnConflict.message", { list }),
            i18n.t("vpnStore.vpnConflict.title"),
            "warning"
          );
        }
        if (!connectionAttempts.isCurrent(attempt)) {
          throw new ConnectCancelled();
        }

        const allowLan = useSettingsStore.getState().allowLan;
        const tunMasking = useSettingsStore.getState().tunMasking;
        const killSwitch = useSettingsStore.getState().killSwitch;
        const killSwitchStrict =
          useSettingsStore.getState().killSwitchStrict;
        const autoApplyMinimalRuRules =
          useSettingsStore.getState().autoApplyMinimalRuRules;
        const defaultTraffic = useSettingsStore.getState().defaultTraffic;
        const dnsLeakProtection =
          useSettingsStore.getState().dnsLeakProtection;
        const forceDisableIpv6 =
          useSettingsStore.getState().forceDisableIpv6;
        // #4: IPv6 внутри ядра. #3: пользовательские DNS — парсим свободный
        // текст (запятая/пробел/перевод строки) в массив, пустые отбрасываем.
        const ipv6 = useSettingsStore.getState().ipv6;
        const customDns = useSettingsStore
          .getState()
          .customDns.split(/[\s,]+/)
          .map((x) => x.trim())
          .filter((x) => x.length > 0);
        // Mux выпилен вместе с sing-box (был его фичей; Mihomo mux не применяет).
        const antiDpi = buildEffectiveAntiDpi();
        // 8.D: per-process правила. Подаём в Rust в camelCase
        // (`exe`/`action`/`comment`); serde на стороне Rust десериализует
        // в `AppRule`. Если правил нет — пустой массив, ветка mihomo
        // воспримет его как «no PROCESS-NAME правил» и не включит
        // дорогой `find-process-mode: always`.
        const appRules = useSettingsStore.getState().appRules;
        // 0.3.0 multi-subscription: engine берём из подписки-источника
        // выбранного сервера через `getEffectiveEngine()`. Этот метод
        // соблюдает приоритет: per-subscription engineOverride →
        // header X-Kwik-Engine → settings.engine (fallback).
        // Если у server'а нет subscriptionId (legacy state до миграции) —
        // используем primary, иначе settings.engine.
        const subStore = useSubscriptionStore.getState();
        const selectedServer = subStore.servers[selectedIndex];
        const selectionSnapshot = {
          primaryId: subStore.primaryId,
          selectedIndex,
          server: selectedServer,
        };
        const sourceId = selectedServer?.subscriptionId ?? subStore.primaryId;
        // Mihomo-only: движок всегда Mihomo. getEffectiveEngine тоже возвращает
        // "mihomo"; передаём его в connect для совместимости IPC-контракта.
        const engine = sourceId
          ? subStore.getEffectiveEngine(sourceId)
          : "mihomo";
        // Obtain an exact backend commit receipt immediately before connect.
        // Rust validates epoch + primary id + generation atomically when reading
        // the indexed server, so a renderer reload or overtaking primary change
        // cannot connect a server from another subscription.
        const result = await subStore.withPrimaryRuntimeReady(
          async (runtimeReceipt) => {
            const currentSubscriptions = useSubscriptionStore.getState();
            if (
              runtimeReceipt.primaryId !== selectionSnapshot.primaryId ||
              !isSameConnectionSelection(selectionSnapshot, {
                primaryId: currentSubscriptions.primaryId,
                selectedIndex: get().selectedIndex,
                server: currentSubscriptions.servers[selectedIndex],
              })
            ) {
              throw new ConnectFailure(
                i18n.t("vpnStore.connectError.selectionChanged"),
                i18n.t("vpnStore.connectError.title")
              );
            }
            return await connectionLifecycle.runExclusive(async () => {
              if (!connectionAttempts.isCurrent(attempt)) {
                throw new ConnectCancelled();
              }
              backendStarted = true;
              const response = await invoke<ConnectResult>("connect", {
                serverIndex: selectedIndex,
                subscriptionEpoch: runtimeReceipt.sessionEpoch,
                subscriptionId: runtimeReceipt.primaryId,
                subscriptionGeneration: runtimeReceipt.generation,
                mode,
                engine,
                allowLan,
                antiDpi,
                tunMasking,
                killSwitch,
                dnsLeakProtection,
                killSwitchStrict,
                forceDisableIpv6,
                autoApplyMinimalRuRules,
                defaultTraffic,
                appRules,
                ipv6,
                customDns,
              });
              const afterConnect = useSubscriptionStore.getState();
              if (!connectionAttempts.isCurrent(attempt)) {
                const cleanup = await cleanupBackendConnection();
                backendCleaned = cleanup.stopped && cleanup.cleanupSucceeded;
                if (!backendCleaned) {
                  throw new BackendCleanupFailure(
                    "cancelled connection cleanup failed",
                    cleanup.error,
                    cleanup.observedRunning,
                    response
                  );
                }
                throw new ConnectCancelled();
              }
              if (
                runtimeReceipt.primaryId !== selectionSnapshot.primaryId ||
                !isSameConnectionSelection(selectionSnapshot, {
                  primaryId: afterConnect.primaryId,
                  selectedIndex: get().selectedIndex,
                  server: afterConnect.servers[selectedIndex],
                })
              ) {
                const selectionError = i18n.t(
                  "vpnStore.connectError.selectionChanged"
                );
                const cleanup = await cleanupBackendConnection();
                backendCleaned = cleanup.stopped && cleanup.cleanupSucceeded;
                if (!backendCleaned) {
                  throw new BackendCleanupFailure(
                    selectionError,
                    cleanup.error,
                    cleanup.observedRunning,
                    response
                  );
                }
                throw new ConnectFailure(
                  selectionError,
                  i18n.t("vpnStore.connectError.title")
                );
              }
              // The validation and visible state transition are synchronous:
              // disconnect/selection changes cannot interleave between them.
              set({
                status: "running",
                socksPort: response.socks_port,
                httpPort: response.http_port,
                socksUsername: response.socks_username ?? null,
                socksPassword: response.socks_password ?? null,
                connectedAt: Date.now(),
                errorMessage: null,
              });
              return response;
            });
          }
        );
        if (!result) {
          throw new ConnectFailure(
            i18n.t("vpnStore.connectError.selectionChanged"),
            i18n.t("vpnStore.connectError.title")
          );
        }
        // 8.F: для mihomo-движка применяем сохранённые пользователем
        // preferredMihomoNodes (см. ProxiesPanel — клик по ноде до connect
        // запоминает её как предпочитаемую). external-controller только
        // что поднялся — Rust сохранил endpoint в connect, теперь дёргаем
        // /proxies/:group для каждой записи. Ошибки глотаем — обычно это
        // означает что имя группы не совпадает (пользователь сменил
        // подписку). UI panel дальше работает в live-режиме как обычно.
        if (engine === "mihomo") {
          const preferred = useSettingsStore.getState().preferredMihomoNodes;
          for (const [group, name] of Object.entries(preferred)) {
            if (!connectionAttempts.isCurrent(attempt)) break;
            try {
              await invoke("mihomo_select_proxy", { group, name });
            } catch {
              // имя группы/ноды устарело — игнорируем
            }
          }
        }
      } catch (e) {
        if (!connectionAttempts.isCurrent(attempt) || e instanceof ConnectCancelled) {
          if (backendStarted && !backendCleaned) {
            try {
              const cleanup = await connectionLifecycle.runExclusive(
                cleanupBackendConnection
              );
              if (!cleanup.stopped || !cleanup.cleanupSucceeded) {
                console.warn(
                  "[vpn] cancelled connect cleanup left backend running:",
                  cleanup.error
                );
              }
            } catch (cleanupError) {
              console.warn("[vpn] cancelled connect cleanup failed:", cleanupError);
            }
          }
          return;
        }
        const message = e instanceof Error ? e.message : String(e);
        if (e instanceof BackendCleanupFailure && e.connectedResult) {
          set({
            status: e.observedRunning === true ? "running" : "error",
            socksPort:
              e.observedRunning === true ? e.connectedResult.socks_port : null,
            httpPort:
              e.observedRunning === true ? e.connectedResult.http_port : null,
            socksUsername:
              e.observedRunning === true
                ? e.connectedResult.socks_username ?? null
                : null,
            socksPassword:
              e.observedRunning === true
                ? e.connectedResult.socks_password ?? null
                : null,
            connectedAt: e.observedRunning === true ? Date.now() : null,
            errorMessage: message,
          });
        } else {
          set({ status: "error", errorMessage: message });
        }
        showToast({
          kind: e instanceof ConnectFailure ? e.toastKind : "error",
          title:
            e instanceof ConnectFailure
              ? e.toastTitle
              : i18n.t("vpnStore.connectError.title"),
          message,
          durationMs: 8000,
        });
      }
    });
  },

  async disconnect() {
    const disconnectAttempt = connectionAttempts.cancel();
    set({ status: "stopping", errorMessage: null });
    try {
      const cleanup = await connectionLifecycle.runExclusive(
        cleanupBackendConnection
      );
      if (!cleanup.stopped || !cleanup.cleanupSucceeded) {
        throw new BackendCleanupFailure(
          "VPN disconnect failed",
          cleanup.error,
          cleanup.observedRunning
        );
      }
      // A disconnect→connect caller (server switch, network change, reset)
      // must not accidentally join the cancelled single-flight promise.
      await connectSingleFlight.waitForIdle();
      if (!connectionAttempts.isCurrent(disconnectAttempt)) return;
      set({
        status: "stopped",
        socksPort: null,
        httpPort: null,
        socksUsername: null,
        socksPassword: null,
        connectedAt: null,
        errorMessage: null,
      });
    } catch (e) {
      if (connectionAttempts.isCurrent(disconnectAttempt)) {
        const message = e instanceof Error ? e.message : String(e);
        const positivelyRunning =
          e instanceof BackendCleanupFailure && e.observedRunning === true;
        set({
          status: positivelyRunning ? "running" : "error",
          ...(!positivelyRunning
            ? {
                socksPort: null,
                httpPort: null,
                socksUsername: null,
                socksPassword: null,
                connectedAt: null,
              }
            : {}),
          errorMessage: message,
        });
        showToast({
          kind: "error",
          title: i18n.t("vpnStore.connectError.title"),
          message,
          durationMs: 8000,
        });
      }
      throw e;
    }
  },
}));

/** Apply a newer main-window broadcast in a secondary renderer. */
export const applyExternalVpnStatus = (status: VpnStatus): void => {
  connectionAttempts.cancel();
  useVpnStore.setState({ status });
};
