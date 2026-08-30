# KwikProxy Secure

> VPN-клиент под Windows на ядре **Mihomo** (Clash Meta).
> Одна кнопка · подключение за ~1.5 секунды · ноль телеметрии ·
> открытый код · обновления только вручную.

«VPN одной кнопкой»: минимум вопросов к пользователю, максимум
совместимости с современными протоколами обхода блокировок.
Архитектура изначально готова к портированию на macOS, iOS и
Android — UI отделён от системного слоя.

[![release](https://img.shields.io/github/v/release/oda02/KwikProxy-Secure?label=release)](https://github.com/oda02/KwikProxy-Secure/releases/latest)
[![tauri](https://img.shields.io/badge/tauri-2-blue)](https://v2.tauri.app/)
[![mihomo](https://img.shields.io/badge/mihomo-1.19-orange)](https://github.com/MetaCubeX/mihomo)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Скачать

**[⬇ Последний релиз](https://github.com/oda02/KwikProxy-Secure/releases/latest)** —
скачай `Kwik_<версия>_x64-setup.exe`, запусти, installer сделает всё сам.

> **Security preview:** in-app updater и in-place upgrade отключены,
> пока не готов транзакционный цикл подписи, замены и rollback всех
> привилегированных бинарников. Новые релизы нужно скачивать вручную;
> перед установкой текущую версию нужно удалить явно.

---

## Что умеет

### Ядро и протоколы

Единственный движок — **Mihomo** (форк Clash Meta), стартует за доли
секунды, без «прогрева». Поддерживаемые протоколы:

**vless** (REALITY, Vision, XHTTP) · **vmess** · **trojan** ·
**shadowsocks** · **hysteria2** (+obfs salamander) · **TUIC** ·
**wireguard** · **AnyTLS**

### Подписки

| Панель | Что отдаёт | Как обрабатывается |
|---|---|---|
| **Marzban / Remnawave / 3x-ui** | clash YAML (по UA `clash-verge`) | парсер `parse_clash_yaml` |
| любая | полный mihomo-профиль с `proxy-groups` | passthrough целиком — группы, правила и url-test провайдера сохраняются |
| любая | base64 / raw-список URI (`vless://`, `vmess://`, …) | универсальный парсер URI |

- **Мульти-подписки** — несколько провайдеров в одном клиенте,
  переключение без повторной загрузки. Офлайн-кеш профилей проходит
  sanitizer и шифруется Windows DPAPI для текущего пользователя.
- **Server-driven UX** — провайдер может прислать дефолты через
  заголовки `X-Kwik-*` (тема, маршрутизация, объявления, ссылки
  поддержки). Пользовательская настройка всегда приоритетнее.
  Заголовки и deep-links — строгий whitelist: они не могут запускать
  процессы, читать файлы или скрывать настройки. Routing-директивы из
  подписки остаются pending: ничего не скачивается и не активируется без
  явного подтверждения в UI.
- **Drag-and-drop** ссылки подписки прямо в окно.

### Режимы подключения

- **Системный прокси** — мгновенный старт; inbound на loopback со
  **случайным портом** `[30000, 60000)` — сторонние процессы не
  детектят VPN по «известному порту».
- **TUN** — весь системный трафик через WinTUN-адаптер (built-in TUN
  Mihomo, `strict-route` против утечек). Имя всегда начинается с точного
  ownership-префикса **`kwikproxy-secure-`**, чтобы cleanup не затронул чужой VPN.
- **LAN** — доступ с других устройств сети, SOCKS5 защищён
  автогенерируемым логином/паролем.

### Защита

- **Kill switch** на Windows Filtering Platform — фильтры уровня ядра,
  5-уровневая защита от orphan-фильтров. DYNAMIC-сессия: при падении
  процесса фильтры снимаются сами — без интернета не останетесь.
- **DNS leak protection** — блок всего :53 мимо VPN-DNS.
- **Leak-test** (DNS / WebRTC / IPv6 / exit-IP) — автоматически после
  подключения или вручную.
- **Self-heal сети**: бэкап системного прокси, восстановление после
  крэша, orphan-cleanup TUN-адаптеров и маршрутов на старте, кнопка
  «восстановить сеть».
- **Детект конфликтующих VPN** перед подключением.

### Обход блокировок

- **uTLS-фингерпринт Chrome** (`global-client-fingerprint`) — TLS-рукопожатие
  неотличимо от браузера.
- **DoH с bootstrap** + DNS `fallback-filter` (анти-подмена ответов),
  split-DNS из routing-профиля, `fake-ip`.
- **Сниффер** SNI/Host/QUIC — точные доменные правила даже при
  «голых» IP-соединениях.
- **hysteria2 obfs salamander**, **ECH** passthrough.

### Маршрутизация

- **Routing-профили** geosite/geoip с авто-обновлением по расписанию —
  «зарубежное через VPN, домашнее напрямую».
- **Per-app правила** (`PROCESS-NAME` / `PROCESS-PATH`): «telegram через
  VPN, банк напрямую». Пикер запущенных процессов + **живой трафик по
  приложениям** прямо в настройках.
- **SSID auto-mode** — авто-отключение в доверенных Wi-Fi, включение
  в чужих.

### Интерфейс

- Современный лёгкий UI: дашборд соединения с live-графиками (трафик,
  стабильность пинга, квота, скорость), карточки локаций с
  пинг-тестом **до** подключения, SVG-флаги стран.
- **RU / EN**, темы dark / light / system.
- System tray + close-to-tray, **floating-окно** поверх всего со
  статусом и скоростью, глобальные хоткеи (`Ctrl+Shift+V` toggle,
  `Ctrl+Shift+M` показать/скрыть — настраиваются).
- Автозапуск с Windows, backup/restore настроек, onboarding-тур,
  экспорт диагностики одной кнопкой.
  URL/token подписки исключён из backup по умолчанию и добавляется только
  отдельным opt-in с предупреждением.

---

## Системные требования

- **Windows 10** 1909+ или **Windows 11** (x64)
- **WebView2** (ставится автоматически, в Windows 11 уже есть)
- **Admin-права один раз** — для установки helper-сервиса (WinTUN +
  kill switch). Helper работает как SYSTEM-service, само приложение —
  от обычного пользователя.

---

## Приватность

Kwik **не собирает телеметрию**, не отправляет crash-репорты «домой»
и не имеет remote-control механизмов. Все логи — локально:

- `%TEMP%\KwikProxy Secure\` — лог приложения и `mihomo-stderr.log`
- `C:\ProgramData\KwikProxy Secure\` — `helper.log`, `mihomo.log` (TUN-режим)

`x-hwid` выключен, пока пользователь сам его не включит. Вместо Windows
MachineGuid клиент выводит отдельный псевдоним для каждой HTTPS-подписки.
Хранилища и установщик изолированы namespace `KwikProxy Secure` /
`kwikproxy-secure.*`; данные и сервисы upstream/других клиентов не мигрируются и
не изменяются автоматически.

Подробный разбор — какие файлы пишутся, какие сетевые запросы и куда
уходят — в [PRIVACY.md](PRIVACY.md).

---

## Сообщить о проблеме

В Settings → «системное» есть кнопка **«выгрузить диагностику»** —
она собирает zip с логами (без приватных данных подписки). Приложи его
к [issue](https://github.com/oda02/KwikProxy-Secure/issues) с описанием:
что делал, что ожидал, что произошло. Кнопка «сообщить о проблеме»
в Settings → «о приложении» откроет форму с уже заполненным окружением.

---

## Сборка из исходников

```powershell
# Требуется Node.js 22+ и Rust stable (msvc).
git clone https://github.com/oda02/KwikProxy-Secure.git
cd KwikProxy
npm ci
npm run tauri:bundle
# Готовый installer: src-tauri/target/release/bundle/nsis/
```

Для разработки — `npm run tauri dev`. Helper-binary собирается
автоматически (`scripts/build-helper.mjs`, npm pre-script).

---

## Архитектура

```
/
├── src/                   # React 19 + TypeScript (strict) + Zustand
│   ├── components/        # SoftHome, TitleBar, SettingsPage, дашборд…
│   ├── stores/            # vpn / subscription / settings / toast / update
│   ├── lib/               # IPC-обёртки, deep-links, графики, флаги
│   └── locales/{ru,en}/   # i18n (react-i18next)
├── src-tauri/             # Rust (tokio)
│   ├── src/
│   │   ├── vpn/           # State machine, mihomo sidecar, TUN, leak-test
│   │   ├── config/        # Парсинг подписок, mihomo_config, routing, geofiles
│   │   ├── platform/      # Windows-специфика (изолирована для портирования)
│   │   ├── ipc/           # Tauri commands
│   │   └── bin/kwik_helper/  # SYSTEM-service: WFP kill switch, TUN
│   └── binaries/          # mihomo.exe, wintun.dll, geo*.dat
├── docs/RELEASE.md        # Релизный процесс
└── .github/workflows/     # CI: NSIS + latest.json на push тега v*.*.*
```

**State machine коннекта**: Idle → Ready → Connecting → Connected →
Ready. Движок и TUN-адаптер создаются при connect и закрываются при
disconnect — никаких фоновых процессов в простое.

**Helper-сервис** (`kwik-helper.exe`) работает под SYSTEM, общается
с приложением через named pipe `\\.\pipe\KwikProxySecure.Helper.v13` (с
access-check'ами), управляет WFP-фильтрами и спавнит mihomo для TUN.

---

## Релизный workflow

Релизы собираются GitHub Actions на push тега (подробнее —
[`docs/RELEASE.md`](docs/RELEASE.md)):

```powershell
# Bump версии: package.json, src-tauri/Cargo.toml, src-tauri/tauri.conf.json
git tag v0.X.Y -m "v0.X.Y — описание"
git push origin main --follow-tags
# CI собирает NSIS, подписывает ed25519, публикует release + latest.json.
```

CHANGELOG в release-нотах генерируется из git log от предыдущего тега.

---

## Roadmap

### Сделано
- ✅ Mihomo-only ядро: все актуальные протоколы, passthrough
  полных профилей провайдера (0.5.0)
- ✅ Kill switch (WFP) + 4-слойная защита сети от крэшей
- ✅ In-app updater fail-closed отключён; релизы публикуются CI/CD
- ✅ Routing-профили, split-DNS, per-app маршрутизация с live-трафиком
- ✅ Новый UI «soft»: дашборд, графики, мульти-подписки (0.4–0.7)
- ✅ Изолированный namespace KwikProxy Secure; без автоматической upstream-миграции

### Запланировано
- [ ] Code signing через [SignPath Foundation](https://signpath.org/about)
  (бесплатно для OSS) — уберёт SmartScreen-предупреждение
- [ ] Слияние нескольких подписок в один список
- [ ] Beta-канал обновлений
- [ ] macOS / Android / iOS порты

### Осознанно не делаем
- Телеметрию и crash-репортинг «домой» — никогда.
- Speed-test внутри клиента (кладёт канал провайдеров).
- Свой auto-failover для URI-подписок — это задача провайдера
  (url-test-группы из полного профиля работают как есть).

---

## Лицензия

[MIT](LICENSE) — используйте, форкайте, распространяйте.

## Благодарности

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — VPN-ядро
- [WireGuard wintun](https://www.wintun.net/) — TUN-драйвер
- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) — geosite / geoip
- [Tauri](https://v2.tauri.app/) — каркас приложения
- [flag-icons](https://github.com/lipis/flag-icons) — SVG-флаги
