# site-xray

**Рентген любого сайта одной командой.** Бинарник на Rust, который за пару секунд отвечает на один вопрос:

> Откуда с этого сайта проще и чище всего брать открытые данные — без браузера?

```bash
site-xray example.com
```

```
site-xray v0.1.0  2026-11-09 21:13 UTC
──────────────────────────────────────────────────────────────────────────────
habr.com  →  https://habr.com/ru/feed/ HTTP 200
  637 мс · 303 КБ · HTTP/2 · 1 редирект(ов) · https · TLS ✔
  “Публикации / Моя лента / Хабр”

◆ ВЕРДИКТ — откуда брать данные без браузера
  Лучший канал — sitemap.xml (https://habr.com/sitemap_articles1.xml): 27207 URL с lastmod,
  чистый XML и один GET вместо браузера.
  · sitemap.xml — 89/100: 27207 URL в 7 документах
  · RSS / Atom — 75/100: Все публикации подряд на Хабре — 40 записей, найден пробой
  · JSON API — 49/100: 7 кандидатов, ни один не ответил JSON
  · в sitemap есть lastmod → можно инкрементально обновлять выгрузку

  План
  1. Выгрузи список URL: curl -s https://habr.com/sitemap_articles1.xml | sed -n 's:.*<loc>\(.*\)</loc>.*:\1:p' > urls.txt
  2. Пройди urls.txt с конкурентностью 4–8 и паузами, кэшируй ответы по URL
  3. С каждого документа снимай JSON-LD (если есть) и OG-мету — это дешевее полноценного парсинга
  4. Инкремент держи по lastmod, если он есть, иначе по хешу контента

  Осторожно
  ! перед сайтом Qrator: лимиты и баны прилетают быстро
  ! robots.txt прячет: /search/, /ru/search/, /en/search/, /ru/users/*/followers/
  ! сайт просит crawl-delay 10

◆ КАНАЛЫ ДАННЫХ
 ★ 1. sitemap.xml              █████████░  89/100  27207 URL в 7 документах
 • 2. RSS / Atom               ████████░░  75/100  Все публикации подряд на Хабре — 40 записей
 • 3. JSON API                 █████░░░░░  49/100  7 кандидатов, ни один не ответил JSON
 • 4. Парсинг HTML (fallback)  ██░░░░░░░░  22/100  страница 303 КБ, text/html
 × 5. Служебные файлы          ──────────       —  нет
 × 6. JSON-LD (schema.org)     ──────────       —  микроразметки нет
```

## Что проверяется

| Блок | Что делает |
|---|---|
| **robots.txt** | правила Disallow/Allow, объявленные sitemap'ы, crawl-delay, что именно сайт прячет (`/admin`, `/search`, `/webapi`) |
| **sitemap.xml** | дерево: индекс → дочерние карты, `.gz`, подсчёт URL, наличие `lastmod`, расширения (image/video/news), обрезка больших карт помечается честно |
| **RSS / Atom** | фиды из `<link rel="alternate">` + проба `/feed`, `/rss.xml`, `/atom.xml`, `/index.xml`, `/?feed=rss2`; проверка по содержимому, а не по заголовку |
| **JSON-LD** | все блоки `application/ld+json`, валидация JSON, типы schema.org, набор полей |
| **JSON-эндпоинты** | прямой проб известных API (`/wp-json`, `/products.json`, `/openapi.json`, `/graphql`, `/index.json`, `/feed.json`…) **и** майнинг JS-бандлов: `fetch()`/`axios`/`xhr.open`, строки с `/api/`, `_next/data`, абсолютные API-хосты. Лучшие кандидаты реально дёргаются GET-ом и помечаются как подтверждённые, если ответ — JSON |
| **Защита** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy → оценка A–E; определение WAF/CDN (Cloudflare, Akamai, CloudFront, Fastly, Sucuri, Imperva, DataDome, Qrator, DDoS-Guard, Vercel, Netlify, Gcore…) и признаков антибота |
| **Стек** | сервер, фреймворк, CMS, e-commerce, headless CMS, аналитика, антибот — по заголовкам, cookie, `generator`, сигнатурам в HTML |
| **Служебные файлы** | `/.well-known/security.txt`, `/llms.txt`, `/humans.txt`, `/manifest.json` |
| **Вердикт** | все каналы взвешиваются 0–100, лучший выбирается с обоснованием, планом действий и предупреждениями (`robots.txt`, лимиты, антибот) |

## Установка

```bash
# из исходников
cd site-xray
cargo build --release
install -m 755 target/release/site-xray /usr/local/bin/site-xray
```

Готовый бинарник под Linux x86_64 — в `bin/site-xray`.

## Использование

```bash
site-xray habr.com                     # отчёт в терминале
site-xray https://example.com --json   # JSON для скриптов: jq '.verdict.headline'
site-xray shop.example --md report.md  # Markdown-отчёт в файл
site-xray example.com --all            # показать все найденные эндпоинты
```

| Опция | Смысл |
|---|---|
| `--json` | машиночитаемый отчёт (`jq .verdict`, `.js.endpoints[]`) |
| `--md [ФАЙЛ]` | сохранить Markdown (по умолчанию `site-xray-<host>.md`) |
| `-o, --out ФАЙЛ` | записать вывод в файл |
| `--all` | все эндпоинты, а не топ-10 |
| `--max-js N` | сколько JS-бандлов качать (по умолчанию 4) |
| `--no-js` / `--no-verify` | не качать бандлы / не проверять эндпоинты живыми запросами |
| `--timeout SEC` | таймаут запроса (по умолчанию 10) |
| `--cache-dir PATH` | каталог кэша ответов (по умолчанию `~/.cache/site-xray`) |
| `--no-cache` | отключить кэш |
| `--offline` | повторно построить отчёт только по кэшированным ответам |
| `--budget SEC` | общий лимит времени на дополнительные проверки (по умолчанию 8; JS-бандлы получают не больше 5) |
| `--insecure` | игнорировать ошибки TLS |
| `--no-color`, `-q` | без цветов / без печати отчёта |
| `SITE_XRAY_DEBUG=1` | тайминги по фазам в stderr |

Код возврата: `0` — отчёт построен, `1` — сайт недоступен, `2` — ошибка аргументов.

## Как считается вердикт

Каждый канал получает балл 0–100; недоступные каналы в рейтинг не попадают, но видны в таблице как `×`.

| Канал | Базовый балл | Бонусы | Штрафы |
|---|---|---|---|
| sitemap.xml | 68 | +8 за ≥100 URL, +9 за `lastmod`, +4 за единственный документ | −6 за >3 индексов, −3 за ошибки |
| RSS/Atom | 60 | +5 объявлен в `<link>`, +8 за ≥10 записей, +7 за свежесть | — |
| JSON API | 74 | +1 за каждые 6 баллов лучшего эндпоинта (подтверждённый JSON) | ниже 74, если JSON никто не подтвердил |
| JSON-LD | 52 | +4 за каждый тип schema.org, +6 за «содержательные» типы (Product, Article, Event…) | — |
| Служебные файлы | 20 | +4 за security.txt, +4 за llms.txt | — |
| HTML-парсинг | 20 | — | всегда последний вариант |

Логика простая: **подтверждённый JSON > sitemap > фид > JSON-LD > HTML**. Всё, что подтверждено живым запросом, весит больше догадок из бандлов.

## Проверено на реальных сайтах

* `ru.wordpress.org` → `JSON API 88/100`: `/wp-json/wp/v2/posts?per_page=2` отвечает JSON → план на WordPress REST
* `www.allbirds.com` → Shopify: `/products.json` отвечает JSON → план выгрузки витрины
* `nextjs.org` → `sitemap.xml 1146 URL` + `/openapi.json` + RSS на 88 записей
* `habr.com` → `sitemap.xml`, 27 000+ URL с `lastmod`, Qrator + crawl-delay 10
* `www.rbc.ru` → главная 401 с челленджем Qrator, но sitemap отдаётся: «бери данные оттуда»
* `ozon.ru` → 403 на главной: честный вывод «сайт закрыт для автоматики, нужен браузер»

Полные примеры — в [`docs/`](docs): `sample-terminal.txt`, `sample-habr.md`, `sample-shopify.md`.

## Скорость

Главная проверяется первой, дальше всё идёт параллельно: robots/extras/фиды/JS — одним блоком, sitemap-дерево — вторым.

* маленький сайт — 100–400 мс (`example.com` — 120 мс);
* типовой сайт — 1–3 с (`vercel.com`, магазин на Shopify);
* тяжёлый (40k+ URL в sitemap, 4 МБ JS, медленный CDN) — 4–8 с.

Жёсткие рамки, чтобы инструмент не «зависал»:

* бюджеты времени: `--budget` для всех проверок, отдельный (меньший) для JS-бандлов — недокачанное просто не попадает в отчёт;
* размеры ответов: бандл ≤1.2 МБ, документ sitemap ≤1.2–2 МБ, проба ≤96 КБ;
* таймауты проб — 3 с, любая фаза ограничена дедлайном; homepage качается первой и никогда не режется.

Хочешь быстрее — `--budget 4 --max-js 2`, хочешь полнее — `--budget 20 --max-js 12 --all`.

## Архитектура

```
src/
  main.rs          CLI, оркестрация фаз, сборка отчёта
  net.rs           HTTP-слой: ручные редиректы (цепочка в отчёте), cookie-jar,
                   лимиты тела, gzip-сниффинг, декодирование cp1251/UTF-8
  model.rs         структуры отчёта (serde): JSON-выход = эта модель
  scan_robots.rs   разбор robots.txt
  scan_sitemap.rs  поиск и обход дерева sitemap (включая .gz и индексы)
  scan_feeds.rs    RSS/Atom/JSON Feed с проверкой содержимого
  scan_html.rs     meta, canonical, JSON-LD, feed-ссылки, inline-JSON (__NEXT_DATA__ и др.)
  scan_js.rs       майнинг эндпоинтов в бандлах + их проверка живыми запросами
  scan_api.rs      проба известных API-путей (WP REST, Shopify, OpenAPI, GraphQL…)
  detect.rs        заголовки защиты, WAF/CDN, стек
  score.rs         баллы каналов, вердикт, план действий
  report.rs        рендер в терминал и Markdown
  ru.rs            русские склонения
```

Зависимости: `reqwest` (rustls), `scraper`, `regex`, `serde`, `flate2`, `encoding_rs`. Без async-рантайма в коде — обычные scoped-потоки, бинарник ~7 МБ.

Тесты: `cargo test` (разбор sitemap, классификация и скоринг эндпоинтов, склонения).

## CORS

Отчёт показывает `Access-Control-Allow-Origin` и связанные CORS-заголовки, полученные от главной страницы. Это предварительная подсказка: API может отвечать другими правилами, а доступ зависит от конкретного URL, `Origin`, метода и заголовков запроса.

## Кэш и офлайн-режим

Ответы сохраняются по URL в `~/.cache/site-xray` (или в каталоге из `--cache-dir`). Повторный запуск использует сохранённые ответы. `--offline` запрещает сетевые запросы и строит отчёт только из того, что уже есть в кэше; при отсутствии нужного ответа команда завершится сообщением о cache miss.

```sh
site-xray example.com
site-xray example.com --offline --md report.md
site-xray example.com --cache-dir ./cache --offline --json
site-xray example.com --no-cache
```
"# site-xray" 
