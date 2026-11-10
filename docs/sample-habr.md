# site-xray: habr.com

`https://habr.com/ru/feed/` · HTTP 200 · 646 мс · 306 КБ · сгенерировано 2026-11-09 21:20 UTC

## Вердикт

**Лучший канал — sitemap.xml (https://habr.com/sitemap_articles1.xml): 27207 URL с lastmod, чистый XML и один GET вместо браузера.**

Почему:

- sitemap.xml — 89/100: 27207 URL в 7 документах
- RSS / Atom — 75/100: Все публикации подряд на Хабре — 40 записей, найден пробой
- JSON API — 41/100: 4 кандидата, ни один не ответил JSON
- в sitemap есть lastmod → можно инкрементально обновлять выгрузку

План:

- Выгрузи список URL: curl -s https://habr.com/sitemap_articles1.xml | sed -n 's:.*<loc>\(.*\)</loc>.*:\1:p' > urls.txt
- Пройди urls.txt с конкурентностью 4–8 и паузами, кэшируй ответы по URL
- С каждого документа снимай JSON-LD (если есть) и OG-мету — это дешевее полноценного парсинга
- Инкремент держи по lastmod, если он есть, иначе по хешу контента

Осторожно:

- ⚠️ перед сайтом Qrator: лимиты и баны прилетают быстро
- ⚠️ robots.txt прячет: /search/, /ru/search/, /en/search/, /ru/users/*/followers/
- ⚠️ сайт просит crawl-delay 10

## Каналы данных

| # | Канал | Балл | Доступ | Резюме |
|---|---|---|---|---|
| 1 | sitemap.xml | 89 | ✔ | 27207 URL в 7 документах |
| 2 | RSS / Atom | 75 | ✔ | Все публикации подряд на Хабре — 40 записей, найден пробой |
| 3 | JSON API | 41 | ✔ | 4 кандидата, ни один не ответил JSON |
| 4 | Парсинг HTML (fallback) | 22 | ✔ | страница 306 КБ, text/html |
| 5 | Служебные файлы | — | ✖ | нет |
| 6 | JSON-LD (schema.org) | — | ✖ | микроразметки нет |

## Стек и защита

- **Server:** QRATOR
- **Технологии:** Google Analytics (gtag) (Аналитика), Яндекс.Метрика (Аналитика), reCAPTCHA (Антибот)
- **CDN/WAF:** Qrator
- **Заголовки:** HSTS ✔, CSP ✖, X-Frame-Options ✔, X-Content-Type-Options ✔, Referrer-Policy ✖, Permissions-Policy ✖ — оценка C (60/100)

## robots.txt

- 50 правил Disallow, 0 Allow, 4 пользовательских групп; crawl-delay: 10 — держи паузы между запросами
- Прячет: /search/, /ru/search/, /en/search/, /ru/users/*/followers/, /en/users/*/followers/, /ru/users/*/following/, /en/users/*/following/

## sitemap.xml

- 27207 URL, 7 документов, lastmod: да
  - `https://habr.com/sitemap.xml` — sitemapindex (24 URL)
  - `https://habr.com/sitemap_articles1.xml` — urlset (child) (5390 URL)
  - `https://habr.com/sitemap_articles2.xml` — urlset (child) (5385 URL)
  - `https://habr.com/sitemap_articles3.xml` — urlset (child) (5377 URL)
  - `https://habr.com/sitemap_articles4.xml` — urlset (child) (5358 URL)
  - `https://habr.com/sitemap_companies.xml` — urlset (child) (5258 URL)
  - `https://habr.com/sitemap_hubs.xml` — urlset (child) (439 URL)

## ФИДЫ

- `https://habr.com/rss` — 40 записей, rss  Mon, 09 Nov 2026 21:20:10 GMT

## JSON-LD

Нет валидных блоков.

## JSON API / эндпоинты

| Балл | Путь | Тип | Проверка | Найдено в |
|---|---|---|---|---|
| 28 | `https://habr.com/kek/v1/auth/habrahabr/?back=${t}&hl=${e}` | api | — | строка в бандле |
| 28 | `/kek/v1/auth/habrahabr/?back=${this.$route.path}&hl=${this.langOptions.hl}` | api | — | строка в бандле |
| 28 | `/kek/v1/auth/habrahabr-register/?back=${this.$route.path}&hl=${this.langOptions.hl}` | api | — | строка в бандле |
| 28 | `https://habr.com/kek/v1/auth/habrahabr/?back=${this.$route.path}&hl=${this.langOptions.hl}` | api | — | строка в бандле |

---

_Сгенерировано site-xray. Уважай robots.txt, ToS и лимиты сайта._
