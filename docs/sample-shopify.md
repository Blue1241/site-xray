# site-xray: www.allbirds.com

`https://www.allbirds.com/` · HTTP 200 · 91 мс · 700 КБ · сгенерировано 2026-11-09 21:20 UTC

## Вердикт

**Лучший канал — открытый JSON API: /products.json (реально отвечает JSON).**

Почему:

- JSON API — 88/100: 3 кандидата, 3 отвечают JSON
- sitemap.xml — 82/100: 1896 URL в 7 документах
- Служебные файлы — 24/100: security.txt / llms.txt на месте
- в sitemap есть lastmod → можно инкрементально обновлять выгрузку
- часть JSON-эндпоинтов реально ответила JSON — это уже готовый API

План:

- Витрина Shopify: curl -s 'https://www.allbirds.com/products.json?limit=250&page=1' → массив products
- Пагинация: page=1..N, пока products не опустеет (limit максимум 250)
- В каждом product: title, handle, variants[].price, images[].src, tags
- Полный список страниц добери из sitemap.xml и обходи его с паузами

Осторожно:

- ⚠️ перед сайтом Cloudflare: лимиты и баны прилетают быстро
- ⚠️ robots.txt прячет: /admin, /cart/, /*/cart/, /checkout

## Каналы данных

| # | Канал | Балл | Доступ | Резюме |
|---|---|---|---|---|
| 1 | JSON API | 88 | ✔ | 3 кандидата, 3 отвечают JSON |
| 2 | sitemap.xml | 82 | ✔ | 1896 URL в 7 документах |
| 3 | Служебные файлы | 24 | ✔ | security.txt / llms.txt на месте |
| 4 | Парсинг HTML (fallback) | 20 | ✔ | страница 700 КБ, text/html |
| 5 | RSS / Atom | — | ✖ | фидов не найдено |
| 6 | JSON-LD (schema.org) | — | ✖ | микроразметки нет |

## Стек и защита

- **Server:** cloudflare
- **Технологии:** Cloudflare (Сервер), Shopify (E-commerce), Google Tag Manager (Аналитика), Amplitude (Аналитика), reCAPTCHA (Антибот), hCaptcha (Антибот)
- **CDN/WAF:** Cloudflare
- **Заголовки:** HSTS ✔, CSP ✔, X-Frame-Options ✔, X-Content-Type-Options ✔, Referrer-Policy ✖, Permissions-Policy ✖ — оценка B (80/100)

## robots.txt

- 54 правил Disallow, 35 Allow, 2 пользовательских групп
- Sitemap: https://www.allbirds.com/sitemap.xml
- Прячет: /admin, /cart/, /*/cart/, /checkout, /*/checkout, /checkouts/, /*/checkouts/, /account, /*/account, /cart.js

## sitemap.xml

- 1896 URL, 7 документов, lastmod: да
  - `https://www.allbirds.com/sitemap.xml` — sitemapindex (8 URL)
  - `https://www.allbirds.com/sitemap_agentic_discovery.xml` — urlset (child) (1 URL)
  - `https://www.allbirds.com/sitemap_blogs_1.xml` — urlset (child) (2 URL)
  - `https://www.allbirds.com/sitemap_collections_1.xml?from=423410055&amp;to=274901696592` — urlset+image (child) (1000 URL)
  - `https://www.allbirds.com/sitemap_collections_2.xml?from=274901925968&amp;to=280946671696` — urlset (child) (349 URL)
  - `https://www.allbirds.com/sitemap_pages_1.xml?from=248230535&amp;to=94637621328` — urlset (child) (175 URL)
  - `https://www.allbirds.com/sitemap_products_1.xml?from=1878193471557&amp;to=7369944137808` — urlset+image (child) (369 URL)

## ФИДЫ

Не найдено.

## JSON-LD

Нет валидных блоков.

## JSON API / эндпоинты

| Балл | Путь | Тип | Проверка | Найдено в |
|---|---|---|---|---|
| 86 | `/products.json` | json | HTTP 200 JSON ✔ | Shopify /products.json · пробой стандартного пути |
| 78 | `/index.json` | json | HTTP 200 JSON ✔ | статический index.json · пробой стандартного пути |
| 66 | `/search.json?q=a` | json | HTTP 200 JSON ✔ | статистический search.json · пробой стандартного пути |

Inline-JSON на странице: 8× <script type="application/json">

---

_Сгенерировано site-xray. Уважай robots.txt, ToS и лимиты сайта._
