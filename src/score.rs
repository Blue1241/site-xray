//! Turns raw findings into ranked "channels" and a human verdict:
//! which way to pull open data from this site without a browser.
use crate::model::*;
use crate::ru::count;

pub fn build(report: &Report, origin: &str) -> (Vec<Channel>, Verdict) {
    let mut channels: Vec<Channel> = Vec::new();

    // ---------- 1. sitemap ----------
    let sm = &report.sitemaps;
    {
        let mut score = 68i32;
        if sm.total_urls >= 100 {
            score += 8;
        }
        if sm.total_urls >= 5_000 {
            score += 4;
        }
        if sm.has_lastmod {
            score += 9;
        }
        if sm.docs.len() == 1 {
            score += 4;
        }
        if sm.nested_indexes > 3 {
            score -= 6;
        }
        if !sm.errors.is_empty() {
            score -= 3;
        }
        let score = score.clamp(0, 99) as u32;
        let primary = sm.primary().or_else(|| sm.docs.first());
        let mut details = Vec::new();
        if let Some(p) = primary {
            details.push(format!("{} — {} URL, lastmod: {}", p.url, sm.total_urls, if sm.has_lastmod { "да" } else { "нет" }));
        }
        if !sm.kinds.is_empty() {
            details.push(format!("расширения: {}", sm.kinds.join(", ")));
        }
        if sm.nested_indexes > 0 {
            details.push(format!("индексов sitemap: {} → документов: {}", sm.nested_indexes, sm.docs.len()));
        }
        channels.push(Channel {
            id: "sitemap".into(),
            name: "sitemap.xml".into(),
            score,
            available: sm.found(),
            summary: if sm.found() {
                format!("{} URL в {}", sm.total_urls, count(sm.docs.len(), "документе", "документах", "документах"))
            } else {
                "не найден".into()
            },
            details,
            how_to: if sm.found() {
                let u = primary.map(|p| p.url.clone()).unwrap_or_else(|| format!("{origin}/sitemap.xml"));
                vec![
                    format!("curl -s {u} | sed -n 's:.*<loc>\\(.*\\)</loc>.*:\\1:p' | head -50"),
                    "или: python3 -c \"import sys,re;print('\\n'.join(re.findall(r'<loc>(.*?)</loc>',sys.stdin.read())))\" < <(curl -s URL)".into(),
                ]
            } else {
                vec![]
            },
        });
    }

    // ---------- 2. RSS / Atom ----------
    {
        let best = report.feeds.iter().max_by_key(|f| (f.items.min(1), f.declared, f.items));
        let current_year = report.generated_at.get(0..4).unwrap_or("2026").to_string();
        let mut score = 60i32;
        if let Some(f) = best {
            if f.items >= 10 {
                score += 8;
            }
            if f.items >= 50 {
                score += 4;
            }
            if f.declared {
                score += 5;
            }
            if f.latest.as_ref().map(|l| l.contains(&current_year)).unwrap_or(false) {
                score += 7;
            }
        }
        let score = score.clamp(0, 96) as u32;
        let mut details = Vec::new();
        for f in report.feeds.iter().take(4) {
            details.push(format!(
                "{} [{}] {}{}",
                f.url,
                f.kind,
                count(f.items, "запись", "записи", "записей"),
                f.latest.as_ref().map(|l| format!(", свежее: {l}")).unwrap_or_default()
            ));
        }
        channels.push(Channel {
            id: "rss".into(),
            name: "RSS / Atom".into(),
            score,
            available: !report.feeds.is_empty(),
            summary: match best {
                Some(f) => format!(
                    "{} — {}{}",
                    f.title.clone().unwrap_or_else(|| "фид".into()),
                    count(f.items, "запись", "записи", "записей"),
                    if f.declared { ", объявлен в <link>" } else { ", найден пробой" }
                ),
                None => "фидов не найдено".into(),
            },
            details,
            how_to: best
                .map(|f| {
                    vec![
                        format!("curl -s {} | sed -n 's:.*<title>\\(.*\\)</title>.*:\\1:p' | head -20", f.url),
                        format!("python3 -c \"import feedparser,json;d=feedparser.parse('{}');print(json.dumps([e.title for e in d.entries],ensure_ascii=False,indent=1))\"", f.url),
                    ]
                })
                .unwrap_or_default(),
        });
    }

    // ---------- 3. JSON-LD ----------
    {
        let j = &report.jsonld;
        let mut score = if j.valid > 0 { 52i32 } else { 0 };
        score += 4 * j.types.len().min(8) as i32;
        let content_types = [
            "Product", "Article", "NewsArticle", "BlogPosting", "Recipe", "Event", "Organization",
            "LocalBusiness", "JobPosting", "Offer", "VideoObject", "FAQPage", "Course", "Review",
        ];
        if j.types.iter().any(|t| content_types.iter().any(|c| t.contains(c))) {
            score += 6;
        }
        let score = score.clamp(0, 94) as u32;
        channels.push(Channel {
            id: "jsonld".into(),
            name: "JSON-LD (schema.org)".into(),
            score,
            available: j.valid > 0,
            summary: if j.valid > 0 {
                format!("{}, типы: {}", count(j.valid, "блок", "блока", "блоков"), j.types.iter().take(6).cloned().collect::<Vec<_>>().join(", "))
            } else {
                "микроразметки нет".into()
            },
            details: if j.props.is_empty() {
                vec![]
            } else {
                vec![format!("поля: {}", j.props.iter().take(12).cloned().collect::<Vec<_>>().join(", "))]
            },
            how_to: if j.valid > 0 {
                vec![
                    "curl -s URL | python3 -c \"import sys,re,json;[print(json.dumps(json.loads(b),ensure_ascii=False,indent=1)[:1200]) for b in re.findall(r'<script type=\\\"application/ld\\+json\\\">(.*?)</script>',sys.stdin.read(),re.S)]\"".into(),
                ]
            } else {
                vec![]
            },
        });
    }

    // ---------- 4. JSON endpoints from JS bundles ----------
    {
        let eps = &report.js.endpoints;
        let verified: Vec<&Endpoint> = eps.iter().filter(|e| e.verified).collect();
        let graphql = eps.iter().find(|e| e.kind == "graphql");
        let mut score = if eps.is_empty() {
            0i32
        } else if !verified.is_empty() {
            // A confirmed JSON endpoint is the cleanest thing there is.
            74 + (eps.first().map(|e| e.score as i32).unwrap_or(0)) / 6
        } else {
            let mut s = 34i32;
            if let Some(best) = eps.first() {
                s += (best.score as i32) / 4;
            }
            s += (verified.len().min(3) * 4) as i32;
            s
        };
        if graphql.is_some() && verified.is_empty() {
            score += 8;
        }
        let score = score.clamp(0, 93) as u32;
        let mut details = Vec::new();
        for e in eps.iter().take(6) {
            details.push(format!(
                "{}  [{}] ×{}{}",
                e.path,
                e.kind,
                e.hits,
                match (&e.status, e.verified) {
                    (Some(s), true) => format!(" · HTTP {s} JSON ✔"),
                    (Some(s), false) => format!(" · HTTP {s}"),
                    _ => String::new(),
                }
            ));
        }
        channels.push(Channel {
            id: "json_api".into(),
            name: "JSON API".into(),
            score,
            available: !eps.is_empty(),
            summary: if eps.is_empty() {
                "в бандлах ничего не нашлось".into()
            } else {
                format!(
                    "{}, {}{}{}",
                    count(eps.len(), "кандидат", "кандидата", "кандидатов"),
                    if verified.is_empty() {
                        "ни один не ответил JSON".to_string()
                    } else {
                        format!("{} {} JSON", verified.len(), crate::ru::plural(verified.len(), "отвечает", "отвечают", "отвечают"))
                    },
                    if graphql.is_some() { ", есть GraphQL" } else { "" },
                    ""
                )
            },
            details,
            how_to: eps
                .iter()
                .filter(|e| !e.path.contains('{') && !e.path.contains('$'))
                .take(2)
                .map(|e| {
                    let p = if e.path.starts_with("http") { e.path.clone() } else { format!("{origin}{}", e.path) };
                    format!("curl -s -H 'Accept: application/json' '{p}' | head -c 2000")
                })
                .collect(),
        });
    }

    // ---------- 5. security.txt / llms.txt ----------
    {
        let st = report.security.extras.iter().find(|p| p.url.ends_with("security.txt") && p.status == 200);
        let llms = report.security.extras.iter().find(|p| p.url.ends_with("llms.txt") && p.status == 200);
        let mut score = 20u32;
        if st.is_some() {
            score += 4;
        }
        if llms.is_some() {
            score += 4;
        }
        let mut details = Vec::new();
        if st.is_some() {
            details.push("есть /.well-known/security.txt — сайт открыто приглашает к автоматизации".into());
        }
        if llms.is_some() {
            details.push("есть llms.txt — готовая выжимка для LLM".into());
        }
        channels.push(Channel {
            id: "meta".into(),
            name: "Служебные файлы".into(),
            score,
            available: st.is_some() || llms.is_some(),
            summary: if st.is_some() || llms.is_some() {
                "security.txt / llms.txt на месте".into()
            } else {
                "нет".into()
            },
            details,
            how_to: llms
                .map(|p| vec![format!("curl -s {}", p.url)])
                .or_else(|| st.map(|p| vec![format!("curl -s {}", p.url)]))
                .unwrap_or_default(),
        });
    }

    // ---------- 6. plain HTML scraping (always possible, least clean) ----------
    {
        let mut score = 20u32;
        if report.http.status == 200 && report.js.inline_states.is_empty() {
            score = 22;
        }
        channels.push(Channel {
            id: "html".into(),
            name: "Парсинг HTML (fallback)".into(),
            score,
            available: report.http.status == 200,
            summary: if report.http.status == 200 {
                format!("страница {} КБ, {}", report.http.size_bytes / 1024, report.http.content_type.clone().unwrap_or_else(|| "?".into()))
            } else {
                format!("главная отдала HTTP {}", report.http.status)
            },
            details: if report.js.inline_states.is_empty() {
                vec!["серверный HTML — данные придётся выковыривать селекторами".into()]
            } else {
                vec!["часть данных уже лежит в inline-JSON, парсить DOM не обязательно".into()]
            },
            how_to: vec![
                format!("curl -s {} | python3 -c \"import sys,re;h=sys.stdin.read();print(len(re.findall(r'<a ',h)),'ссылок')\"", report.http.final_url),
            ],
        });
    }

    channels.sort_by(|a, b| b.available.cmp(&a.available).then(b.score.cmp(&a.score)));

    // ---------- verdict ----------
    let best = channels.iter().find(|c| c.available).cloned();
    let mut reasons: Vec<String> = Vec::new();
    let mut cautions: Vec<String> = Vec::new();
    let mut plan: Vec<String> = Vec::new();

    let blocked = report.http.status != 200;
    let headline = if blocked {
        let signals: Vec<String> = report
            .security
            .bot_protection
            .iter()
            .filter(|b| !b.starts_with("главная отдала HTTP"))
            .cloned()
            .collect();
        let why = if signals.is_empty() {
            String::new()
        } else {
            format!(", {}", signals.join("; "))
        };
        match best.as_ref() {
            Some(c) if c.score >= 50 => format!(
                "Главная отдала HTTP {}{} — но канал «{}» доступен: {}, бери данные оттуда.",
                report.http.status, why, c.name, c.summary
            ),
            _ => format!(
                "Сайт закрыт для автоматики: главная вернула HTTP {}{}. Открытых каналов не видно — нужен реальный браузер или договорённость с владельцем.",
                report.http.status, why
            ),
        }
    } else {
        match best.as_ref().map(|c| c.id.as_str()) {
        Some("sitemap") => format!(
            "Лучший канал — sitemap.xml ({}): {} URL{}, чистый XML и один GET вместо браузера.",
            sm.primary().map(|p| p.url.clone()).unwrap_or_default(),
            sm.total_urls,
            if sm.has_lastmod { " с lastmod" } else { "" }
        ),
        Some("rss") => {
            let f = report.feeds.iter().max_by_key(|f| f.items);
            format!(
                "Лучший канал — RSS/Atom: {} записей{} с готовыми полями (title/link/date).",
                f.map(|f| f.items).unwrap_or(0),
                f.and_then(|f| f.latest.clone()).map(|l| format!(", свежее {l}")).unwrap_or_default()
            )
        }
        Some("jsonld") => format!(
            "Лучший канал — JSON-LD: {} типа schema.org уже размечены, бери поля прямо из HTML.",
            report.jsonld.types.len()
        ),
        Some("json_api") => {
            let first = report.js.endpoints.iter().find(|e| e.verified).or_else(|| report.js.endpoints.first());
            let probed = first
                .map(|e| e.evidence.contains("пробой") || e.evidence.contains("WordPress"))
                .unwrap_or(false);
            let origin_txt = if probed { "открытый JSON API" } else { "JSON API из бандлов" };
            format!(
                "Лучший канал — {}: {}{}.",
                origin_txt,
                first.map(|e| e.path.clone()).unwrap_or_default(),
                first.map(|e| if e.verified { " (реально отвечает JSON)" } else { " (нужно проверить)" }).unwrap_or("")
            )
        }
        Some(other) => format!("Сайт отдаёт данные только через HTML/служебные файлы ({other})."),
        None => "Сайт закрыт: данных в открытом виде не видно.".to_string(),
    }
    };

    for c in channels.iter().filter(|c| c.available).take(3) {
        reasons.push(format!("{} — {}/100: {}", c.name, c.score, c.summary));
    }
    if report.sitemaps.has_lastmod {
        reasons.push("в sitemap есть lastmod → можно инкрементально обновлять выгрузку".into());
    }
    if report.js.endpoints.iter().any(|e| e.verified) {
        reasons.push("часть JSON-эндпоинтов реально ответила JSON — это уже готовый API".into());
    }

    if !report.security.bot_protection.is_empty() {
        cautions.push(format!(
            "антибот активен ({}): делай паузы 1–2 с, шли обычный UA и не бомби эндпоинты",
            report.security.bot_protection.join("; ")
        ));
    }
    if !report.security.cdn_waf.is_empty() {
        cautions.push(format!(
            "перед сайтом {}: лимиты и баны прилетают быстро",
            report.security.cdn_waf.join(", ")
        ));
    }
    if let Some(r) = &report.robots {
        if r.disallow.iter().any(|d| d == "/") {
            cautions.push("robots.txt запрещает всё (Disallow: /) — уточни разрешение у владельца".into());
        } else if !r.notable.is_empty() {
            cautions.push(format!("robots.txt прячет: {}", r.notable.iter().take(4).cloned().collect::<Vec<_>>().join(", ")));
        }
        if let Some(cd) = &r.crawl_delay {
            cautions.push(format!("сайт просит crawl-delay {cd}"));
        }
    }
    if report.sitemaps.found() && !report.sitemaps.has_lastmod {
        cautions.push("в sitemap нет lastmod → дедуплицируй по URL и сам считай хеши страниц".into());
    }
    if report.jsonld.blocks > report.jsonld.valid && report.jsonld.blocks > 0 {
        cautions.push(format!(
            "{}/{} блоков JSON-LD невалидны — парсер должен быть терпимым",
            report.jsonld.blocks - report.jsonld.valid,
            report.jsonld.blocks
        ));
    }

    if blocked {
        plan.push("Сначала реши доступ: браузерный TLS-отпечаток и cookie-сессия (curl-impersonate, Playwright) — либо ищи API-поддомен".into());
    }
    match best.as_ref().map(|c| c.id.as_str()) {
        Some("sitemap") => {
            plan.push(format!(
                "Выгрузи список URL: curl -s {} | sed -n 's:.*<loc>\\(.*\\)</loc>.*:\\1:p' > urls.txt",
                sm.primary().map(|p| p.url.clone()).unwrap_or_default()
            ));
            plan.push("Пройди urls.txt с конкурентностью 4–8 и паузами, кэшируй ответы по URL".into());
            plan.push("С каждого документа снимай JSON-LD (если есть) и OG-мету — это дешевее полноценного парсинга".into());
            plan.push("Инкремент держи по lastmod, если он есть, иначе по хешу контента".into());
        }
        Some("rss") => {
            let u = report.feeds.first().map(|f| f.url.clone()).unwrap_or_default();
            plan.push(format!("Забери фид: curl -s {u} > feed.xml"));
            plan.push("Разбирай XML напрямую: title/link/pubDate/description — без HTML-парсера".into());
            plan.push("Опрашивай раз в 15–30 минут, дедуплицируй по GUID/link".into());
            plan.push("Если нужны полные тексты — дотягивай страницы из <link> по sitemap или напрямую".into());
        }
        Some("jsonld") => {
            plan.push(format!("Забирай {} и вытаскивай <script type=\"application/ld+json\">", report.http.final_url));
            plan.push("Склеивай @graph, приводи @type к своей схеме (Product/Article/Event…)".into());
            plan.push("Список страниц возьми из sitemap, иначе из меню/пагинации".into());
        }
        Some("json_api") => {
            let first = report.js.endpoints.first();
            let kind = first.map(|e| e.kind.clone()).unwrap_or_default();
            let p = first
                .map(|e| {
                    if e.path.starts_with("http") {
                        e.path.clone()
                    } else {
                        format!("{origin}{}", e.path)
                    }
                })
                .unwrap_or_default();
            match kind.as_str() {
                "wp-rest" => {
                    plan.push(format!("Список маршрутов API: curl -s {origin}/wp-json | jq '.routes | keys'"));
                    plan.push("Контент: /wp-json/wp/v2/posts?per_page=100&page=N (пагинация через X-WP-TotalPages)".into());
                    plan.push("Рубрики, метки, медиа: /wp-json/wp/v2/categories, /tags, /media".into());
                    plan.push("Уважай лимиты: 1–2 запроса в секунду, кэш на диск, свой UA".into());
                }
                "graphql" => {
                    plan.push(format!("Схема: curl -s '{p}' — проверь, что интроспекция не отключена"));
                    plan.push("Данные: POST {\"query\":\"{ posts(first:20){ nodes{ title slug date } } }\"}".into());
                    plan.push("Часто рядом открыт playground: /graphiql, /__graphql".into());
                }
                _ if first.map(|e| e.path.contains("/products.json")).unwrap_or(false) => {
                    plan.push(format!("Витрина Shopify: curl -s '{p}?limit=250&page=1' → массив products"));
                    plan.push("Пагинация: page=1..N, пока products не опустеет (limit максимум 250)".into());
                    plan.push("В каждом product: title, handle, variants[].price, images[].src, tags".into());
                }
                _ if first.map(|e| e.path.contains("openapi") || e.path.contains("swagger")).unwrap_or(false) => {
                    plan.push(format!("Скачай схему: curl -s '{p}' → openapi.json"));
                    plan.push("Сгенерируй клиент: openapi-generator-cli generate -i openapi.json -g python".into());
                    plan.push("Прогони по методам GET: это официальный контракт, а не догадки".into());
                }
                _ if first.map(|e| e.path.contains("index.json")).unwrap_or(false) => {
                    plan.push(format!("Забери индекс: curl -s '{p}' → список записей с url/title/date"));
                    plan.push("Индекс обновляется при публикации — опрашивай его, а страницы тяни по url".into());
                }
                _ => {
                    plan.push(format!("Проверь руками: curl -s '{p}' | head -c 2000"));
                    plan.push("Найди в бандле вызовы этого пути — там же обычно лежат параметры (limit/offset/page)".into());
                    plan.push("Лимитируй себя: 1 запрос в 1–2 с, кэш на диск, свой UA с контактом".into());
                }
            }
            if report.sitemaps.found() {
                plan.push("Полный список страниц добери из sitemap.xml и обходи его с паузами".into());
            } else {
                plan.push("Всё, что не отдаётся JSON-ом, добирай из HTML как вторичный канал".into());
            }
        }
        _ => {
            plan.push("Проверь alternate-домены и поддомены (api., m., old.) — открытые данные часто там".into());
            plan.push("Попробуй /robots.txt, /sitemap.xml, /feed вручную — иногда они просто не объявлены".into());
            plan.push("Если ничего нет — только HTML-парсинг с уважением к robots.txt и ToS".into());
        }
    }

    for (i, p) in plan.iter_mut().enumerate() {
        *p = format!("{}. {}", i + 1, p);
    }

    let verdict = Verdict {
        best: best.as_ref().map(|c| c.name.clone()),
        headline,
        reasons,
        cautions,
        plan,
    };
    (channels, verdict)
}
