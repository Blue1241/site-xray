//! Security headers, WAF/CDN fingerprinting and tech-stack signatures.
use crate::model::{HeaderCheck, Probe, SecurityReport, TechHit};
use crate::net::{Net, Resp};

pub fn security(resp: &Resp, body_sample: &str, extras: Vec<Probe>) -> SecurityReport {
    let h = |n: &str| resp.header(n);
    let mut checks: Vec<HeaderCheck> = Vec::new();

    let hsts = h("strict-transport-security");
    checks.push(HeaderCheck {
        name: "HSTS".into(),
        present: hsts.is_some(),
        value: hsts.clone(),
        note: hsts.as_ref().map(|v| {
            if v.to_ascii_lowercase().contains("includesubdomains") {
                "max-age + includeSubDomains".into()
            } else {
                "нет includeSubDomains".to_string()
            }
        }),
    });

    let csp = h("content-security-policy");
    checks.push(HeaderCheck {
        name: "CSP".into(),
        present: csp.is_some(),
        value: csp.clone().map(|c| truncate(&c, 90)),
        note: csp.as_ref().map(|c| {
            let low = c.to_ascii_lowercase();
            if low.contains("unsafe-inline") || low.contains("unsafe-eval") {
                "есть unsafe-inline/unsafe-eval".into()
            } else {
                "строгая".to_string()
            }
        }),
    });

    let xfo = h("x-frame-options");
    let frame_ancestors = csp
        .as_ref()
        .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
        .unwrap_or(false);
    checks.push(HeaderCheck {
        name: "X-Frame-Options".into(),
        present: xfo.is_some() || frame_ancestors,
        value: xfo.clone(),
        note: if xfo.is_none() && frame_ancestors {
            Some("закрыто через CSP frame-ancestors".into())
        } else {
            None
        },
    });

    let xcto = h("x-content-type-options");
    checks.push(HeaderCheck {
        name: "X-Content-Type-Options".into(),
        present: xcto.as_deref().map(|v| v.eq_ignore_ascii_case("nosniff")).unwrap_or(false),
        value: xcto.clone(),
        note: None,
    });

    let rp = h("referrer-policy");
    checks.push(HeaderCheck {
        name: "Referrer-Policy".into(),
        present: rp.is_some(),
        value: rp.clone(),
        note: None,
    });

    let pp = h("permissions-policy");
    checks.push(HeaderCheck {
        name: "Permissions-Policy".into(),
        present: pp.is_some(),
        value: pp.clone().map(|v| truncate(&v, 70)),
        note: None,
    });

    let score = checks
        .iter()
        .take(5)
        .filter(|c| c.present)
        .count() as u32
        * 20
        + if pp.is_some() { 4 } else { 0 };
    let score = score.min(100);
    let grade = match score {
        95..=100 => "A",
        80..=94 => "B",
        60..=79 => "C",
        40..=59 => "D",
        _ => "E",
    };

    // ---- WAF / CDN ----
    let mut hays: Vec<String> = Vec::new();
    for (k, v) in resp.headers.iter() {
        hays.push(format!("{}: {}", k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_ascii_lowercase()));
    }
    let all_headers = hays.join("\n");
    let body = body_sample.to_ascii_lowercase();

    let waf_rules: &[(&str, &[&str])] = &[
        ("Cloudflare", &["cf-ray", "__cf_bm", "cf-mitigated", "cf-cache-status", "cloudflare"]),
        ("Cloudflare Pages", &["pages.dev", "x-served-by: cloudflare"]),
        ("Akamai", &["akamai-grn", "akamaighost", "x-akamai-"]),
        ("AWS CloudFront", &["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"]),
        ("Fastly", &["x-fastly", "fastly-io", "x-served-by: cache-"]),
        ("Sucuri", &["x-sucuri-id", "x-sucuri-cache", "sucuri"]),
        ("Imperva / Incapsula", &["x-iinfo", "incap_ses", "visid_incap"]),
        ("DataDome", &["x-datadome", "datadome"]),
        ("PerimeterX / HUMAN", &["x-px-", "_px"]),
        ("Qrator", &["qrator", "x-qrator"]),
        ("DDoS-Guard", &["ddos-guard", "__ddg"]),
        ("Vercel", &["x-vercel-id", "x-vercel-cache"]),
        ("Netlify", &["x-nf-request-id"]),
        ("Bunny CDN", &["bunnycdn", "x-bunny"]),
        ("Gcore / G-Core", &["x-gcore", "gcore"]),
        ("Yandex Cloud / CDN", &["x-yandex-", "yandexcloud"]),
        ("Selectel", &["selectel"]),
        ("Variti", &["variti", "x-variti"]),
        ("Reblaze", &["reblaze", "rbzid"]),
        ("Alibaba Cloud WAF", &["aliyungf", "x-alibaba"]),
    ];
    let mut cdn_waf: Vec<String> = Vec::new();
    for (name, needles) in waf_rules {
        if needles.iter().any(|n| all_headers.contains(n)) && !cdn_waf.contains(&name.to_string()) {
            cdn_waf.push(name.to_string());
        }
    }

    let mut bot_signals: Vec<String> = Vec::new();
    for (needle, label) in [
        ("just a moment", "страница Cloudflare «Just a moment…»"),
        ("checking your browser", "проверка браузера (JS-челлендж)"),
        ("attention required", "Cloudflare «Attention Required»"),
        ("captcha-delivery.com", "DataDome captcha"),
        ("_incapsula_resource", "Imperva JS-челлендж"),
        ("enable javascript and cookies to continue", "JS/cookie-челлендж"),
        ("ddos-guard", "DDoS-Guard челлендж"),
        ("qrator", "Qrator челлендж"),
    ] {
        if body.contains(needle) {
            bot_signals.push(label.to_string());
        }
    }
    if resp.status == 403 || resp.status == 429 || resp.status == 503 {
        bot_signals.push(format!("главная отдала HTTP {} — вероятно фильтр ботов", resp.status));
    }
    if body.contains("verify you are human") || body.contains("are you a robot") {
        bot_signals.push("страница проверки «вы не робот»".into());
    }

    let mut cookies: Vec<String> = Vec::new();
    for v in resp.headers.get_all("set-cookie").iter() {
        if let Ok(s) = v.to_str() {
            let name = s.split('=').next().unwrap_or("").trim().to_string();
            if !name.is_empty() && !cookies.contains(&name) {
                cookies.push(name);
            }
        }
    }
    cookies.truncate(12);

    SecurityReport {
        headers: checks,
        score,
        grade: grade.to_string(),
        cdn_waf,
        bot_protection: bot_signals,
        cookies,
        extras,
        tls: resp.final_url.starts_with("https"),
    }
}

pub fn extras(net: &Net, origin: &str) -> Vec<Probe> {
    let paths = [
        ("/.well-known/security.txt", "security.txt — контакт для отчётов об уязвимостях"),
        ("/llms.txt", "llms.txt — карта сайта для LLM/агентов"),
        ("/humans.txt", "humans.txt"),
        ("/manifest.json", "PWA-манифест"),
    ];
    let urls: Vec<String> = paths.iter().map(|(p, _)| format!("{origin}{p}")).collect();
    let res = net.get_many_t(&urls, 64 * 1024, 7, std::time::Duration::from_secs(3));
    let mut out = Vec::new();
    for ((p, note), r) in paths.iter().zip(res.into_iter()) {
        let (status, note) = match r {
            Ok(resp) => {
                let ct = resp.content_type().unwrap_or_default();
                let ok = resp.status == 200
                    && !(ct.contains("html") && resp.body.len() < 2000 && resp.text().to_ascii_lowercase().contains("<html"));
                (if ok { resp.status } else { 404 }, note.to_string())
            }
            Err(_) => (0, note.to_string()),
        };
        out.push(Probe {
            url: format!("{origin}{p}"),
            status,
            note,
        });
    }
    out
}

pub fn tech(resp: &Resp, html: &str, cookies: &[String]) -> Vec<TechHit> {
    let mut head = String::new();
    for (k, v) in resp.headers.iter() {
        head.push_str(&format!("{}: {}\n", k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_ascii_lowercase()));
    }
    let body = html.to_ascii_lowercase();
    let cookie_str = cookies.join(";").to_ascii_lowercase();
    let mut hits: Vec<TechHit> = Vec::new();
    let mut push = |name: &str, cat: &str, ev: &str| {
        if !hits.iter().any(|h| h.name == name) {
            hits.push(TechHit { name: name.into(), category: cat.into(), evidence: ev.into() });
        }
    };

    // Server / edge
    if let Some(s) = resp.header("server") {
        let low = s.to_ascii_lowercase();
        for (needle, name) in [
            ("nginx", "nginx"), ("apache", "Apache"), ("openresty", "OpenResty"),
            ("cloudflare", "Cloudflare"), ("gunicorn", "Gunicorn"), ("iis", "IIS"),
            ("caddy", "Caddy"), ("ddos-guard", "DDoS-Guard"), ("angie", "Angie"),
            ("liteSpeed", "LiteSpeed"), ("vercel", "Vercel"),
        ] {
            if low.contains(&needle.to_ascii_lowercase()) {
                push(name, "Сервер", "заголовок Server");
            }
        }
    }
    if let Some(p) = resp.header("x-powered-by") {
        let low = p.to_ascii_lowercase();
        if low.contains("php") { push("PHP", "Бэкенд", "X-Powered-By"); }
        if low.contains("asp.net") { push("ASP.NET", "Бэкенд", "X-Powered-By"); }
        if low.contains("express") { push("Express (Node.js)", "Бэкенд", "X-Powered-By"); }
        if low.contains("next.js") { push("Next.js", "Фреймворк", "X-Powered-By"); }
        if low.contains("nuxt") { push("Nuxt", "Фреймворк", "X-Powered-By"); }
    }

    // Frameworks / CMS via HTML + headers
    let rules: &[(&str, &str, &str)] = &[
        ("__next_data__", "Next.js", "Фреймворк"),
        ("/_next/static", "Next.js", "Фреймворк"),
        ("__nuxt", "Nuxt", "Фреймворк"),
        ("_nuxt/", "Nuxt", "Фреймворк"),
        ("__remixcontext", "Remix", "Фреймворк"),
        ("_sveltekit", "SvelteKit", "Фреймворк"),
        ("/_app/immutable", "SvelteKit", "Фреймворк"),
        ("astro-island", "Astro", "Фреймворк"),
        ("__gatsby", "Gatsby", "Фреймворк"),
        ("data-reactroot", "React", "JS-фреймворк"),
        ("__react", "React", "JS-фреймворк"),
        ("react.production.min.js", "React", "JS-фреймворк"),
        ("vue.js", "Vue", "JS-фреймворк"),
        ("vue.runtime", "Vue", "JS-фреймворк"),
        ("ng-version", "Angular", "JS-фреймворк"),
        ("wp-content", "WordPress", "CMS"),
        ("wp-includes", "WordPress", "CMS"),
        ("wp-json", "WordPress REST API", "API"),
        ("/sites/default/files", "Drupal", "CMS"),
        ("joomla", "Joomla", "CMS"),
        ("bitrix", "1C-Битрикс", "CMS"),
        ("tilda", "Tilda", "Конструктор"),
        ("modx", "MODX", "CMS"),
        ("cdn.shopify.com", "Shopify", "E-commerce"),
        ("woocommerce", "WooCommerce", "E-commerce"),
        ("opencart", "OpenCart", "E-commerce"),
        ("magento", "Magento", "E-commerce"),
        ("prestashop", "PrestaShop", "E-commerce"),
        ("/static/version", "Magento", "E-commerce"),
        ("wixstatic", "Wix", "Конструктор"),
        ("webflow", "Webflow", "Конструктор"),
        ("squarespace", "Squarespace", "Конструктор"),
        ("ghost/api", "Ghost", "CMS"),
        ("strapi", "Strapi", "Headless CMS"),
        ("contentful", "Contentful", "Headless CMS"),
        ("sanity.io", "Sanity", "Headless CMS"),
        ("datocms", "DatoCMS", "Headless CMS"),
        ("hubspot", "HubSpot", "Маркетинг"),
        ("googletagmanager.com/gtm.js", "Google Tag Manager", "Аналитика"),
        ("google-analytics.com", "Google Analytics", "Аналитика"),
        ("gtag/js", "Google Analytics (gtag)", "Аналитика"),
        ("mc.yandex.ru/metrika", "Яндекс.Метрика", "Аналитика"),
        ("top-fwz1.mail.ru", "Mail.ru top", "Аналитика"),
        ("vk.com/rtrg", "VK Pixel", "Аналитика"),
        ("jquery.min.js", "jQuery", "JS-библиотека"),
        ("jquery.js", "jQuery", "JS-библиотека"),
        ("jquery-3", "jQuery", "JS-библиотека"),
        ("bootstrap.min.css", "Bootstrap", "CSS"),
        ("bootstrap.css", "Bootstrap", "CSS"),
        ("bootstrap.bundle", "Bootstrap", "CSS"),
        ("tailwind", "Tailwind CSS", "CSS"),
        ("alpinejs", "Alpine.js", "JS-фреймворк"),
        ("htmx", "htmx", "JS-библиотека"),
        ("@hotwired/turbo", "Turbo", "JS-библиотека"),
        ("turbo.js", "Turbo", "JS-библиотека"),
        ("svelte-", "Svelte", "JS-фреймворк"),
        ("ember-cli", "Ember", "JS-фреймворк"),
        ("ember.js", "Ember", "JS-фреймворк"),
        ("amplitude", "Amplitude", "Аналитика"),
        ("segment.com", "Segment", "Аналитика"),
        ("sentry", "Sentry", "Мониторинг"),
        ("hotjar", "Hotjar", "Аналитика"),
        ("intercom", "Intercom", "Чат"),
        ("jivo", "Jivo", "Чат"),
        ("bitrix24", "Битрикс24", "Чат"),
        ("recaptcha", "reCAPTCHA", "Антибот"),
        ("hcaptcha", "hCaptcha", "Антибот"),
        ("smartcaptcha", "Yandex SmartCaptcha", "Антибот"),
        ("cloudflareinsights", "Cloudflare Web Analytics", "Аналитика"),
    ];
    for (needle, name, cat) in rules {
        if body.contains(needle) || head.contains(needle) {
            push(name, cat, "HTML/заголовки");
        }
    }
    for c in ["phpsessid", "_ym_uid", "bitrix", "laravel_session", "jsessionid", "_shopify", "cf_clearance", "__ddg"] {
        if cookie_str.contains(c) {
            match c {
                "phpsessid" => push("PHP", "Бэкенд", "cookie PHPSESSID"),
                "laravel_session" => push("Laravel", "Бэкенд", "cookie laravel_session"),
                "jsessionid" => push("Java (JSP/Spring)", "Бэкенд", "cookie JSESSIONID"),
                "bitrix" => push("1C-Битрикс", "CMS", "cookie bitrix"),
                "_shopify" => push("Shopify", "E-commerce", "cookie shopify"),
                "cf_clearance" => push("Cloudflare bot management", "Антибот", "cookie cf_clearance"),
                "__ddg" => push("DDoS-Guard", "Антибот", "cookie __ddg"),
                _ => {}
            }
        }
    }
    hits
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}
