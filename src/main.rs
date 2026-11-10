//! site-xray — one command, everything a site tells you about itself.
mod detect;
mod model;
mod net;
mod report;
mod ru;
mod scan_api;
mod scan_feeds;
mod scan_html;
mod scan_js;
mod scan_robots;
mod scan_sitemap;
mod score;

use model::*;
use net::{host_of, origin_of, Net};
use report::Style;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use url::Url;

const HELP: &str = r#"site-xray — рентген сайта одной командой

  site-xray example.com

Что проверяется:
  robots.txt · дерево sitemap.xml · RSS/Atom-фиды · JSON-LD (schema.org)
  скрытые JSON-эндпоинты в JS-бандлах · заголовки защиты · Cloudflare/WAF
  технологический стек  →  вердикт: откуда брать данные без браузера

Использование:
  site-xray <url|домен> [опции]

Опции:
  --json            вывести отчёт в JSON (для скриптов)
  --md [ФАЙЛ]       сохранить Markdown-отчёт (по умолчанию site-xray-<host>.md)
  -o, --out ФАЙЛ    записать вывод в файл
  --all             показать все найденные эндпоинты
  --max-js N        сколько JS-бандлов качать (по умолчанию 4)
  --no-js           не качать JS-бандлы
  --no-verify       не проверять эндпоинты живыми запросами
  --timeout SEC     таймаут запроса (по умолчанию 10)
  --budget SEC      сколько всего секунд тратить на дополнительные проверки (по умолчанию 8)
  --cache-dir PATH  каталог кэша (по умолчанию ~/.cache/site-xray)
  --no-cache         не читать и не записывать кэш
  --offline          собрать отчёт только из кэшированных ответов
  --insecure        игнорировать ошибки TLS
  --no-color        без ANSI-цветов
  -q, --quiet       не печатать отчёт (полезно с --md/-o)
  -V, --version     версия
  -h, --help        эта справка

Примеры:
  site-xray habr.com
  site-xray https://example.com --json | jq .verdict
  site-xray shop.example --md report.md
"#;

struct Opts {
    target: String,
    json: bool,
    md: Option<String>,
    out: Option<String>,
    all: bool,
    max_js: usize,
    js: bool,
    verify: bool,
    timeout: u64,
    budget: u64,
    insecure: bool,
    color: bool,
    quiet: bool,
    cache_dir: Option<String>,
    no_cache: bool,
    offline: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{HELP}");
        std::process::exit(2);
    }
    let mut target: Option<String> = None;
    let mut opts = Opts {
        target: String::new(),
        json: false,
        md: None,
        out: None,
        all: false,
        max_js: 4,
        js: true,
        verify: true,
        timeout: 10,
        budget: 8,
        insecure: false,
        color: std::env::var_os("NO_COLOR").is_none() && atty_stdout(),
        quiet: false,
        cache_dir: None, no_cache: false, offline: false,
    };

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => {
                print!("{HELP}");
                return;
            }
            "-V" | "--version" => {
                println!("site-xray {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--json" => opts.json = true,
            "--all" => opts.all = true,
            "--no-js" => opts.js = false,
            "--no-verify" => opts.verify = false,
            "--insecure" => opts.insecure = true,
            "--budget" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(v) => opts.budget = v.clamp(1, 120),
                    None => fail("--budget требует число секунд"),
                }
            }
            "--no-color" => opts.color = false,
            "--no-cache" => opts.no_cache = true,
            "--offline" => opts.offline = true,
            "--cache-dir" => { i += 1; opts.cache_dir = args.get(i).cloned(); if opts.cache_dir.is_none() { fail("--cache-dir требует путь"); } },
            "-q" | "--quiet" => opts.quiet = true,
            "--md" => {
                let next = args.get(i + 1);
                if let Some(n) = next {
                    if !n.starts_with('-') {
                        opts.md = Some(n.clone());
                        i += 1;
                    }
                }
                if opts.md.is_none() {
                    opts.md = Some(String::new()); // placeholder → default name
                }
            }
            "-o" | "--out" => {
                i += 1;
                match args.get(i) {
                    Some(v) => opts.out = Some(v.clone()),
                    None => fail("--out требует путь к файлу"),
                }
            }
            "--max-js" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<usize>().ok()) {
                    Some(v) => opts.max_js = v.clamp(1, 40),
                    None => fail("--max-js требует число"),
                }
            }
            "--timeout" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(v) => opts.timeout = v.clamp(1, 60),
                    None => fail("--timeout требует число секунд"),
                }
            }
            other if other.starts_with('-') => fail(&format!("неизвестная опция {other}")),
            other => {
                if target.is_some() {
                    fail("можно указать только один адрес");
                }
                target = Some(other.to_string());
            }
        }
        i += 1;
    }

    let Some(target) = target else {
        eprint!("{HELP}");
        std::process::exit(2);
    };
    opts.target = target;

    let code = run(opts);
    std::process::exit(code);
}

fn fail(msg: &str) -> ! {
    eprintln!("site-xray: {msg}");
    eprintln!("подсказка: site-xray --help");
    std::process::exit(2);
}

fn run(opts: Opts) -> i32 {
    let started = Instant::now();
    let mut net = match Net::new(opts.timeout, opts.insecure) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("site-xray: {e}");
            return 1;
        }
    };

    let cache_dir = opts.cache_dir.clone().or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.cache/site-xray")));
    if let Some(d) = cache_dir { net.configure_cache(d, !opts.no_cache, opts.offline); }
    // ---- 1. homepage (with https → http fallback) ----
    let candidates = url_candidates(&opts.target);
    let mut home = None;
    let mut last_err = String::new();
    for url in &candidates {
        match net.get(url) {
            Ok(r) => {
                home = Some(r);
                break;
            }
            Err(e) => last_err = format!("{url} → {e}"),
        }
    }
    let Some(home) = home else {
        eprintln!("site-xray: не удалось получить главную страницу ({last_err})");
        eprintln!("проверь адрес, сеть или TLS (--insecure)");
        return 1;
    };
    let final_url = home.final_url.clone();
    let t_home = started.elapsed().as_millis();
    net.set_deadline(std::time::Duration::from_secs(opts.budget));
    // JS bundles are the least valuable and the biggest — they get the tighter budget.
    let js_budget = opts.budget.min(5);
    let js_net = {
        let mut n = net.fork();
        n.set_deadline(std::time::Duration::from_secs(js_budget));
        n
    };
    let origin = origin_of(&final_url);
    let html = if home.is_html() { home.text() } else { String::new() };
    let page = scan_html::scan(&html, &final_url);

    // ---- 2. robots.txt, service files and feeds — all independent, in parallel ----
    let robots_url = format!("{origin}/robots.txt");
    let declared: Vec<scan_feeds::Declared> = page
        .feed_links
        .iter()
        .map(|(u, t)| scan_feeds::Declared {
            url: u.clone(),
            kind: if t.contains("atom") {
                "atom".into()
            } else if t.contains("json") {
                "json-feed".into()
            } else {
                "rss".into()
            },
        })
        .collect();
    let (robots_parsed, extras, feeds, js_report) = std::thread::scope(|s| {
        let robots_h = {
            let net = &net;
            let url = robots_url.clone();
            s.spawn(move || net.get(&url).map(|r| scan_robots::parse(&robots_url, &r)))
        };
        let extras_h = {
            let net = &net;
            let origin = origin.clone();
            s.spawn(move || detect::extras(net, &origin))
        };
        let feeds_h = {
            let net = &net;
            let origin = origin.clone();
            let declared = declared.clone();
            s.spawn(move || scan_feeds::discover(net, &origin, &declared))
        };
        let api_h = {
            let net = &net;
            let origin = origin.clone();
            s.spawn(move || scan_api::probe(net, &origin))
        };
        let js_h = {
            let net = &js_net;
            let final_url = final_url.clone();
            let origin = origin.clone();
            let scripts = page.scripts.clone();
            let hints = page.api_hints.clone();
            let build_id = page.next_build_id.clone();
            let enabled = opts.js;
            let max_bundles = opts.max_js;
            let verify = opts.verify;
            s.spawn(move || {
                if !enabled {
                    return JsReport::default();
                }
                scan_js::mine(net, &final_url, &origin, &scripts, &hints, build_id.as_deref(), max_bundles, verify)
            })
        };
        let robots = robots_h.join().ok().and_then(|r| r.ok());
        let extras = extras_h.join().unwrap_or_default();
        let feeds = feeds_h.join().unwrap_or_default();
        let mut js = js_h.join().unwrap_or_default();
        let probed = api_h.join().unwrap_or_default();
        // Probed APIs first, then whatever the bundles suggested.
        let mut merged: Vec<Endpoint> = probed;
        for e in js.endpoints.drain(..) {
            if merged.iter().any(|p| p.path == e.path) {
                continue;
            }
            merged.push(e);
        }
        merged.sort_by(|a, b| b.score.cmp(&a.score).then(b.hits.cmp(&a.hits)));
        merged.truncate(40);
        js.endpoints = merged;
        (robots, extras, feeds, js)
    });
    let t_robots = started.elapsed().as_millis();

    // ---- 3. sitemap tree (needs robots.txt, so it goes last; own fresh budget) ----
    net.set_deadline(std::time::Duration::from_secs(opts.budget));
    let robots_sitemaps = robots_parsed.as_ref().map(|r| r.sitemaps.clone()).unwrap_or_default();
    let sitemaps = scan_sitemap::discover(&net, &origin, &robots_sitemaps);

    let t_scan = started.elapsed().as_millis();

    // ---- 5. security / tech ----
    let t_feeds = started.elapsed().as_millis();
    let security = detect::security(&home, &html, extras);
    let tech = detect::tech(&home, &html, &security.cookies);

    let http = HttpInfo {
        requested: home.requested.clone(),
        final_url: final_url.clone(),
        status: home.status,
        redirect_chain: home.redirects.clone(),
        ms: home.ms,
        size_bytes: home.body.len(),
        truncated: home.truncated,
        server: home.header("server"),
        powered_by: home.header("x-powered-by"),
        content_type: home.content_type(),
        http_version: home.http_version.clone(),
        lang: page.lang.clone(),
        title: page.title.clone(),
        description: page.description.clone(),
        canonical: page.canonical.clone(),
        generator: page.generator.clone(),
        meta_robots: page.meta_robots.clone(),
        tls: final_url.starts_with("https"),
    };

    let mut js_report = js_report;
    for st in &page.inline_states {
        if !js_report.inline_states.iter().any(|x| x == st) {
            js_report.inline_states.push(st.clone());
        }
    }
    if page.og_tags > 0 {
        js_report.notes.push(format!("OpenGraph: {} тегов", page.og_tags));
    }
    if !page.html_forms.is_empty() {
        js_report.notes.push(format!(
            "формы на странице: {}",
            page.html_forms.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    let mut rep = Report {
        tool: "site-xray".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        generated_at: now_utc(),
        elapsed_ms: 0,
        target: opts.target.clone(),
        http,
        cors: { let ao=home.header("access-control-allow-origin"); let cred=home.header("access-control-allow-credentials"); let verdict=if ao.as_deref()==Some("*") || ao.as_deref()==Some(origin.as_str()) { "из браузера можно (по заголовкам главной)" } else { "CORS для главной не разрешён; API может иметь отдельные правила" }.to_string(); CorsInfo { allow_origin:ao, allow_methods:home.header("access-control-allow-methods"), allow_headers:home.header("access-control-allow-headers"), credentials:cred, verdict } },
        robots: robots_parsed,
        sitemaps,
        feeds,
        jsonld: page.jsonld.clone(),
        js: js_report,
        security,
        tech,
        channels: vec![],
        verdict: Verdict::default(),
    };
    let (channels, verdict) = score::build(&rep, &origin);
    rep.channels = channels;
    rep.verdict = verdict;
    rep.elapsed_ms = started.elapsed().as_millis() as u64;

    if std::env::var_os("SITE_XRAY_DEBUG").is_some() {
        eprintln!(
            "debug: главная {t_home} мс · параллельный блок (robots/файлы/фиды/js) {t_robots} мс · sitemap {t_scan} мс · сборка {t_feeds} мс · всего {} мс",
            started.elapsed().as_millis()
        );
    }

    // ---- 6. output ----
    let style = Style { color: opts.color && !opts.json };
    let terminal = report::render(&rep, &style, if opts.all { 40 } else { 10 });

    if let Some(path) = &opts.md {
        let path = if path.is_empty() {
            format!("site-xray-{}.md", sanitize(&host_of(&final_url)))
        } else {
            path.clone()
        };
        match std::fs::write(&path, report::render_markdown(&rep)) {
            Ok(_) => eprintln!("markdown-отчёт: {path}"),
            Err(e) => eprintln!("не удалось записать {path}: {e}"),
        }
    }

    let body = if opts.json {
        match serde_json::to_string_pretty(&rep) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("site-xray: не удалось сериализовать отчёт: {e}");
                return 1;
            }
        }
    } else {
        terminal
    };

    if let Some(path) = &opts.out {
        if let Err(e) = std::fs::write(path, &body) {
            eprintln!("не удалось записать {path}: {e}");
            return 1;
        }
        eprintln!("отчёт записан: {path}");
    }
    if !opts.quiet {
        println!("{body}");
    }
    if let Some(path) = &opts.out {
        let _ = path;
    }
    0
}

fn url_candidates(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return vec![ensure_path(trimmed)];
    }
    vec![ensure_path(&format!("https://{trimmed}")), ensure_path(&format!("http://{trimmed}"))]
}

fn ensure_path(u: &str) -> String {
    match Url::parse(u) {
        Ok(url) => {
            let mut url = url;
            if url.path().is_empty() {
                url.set_path("/");
            }
            url.to_string()
        }
        Err(_) => u.to_string(),
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn atty_stdout() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        unsafe { isatty(1) == 1 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}
