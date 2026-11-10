//! JS bundle mining: pull endpoint-looking strings out of scripts, score them,
//! then actually hit the best ones to see which answer with JSON.
use crate::model::{Endpoint, JsReport};
use crate::net::{absolutize, host_of, Net};
use regex::Regex;
use std::collections::HashMap;
use std::time::Duration;

pub fn mine(
    net: &Net,
    page_url: &str,
    _origin: &str,
    scripts: &[String],
    api_hints: &[String],
    next_build_id: Option<&str>,
    max_bundles: usize,
    verify: bool,
) -> JsReport {
    let mut report = JsReport {
        scripts_declared: scripts.len(),
        ..Default::default()
    };

    // Pick the most promising bundles: same host first, "main/app/index/chunk" names next.
    let mut ranked: Vec<(i32, String)> = scripts
        .iter()
        .map(|s| {
            let mut score = 0;
            if host_of(s) == host_of(page_url) {
                score += 30;
            }
            let low = s.to_ascii_lowercase();
            for needle in ["main", "app", "index", "runtime", "chunk", "bundle", "vendor", "_next/static"] {
                if low.contains(needle) {
                    score += 6;
                }
            }
            if low.ends_with(".mjs") || low.contains(".js?") || low.ends_with(".js") {
                score += 4;
            }
            (-score, s.clone())
        })
        .collect();
    ranked.sort();
    let picked: Vec<String> = ranked.into_iter().take(max_bundles).map(|(_, s)| s).collect();

    let results = net.get_many(&picked, 1_200_000, 10);
    let mut hits: HashMap<String, Endpoint> = HashMap::new();
    let mut evidence: HashMap<String, String> = HashMap::new();

    for (idx, res) in results.into_iter().enumerate() {
        let Ok(resp) = res else {
            report.notes.push(format!("{} → не загрузился", shorten(&picked[idx])));
            continue;
        };
        if resp.status != 200 {
            continue;
        }
        report.bundles_scanned += 1;
        report.bundles_bytes += resp.body.len();
        let text = resp.text();
        for (path, kind, ev) in extract(&text) {
            let score = score_path(&path, &kind);
            if score < 22 {
                continue;
            }
            let key = normalize(&path);
            let entry = hits.entry(key).or_insert_with(|| Endpoint {
                path: path.clone(),
                score,
                kind: kind.clone(),
                evidence: ev.clone(),
                hits: 0,
                ..Default::default()
            });
            entry.hits += 1;
            if score > entry.score {
                entry.score = score;
                entry.kind = kind.clone();
                entry.evidence = ev.clone();
                entry.path = path.clone();
            }
            evidence.insert(normalize(&path), shorten(&picked[idx]));
        }
    }

    for h in api_hints {
        let entry = hits.entry(normalize(h)).or_insert_with(|| Endpoint {
            path: h.clone(),
            score: score_path(h, "api"),
            kind: "api".into(),
            evidence: "в HTML".into(),
            hits: 1,
            ..Default::default()
        });
        if entry.evidence.is_empty() {
            entry.evidence = "в HTML".into();
        }
    }

    if let Some(bid) = next_build_id {
        for route in ["/", "/index"] {
            let p = format!("/_next/data/{bid}{route}.json");
            hits.entry(normalize(&p)).or_insert_with(|| Endpoint {
                path: p.clone(),
                score: 88,
                kind: "next-data".into(),
                evidence: "buildId из __NEXT_DATA__".into(),
                ..Default::default()
            });
        }
        report.notes.push(format!(
            "Next.js buildId = {bid}: JSON страниц доступен как /_next/data/{bid}/<route>.json"
        ));
    }

    let mut endpoints: Vec<Endpoint> = hits.into_values().collect();
    endpoints.sort_by(|a, b| b.score.cmp(&a.score).then(b.hits.cmp(&a.hits)));
    endpoints.truncate(40);

    // Verify: a GET that really returns JSON is worth more than any regex.
    if verify {
        let mut targets: Vec<(usize, String)> = Vec::new();
        for (i, e) in endpoints.iter().enumerate() {
            if targets.len() >= 6 {
                break;
            }
            if e.path.contains('{') || e.path.contains('$') || e.path.contains(':') || e.path.contains('<') {
                continue;
            }
            if let Some(abs) = absolutize(page_url, &e.path) {
                if let Some(host) = evidence.get(&normalize(&e.path)) {
                    let _ = host;
                }
                if !targets.iter().any(|(_, u)| u == &abs) {
                    targets.push((i, abs));
                }
            }
        }
        let urls: Vec<String> = targets.iter().map(|(_, u)| u.clone()).collect();
        let res = net.get_many_t(&urls, 128 * 1024, 6, Duration::from_secs(3));
        for ((i, _), r) in targets.iter().zip(res.into_iter()) {
            if let Ok(resp) = r {
                let ctype = resp.content_type();
                let text = resp.text();
                let looks_json = ctype.as_deref().map(|c| c.contains("json")).unwrap_or(false)
                    || text.trim_start().starts_with('{')
                    || text.trim_start().starts_with('[');
                let e = &mut endpoints[*i];
                e.status = Some(resp.status);
                e.ctype = ctype.clone();
                if resp.status == 200 && looks_json {
                    e.verified = true;
                    e.score = (e.score + 8).min(100);
                    e.evidence = format!("{} · подтверждён JSON", e.evidence);
                } else if resp.status == 405 {
                    // Alive, but only answers POST — still a real API.
                    e.evidence = format!("{} · только POST", e.evidence);
                } else if resp.status == 403 || resp.status == 429 {
                    e.score = e.score.saturating_sub(6);
                    e.evidence = format!("{} · закрыт ({})", e.evidence, resp.status);
                } else if resp.status >= 400 && resp.status != 401 {
                    e.score = e.score.saturating_sub(12);
                }
            }
        }
        // Re-rank with the verification bonus.
        endpoints.sort_by(|a, b| b.score.cmp(&a.score).then(b.hits.cmp(&a.hits)));
    }

    report.endpoints = endpoints;
    report
}

/// Extract (path, kind, evidence) triples from one bundle.
fn extract(text: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();

    // 1) explicit calls: fetch("/api/x"), axios.get(`/api/x`), xhr.open("GET","/api/x")
    if let Ok(re) = Regex::new(
        r#"(?i)(?:fetch|axios\s*\.\s*(?:get|post|put|patch|delete)|\.open)\s*\(\s*(?:["'`]GET["'`]\s*,\s*)?[`"']([^`"'\s]{3,180})[`"']"#,
    ) {
        for c in re.captures_iter(text).take(400) {
            let p = c[1].to_string();
            if !interesting(&p) {
                continue;
            }
            out.push((p.clone(), kind_of(&p), "fetch/axios".into()));
        }
    }

    // 2) any quoted string that smells like a path with an API-ish segment
    if let Ok(re) = Regex::new(r#"["'`]([A-Za-z0-9_\-./~{}$%:?&=+\[\]]{3,160})["'`]"#) {
        for c in re.captures_iter(text).take(6000) {
            let p = c[1].to_string();
            if !interesting(&p) {
                continue;
            }
            out.push((p.clone(), kind_of(&p), "строка в бандле".into()));
        }
    }

    // 3) absolute API hosts
    if let Ok(re) = Regex::new(
        r#"https?://[A-Za-z0-9.-]*?(?:api|gateway|graphql|rest)[A-Za-z0-9.-]*\.[A-Za-z]{2,}[A-Za-z0-9_\-./{}$%:?&=+~]{0,120}"#,
    ) {
        for m in re.find_iter(text).take(40) {
            let p = m.as_str().to_string();
            out.push((p.clone(), kind_of(&p), "абсолютный URL".into()));
        }
    }

    out
}

fn interesting(p: &str) -> bool {
    let low = p.to_ascii_lowercase();
    if p.len() < 4 || low.contains(' ') {
        return false;
    }
    // "GET", "POST", mime types and other call-argument noise
    if !p.contains('/') && !p.contains('.') {
        return false;
    }
    let markers = [
        "/api", "/graphql", "/gql", "/wp-json", "/json", ".json", "/rest", "/v1/", "/v2/",
        "/v3/", "/v4/", "/ajax", "/rpc", "/_next/data", "/_nuxt", "/feed", "/search", "/query",
        "/catalog", "/products", "/items", "/data/", "/export", "/sitemap",
    ];
    if !markers.iter().any(|m| low.contains(m)) {
        return false;
    }
    let statics = [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".css", ".woff", ".woff2",
        ".ttf", ".ico", ".map", ".mp4", ".webm", ".pdf", ".xml.gz",
    ];
    if statics.iter().any(|s| low.ends_with(s)) {
        return false;
    }
    // Drop obvious noise: sourcemap hints, html entity salad, locale key paths.
    if low.starts_with('/') || low.starts_with("http") || low.starts_with("./") || !low.contains('/') {
        true
    } else {
        false
    }
}

fn kind_of(p: &str) -> String {
    let low = p.to_ascii_lowercase();
    if low.contains("graphql") || low.contains("/gql") {
        "graphql".into()
    } else if low.contains("wp-json") {
        "wp-rest".into()
    } else if low.contains("_next/data") {
        "next-data".into()
    } else if low.ends_with(".json") || low.contains(".json?") {
        "json".into()
    } else if low.contains("/api") || low.contains("/v1") || low.contains("/v2") || low.contains("/rest") {
        "api".into()
    } else if low.contains("feed") || low.contains("rss") {
        "feed".into()
    } else {
        "path".into()
    }
}

fn score_path(path: &str, kind: &str) -> u32 {
    let low = path.to_ascii_lowercase();
    let mut s = 18u32;
    s += match kind {
        "graphql" => 30,
        "wp-rest" => 26,
        "next-data" => 32,
        "json" => 24,
        "api" => 16,
        "feed" => 8,
        _ => 0,
    };
    if low.contains("/v1/") || low.contains("/v2/") || low.contains("/v3/") {
        s += 8;
    }
    if low.contains("/public") || low.contains("/open") || low.contains("/export") || low.contains("/catalog") || low.contains("/products") {
        s += 6;
    }
    if path.len() <= 48 {
        s += 6;
    }
    if path.len() > 110 {
        s = s.saturating_sub(10);
    }
    if path.contains('{') || path.contains('$') || path.contains('<') || path.contains(':') {
        s = s.saturating_sub(14);
    }
    if low.contains("/assets/") || low.contains("/static/") || low.contains("/icons/") || low.contains("/img/") {
        s = s.saturating_sub(12);
    }
    if low.contains("localhost") || low.contains("127.0.0.1") || low.contains("example.com") {
        s = s.saturating_sub(18);
    }
    s.min(97)
}

fn normalize(p: &str) -> String {
    let mut s = p.trim().to_string();
    if let Some(pos) = s.find('#') {
        s.truncate(pos);
    }
    while s.ends_with('/') && s.len() > 1 {
        s.pop();
    }
    s
}

fn shorten(u: &str) -> String {
    let u = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://")).unwrap_or(u);
    if u.len() > 60 {
        let tail: String = u.chars().rev().take(55).collect::<Vec<_>>().into_iter().rev().collect();
        format!("…{tail}")
    } else {
        u.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_static_assets_and_noise() {
        assert!(!interesting("/static/logo.png"));
        assert!(!interesting("GET"));
        assert!(!interesting("text/html"));
        assert!(interesting("/api/v1/products?limit=10"));
        assert!(interesting("/_next/data/abc123/index.json"));
        assert!(interesting("https://api.example.org/graphql"));
    }

    #[test]
    fn classifies_kinds() {
        assert_eq!(kind_of("/wp-json/wp/v2/posts"), "wp-rest");
        assert_eq!(kind_of("/graphql"), "graphql");
        assert_eq!(kind_of("/_next/data/x/y.json"), "next-data");
        assert_eq!(kind_of("/catalog.json?page=2"), "json");
        assert_eq!(kind_of("/api/v2/items"), "api");
    }

    #[test]
    fn scores_confirmed_paths_higher() {
        assert!(score_path("/_next/data/bid/index.json", "next-data") > score_path("/assets/foo.json", "json"));
        assert!(score_path("/localhost/api/x", "api") < score_path("/api/x", "api"));
    }

    #[test]
    fn normalizes_trailing_slashes() {
        assert_eq!(normalize("/api/v1/"), "/api/v1");
        assert_eq!(normalize("/api/v1/#frag"), "/api/v1");
    }
}
