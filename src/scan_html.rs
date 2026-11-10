//! Homepage parsing: meta, JSON-LD, feed links, script bundles, inline JSON state.
use crate::model::JsonLdReport;
use crate::net::absolutize;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::BTreeSet;
use url::Url;

/// Treat only recognized methods as such; invalid page text must not be printed
/// verbatim or interpreted as an authorization to send a GET probe.
pub fn form_method(raw: Option<&str>) -> &'static str {
    match raw.unwrap_or("get").trim().to_ascii_lowercase().as_str() {
        "" | "get" => "GET",
        "post" => "POST",
        "dialog" => "DIALOG",
        _ => "OTHER",
    }
}

pub struct HtmlScan {
    pub title: Option<String>,
    pub description: Option<String>,
    pub canonical: Option<String>,
    pub generator: Option<String>,
    pub meta_robots: Option<String>,
    pub lang: Option<String>,
    pub og_tags: usize,
    pub feed_links: Vec<(String, String)>, // (absolute url, type)
    pub jsonld: JsonLdReport,
    pub scripts: Vec<String>,
    pub inline_states: Vec<String>,
    pub next_build_id: Option<String>,
    pub html_forms: Vec<String>,
    pub api_hints: Vec<String>,
}

pub fn scan(html: &str, page_url: &str) -> HtmlScan {
    let doc = Html::parse_document(html);
    let sel = |s: &str| Selector::parse(s).ok();

    let title = sel("title")
        .and_then(|s| doc.select(&s).next())
        .map(|e| clean(&e.text().collect::<Vec<_>>().join(" ")))
        .filter(|s| !s.is_empty());
    let lang = sel("html")
        .and_then(|s| doc.select(&s).next())
        .and_then(|e| e.value().attr("lang").map(|v| v.to_string()));

    let meta = |name: &str| -> Option<String> {
        let s = sel(&format!(
            "meta[name=\"{0}\"], meta[property=\"{0}\"], meta[itemprop=\"{0}\"]",
            name
        ))?;
        doc.select(&s)
            .next()
            .and_then(|e| e.value().attr("content").map(|c| clean(c)))
            .filter(|c| !c.is_empty())
    };
    let description = meta("description").or_else(|| meta("og:description"));
    let generator = meta("generator");
    let meta_robots = meta("robots");
    let og_tags = sel("meta[property^=\"og:\"]")
        .map(|s| doc.select(&s).count())
        .unwrap_or(0);

    let canonical = sel("link[rel=\"canonical\"]")
        .and_then(|s| doc.select(&s).next())
        .and_then(|e| e.value().attr("href"))
        .and_then(|h| absolutize(page_url, h));

    // ---- feeds declared in the head ----
    let mut feed_links = Vec::new();
    if let Some(s) = sel("link[rel=\"alternate\"]") {
        for el in doc.select(&s) {
            let Some(href) = el.value().attr("href") else { continue };
            let ty = el.value().attr("type").unwrap_or("").to_ascii_lowercase();
            let is_feed = ty.contains("rss")
                || ty.contains("atom")
                || ty.contains("feed+json")
                || ty.contains("application/json");
            if !is_feed {
                continue;
            }
            if let Some(abs) = absolutize(page_url, href) {
                if !feed_links.iter().any(|(u, _)| u == &abs) {
                    feed_links.push((abs, ty));
                }
            }
        }
    }

    // ---- JSON-LD ----
    let jsonld = scan_jsonld(&doc, &sel);

    // ---- scripts ----
    let mut scripts: Vec<String> = Vec::new();
    let mut api_hints: Vec<String> = Vec::new();
    if let Some(s) = sel("script[src]") {
        for el in doc.select(&s) {
            let Some(src) = el.value().attr("src") else { continue };
            if let Some(abs) = absolutize(page_url, src) {
                if !scripts.contains(&abs) {
                    scripts.push(abs);
                }
            }
        }
    }

    // ---- inline state blobs (the "hidden JSON" that ships in the HTML) ----
    let mut inline_states: Vec<String> = Vec::new();
    for marker in [
        "__NEXT_DATA__",
        "__NUXT__",
        "__APOLLO_STATE__",
        "__INITIAL_STATE__",
        "__PRELOADED_STATE__",
        "__REDUX_STATE__",
        "__remixContext",
        "__SVELTEKIT__",
        "window.__INITIAL_DATA__",
        "__NUXT_DATA__",
    ] {
        if html.contains(marker) {
            inline_states.push(marker.trim_start_matches("window.").to_string());
        }
    }
    if let Some(s) = sel("script[type=\"application/json\"]") {
        let n = doc.select(&s).count();
        if n > 0 {
            inline_states.push(format!("{n}× <script type=\"application/json\">"));
        }
    }
    let next_build_id = Regex::new(r#""buildId"\s*:\s*"([A-Za-z0-9_\-]{4,64})""#)
        .ok()
        .and_then(|re| re.captures(html))
        .map(|c| c[1].to_string());

    // ---- forms that post/get JSON ----
    let mut html_forms: Vec<String> = Vec::new();
    if let Some(s) = sel("form[action]") {
        for el in doc.select(&s) {
            let Some(action) = el.value().attr("action") else { continue };
            let method = form_method(el.value().attr("method"));
            if let Some(mut url) = absolutize(page_url, action).and_then(|abs| Url::parse(&abs).ok()) {
                // Actions may contain CSRF tokens or other sensitive query values.
                // These notes are for display only, never for making requests.
                url.set_query(None);
                url.set_fragment(None);
                let _ = url.set_username("");
                let _ = url.set_password(None);
                let entry = format!("{method} {url}");
                if !html_forms.contains(&entry) {
                    html_forms.push(entry);
                }
            }
        }
    }
    html_forms.truncate(8);

    // ---- /api/ style paths mentioned in attributes ----
    if let Ok(re) = Regex::new(r#""(/(?:api|rest|graphql|wp-json|ajax)[A-Za-z0-9_\-/.]{0,80})""#) {
        let mut set = BTreeSet::new();
        for c in re.captures_iter(html).take(200) {
            set.insert(c[1].to_string());
        }
        api_hints = set.into_iter().take(10).collect();
    }

    HtmlScan {
        title,
        description,
        canonical,
        generator,
        meta_robots,
        lang,
        og_tags,
        feed_links,
        jsonld,
        scripts,
        inline_states,
        next_build_id,
        html_forms,
        api_hints,
    }
}

fn scan_jsonld(doc: &Html, sel: &dyn Fn(&str) -> Option<Selector>) -> JsonLdReport {
    let mut out = JsonLdReport::default();
    let Some(s) = sel("script[type=\"application/ld+json\"]") else {
        return out;
    };
    let mut types: Vec<String> = Vec::new();
    let mut props: BTreeSet<String> = BTreeSet::new();
    for el in doc.select(&s) {
        out.blocks += 1;
        let raw = el.inner_html();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(v) => {
                out.valid += 1;
                collect(&v, &mut types, &mut props);
            }
            Err(_) => {
                // Broken JSON is common; note it but keep going.
            }
        }
    }
    types.sort();
    types.dedup();
    out.types = types;
    out.props = props.into_iter().take(18).collect();
    if out.valid > 0 {
        out.samples.push(format!(
            "{} блок(ов) JSON-LD, {} валидных, {} типов schema.org",
            out.blocks,
            out.valid,
            out.types.len()
        ));
    }
    out
}

fn collect(v: &serde_json::Value, types: &mut Vec<String>, props: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if k == "@type" {
                    match val {
                        serde_json::Value::String(s) => types.push(s.clone()),
                        serde_json::Value::Array(arr) => {
                            for a in arr {
                                if let Some(s) = a.as_str() {
                                    types.push(s.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                } else if !k.starts_with('@') && val.is_string() || val.is_number() {
                    props.insert(k.clone());
                } else if !k.starts_with('@') {
                    props.insert(k.clone());
                }
                collect(val, types, props);
            }
        }
        serde_json::Value::Array(arr) => {
            for a in arr {
                collect(a, types, props);
            }
        }
        _ => {}
    }
}

fn clean(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
