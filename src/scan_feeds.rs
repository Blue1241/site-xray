//! RSS / Atom / JSON Feed discovery: declared <link rel="alternate"> plus the
//! usual probe paths. Verified by content sniffing, not by the label on the tin.
use crate::model::FeedInfo;
use crate::net::Net;
use regex::Regex;
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Clone)]
pub struct Declared {
    pub url: String,
    pub kind: String,
}

pub fn discover(net: &Net, origin: &str, declared: &[Declared]) -> Vec<FeedInfo> {
    let mut candidates: Vec<(String, bool, String)> = Vec::new(); // url, declared, kind hint
    for d in declared {
        candidates.push((d.url.clone(), true, d.kind.clone()));
    }
    for p in [
        "/feed",
        "/feed.xml",
        "/rss",
        "/rss.xml",
        "/atom.xml",
        "/index.xml",
        "/blog/feed",
        "/?feed=rss2",
    ] {
        candidates.push((format!("{origin}{p}"), false, String::new()));
    }
    let mut seen = BTreeSet::new();
    candidates.retain(|(u, _, _)| seen.insert(u.clone()));

    let urls: Vec<String> = candidates.iter().map(|(u, _, _)| u.clone()).collect();
    let results = net.get_many_t(&urls, 768 * 1024, 10, Duration::from_secs(3));
    let mut feeds: Vec<FeedInfo> = Vec::new();
    for (idx, res) in results.into_iter().enumerate() {
        let (url, declared, hint) = &candidates[idx];
        let Ok(resp) = res else { continue };
        if resp.status != 200 || resp.body.is_empty() {
            continue;
        }
        let text = resp.text();
        let head: String = text.chars().take(4000).collect::<String>().to_ascii_lowercase();
        let kind = if head.contains("<rss") || head.contains("<rdf:rdf") {
            "rss"
        } else if head.contains("<feed") && head.contains("atom") {
            "atom"
        } else if head.trim_start().starts_with('{') && head.contains("\"items\"") {
            "json-feed"
        } else {
            // Be strict: an HTML page that merely mentions RSS is not a feed.
            continue;
        };
        let items = match kind {
            "rss" => Regex::new(r"(?i)<item[\s>]").unwrap().find_iter(&text).count(),
            "atom" => Regex::new(r"(?i)<entry[\s>]").unwrap().find_iter(&text).count(),
            _ => serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("items").and_then(|i| i.as_array().map(|a| a.len())))
                .unwrap_or(0),
        };
        let title = pick_title(&text, kind);
        let latest = pick_latest(&text, kind);
        if items == 0 && title.is_none() {
            continue;
        }
        feeds.push(FeedInfo {
            url: url.clone(),
            status: resp.status,
            kind: if hint.is_empty() { kind.to_string() } else { hint.clone() },
            title,
            items,
            latest,
            declared: *declared,
            bytes: resp.body.len(),
        });
    }
    // Declared feeds first, then by item count.
    feeds.sort_by(|a, b| {
        b.declared
            .cmp(&a.declared)
            .then(b.items.cmp(&a.items))
            .then(a.url.len().cmp(&b.url.len()))
    });
    let mut seen_feeds: BTreeSet<(usize, Option<String>, Option<String>)> = BTreeSet::new();
    feeds.retain(|f| seen_feeds.insert((f.items, f.title.clone(), f.latest.clone())));
    if feeds.iter().any(|f| f.items > 0) {
        feeds.retain(|f| f.items > 0 || f.declared);
    }
    feeds.truncate(10);
    feeds
}

fn pick_title(text: &str, kind: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<title[^>]*>\s*(?:<!\[CDATA\[)?\s*(.{0,200}?)\s*(?:\]\]>)?\s*</title>").ok()?;
    if kind == "json-feed" {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        return v
            .get("title")
            .and_then(|t| t.as_str())
            .map(|s| s.trim().to_string());
    }
    let mut hits = re.captures_iter(text);
    // First <title> is the channel title for RSS, feed title for Atom.
    hits.next().map(|c| strip_tags(&c[1]))
}

fn pick_latest(text: &str, kind: &str) -> Option<String> {
    let patterns: &[&str] = match kind {
        "atom" => &[r"(?is)<updated>\s*(.{4,40}?)\s*</updated>"],
        "json-feed" => &[],
        _ => &[
            r"(?is)<lastBuildDate>\s*(.{4,40}?)\s*</lastBuildDate>",
            r"(?is)<pubDate>\s*(.{4,40}?)\s*</pubDate>",
        ],
    };
    for p in patterns {
        if let Ok(re) = Regex::new(p) {
            if let Some(c) = re.captures(text) {
                return Some(c[1].trim().to_string());
            }
        }
    }
    if kind == "json-feed" {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        return v
            .get("items")
            .and_then(|i| i.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("date_published"))
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());
    }
    None
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}
