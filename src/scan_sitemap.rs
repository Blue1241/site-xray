//! sitemap.xml discovery: seeded from robots.txt, followed recursively through
//! <sitemapindex>, with .gz support and a hard cap on work done.
use crate::model::{SitemapDoc, SitemapReport};
use crate::net::Net;
use regex::Regex;
use std::collections::BTreeSet;

pub fn discover(net: &Net, origin: &str, robots_sitemaps: &[String]) -> SitemapReport {
    let mut report = SitemapReport::default();
    let mut candidates: Vec<String> = Vec::new();
    for s in robots_sitemaps {
        candidates.push(s.clone());
    }
    for p in [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-index.xml",
        "/sitemap.xml.gz",
        "/wp-sitemap.xml",
        "/sitemap/sitemap.xml",
        "/news-sitemap.xml",
    ] {
        candidates.push(format!("{origin}{p}"));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    candidates.retain(|c| seen.insert(c.clone()));
    report.tried = candidates.clone();

    let results = net.get_many(&candidates, 2 * 1024 * 1024, 7);

    // Level 1
    let mut children: Vec<String> = Vec::new();
    for (idx, res) in results.into_iter().enumerate() {
        let url = &candidates[idx];
        match res {
            Ok(resp) => {
                let gz = url.ends_with(".gz");
                let text = resp.text();
                let (kind, locs) = classify(&text);
                if resp.status != 200 || kind == "unknown" {
                    if resp.status != 404 {
                        report.errors.push(format!("{url} → HTTP {} ({kind})", resp.status));
                    }
                    continue;
                }
                let doc_urls = locs.len();
                report.docs.push(SitemapDoc {
                    url: url.clone(),
                    status: resp.status,
                    kind: kind.clone(),
                    urls: doc_urls,
                    gz,
                    lastmod: text.contains("<lastmod>"),
                    truncated: resp.truncated,
                });
                if resp.truncated {
                    report.truncated_docs += 1;
                }
                if kind == "sitemapindex" {
                    report.nested_indexes += 1;
                    for l in locs.into_iter().take(6) {
                        children.push(l);
                    }
                } else {
                    report.total_urls += doc_urls;
                    report.has_lastmod |= text.contains("<lastmod>");
                    collect_kinds(&text, &mut report.kinds);
                    for l in locs.iter().take(40) {
                        if report.sample_urls.len() < 24 && !report.sample_urls.contains(l) {
                            report.sample_urls.push(l.clone());
                        }
                    }
                }
            }
            Err(e) => {
                if !url.contains("sitemap") || url.ends_with("/sitemap.xml") {
                    report.errors.push(format!("{url} → {e}"));
                }
            }
        }
    }

    // Level 2: child sitemaps from the index (parallel, capped).
    children.retain(|c| seen.insert(c.clone()));
    if !children.is_empty() {
        let results = net.get_many(&children, 1_200_000, 8);
        for (idx, res) in results.into_iter().enumerate() {
            let url = &children[idx];
            let Ok(resp) = res else { continue };
            if resp.status != 200 {
                continue;
            }
            let text = resp.text();
            let (kind, locs) = classify(&text);
            if kind == "unknown" || kind == "sitemapindex" {
                continue;
            }
            report.total_urls += locs.len();
            report.has_lastmod |= text.contains("<lastmod>");
            collect_kinds(&text, &mut report.kinds);
            report.docs.push(SitemapDoc {
                url: url.clone(),
                status: resp.status,
                kind: format!("{kind} (child)"),
                urls: locs.len(),
                gz: url.ends_with(".gz"),
                lastmod: text.contains("<lastmod>"),
                truncated: resp.truncated,
            });
            if resp.truncated {
                report.truncated_docs += 1;
            }
            for l in locs.iter().take(40) {
                if report.sample_urls.len() < 24 && !report.sample_urls.contains(l) {
                    report.sample_urls.push(l.clone());
                }
            }
        }
    }
    report.kinds.sort();
    report.kinds.dedup();
    report.docs.sort_by(|a, b| a.url.cmp(&b.url));
    report
}

fn classify(text: &str) -> (String, Vec<String>) {
    let low = text.to_ascii_lowercase();
    let loc_re = loc_regex();
    let locs: Vec<String> = loc_re
        .captures_iter(text)
        .map(|c| c[1].trim().to_string())
        .filter(|s| s.starts_with("http"))
        .collect();
    let kind = if low.contains("<sitemapindex") {
        "sitemapindex"
    } else if low.contains("<urlset") || low.contains("<url>") {
        if low.contains("<news:news") {
            "urlset+news"
        } else if low.contains("<image:image") {
            "urlset+image"
        } else if low.contains("<video:video") {
            "urlset+video"
        } else {
            "urlset"
        }
    } else if low.contains("<rss") || low.contains("<feed") {
        // Some sites point robots.txt straight at an RSS feed.
        "feed"
    } else {
        "unknown"
    };
    (kind.to_string(), locs)
}

fn collect_kinds(text: &str, kinds: &mut Vec<String>) {
    let low = text.to_ascii_lowercase();
    for (probe, label) in [
        ("<image:image", "image-теги"),
        ("<video:video", "video-теги"),
        ("<news:news", "news-теги"),
        ("<xhtml:link", "hreflang-альтернативы"),
    ] {
        if low.contains(probe) && !kinds.contains(&label.to_string()) {
            kinds.push(label.to_string());
        }
    }
}

fn loc_regex() -> Regex {
    Regex::new(r"(?is)<loc>\s*(?:<!\[CDATA\[)?\s*(https?://[^<\s\]]+?)\s*(?:\]\]>)?\s*</loc>").unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urlset_with_cdata() {
        let xml = r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://example.com/a</loc><lastmod>2026-01-01</lastmod></url>
        <url><loc><![CDATA[https://example.com/b?x=1&y=2]]></loc></url>
        </urlset>"#;
        let (kind, locs) = classify(xml);
        assert_eq!(kind, "urlset");
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[1], "https://example.com/b?x=1&y=2");
    }

    #[test]
    fn detects_index_and_extensions() {
        let xml = r#"<sitemapindex><sitemap><loc>https://example.com/s1.xml</loc></sitemap></sitemapindex>"#;
        assert_eq!(classify(xml).0, "sitemapindex");

        let xml2 = r#"<urlset><url><loc>https://example.com/a</loc><image:image><image:loc>x.jpg</image:loc></image:image></url></urlset>"#;
        let (kind, _) = classify(xml2);
        assert_eq!(kind, "urlset+image");
        let mut kinds = Vec::new();
        collect_kinds(xml2, &mut kinds);
        assert_eq!(kinds, vec!["image-теги"]);
    }

    #[test]
    fn html_page_is_not_a_sitemap() {
        assert_eq!(classify("<html><body>hi</body></html>").0, "unknown");
    }
}
