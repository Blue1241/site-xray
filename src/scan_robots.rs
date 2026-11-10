//! robots.txt parsing.
use crate::model::RobotsInfo;
use crate::net::Resp;
use std::collections::BTreeSet;

const NOTABLE: &[&str] = &[
    "admin", "api", "internal", "private", "cart", "checkout", "login", "auth", "search",
    "user", "account", "cabinet", "personal", "cgi-bin", "wp-admin", "backup", "tmp",
];

pub fn parse(url: &str, resp: &Resp) -> RobotsInfo {
    let text = resp.text();
    let mut info = RobotsInfo {
        url: url.to_string(),
        status: resp.status,
        found: resp.status == 200 && text.to_ascii_lowercase().contains("user-agent"),
        ..Default::default()
    };
    if !info.found {
        return info;
    }
    let mut sitemaps = BTreeSet::new();
    let mut disallow: Vec<String> = Vec::new();
    let mut allow: Vec<String> = Vec::new();
    let mut agents: BTreeSet<String> = BTreeSet::new();
    for raw in text.lines().take(4000) {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().to_string();
        match key.as_str() {
            "user-agent" => {
                agents.insert(val.to_ascii_lowercase());
            }
            "sitemap" => {
                if !val.is_empty() {
                    sitemaps.insert(val);
                }
            }
            "disallow" => {
                if !val.is_empty() && disallow.len() < 200 {
                    disallow.push(val);
                }
            }
            "allow" => {
                if !val.is_empty() && allow.len() < 200 {
                    allow.push(val);
                }
            }
            "crawl-delay" => info.crawl_delay = Some(val),
            _ => {}
        }
    }
    info.sitemaps = sitemaps.into_iter().collect();
    info.agents = agents.into_iter().collect();
    let mut notable: Vec<String> = Vec::new();
    let mut seen_notable = BTreeSet::new();
    for d in disallow.iter() {
        let low = d.to_ascii_lowercase();
        if NOTABLE.iter().any(|n| low.contains(n)) && seen_notable.insert(d.clone()) {
            notable.push(d.clone());
        }
    }
    notable.truncate(10);
    info.notable = notable;
    info.notes.push(format!(
        "{} правил Disallow, {} Allow, {} пользовательских групп",
        disallow.len(),
        allow.len(),
        info.agents.len()
    ));
    if disallow.len() == 1 && disallow[0] == "/" {
        info.notes.push("весь сайт закрыт для роботов (Disallow: /)".into());
    }
    if let Some(cd) = &info.crawl_delay {
        info.notes.push(format!("crawl-delay: {cd} — держи паузы между запросами"));
    }
    info.disallow = disallow.into_iter().take(40).collect();
    info.allow = allow.into_iter().take(20).collect();
    info
}
