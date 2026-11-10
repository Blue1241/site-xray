//! Direct probing of well-known machine-readable endpoints.
//! A hit here beats any JS-bundle guessing: the site answers with JSON on purpose.
use crate::model::Endpoint;
use crate::net::Net;
use std::time::Duration;

const PROBES: &[(&str, &str, &str, u32)] = &[
    // path, kind, label, base score
    ("/wp-json/wp/v2/posts?per_page=2", "wp-rest", "WordPress REST: /wp-json/wp/v2/posts", 88),
    ("/wp-json", "wp-rest", "WordPress REST-индекс /wp-json", 74),
    ("/products.json", "json", "Shopify /products.json", 86),
    ("/index.json", "json", "статический index.json", 78),
    ("/feed.json", "json", "JSON Feed", 76),
    ("/search.json?q=a", "json", "статистический search.json", 66),
    ("/openapi.json", "api", "OpenAPI-спека", 88),
    ("/swagger.json", "api", "Swagger-спека", 86),
    ("/.well-known/openapi.json", "api", "OpenAPI в .well-known", 86),
    ("/graphql?query=%7B__typename%7D", "graphql", "GraphQL (GET-интроспекция)", 84),
    ("/api/v1", "api", "корень /api/v1", 66),
    ("/api", "api", "корень /api", 60),
    ("/data.json", "json", "data.json", 62),
];

pub fn probe(net: &Net, origin: &str) -> Vec<Endpoint> {
    let urls: Vec<String> = PROBES.iter().map(|(p, _, _, _)| format!("{origin}{p}")).collect();
    let results = net.get_many_t(&urls, 96 * 1024, 8, Duration::from_secs(3));
    let mut out = Vec::new();
    for ((path, kind, label, score), res) in PROBES.iter().zip(results.into_iter()) {
        let Ok(resp) = res else { continue };
        if resp.status != 200 || resp.body.len() < 16 {
            continue;
        }
        let ctype = resp.content_type();
        let text = resp.text();
        let trimmed = text.trim_start();
        let is_json = ctype.as_deref().map(|c| c.contains("json")).unwrap_or(false)
            || trimmed.starts_with('{')
            || trimmed.starts_with('[');
        if !is_json {
            continue;
        }
        // A JSON error stub is not an API.
        let low = text.to_ascii_lowercase();
        if text.len() < 60 && (low.contains("not found") || low.contains("forbidden") || low.contains("error")) {
            continue;
        }
        out.push(Endpoint {
            path: path.to_string(),
            score: *score,
            kind: kind.to_string(),
            evidence: format!("{} · пробой стандартного пути", label),
            hits: 1,
            status: Some(resp.status),
            ctype,
            verified: true,
        });
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out
}
