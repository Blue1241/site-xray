//! Data model for the X-Ray report. Everything here is serializable to JSON.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HttpInfo {
    pub requested: String,
    pub final_url: String,
    pub status: u16,
    pub redirect_chain: Vec<String>,
    pub ms: u64,
    pub size_bytes: usize,
    pub truncated: bool,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub content_type: Option<String>,
    pub http_version: String,
    pub lang: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub canonical: Option<String>,
    pub generator: Option<String>,
    pub meta_robots: Option<String>,
    pub tls: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RobotsInfo {
    pub url: String,
    pub status: u16,
    pub found: bool,
    pub sitemaps: Vec<String>,
    pub disallow: Vec<String>,
    pub allow: Vec<String>,
    pub crawl_delay: Option<String>,
    pub agents: Vec<String>,
    pub notable: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SitemapDoc {
    pub url: String,
    pub status: u16,
    pub kind: String,
    pub urls: usize,
    pub gz: bool,
    pub lastmod: bool,
    pub truncated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SitemapReport {
    pub tried: Vec<String>,
    pub docs: Vec<SitemapDoc>,
    pub total_urls: usize,
    pub has_lastmod: bool,
    pub kinds: Vec<String>,
    pub nested_indexes: usize,
    pub truncated_docs: usize,
    pub sample_urls: Vec<String>,
    pub errors: Vec<String>,
}

impl SitemapReport {
    pub fn found(&self) -> bool {
        !self.docs.is_empty()
    }
    pub fn primary(&self) -> Option<&SitemapDoc> {
        self.docs.iter().find(|d| d.kind != "sitemapindex")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FeedInfo {
    pub url: String,
    pub status: u16,
    pub kind: String, // rss / atom / json-feed
    pub title: Option<String>,
    pub items: usize,
    pub latest: Option<String>,
    pub declared: bool,
    pub bytes: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct JsonLdReport {
    pub blocks: usize,
    pub valid: usize,
    pub types: Vec<String>,
    pub props: Vec<String>,
    pub samples: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Endpoint {
    pub path: String,
    pub score: u32,
    pub kind: String, // json / graphql / wp-rest / next-data / api / form / feed
    pub evidence: String,
    pub hits: usize,
    pub status: Option<u16>,
    pub ctype: Option<String>,
    pub verified: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct JsReport {
    pub scripts_declared: usize,
    pub bundles_scanned: usize,
    pub bundles_bytes: usize,
    pub endpoints: Vec<Endpoint>,
    pub inline_states: Vec<String>,
    pub notes: Vec<String>,
}

/// A name found in a public source or confirmed by a dictionary DNS lookup.
/// A `*.` prefix denotes a certificate wildcard, not a confirmed DNS host.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SubdomainFinding {
    pub name: String,
    pub sources: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SubdomainSource {
    pub name: String,
    pub status: String,
    pub records: usize,
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SubdomainReport {
    pub domain: Option<String>,
    pub subdomains: Vec<SubdomainFinding>,
    pub sources: Vec<SubdomainSource>,
    pub dictionary_checked: usize,
    pub dictionary_total: usize,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HiddenFinding {
    pub path: String,
    pub status: u16,
    /// Redirects are not followed during active checks.
    pub location: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HiddenReport {
    pub attempted: usize,
    pub checked: usize,
    pub total: usize,
    pub findings: Vec<HiddenFinding>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PhpForm {
    pub action: String,
    pub method: String,
    pub same_origin: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PhpParameter {
    /// The endpoint is reported without query values or credentials.
    pub endpoint: String,
    pub name: String,
    pub method: String,
    pub source: String,
    pub idor_candidate: bool,
    pub tested: bool,
    pub skip_reason: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PhpFinding {
    pub endpoint: String,
    pub parameter: String,
    pub status: u16,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PhpReport {
    pub forms: Vec<PhpForm>,
    pub parameters: Vec<PhpParameter>,
    pub sql_errors: Vec<PhpFinding>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HeaderCheck {
    pub name: String,
    pub present: bool,
    pub value: Option<String>,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Probe {
    pub url: String,
    pub status: u16,
    pub note: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SecurityReport {
    pub headers: Vec<HeaderCheck>,
    pub score: u32,
    pub grade: String,
    pub cdn_waf: Vec<String>,
    pub bot_protection: Vec<String>,
    pub cookies: Vec<String>,
    pub extras: Vec<Probe>,
    pub tls: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TechHit {
    pub name: String,
    pub category: String,
    pub evidence: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub score: u32,
    pub available: bool,
    pub summary: String,
    pub details: Vec<String>,
    pub how_to: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Verdict {
    pub best: Option<String>,
    pub headline: String,
    pub reasons: Vec<String>,
    pub cautions: Vec<String>,
    pub plan: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CorsInfo { pub allow_origin: Option<String>, pub allow_methods: Option<String>, pub allow_headers: Option<String>, pub credentials: Option<String>, pub verdict: String }

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub generated_at: String,
    pub elapsed_ms: u64,
    pub target: String,
    pub http: HttpInfo,
    pub cors: CorsInfo,
    pub robots: Option<RobotsInfo>,
    pub sitemaps: SitemapReport,
    pub feeds: Vec<FeedInfo>,
    pub jsonld: JsonLdReport,
    pub js: JsReport,
    pub security: SecurityReport,
    pub tech: Vec<TechHit>,
    /// Optional scans are omitted from JSON unless explicitly requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomains: Option<SubdomainReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<HiddenReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub php: Option<PhpReport>,
    pub channels: Vec<Channel>,
    pub verdict: Verdict,
}
