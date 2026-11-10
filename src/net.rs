//! Tiny HTTP layer: manual redirect following (so the report can show the chain),
//! hard body size limits, gzip sniffing and charset-aware decoding.
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, ACCEPT, ACCEPT_LANGUAGE, CACHE_CONTROL};
use reqwest::redirect::Policy;
use std::io::Read;
use std::time::{Duration, Instant};
use url::Url;

pub const UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

#[derive(Clone)]
pub struct Resp {
    pub requested: String,
    pub final_url: String,
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub truncated: bool,
    pub ms: u64,
    pub redirects: Vec<String>,
    pub http_version: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
    }
    pub fn text(&self) -> String {
        let ctype = self.header("content-type");
        decode(&self.body, ctype.as_deref())
    }
    pub fn content_type(&self) -> Option<String> {
        self.header("content-type").map(|c| {
            c.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
        })
    }
    pub fn is_html(&self) -> bool {
        match self.content_type() {
            Some(ct) => ct.contains("html") || ct.contains("xml"),
            None => true,
        }
    }
}

pub struct Net {
    client: Client,
    max_body: usize,
    pub timeout: Duration,
    /// Hard wall-clock deadline for optional work (probes, bundles, sitemaps).
    deadline: Option<Instant>,
    cache: Option<(String,bool,bool)>,
}

impl Net {
    pub fn new(timeout_secs: u64, insecure: bool) -> Result<Net, String> {
        let client = Client::builder()
            .user_agent(UA)
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(6))
            .redirect(Policy::none())
            .cookie_store(true)
            .danger_accept_invalid_certs(insecure)
            .gzip(true)
            .brotli(true)
            .deflate(true)
            .pool_max_idle_per_host(16)
            .build()
            .map_err(|e| format!("не удалось создать HTTP-клиент: {e}"))?;
        Ok(Net {
            client,
            max_body: 4 * 1024 * 1024,
            timeout: Duration::from_secs(timeout_secs),
            deadline: None,
            cache: None,
        })
    }

    /// A second handle with its own deadline, sharing the connection pool and cookie jar.
    pub fn fork(&self) -> Net {
        Net {
            client: self.client.clone(),
            max_body: self.max_body,
            timeout: self.timeout,
            deadline: self.deadline,
            cache: self.cache.clone(),
        }
    }

    pub fn configure_cache(&mut self, dir: String, enabled: bool, offline: bool) { self.cache = if enabled || offline { Some((dir, enabled, offline)) } else { None }; }

    /// Everything except the homepage is "optional": past this instant we stop starting new requests.
    pub fn set_deadline(&mut self, after: Duration) {
        self.deadline = Some(Instant::now() + after);
    }

    fn remaining(&self) -> Option<Duration> {
        self.deadline.map(|d| d.saturating_duration_since(Instant::now()))
    }

    pub fn get(&self, url: &str) -> Result<Resp, String> {
        self.get_limited(url, self.max_body)
    }

    pub fn get_limited(&self, url: &str, max: usize) -> Result<Resp, String> {
        self.get_limited_t(url, max, self.timeout)
    }

    /// Same as `get_limited`, but with a per-request timeout (used for cheap probes).
    pub fn get_limited_t(&self, url: &str, max: usize, timeout: Duration) -> Result<Resp, String> {
        if let Some((dir, write, offline)) = &self.cache {
            let key = format!("{:016x}", { use std::hash::{Hash,Hasher}; let mut h=std::collections::hash_map::DefaultHasher::new(); url.hash(&mut h); h.finish() });
            let path = std::path::Path::new(dir).join(format!("{key}.json"));
            if path.exists() { if let Ok(data)=std::fs::read(&path) { if let Ok(c)=serde_json::from_slice::<Cached>(&data) { return Ok(c.into_resp(url)); } } }
            if *offline { return Err(format!("нет ответа в офлайн-кэше: {url}")); }
            let result=self.fetch_live(url,max,timeout)?;
            if *write { let _=std::fs::create_dir_all(dir); let c=Cached::from_resp(&result); if let Ok(data)=serde_json::to_vec(&c) { let _=std::fs::write(path,data); } }
            return Ok(result);
        }
        self.fetch_live(url,max,timeout)
    }

    fn fetch_live(&self, url: &str, max: usize, timeout: Duration) -> Result<Resp,String> {
        let timeout = match self.remaining() {
            Some(left) if left.is_zero() => return Err("пропущено: бюджет времени исчерпан".to_string()),
            Some(left) => timeout.min(left),
            None => timeout,
        };
        let mut current = url.to_string();
        let mut chain: Vec<String> = Vec::new();
        let mut total_ms: u64 = 0;
        let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for _hop in 0..12 {
            if !visited.insert(current.clone()) {
                break;
            }
            let started = Instant::now();
            let resp = self
                .client
                .get(&current)
                .timeout(timeout)
                .header(ACCEPT, "text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8")
                .header(ACCEPT_LANGUAGE, "ru,en;q=0.8")
                .header(CACHE_CONTROL, "no-cache")
                .send()
                .map_err(|e| short_err(e))?;
            let elapsed = started.elapsed().as_millis() as u64;
            total_ms += elapsed;
            let status = resp.status().as_u16();
            let version = match resp.version() {
                reqwest::Version::HTTP_2 => "HTTP/2",
                reqwest::Version::HTTP_11 => "HTTP/1.1",
                reqwest::Version::HTTP_10 => "HTTP/1.0",
                other => return_version(other),
            }
            .to_string();

            if (300..400).contains(&status) {
                if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                    let next = Url::parse(&current)
                        .ok()
                        .and_then(|base| base.join(loc.trim()).ok())
                        .map(|u| u.to_string());
                    if let Some(next) = next {
                        chain.push(format!("{status} → {current}"));
                        current = next;
                        continue;
                    }
                }
            }

            let headers = resp.headers().clone();
            let mut body = Vec::new();
            let truncated = {
                let mut take = resp.take(max as u64);
                take.read_to_end(&mut body).map_err(|e| e.to_string())?;
                body.len() >= max
            };
            return Ok(Resp {
                requested: url.to_string(),
                final_url: current,
                status,
                headers,
                body,
                truncated,
                ms: total_ms,
                redirects: chain,
                http_version: version,
            });
        }
        Err("слишком много редиректов ( > 12 )".to_string())
    }

    /// Fetch a batch of URLs in parallel (bounded), keeping the input order.
    pub fn get_many(&self, urls: &[String], max: usize, parallel: usize) -> Vec<Result<Resp, String>> {
        self.get_many_t(urls, max, parallel, self.timeout)
    }

    pub fn get_many_t(&self, urls: &[String], max: usize, parallel: usize, timeout: Duration) -> Vec<Result<Resp, String>> {
        let parallel = parallel.max(1);
        let mut out: Vec<Option<Result<Resp, String>>> = (0..urls.len()).map(|_| None).collect();
        for chunk in 0..urls.len().div_ceil(parallel) {
            let start = chunk * parallel;
            let end = (start + parallel).min(urls.len());
            if matches!(self.remaining(), Some(left) if left.is_zero()) {
                for slot in out.iter_mut().skip(start) {
                    *slot = Some(Err("пропущено: бюджет времени исчерпан".to_string()));
                }
                break;
            }
            std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for i in start..end {
                    let url = urls[i].clone();
                    handles.push((i, scope.spawn(move || self.get_limited_t(&url, max, timeout))));
                }
                for (i, h) in handles {
                    if let Ok(res) = h.join() {
                        out[i] = Some(res);
                    }
                }
            });
        }
        out.into_iter()
            .map(|o| o.unwrap_or_else(|| Err("поток упал".to_string())))
            .collect()
    }
}

#[derive(serde::Serialize,serde::Deserialize)]
struct Cached { status:u16, final_url:String, body:Vec<u8>, headers:Vec<(String,String)>, truncated:bool, ms:u64, redirects:Vec<String>, http_version:String }
impl Cached {
 fn from_resp(r:&Resp)->Self { Self { status:r.status, final_url:r.final_url.clone(), body:r.body.clone(), headers:r.headers.iter().filter_map(|(k,v)|v.to_str().ok().map(|x|(k.to_string(),x.to_string()))).collect(), truncated:r.truncated, ms:r.ms, redirects:r.redirects.clone(), http_version:r.http_version.clone() } }
 fn into_resp(self,url:&str)->Resp { let mut h=HeaderMap::new(); for (k,v) in self.headers { if let (Ok(k),Ok(v))=(reqwest::header::HeaderName::from_bytes(k.as_bytes()),reqwest::header::HeaderValue::from_str(&v)){h.insert(k,v);} } Resp {requested:url.into(),final_url:self.final_url,status:self.status,headers:h,body:self.body,truncated:self.truncated,ms:self.ms,redirects:self.redirects,http_version:self.http_version} }
}

fn return_version(v: reqwest::Version) -> &'static str {
    let _ = v;
    "HTTP/?"
}

fn short_err(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "таймаут".to_string()
    } else if e.is_connect() {
        format!("не удалось подключиться ({})", e.source_hint())
    } else if e.is_body() || e.is_decode() {
        format!("ошибка тела ответа ({})", e.source_hint())
    } else {
        let s = e.to_string();
        if s.len() > 120 {
            format!("{}…", &s[..120])
        } else {
            s
        }
    }
}

trait SourceHint {
    fn source_hint(&self) -> String;
}
impl SourceHint for reqwest::Error {
    fn source_hint(&self) -> String {
        self.source()
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.to_string())
    }
}
use std::error::Error;

/// Decode bytes to text: BOM → Content-Type charset → <meta charset> sniff → UTF-8 lossy.
pub fn decode(bytes: &[u8], content_type: Option<&str>) -> String {
    let bytes = if is_gzip(bytes) { &gunzip(bytes)[..] } else { bytes };
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).to_string();
    }
    let mut label: Option<String> = None;
    if let Some(ct) = content_type {
        for part in ct.split(';') {
            let p = part.trim();
            if let Some(rest) = p.to_ascii_lowercase().strip_prefix("charset=") {
                label = Some(rest.trim_matches('"').to_string());
            }
        }
    }
    if label.is_none() {
        let head = &bytes[..bytes.len().min(4096)];
        let sniff = String::from_utf8_lossy(head).to_ascii_lowercase();
        if let Some(pos) = sniff.find("charset=") {
            let rest = &sniff[pos + 8..];
            let cand: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if cand.len() >= 3 {
                label = Some(cand);
            }
        }
    }
    if let Some(l) = label {
        if let Some(enc) = encoding_rs::Encoding::for_label(l.as_bytes()) {
            let (cow, _, _) = enc.decode(bytes);
            return cow.into_owned();
        }
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).to_string(),
    }
}

pub fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

pub fn gunzip(bytes: &[u8]) -> Vec<u8> {
    use flate2::read::GzDecoder;
    let mut out = Vec::new();
    let mut dec = GzDecoder::new(bytes);
    if dec.read_to_end(&mut out).is_ok() {
        out
    } else {
        bytes.to_vec()
    }
}

/// Join a possibly relative URL against a base, returning an absolute http(s) URL.
pub fn absolutize(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() || href.starts_with("data:") || href.starts_with("javascript:") || href.starts_with("mailto:") || href.starts_with('#') {
        return None;
    }
    let base = Url::parse(base).ok()?;
    let joined = base.join(href).ok()?;
    if joined.scheme() != "http" && joined.scheme() != "https" {
        return None;
    }
    Some(joined.to_string())
}

pub fn host_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default()
}

pub fn origin_of(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or(""), if let Some(p) = u.port() { format!(":{p}") } else { String::new() }),
        Err(_) => url.to_string(),
    }
}
