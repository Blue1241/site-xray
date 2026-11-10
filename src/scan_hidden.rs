//! Opt-in checks of common paths. Responses are never cached or followed off-site.
use crate::model::{HiddenFinding, HiddenReport};
use crate::net::{Net, Resp};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const PATHS: &[&str] = &[
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local",
    "/backup.zip", "/backup.sql", "/database.sql",
    "/admin/", "/administrator/", "/panel/", "/login/",
    "/phpinfo.php", "/info.php", "/test.php",
    "/api/", "/api/v1/", "/api/users", "/api/config",
    "/wp-admin/", "/wp-json/wp/v2/users", "/server-status", "/actuator/health",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/.well-known/security.txt", "/humans.txt",
];
const BODY_LIMIT: usize = 64 * 1024;
const DELAY: Duration = Duration::from_millis(200);

pub struct HiddenScanner {
    base_url: String,
}

impl HiddenScanner {
    pub fn new(base_url: &str) -> Self {
        Self { base_url: base_url.trim_end_matches('/').to_string() }
    }

    /// `disabled` explains why active requests were not authorised/possible.
    pub fn scan(&self, net: &Net, disabled: Option<&str>) -> HiddenReport {
        let mut report = HiddenReport { total: PATHS.len(), ..HiddenReport::default() };
        if let Some(reason) = disabled {
            report.warnings.push(format!("Активные запросы пропущены: {reason}."));
            return report;
        }
        // A random missing path detects common soft-404 and catch-all responses.
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let missing = format!("{}/.site-xray-missing-{nonce:x}", self.base_url);
        let baseline = match net.get_probe(&missing, BODY_LIMIT, Duration::from_secs(3)) {
            Ok(resp) if resp.status == 429 || resp.status == 503 => {
                report.warnings.push(format!("HTTP {} на контрольном пути: проверка остановлена.", resp.status));
                return report;
            }
            Ok(resp) => Some(resp),
            Err(_) => {
                report.warnings.push("Не удалось проверить ответ для несуществующего пути; возможны ложные совпадения.".into());
                None
            }
        };
        pause(net);
        let mut errors = 0;
        for path in PATHS {
            if expired(net) { break; }
            let url = format!("{}{path}", self.base_url);
            report.attempted += 1;
            match net.get_probe(&url, BODY_LIMIT, Duration::from_secs(3)) {
                Ok(resp) => {
                    report.checked += 1;
                    if resp.status == 429 || resp.status == 503 {
                        report.warnings.push(format!("HTTP {}: проверка путей остановлена, чтобы не увеличивать нагрузку.", resp.status));
                        break;
                    }
                    let soft_404 = baseline.as_ref().is_some_and(|base| same_as_missing(base, &resp));
                    if resp.status != 404 && resp.status != 403 && !soft_404 {
                        report.findings.push(HiddenFinding {
                            path: (*path).to_string(), status: resp.status, location: safe_location(&resp),
                        });
                    }
                }
                Err(_) => errors += 1,
            }
            pause(net);
        }
        if errors > 0 { report.warnings.push(format!("Нет ответа для {errors} путей (ошибка или таймаут).")); }
        if report.attempted < report.total {
            report.warnings.push(format!("Проверка неполная: попыток {}/{} (бюджет или остановка).", report.attempted, report.total));
        }
        report
    }
}

fn expired(net: &Net) -> bool {
    matches!(net.remaining(), Some(left) if left.is_zero())
}

fn pause(net: &Net) {
    let delay = net.remaining().map(|left| left.min(DELAY)).unwrap_or(DELAY);
    if !delay.is_zero() { std::thread::sleep(delay); }
}

fn same_as_missing(base: &Resp, candidate: &Resp) -> bool {
    if base.status != candidate.status { return false; }
    if (300..400).contains(&base.status) && base.header("location").is_some()
        && base.header("location") == candidate.header("location") { return true; }
    if base.body == candidate.body { return true; }
    // Some soft-404 templates echo the requested path.
    let normal = |resp: &Resp| -> Option<String> {
        let path = Url::parse(&resp.requested).ok()?.path().to_string();
        let text = std::str::from_utf8(&resp.body).ok()?;
        Some(text.replace(&path, "[PATH]"))
    };
    match (normal(base), normal(candidate)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn safe_location(resp: &Resp) -> Option<String> {
    let base = Url::parse(&resp.requested).ok()?;
    let mut location = base.join(&resp.header("location")?).ok()?;
    if !matches!(location.scheme(), "http" | "https") { return None; }
    location.set_query(None);
    location.set_fragment(None);
    let _ = location.set_username("");
    let _ = location.set_password(None);
    Some(location.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    fn response(url: &str, status: u16, body: &str) -> Resp {
        Resp { requested: url.into(), final_url: url.into(), status, headers: HeaderMap::new(),
            body: body.as_bytes().to_vec(), truncated: false, ms: 0, redirects: vec![], http_version: "HTTP/1.1".into() }
    }

    #[test]
    fn filters_static_and_reflecting_soft_404s() {
        let base = response("http://example.test/missing", 200, "Not found: /missing");
        assert!(same_as_missing(&base, &response("http://example.test/.env", 200, "Not found: /.env")));
        assert!(!same_as_missing(&base, &response("http://example.test/.env", 200, "real config")));
        assert!(!same_as_missing(&base, &response("http://example.test/.env", 401, "Not found: /.env")));
    }

    #[test]
    fn rate_limit_on_baseline_stops_before_probing_paths() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let flag = stop.clone();
        let requests = count.clone();
        let server = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut buf = [0; 2048];
                        if stream.read(&mut buf).is_err() { continue; }
                        requests.fetch_add(1, Ordering::Relaxed);
                        let _ = stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        });
        let mut net = Net::new(2, false).unwrap();
        net.set_deadline(Duration::from_secs(2));
        let report = HiddenScanner::new(&format!("http://{addr}")).scan(&net, None);
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert_eq!(report.attempted, 0);
        assert!(report.warnings.iter().any(|w| w.contains("429")));
    }
}
