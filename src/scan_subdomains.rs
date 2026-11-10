//! Public-source subdomain discovery and a small, bounded DNS dictionary.
use crate::model::{SubdomainFinding, SubdomainReport, SubdomainSource};
use crate::net::{Net, Resp};
use scraper::{Html, Selector};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const WORDS: &[&str] = &[
    "www", "mail", "webmail", "api", "app", "admin", "portal", "dev", "staging", "stage",
    "test", "vpn", "ftp", "autodiscover", "m", "cdn", "static", "blog", "docs", "status",
];
const MAX_NAMES: usize = 1000;
const SOURCE_LIMIT: usize = 2 * 1024 * 1024;
const DNS_LIMIT: usize = 32 * 1024;

pub struct SubdomainScanner {
    domain: Option<String>,
}

struct Sources {
    crt: String,
    rapid: String,
    dns: String,
}

impl SubdomainScanner {
    pub fn new(host: &str) -> Self {
        Self { domain: registrable_domain(host) }
    }

    pub fn scan(&self, net: &Net, verify_dns: bool, offline: bool) -> SubdomainReport {
        let Some(domain) = &self.domain else {
            return SubdomainReport {
                dictionary_total: WORDS.len(),
                warnings: vec!["Для IP, localhost или неизвестного публичного суффикса поиск поддоменов не выполняется.".into()],
                ..SubdomainReport::default()
            };
        };
        let sources = Sources {
            crt: format!("https://crt.sh/?q=%25.{domain}&output=json"),
            rapid: format!("https://rapiddns.io/subdomain/{domain}?full=1"),
            dns: "https://dns.google/resolve".into(),
        };
        self.scan_with_sources(net, verify_dns, offline, &sources)
    }

    fn scan_with_sources(&self, net: &Net, verify_dns: bool, offline: bool, sources: &Sources) -> SubdomainReport {
        let Some(domain) = &self.domain else { return SubdomainReport::default() };
        let mut report = SubdomainReport {
            domain: Some(domain.clone()),
            dictionary_total: WORDS.len(),
            ..SubdomainReport::default()
        };
        let mut names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let urls = vec![sources.crt.clone(), sources.rapid.clone()];
        let results = net.get_many_t(&urls, SOURCE_LIMIT, 2, Duration::from_secs(4).min(net.timeout));
        for (source, result) in ["crt.sh", "RapidDNS"].into_iter().zip(results) {
            let parsed = result.and_then(|resp| {
                if resp.status != 200 {
                    return Err(format!("HTTP {}", resp.status));
                }
                if resp.truncated {
                    return Err("ответ обрезан по лимиту размера".into());
                }
                if source == "crt.sh" {
                    parse_crt(&resp.text(), domain)
                } else {
                    parse_rapid(&resp.text(), domain)
                }
            });
            match parsed {
                Ok(found) => {
                    let count = found.len();
                    for name in found {
                        insert_name(&mut names, name, source);
                    }
                    report.sources.push(SubdomainSource { name: source.into(), status: "ok".into(), records: count, message: None });
                }
                Err(message) => report.sources.push(SubdomainSource { name: source.into(), status: "error".into(), records: 0, message: Some(message) }),
            }
        }

        if offline || !verify_dns {
            report.sources.push(SubdomainSource {
                name: "DNS-словарь".into(), status: "skipped".into(), records: 0,
                message: Some(if offline { "--offline" } else { "--no-verify" }.into()),
            });
        } else {
            let source = scan_dictionary(net, domain, &sources.dns, &mut names, &mut report);
            report.sources.push(source);
        }
        if names.len() > MAX_NAMES {
            report.warnings.push(format!("Показаны первые {MAX_NAMES} имён; остальные отброшены."));
        }
        report.subdomains = names.into_iter().take(MAX_NAMES)
            .map(|(name, sources)| SubdomainFinding { name, sources: sources.into_iter().collect() })
            .collect();
        report
    }
}

/// PSL handles multi-label and private suffixes (co.uk, github.io, …).
fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return None;
    }
    let parsed = Url::parse(&format!("http://{host}/")).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !valid_host(&host) || !psl::suffix(host.as_bytes())?.is_known() {
        return None;
    }
    psl::domain_str(&host).map(str::to_string)
}

fn valid_host(host: &str) -> bool {
    host.len() <= 253 && !host.is_empty() && host.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Require an exact label boundary, not a naive `ends_with(domain)` check.
fn normalize_name(raw: &str, domain: &str) -> Option<String> {
    let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let (wildcard, host) = match raw.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, raw.as_str()),
    };
    if !valid_host(host) || !(host == domain || host.ends_with(&format!(".{domain}"))) {
        return None;
    }
    if !wildcard && host == domain {
        return None;
    }
    Some(if wildcard { format!("*.{host}") } else { host.to_string() })
}

fn insert_name(names: &mut BTreeMap<String, BTreeSet<String>>, name: String, source: &str) {
    names.entry(name).or_default().insert(source.to_string());
}

fn parse_crt(body: &str, domain: &str) -> Result<BTreeSet<String>, String> {
    let json: Value = serde_json::from_str(body).map_err(|e| format!("некорректный JSON: {e}"))?;
    let entries = json.as_array().ok_or("crt.sh вернул не массив JSON")?;
    let mut names = BTreeSet::new();
    for item in entries {
        if let Some(value) = item.get("name_value").and_then(Value::as_str) {
            for line in value.lines() {
                if let Some(name) = normalize_name(line, domain) { names.insert(name); }
            }
        }
    }
    Ok(names)
}

fn parse_rapid(body: &str, domain: &str) -> Result<BTreeSet<String>, String> {
    let doc = Html::parse_document(body);
    let table = Selector::parse("table").expect("static selector");
    if doc.select(&table).next().is_none() {
        return Err("RapidDNS вернул страницу без таблицы результатов".into());
    }
    let selector = Selector::parse("td").expect("static selector");
    Ok(doc.select(&selector).filter_map(|cell| {
        let text = cell.text().collect::<String>();
        normalize_name(&text, domain)
    }).collect())
}

fn dns_url(base: &str, host: &str, kind: &str) -> Option<String> {
    let mut url = Url::parse(base).ok()?;
    url.query_pairs_mut().append_pair("name", host).append_pair("type", kind);
    Some(url.to_string())
}

/// Google DNS JSON API: NXDOMAIN and NOERROR/no answers are successful lookups.
/// A CNAME also counts when checking for wildcard DNS, but only an IP proves a
/// dictionary name resolved.
fn dns_answer(resp: Resp) -> Result<(bool, bool), String> {
    if resp.status != 200 || resp.truncated {
        return Err(format!("DNS: HTTP {} или обрезанный ответ", resp.status));
    }
    let value: Value = serde_json::from_slice(&resp.body).map_err(|_| "DNS вернул некорректный JSON")?;
    match value.get("Status").and_then(Value::as_u64) {
        Some(0 | 3) => (),
        Some(status) => return Err(format!("DNS: код {status}")),
        None => return Err("DNS: отсутствует Status".into()),
    }
    let mut record = false;
    let mut address = false;
    if let Some(answers) = value.get("Answer").and_then(Value::as_array) {
        for answer in answers {
            let kind = answer.get("type").and_then(Value::as_u64).unwrap_or(0);
            if matches!(kind, 1 | 5 | 28) { record = true; }
            if matches!(kind, 1 | 28) && answer.get("data").and_then(Value::as_str)
                .and_then(|s| s.parse::<IpAddr>().ok()).is_some() { address = true; }
        }
    }
    Ok((record, address))
}

fn scan_dictionary(net: &Net, domain: &str, dns: &str, names: &mut BTreeMap<String, BTreeSet<String>>, report: &mut SubdomainReport) -> SubdomainSource {
    let mut source = SubdomainSource { name: "DNS-словарь".into(), ..SubdomainSource::default() };
    // If the zone resolves arbitrary names, dictionary matches are not reliable.
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let sentinel = format!("site-xray-{nonce:x}.{domain}");
    let sentinel_urls: Vec<String> = ["A", "AAAA"].iter().filter_map(|kind| dns_url(dns, &sentinel, kind)).collect();
    if sentinel_urls.len() != 2 {
        source.status = "error".into(); source.message = Some("неверный URL DNS-сервиса".into()); return source;
    }
    let baseline = net.get_many_t(&sentinel_urls, DNS_LIMIT, 2, Duration::from_secs(3).min(net.timeout));
    let mut wildcard = false;
    for response in baseline {
        match response.and_then(dns_answer) {
            Ok((record, _)) => wildcard |= record,
            Err(e) => { source.status = "error".into(); source.message = Some(format!("не удалось проверить wildcard DNS: {e}")); return source; }
        }
    }
    if wildcard {
        source.status = "skipped".into();
        source.message = Some("обнаружен wildcard DNS; результаты словаря ненадёжны".into());
        return source;
    }

    let mut urls = Vec::with_capacity(WORDS.len() * 2);
    for word in WORDS {
        let host = format!("{word}.{domain}");
        for kind in ["A", "AAAA"] {
            if let Some(url) = dns_url(dns, &host, kind) { urls.push(url); }
        }
    }
    let results = net.get_many_t(&urls, DNS_LIMIT, 4, Duration::from_secs(3).min(net.timeout));
    let mut failed = 0;
    for (word, pair) in WORDS.iter().zip(results.chunks(2)) {
        let mut address = false;
        let mut complete = pair.len() == 2;
        for response in pair {
            match response.clone().and_then(dns_answer) {
                Ok((_, found)) => address |= found,
                Err(_) => complete = false,
            }
        }
        if complete { report.dictionary_checked += 1; } else { failed += 1; }
        if address {
            insert_name(names, format!("{word}.{domain}"), "DNS-словарь");
            source.records += 1;
        }
    }
    source.status = if failed == 0 { "ok" } else { "partial" }.into();
    if failed > 0 { source.message = Some(format!("неполных DNS-проверок: {failed} (таймаут, ошибка или бюджет)")); }
    source
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_public_suffix_list_and_rejects_non_domains() {
        assert_eq!(registrable_domain("ya.mininuniver.ru").as_deref(), Some("mininuniver.ru"));
        assert_eq!(registrable_domain("sub.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("foo.user.github.io").as_deref(), Some("user.github.io"));
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("internal.local"), None);
    }

    #[test]
    fn parses_multilevel_names_wildcards_and_label_boundaries() {
        let crt = r#"[{"name_value":"API.Example.com\n*.deep.example.com\nnotexample.com\nexample.com\nsub.api.example.com"}]"#;
        let names = parse_crt(crt, "example.com").unwrap();
        assert_eq!(names.into_iter().collect::<Vec<_>>(), vec!["*.deep.example.com", "api.example.com", "sub.api.example.com"]);
        let rapid = "<table><tr><td class='name'>www.example.com</td><td>evil-example.com</td><td><b>api.example.com</b></td></tr></table>";
        let names = parse_rapid(rapid, "example.com").unwrap();
        assert_eq!(names.into_iter().collect::<Vec<_>>(), vec!["api.example.com", "www.example.com"]);
        assert!(parse_rapid("<html><title>Access denied</title></html>", "example.com").is_err());
        assert!(parse_rapid("<table><tbody></tbody></table>", "example.com").unwrap().is_empty());
    }

    #[test]
    fn public_sources_and_dictionary_work_independently_with_wildcard_detection() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0; 4096];
                        let Ok(n) = stream.read(&mut buf) else { continue };
                        let request = String::from_utf8_lossy(&buf[..n]);
                        let path = request.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("/");
                        let (status, body) = if path == "/crt" {
                            ("500 Error", "failed")
                        } else if path == "/rapid" {
                            ("200 OK", "<table><tr><td>api.example.com</td><td>badexample.com</td></tr></table>")
                        } else if path.starts_with("/wild?") {
                            ("200 OK", r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1"}]}"#)
                        } else if path.starts_with("/dns?") && path.contains("name=api.example.com") && path.contains("type=A") && !path.contains("type=AAAA") {
                            ("200 OK", r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1"}]}"#)
                        } else {
                            ("200 OK", r#"{"Status":3}"#)
                        };
                        let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
                    Err(_) => break,
                }
            }
        });
        let base = format!("http://{addr}");
        let sources = Sources { crt: format!("{base}/crt"), rapid: format!("{base}/rapid"), dns: format!("{base}/dns") };
        let mut net = Net::new(3, false).unwrap();
        net.set_deadline(Duration::from_secs(10));
        let scanner = SubdomainScanner::new("www.example.com");
        let report = scanner.scan_with_sources(&net, true, false, &sources);
        assert_eq!(report.sources[0].status, "error");
        assert_eq!(report.sources[1].status, "ok");
        assert_eq!(report.dictionary_checked, WORDS.len());
        let api = report.subdomains.iter().find(|f| f.name == "api.example.com").unwrap();
        assert!(api.sources.contains(&"RapidDNS".to_string()));
        assert!(api.sources.contains(&"DNS-словарь".to_string()));
        assert!(!report.subdomains.iter().any(|f| f.name == "badexample.com"));
        let wildcard = Sources { dns: format!("{base}/wild"), ..sources };
        let report = scanner.scan_with_sources(&net, true, false, &wildcard);
        assert_eq!(report.dictionary_checked, 0);
        assert!(report.sources[2].message.as_deref().unwrap().contains("wildcard"));
        stop.store(true, Ordering::Relaxed);
        thread.join().unwrap();
    }
}
