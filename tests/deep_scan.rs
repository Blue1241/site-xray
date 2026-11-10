use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TestServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start(redirect_to: Option<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let running = stop.clone();
        let seen = requests.clone();
        let thread = thread::spawn(move || {
            while !running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => handle(stream, &seen, redirect_to.as_deref()),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        });
        Self { addr, requests, stop, thread: Some(thread) }
    }
    fn url(&self) -> String { format!("http://{}/", self.addr) }
    fn seen(&self) -> Vec<String> { self.requests.lock().unwrap().clone() }
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}
impl Drop for TestServer { fn drop(&mut self) { self.shutdown(); } }

fn handle(mut stream: TcpStream, seen: &Arc<Mutex<Vec<String>>>, redirect_to: Option<&str>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut data = Vec::new();
    let mut buf = [0; 2048];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => { data.extend_from_slice(&buf[..n]); if data.windows(4).any(|s| s == b"\r\n\r\n") { break; } }
        }
    }
    let request = String::from_utf8_lossy(&data);
    let path = request.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("/");
    seen.lock().unwrap().push(path.to_string());
    let home = r#"<!doctype html><html><head><title>Local test</title></head><body>
      <form action='/search.php' method='GET'><input name='id'><input type='hidden' name='csrf_token' value='PRIVATE_TOKEN'></form>
      <form action='/false.php'><input name='q'></form>
      <form action='/big.php'><input name='term'></form>
      <form action='/private.php?csrf_token=PRIVATE_ACTION'><input name='q'></form>
      <form action='/login.php' method='POST'><input name='password'></form>
      <form action='http://external.invalid/collect'><input name='outside'></form>
      <a href='/search.php?id=123'>query</a><a href='/delete.php?id=1'>dangerous</a><a href='/?logout=1'>logout</a>
    </body></html>"#;
    let large_body = "x".repeat(100 * 1024);
    let (status, body, extra) = if path == "/" && redirect_to.is_some() {
        ("302 Found", "", format!("Location: {}\r\n", redirect_to.unwrap()))
    } else if path == "/" {
        ("200 OK", home, String::new())
    } else if path == "/.git/config" {
        ("200 OK", "SECRET_CONFIG_VALUE", String::new())
    } else if path == "/.git/HEAD" {
        ("302 Found", "", "Location: /redirect-target?token=PRIVATE_REDIRECT\r\n".into())
    } else if path == "/admin/" {
        ("200 OK", "local admin page", String::new())
    } else if path == "/.env" {
        ("403 Forbidden", "forbidden", String::new())
    } else if path.starts_with("/search.php?") {
        if path.contains("%27") {
            ("500 Internal Server Error", "You have an error in your SQL syntax", String::new())
        } else {
            ("200 OK", "normal search", String::new())
        }
    } else if path.starts_with("/false.php?") {
        ("200 OK", "SQL syntax appears on both baseline and test", String::new())
    } else if path.starts_with("/big.php?") {
        ("200 OK", if path.contains("%27") { large_body.as_str() } else { "baseline" }, String::new())
    } else {
        ("404 Not Found", "not found", String::new())
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len());
    let _ = stream.write_all(response.as_bytes());
}

fn run(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_site-xray")).args(args).output().unwrap();
    assert!(output.status.success(), "status {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    output
}

fn temp_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("site-xray-{name}-{}-{nonce}", std::process::id()))
}

#[test]
fn deep_scan_reports_candidates_without_leaking_bodies_or_following_redirects() {
    let server = TestServer::start(None);
    let cache = temp_path("cache");
    let output = run(&[&server.url(), "--deep", "--no-js", "--budget", "12", "--cache-dir", cache.to_str().unwrap(), "--json"]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["subdomains"]["domain"].is_null()); // IP: no external subdomain requests
    assert_eq!(report["hidden"]["total"].as_u64().unwrap(), 27);
    assert_eq!(report["hidden"]["checked"].as_u64().unwrap(), 27);
    let hidden = report["hidden"]["findings"].as_array().unwrap();
    assert!(hidden.iter().any(|f| f["path"] == "/.git/config" && f["status"] == 200));
    assert!(hidden.iter().any(|f| f["path"] == "/.git/HEAD" && f["status"] == 302));
    assert!(!hidden.iter().any(|f| f["path"] == "/.env"));
    let params = report["php"]["parameters"].as_array().unwrap();
    assert!(params.iter().any(|p| p["name"] == "id" && p["idor_candidate"] == true && p["tested"] == true));
    assert!(params.iter().any(|p| p["name"] == "outside" && p["tested"] == false));
    assert!(params.iter().any(|p| p["name"] == "password" && p["tested"] == false));
    assert!(params.iter().any(|p| p["name"] == "term" && p["tested"] == false
        && p["skip_reason"].as_str().unwrap_or("").contains("обрезан")));
    let findings = report["php"]["sql_errors"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["parameter"], "id");
    let output_text = String::from_utf8(output.stdout).unwrap();
    assert!(!output_text.contains("SECRET_CONFIG_VALUE"));
    assert!(!output_text.contains("PRIVATE_TOKEN"));
    assert!(!output_text.contains("PRIVATE_ACTION"));
    assert!(!output_text.contains("PRIVATE_REDIRECT"));
    let requests = server.seen();
    assert!(requests.iter().any(|r| r == "/search.php?id=test%27"));
    assert!(!requests.iter().any(|r| r.starts_with("/redirect-target")));
    assert!(!requests.iter().any(|r| r.starts_with("/delete.php?")));
    assert!(!requests.iter().any(|r| r.starts_with("/?logout=")));
    assert!(!requests.iter().any(|r| r.starts_with("/private.php?")));
    assert!(!requests.iter().any(|r| r.starts_with("/login.php?")));
    for entry in std::fs::read_dir(&cache).unwrap() {
        let value: Value = serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
        let bytes: Vec<u8> = serde_json::from_value(value["body"].clone()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("SECRET_CONFIG_VALUE"));
    }
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn no_verify_and_offline_do_not_run_active_checks() {
    let mut server = TestServer::start(None);
    let cache = temp_path("offline");
    let args = [&server.url(), "--deep", "--no-js", "--no-verify", "--cache-dir", cache.to_str().unwrap(), "--json"];
    let report: Value = serde_json::from_slice(&run(&args).stdout).unwrap();
    assert_eq!(report["hidden"]["attempted"], 0);
    assert!(report["php"]["parameters"].as_array().unwrap().iter().all(|p| p["tested"] == false));
    assert!(!server.seen().iter().any(|r| r == "/.git/config" || r.starts_with("/search.php?")));
    server.shutdown();
    let report: Value = serde_json::from_slice(&run(&[&server.url(), "--deep", "--offline", "--no-js", "--cache-dir", cache.to_str().unwrap(), "--json"]).stdout).unwrap();
    assert_eq!(report["hidden"]["attempted"], 0);
    assert!(report["hidden"]["warnings"].to_string().contains("--offline"));
    assert!(report["php"]["parameters"].as_array().unwrap().iter().all(|p| p["tested"] == false));
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn cross_host_redirect_does_not_authorize_the_new_host() {
    let target = TestServer::start(None);
    let redirect = TestServer::start(Some(target.url()));
    let report: Value = serde_json::from_slice(&run(&[&redirect.url(), "--hidden", "--php", "--no-js", "--no-cache", "--json"]).stdout).unwrap();
    assert_eq!(report["hidden"]["attempted"], 0);
    assert!(report["hidden"]["warnings"].to_string().contains("хост или порт"));
    assert!(report["php"]["parameters"].as_array().unwrap().iter().all(|p| p["tested"] == false));
    assert!(!target.seen().iter().any(|r| r == "/.git/config" || r.starts_with("/search.php?")));
}

#[test]
fn optional_scans_are_absent_by_default() {
    let server = TestServer::start(None);
    let output = run(&[&server.url(), "--no-js", "--no-verify", "--no-cache", "--json"]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    for key in ["subdomains", "hidden", "php"] {
        assert!(report.get(key).is_none(), "unexpected optional section {key}");
    }
    assert!(!server.seen().iter().any(|r| r == "/.git/config" || r.starts_with("/search.php?")));
}

#[test]
fn optional_sections_are_in_terminal_and_markdown() {
    let server = TestServer::start(None);
    let md = temp_path("report.md");
    let output = run(&[&server.url(), "--php", "--no-verify", "--no-js", "--no-cache", "--md", md.to_str().unwrap(), "--no-color"]);
    assert!(String::from_utf8(output.stdout).unwrap().contains("ФОРМЫ И ПАРАМЕТРЫ"));
    let markdown = std::fs::read_to_string(&md).unwrap();
    assert!(markdown.contains("## Формы и параметры"));
    assert!(markdown.contains("IDOR"));
    let _ = std::fs::remove_file(md);
}
