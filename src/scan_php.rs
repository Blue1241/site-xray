//! Extract form/query parameters and, when opted in, look for differential SQL errors.
//! This cannot prove SQL injection or IDOR; authorization checks need distinct users.
use crate::model::{PhpFinding, PhpForm, PhpParameter, PhpReport};
use crate::net::Net;
use scraper::{ElementRef, Html, Selector};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

const MAX_PARAMETERS: usize = 80;
const MAX_PROBES: usize = 12;
const BODY_LIMIT: usize = 96 * 1024;
const DELAY: Duration = Duration::from_millis(200);
const SQL_SIGNATURES: &[&str] = &[
    "sql syntax", "mysql_fetch", "warning: mysqli", "sqlstate[", "pdoexception",
    "unclosed quotation mark after the character string", "unterminated quoted string",
    "pg_query(): query failed", "sqlite3::", "ora-01756",
];

struct Candidate {
    info: PhpParameter,
    endpoint: Url,
}

pub struct PhpScanner {
    page_url: String,
}

impl PhpScanner {
    pub fn new(page_url: &str) -> Self {
        Self { page_url: page_url.to_string() }
    }

    pub fn scan(&self, net: &Net, html: &str, disabled: Option<&str>) -> PhpReport {
        let mut report = PhpReport::default();
        let Ok(page) = Url::parse(&self.page_url) else {
            report.warnings.push("Не удалось разобрать URL страницы.".into());
            return report;
        };
        let (forms, mut candidates, truncated) = extract(html, &page);
        report.forms = forms;
        if truncated { report.warnings.push(format!("Разбор ограничен {MAX_PARAMETERS} параметрами.")); }
        if let Some(reason) = disabled {
            report.warnings.push(format!("Активные проверки пропущены: {reason}."));
        }
        let mut probes = 0;
        let mut stopped = false;
        let mut failed = 0;
        for candidate in &mut candidates {
            if candidate.info.skip_reason.is_some() { continue; }
            if let Some(reason) = disabled {
                candidate.info.skip_reason = Some(reason.to_string());
                continue;
            }
            if stopped {
                candidate.info.skip_reason = Some("проверка остановлена после ограничения сервером".into());
                continue;
            }
            if probes >= MAX_PROBES {
                candidate.info.skip_reason = Some(format!("лимит {MAX_PROBES} параметров"));
                continue;
            }
            if expired(net) {
                candidate.info.skip_reason = Some("бюджет времени исчерпан".into());
                continue;
            }
            probes += 1;
            // Do not replay existing query values, which could include secrets or actions.
            let baseline_url = with_value(&candidate.endpoint, &candidate.info.name, "test");
            let quote_url = with_value(&candidate.endpoint, &candidate.info.name, "test'");
            let baseline = net.get_probe(&baseline_url, BODY_LIMIT, Duration::from_secs(3));
            pause(net);
            let baseline = match baseline {
                Ok(r) if r.status == 429 || r.status == 503 => {
                    stopped = true;
                    candidate.info.skip_reason = Some(format!("HTTP {}", r.status));
                    continue;
                }
                Ok(r) if !r.truncated => r,
                Ok(_) => { candidate.info.skip_reason = Some("базовый ответ обрезан".into()); failed += 1; continue; }
                Err(_) if expired(net) => { candidate.info.skip_reason = Some("бюджет времени исчерпан".into()); failed += 1; continue; }
                Err(_) => { candidate.info.skip_reason = Some("нет базового ответа".into()); failed += 1; continue; }
            };
            let injected = net.get_probe(&quote_url, BODY_LIMIT, Duration::from_secs(3));
            pause(net);
            let injected = match injected {
                Ok(r) if r.status == 429 || r.status == 503 => {
                    stopped = true;
                    candidate.info.skip_reason = Some(format!("HTTP {}", r.status));
                    continue;
                }
                Ok(r) if !r.truncated => r,
                Ok(_) => { candidate.info.skip_reason = Some("ответ на пробу обрезан".into()); failed += 1; continue; }
                Err(_) if expired(net) => { candidate.info.skip_reason = Some("бюджет времени исчерпан".into()); failed += 1; continue; }
                Err(_) => { candidate.info.skip_reason = Some("нет ответа на пробу".into()); failed += 1; continue; }
            };
            candidate.info.tested = true;
            let before = baseline.text().to_ascii_lowercase();
            let after = injected.text().to_ascii_lowercase();
            if let Some(signature) = SQL_SIGNATURES.iter().find(|s| after.contains(**s) && !before.contains(**s)) {
                report.sql_errors.push(PhpFinding {
                    endpoint: candidate.info.endpoint.clone(), parameter: candidate.info.name.clone(),
                    status: injected.status, signature: (*signature).to_string(),
                });
            }
        }
        if stopped { report.warnings.push("Проверка параметров остановлена после HTTP 429/503.".into()); }
        if failed > 0 { report.warnings.push(format!("Для {failed} параметров не получена полная пара ответов.")); }
        if candidates.iter().any(|c| c.info.skip_reason.as_deref().is_some_and(|r| r.starts_with("лимит"))) {
            report.warnings.push(format!("Активная проверка ограничена {MAX_PROBES} параметрами."));
        }
        if candidates.iter().any(|c| c.info.skip_reason.as_deref() == Some("бюджет времени исчерпан")) {
            report.warnings.push("Часть параметров не проверена: бюджет времени исчерпан.".into());
        }
        report.parameters = candidates.into_iter().map(|c| c.info).collect();
        report
    }
}

fn extract(html: &str, page: &Url) -> (Vec<PhpForm>, Vec<Candidate>, bool) {
    let doc = Html::parse_document(html);
    let forms_sel = Selector::parse("form").expect("static selector");
    let controls_sel = Selector::parse("input[name], select[name], textarea[name]").expect("static selector");
    let links_sel = Selector::parse("a[href], area[href]").expect("static selector");
    let mut forms = Vec::new();
    let mut candidates = Vec::new();
    let mut seen = HashMap::new();
    let mut truncated = false;

    for form in doc.select(&forms_sel) {
        let method = crate::scan_html::form_method(form.value().attr("method")).to_string();
        let action = form.value().attr("action").unwrap_or("").trim();
        let Ok(url) = page.join(action) else { continue };
        if !matches!(url.scheme(), "http" | "https") { continue; }
        let same_origin = same_origin(page, &url);
        let clean = clean_endpoint(&url);
        if forms.len() < MAX_PARAMETERS {
            let entry = PhpForm { action: clean.to_string(), method: method.clone(), same_origin };
            if !forms.iter().any(|f: &PhpForm| f.action == entry.action && f.method == entry.method) { forms.push(entry); }
        } else { truncated = true; }
        let sensitive_query = url.query_pairs().any(|(name, _)| sensitive_name(&name));
        for control in form.select(&controls_sel) {
            let Some(name) = control.value().attr("name") else { continue };
            let kind = control.value().attr("type").unwrap_or("").trim().to_ascii_lowercase();
            let disabled_control = control.value().attr("disabled").is_some()
                || control.ancestors().filter_map(ElementRef::wrap).any(|ancestor| {
                    ancestor.value().name() == "fieldset" && ancestor.value().attr("disabled").is_some()
                })
                || matches!(kind.as_str(), "hidden" | "password" | "file" | "submit" | "button" | "reset" | "image");
            let extra_reason = if disabled_control { Some("скрытое, отключённое или чувствительное поле") } else { None };
            add_candidate(&mut candidates, &mut seen, &mut truncated, page, &url, name, &method, "форма", sensitive_query, extra_reason);
        }
        for (name, _) in url.query_pairs() {
            add_candidate(&mut candidates, &mut seen, &mut truncated, page, &url, &name, &method, "action формы", sensitive_query, None);
        }
    }
    // Include controls outside a form, but never guess where to send them.
    for control in doc.select(&controls_sel) {
        let in_form = control.ancestors().filter_map(ElementRef::wrap).any(|el| el.value().name() == "form");
        if !in_form {
            if let Some(name) = control.value().attr("name") {
                add_candidate(&mut candidates, &mut seen, &mut truncated, page, page, name, "GET", "поле", false, Some("поле вне формы"));
            }
        }
    }
    for link in doc.select(&links_sel) {
        let Some(href) = link.value().attr("href") else { continue };
        let Ok(url) = page.join(href.trim()) else { continue };
        if !matches!(url.scheme(), "http" | "https") { continue; }
        let sensitive_query = url.query_pairs().any(|(name, _)| sensitive_name(&name));
        for (name, _) in url.query_pairs() {
            add_candidate(&mut candidates, &mut seen, &mut truncated, page, &url, &name, "GET", "ссылка", sensitive_query, None);
        }
    }
    let sensitive_query = page.query_pairs().any(|(name, _)| sensitive_name(&name));
    for (name, _) in page.query_pairs() {
        add_candidate(&mut candidates, &mut seen, &mut truncated, page, page, &name, "GET", "URL страницы", sensitive_query, None);
    }
    (forms, candidates, truncated)
}

#[allow(clippy::too_many_arguments)]
fn add_candidate(
    candidates: &mut Vec<Candidate>, seen: &mut HashMap<(String, String, String), usize>, truncated: &mut bool,
    page: &Url, url: &Url, name: &str, method: &str, source: &str, sensitive_query: bool, extra_reason: Option<&str>,
) {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) { return; }
    let endpoint = clean_endpoint(url);
    let reason = if !same_origin(page, url) { Some("внешний адрес или URL с учётными данными") }
        else if method != "GET" { Some("не GET-форма") }
        else if sensitive_query || sensitive_name(name) { Some("чувствительный параметр") }
        else if risky_path(url) || risky_parameter(name) { Some("путь или параметр может менять состояние") }
        else { extra_reason };
    let info = PhpParameter {
        endpoint: endpoint.to_string(), name: name.to_string(), method: method.to_string(), source: source.to_string(),
        idor_candidate: idor_name(name), tested: false, skip_reason: reason.map(str::to_string),
    };
    let key = (info.endpoint.clone(), info.name.clone(), info.method.clone());
    if let Some(&i) = seen.get(&key) {
        // Prefer a testable occurrence over the same field in a disabled control.
        if candidates[i].info.skip_reason.is_some() && info.skip_reason.is_none() {
            candidates[i] = Candidate { info, endpoint };
        }
    } else if candidates.len() < MAX_PARAMETERS {
        seen.insert(key, candidates.len());
        candidates.push(Candidate { info, endpoint });
    } else { *truncated = true; }
}

fn same_origin(page: &Url, url: &Url) -> bool {
    page.origin() == url.origin() && url.username().is_empty() && url.password().is_none()
}

fn clean_endpoint(url: &Url) -> Url {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url
}

fn sensitive_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["password", "passwd", "csrf", "xsrf", "token", "nonce", "secret", "session", "signature", "auth", "api_key", "apikey", "email"]
        .iter().any(|part| n.contains(part)) || matches!(n.as_str(), "pwd" | "pass" | "sid" | "key" | "sig" | "jwt" | "otp")
}

fn risky_path(url: &Url) -> bool {
    has_action_word(&url.path().to_ascii_lowercase())
}

fn risky_parameter(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    has_action_word(&name) || matches!(name.as_str(), "action" | "act" | "cmd" | "command" | "op" | "operation")
}

fn has_action_word(value: &str) -> bool {
    value.split(|c: char| !c.is_ascii_alphanumeric()).any(|part| matches!(part,
        "logout" | "signout" | "unsubscribe" | "delete" | "remove" | "destroy" | "update" | "save" | "reset"))
}

fn idor_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase().replace('-', "_");
    let n = n.trim_end_matches("[]");
    matches!(n, "id" | "uid" | "uuid" | "userid" | "accountid" | "objectid" | "orderid") || n.ends_with("_id")
}

fn with_value(endpoint: &Url, name: &str, value: &str) -> String {
    let mut url = endpoint.clone();
    url.query_pairs_mut().append_pair(name, value);
    url.to_string()
}

fn expired(net: &Net) -> bool {
    matches!(net.remaining(), Some(left) if left.is_zero())
}

fn pause(net: &Net) {
    let delay = net.remaining().map(|left| left.min(DELAY)).unwrap_or(DELAY);
    if !delay.is_zero() { std::thread::sleep(delay); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_structured_parameters_and_restricts_scope() {
        let page = Url::parse("https://example.com/dir/index.php").unwrap();
        let html = r#"
            <FORM action='../search.php' method='get'><input value=x NAME='id'><input name='csrf_token' type=hidden><input name='nonce' type=' hidden '><fieldset disabled><input name='disabled_id'></fieldset></FORM>
            <form action='/login' method='POST'><input name='password'></form>
            <form action='https://evil.example/collect'><input name='item'></form>
            <form action='/odd' method='unexpected'><input name='query'></form>
            <a href='/product.php?product_id=3&amp;view=full'>product</a>
            <a href='/delete.php?id=1'>delete</a>
            <a href='/?logout=1'>logout</a>
            <input name='orphan'>
        "#;
        let (forms, params, _) = extract(html, &page);
        assert_eq!(forms.len(), 4);
        assert!(forms.iter().any(|form| form.action.ends_with("/odd") && form.method == "OTHER"));
        let id = params.iter().find(|p| p.info.name == "id" && p.info.endpoint.ends_with("/search.php")).unwrap();
        assert!(id.info.idor_candidate && id.info.skip_reason.is_none());
        assert_eq!(with_value(&id.endpoint, "id", "test'"), "https://example.com/search.php?id=test%27");
        assert!(params.iter().find(|p| p.info.name == "csrf_token").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "nonce").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "disabled_id").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "logout").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "query").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "password").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "item").unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "product_id").unwrap().info.idor_candidate);
        assert!(params.iter().find(|p| p.info.endpoint.ends_with("/delete.php")).unwrap().info.skip_reason.is_some());
        assert!(params.iter().find(|p| p.info.name == "orphan").unwrap().info.skip_reason.is_some());
        assert!(sensitive_name("XSRF") && sensitive_name("nonce") && sensitive_name("signature"));
        assert!(risky_parameter("logout") && risky_parameter("action"));
    }
}
