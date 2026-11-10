//! Terminal + Markdown rendering.
use crate::model::*;
use crate::ru::count;

pub struct Style {
    pub color: bool,
}

impl Style {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    fn magenta(&self, s: &str) -> String {
        self.wrap("35", s)
    }
    fn ok(&self, b: bool) -> String {
        if b {
            self.green("✔")
        } else {
            self.red("✖")
        }
    }
}

fn human_kb(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} МБ", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{} КБ", bytes / 1024)
    } else {
        format!("{bytes} Б")
    }
}

fn bar(score: u32, width: usize) -> String {
    let filled = ((score as f64 / 100.0) * width as f64).round() as usize;
    let mut s = String::new();
    for i in 0..width {
        s.push(if i < filled { '█' } else { '░' });
    }
    s
}

fn score_color(st: &Style, score: u32, s: &str) -> String {
    if score >= 80 {
        st.green(s)
    } else if score >= 55 {
        st.yellow(s)
    } else {
        st.dim(s)
    }
}

pub fn render(report: &Report, style: &Style, max_endpoints: usize) -> String {
    let mut o = String::new();
    let mut line = |s: String| {
        o.push_str(&s);
        o.push('\n');
    };

    // ---- header ----
    line(format!(
        "{} {}  {}",
        style.cyan(&style.bold("site-xray")),
        style.dim(concat!("v", env!("CARGO_PKG_VERSION"))),
        style.dim(&report.generated_at)
    ));
    line(style.dim(&"─".repeat(78)));
    let http = &report.http;
    line(format!(
        "{}  {}  {} {}",
        style.bold(&report.target),
        style.dim("→"),
        style.cyan(&http.final_url),
        if http.status == 200 { style.green("HTTP 200") } else { style.red(&format!("HTTP {}", http.status)) }
    ));
    let chain = if http.redirect_chain.is_empty() {
        "без редиректов".to_string()
    } else {
        format!("{} редирект(ов)", http.redirect_chain.len())
    };
    line(format!(
        "  {} · {} · {} · {} · {} · TLS {}",
        style.dim(&format!("{} мс", http.ms)),
        style.dim(&human_kb(http.size_bytes)),
        style.dim(&http.http_version),
        style.dim(&chain),
        style.dim(if http.tls { "https" } else { "http" }),
        style.ok(http.tls)
    ));
    if let Some(t) = &http.title {
        line(format!("  {}", style.dim(&format!("\u{201c}{t}\u{201d}"))));
    }

    // ---- verdict ----
    line(String::new());
    line(style.bold("◆ ВЕРДИКТ — откуда брать данные без браузера"));
    line(format!("  {}", style.green(&style.bold(&report.verdict.headline))));
    if !report.verdict.reasons.is_empty() {
        for r in &report.verdict.reasons {
            line(format!("  {} {}", style.dim("·"), r));
        }
    }
    if !report.verdict.plan.is_empty() {
        line(String::new());
        line(format!("  {}", style.bold("План")));
        for p in &report.verdict.plan {
            line(format!("  {}", p));
        }
    }
    if !report.verdict.cautions.is_empty() {
        line(String::new());
        line(format!("  {}", style.yellow(&style.bold("Осторожно"))));
        for c in &report.verdict.cautions {
            line(format!("  {} {}", style.yellow("!"), c));
        }
    }

    // ---- channels table ----
    line(String::new());
    line(style.bold("◆ КАНАЛЫ ДАННЫХ"));
    for (i, c) in report.channels.iter().enumerate() {
        let mark = if c.id == report.channels.first().map(|x| x.id.clone()).unwrap_or_default() && c.available {
            style.green("★")
        } else if c.available {
            style.dim("•")
        } else {
            style.red("×")
        };
        let name = format!("{:<24}", trunc(&c.name, 24));
        let (bar_s, score_s) = if c.available {
            (
                score_color(style, c.score, &bar(c.score, 10)),
                score_color(style, c.score, &format!("{:>3}/100", c.score)),
            )
        } else {
            (style.dim(&"─".repeat(10)), style.dim("      —"))
        };
        line(format!(
            " {} {}. {} {} {}  {}",
            mark,
            i + 1,
            style.bold(&name),
            bar_s,
            score_s,
            style.dim(&c.summary)
        ));
        for d in c.details.iter().take(3) {
            line(format!("        {}", style.dim(&trunc(d, 96))));
        }
    }

    line(style.bold("◆ CORS"));
    line(format!("  {} · Access-Control-Allow-Origin: {}", report.cors.verdict, report.cors.allow_origin.as_deref().unwrap_or("не указан")));
    if let Some(v)=&report.cors.allow_methods { line(format!("  методы: {v}")); }
    // ---- stack & security ----
    line(String::new());
    line(style.bold("◆ СТЕК И ЗАЩИТА"));
    let mut facts: Vec<String> = Vec::new();
    if let Some(s) = &http.server {
        facts.push(format!("server: {}", trunc(s, 30)));
    }
    if let Some(p) = &http.powered_by {
        facts.push(format!("x-powered-by: {}", trunc(p, 30)));
    }
    if !report.security.cdn_waf.is_empty() {
        facts.push(format!("CDN/WAF: {}", report.security.cdn_waf.join(", ")));
    }
    if !facts.is_empty() {
        line(format!("  {}", facts.join("  ·  ")));
    }
    if !report.tech.is_empty() {
        let tech: Vec<String> = report
            .tech
            .iter()
            .map(|t| format!("{} {}", t.name, style.dim(&format!("({})", t.category))))
            .collect();
        line(format!("  Технологии: {}", tech.join(", ")));
    }
    let head: Vec<String> = report
        .security
        .headers
        .iter()
        .map(|h| format!("{} {}", h.name, style.ok(h.present)))
        .collect();
    line(format!(
        "  Заголовки: {}   {} {}",
        head.join("  "),
        style.bold(&format!("оценка {}", report.security.grade)),
        style.dim(&format!("({}/100)", report.security.score))
    ));
    if report.http.status != 200 {
        line(format!(
            "  {}",
            style.yellow(&format!(
                "заголовки сняты со страницы-заглушки (HTTP {}) — реальная оценка может быть выше",
                report.http.status
            ))
        ));
    }
    if !report.security.bot_protection.is_empty() {
        line(format!("  {} {}", style.yellow("антибот:"), report.security.bot_protection.join("; ")));
    } else {
        line(format!("  антибот: {}", style.dim("признаков не найдено")));
    }

    // ---- robots ----
    line(String::new());
    match &report.robots {
        Some(r) if r.found => {
            line(format!("◆ ROBOTS.TXT  {}", style.green("200")));
            line(format!("  {}", r.notes.join("; ")));
            if !r.sitemaps.is_empty() {
                line(format!("  Sitemap: {}", style.cyan(&r.sitemaps.join(", "))));
            }
            if !r.notable.is_empty() {
                line(format!("  прячет: {}", report_dim(style, &r.notable.join(", "))));
            }
        }
        Some(r) => line(format!("◆ ROBOTS.TXT  {} HTTP {}", style.red("нет"), r.status)),
        None => line(format!("◆ ROBOTS.TXT  {}", style.dim("не проверялся"))),
    }

    // ---- sitemaps ----
    line(String::new());
    let sm = &report.sitemaps;
    if sm.found() {
        line(format!(
            "◆ SITEMAP  {}  {}",
            style.green("найден"),
            style.dim(&format!("{} URL · {} · lastmod {}", sm.total_urls, count(sm.docs.len(), "документ", "документа", "документов"), if sm.has_lastmod { "✔" } else { "✖" }))
        ));
        for d in sm.docs.iter().take(6) {
            line(format!(
                "  {} {} {} {}",
                style.dim("·"),
                style.cyan(&trunc(&d.url, 62)),
                style.dim(&format!("{} {}", d.kind, d.urls)),
                style.dim(&format!("HTTP {}", d.status))
            ));
        }
        if sm.truncated_docs > 0 {
            line(format!(
                "  {}",
                style.yellow(&format!(
                    "{} не целиком (лимит на размер) — реальное число URL больше",
                    count(sm.truncated_docs, "документ прочитан", "документа прочитаны", "документов прочитаны")
                ))
            ));
        }
        if !sm.kinds.is_empty() {
            line(format!("  расширения: {}", sm.kinds.join(", ")));
        }
        if !sm.sample_urls.is_empty() {
            line(format!("  примеры: {}", style.dim(&trunc(&sm.sample_urls.join("  "), 200))));
        }
    } else {
        line(format!("◆ SITEMAP  {}", style.red("не найден")));
        line(format!("  {}", style.dim(&format!("проверено: {}", sm.tried.iter().take(4).cloned().collect::<Vec<_>>().join(", ")))));
    }

    // ---- feeds ----
    line(String::new());
    if report.feeds.is_empty() {
        line(format!("◆ ФИДЫ  {}", style.red("не найдено")));
    } else {
        line(format!("◆ ФИДЫ  {}", style.green(&format!("{}", report.feeds.len()))));
        for f in report.feeds.iter().take(5) {
            line(format!(
                "  {} {} {} {}",
                style.dim("·"),
                style.cyan(&trunc(&f.url, 52)),
                style.dim(&format!("[{}] {} записей{}", f.kind, f.items, if f.declared { ", объявлен" } else { "" })),
                style.dim(f.latest.as_deref().unwrap_or(""))
            ));
            if let Some(t) = &f.title {
                line(format!("      {}", style.dim(t)));
            }
        }
    }

    // ---- JSON-LD ----
    line(String::new());
    let j = &report.jsonld;
    if j.valid > 0 {
        line(format!(
            "◆ JSON-LD  {}  {}",
            style.green(&count(j.valid, "блок", "блока", "блоков")),
            style.dim(&format!("типы: {}", j.types.iter().take(10).cloned().collect::<Vec<_>>().join(", ")))
        ));
        if !j.props.is_empty() {
            line(format!("  поля: {}", style.dim(&trunc(&j.props.join(", "), 190))));
        }
    } else {
        line(format!("◆ JSON-LD  {}", style.red("нет валидных блоков")));
    }

    // ---- JS endpoints ----
    line(String::new());
    let js = &report.js;
    if js.endpoints.is_empty() {
        line(format!(
            "◆ JSON API / ЭНДПОИНТЫ  {}  {}",
            style.yellow("ничего не найдено"),
            style.dim(&format!("просканировано {} бандл(ов), {}", js.bundles_scanned, human_kb(js.bundles_bytes)))
        ));
    } else {
        line(format!(
            "◆ JSON API / ЭНДПОИНТЫ  {}  {}",
            style.green(&count(js.endpoints.len(), "кандидат", "кандидата", "кандидатов")),
            style.dim(&format!("бандлов: {}, {}", js.bundles_scanned, human_kb(js.bundles_bytes)))
        ));
        for e in js.endpoints.iter().take(max_endpoints) {
            let status = match (&e.status, e.verified) {
                (Some(s), true) => style.green(&format!("HTTP {s} JSON ✔")),
                (Some(s), false) => style.dim(&format!("HTTP {s}")),
                _ => style.dim("не проверен"),
            };
            line(format!(
                "  {} {} {} {}",
                score_color(style, e.score, &format!("{:>3}", e.score)),
                style.cyan(&trunc(&e.path, 56)),
                style.dim(&format!("{:<9}", e.kind)),
                status
            ));
            line(format!(
                "      {}",
                style.dim(&format!("×{} · {}", e.hits, e.evidence))
            ));
        }
        if js.endpoints.len() > max_endpoints {
            line(format!("  {}", style.dim(&format!("… ещё {} (запусти с --all)", js.endpoints.len() - max_endpoints))));
        }
    }
    for s in &js.inline_states {
        line(format!("  {} inline-JSON: {}", style.magenta("▣"), style.dim(s)));
    }
    for n in js.notes.iter().take(3) {
        line(format!("  {}", style.dim(&trunc(n, 100))));
    }

    // ---- optional security-oriented scans ----
    if let Some(sub) = &report.subdomains {
        line(String::new());
        line(style.bold(&format!("◆ ПОДДОМЕНЫ  {}", sub.domain.as_deref().unwrap_or("домен не определён"))));
        for source in &sub.sources {
            let message = source.message.as_deref().map(|m| format!(" · {m}")).unwrap_or_default();
            line(format!("  {}: {} · {} записей{}", source.name, source.status, source.records, message));
        }
        line(style.dim(&format!("  DNS-словарь: проверено {}/{}", sub.dictionary_checked, sub.dictionary_total)));
        for finding in sub.subdomains.iter().take(max_endpoints) {
            line(format!("  {} {}  {}", style.dim("·"), style.cyan(&finding.name), style.dim(&finding.sources.join(", "))));
        }
        if sub.subdomains.len() > max_endpoints {
            line(style.dim(&format!("  … ещё {} (запусти с --all)", sub.subdomains.len() - max_endpoints)));
        }
        if !sub.subdomains.is_empty() {
            line(style.dim("  Имена из публичных источников не обязательно существуют; * — wildcard сертификата."));
        }
        for warning in &sub.warnings { line(format!("  {} {}", style.yellow("!"), warning)); }
    }
    if let Some(hidden) = &report.hidden {
        line(String::new());
        line(style.bold(&format!("◆ СКРЫТЫЕ ПУТИ  ответов {}/{}", hidden.checked, hidden.total)));
        for finding in hidden.findings.iter().take(max_endpoints) {
            let redirect = finding.location.as_deref().map(|l| format!(" → {l}")).unwrap_or_default();
            line(format!("  {} HTTP {}{}", style.cyan(&finding.path), finding.status, redirect));
        }
        if hidden.findings.len() > max_endpoints {
            line(style.dim(&format!("  … ещё {} (запусти с --all)", hidden.findings.len() - max_endpoints)));
        }
        if hidden.checked > 0 {
            line(style.dim("  Это кандидаты, а не подтверждённые утечки; содержимое не сохраняется."));
        }
        for warning in &hidden.warnings { line(format!("  {} {}", style.yellow("!"), warning)); }
    }
    if let Some(php) = &report.php {
        line(String::new());
        line(style.bold(&format!("◆ ФОРМЫ И ПАРАМЕТРЫ  форм: {} · параметров: {}", php.forms.len(), php.parameters.len())));
        for form in php.forms.iter().take(max_endpoints) {
            line(format!("  форма {} {}{}", form.method, style.cyan(&form.action), if form.same_origin { "" } else { " (внешняя)" }));
        }
        for p in php.parameters.iter().take(max_endpoints) {
            let state = if p.tested { "проверен".to_string() } else { format!("не проверен: {}", p.skip_reason.as_deref().unwrap_or("нет ответа")) };
            let idor = if p.idor_candidate { " · ID-параметр" } else { "" };
            line(format!("  {} {} ?{}  {}{}", p.method, style.cyan(&p.endpoint), p.name, style.dim(&state), idor));
        }
        if php.parameters.len() > max_endpoints {
            line(style.dim(&format!("  … ещё {} (запусти с --all)", php.parameters.len() - max_endpoints)));
        }
        for finding in &php.sql_errors {
            line(format!("  {} возможная SQL-ошибка: {} ?{} · HTTP {} · {}", style.yellow("!"), finding.endpoint, finding.parameter, finding.status, finding.signature));
        }
        line(style.dim("  SQL-ошибки не доказывают SQLi; IDOR требует проверки прав с разными пользователями."));
        for warning in &php.warnings { line(format!("  {} {}", style.yellow("!"), warning)); }
    }

    // ---- extras ----
    let extras: Vec<&Probe> = report.security.extras.iter().filter(|p| p.status == 200).collect();
    if !extras.is_empty() {
        line(String::new());
        line(format!("◆ СЛУЖЕБНЫЕ ФАЙЛЫ"));
        for p in extras {
            line(format!("  {} {} {}", style.green("✔"), style.cyan(&p.url), style.dim(&p.note)));
        }
    }

    line(String::new());
    line(style.dim(&format!(
        "готово за {} мс · site-xray · открытые данные, без браузера",
        report.elapsed_ms
    )));
    o
}

fn report_dim(st: &Style, s: &str) -> String {
    st.dim(s)
}

fn trunc(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

pub fn render_markdown(report: &Report) -> String {
    let mut o = String::new();
    o.push_str(&format!("# site-xray: {}\n\n", report.target));
    o.push_str(&format!(
        "`{}` · HTTP {} · {} мс · {} · сгенерировано {}\n\n",
        report.http.final_url,
        report.http.status,
        report.http.ms,
        human_kb(report.http.size_bytes),
        report.generated_at
    ));
    o.push_str(&format!("## Вердикт\n\n**{}**\n\n", report.verdict.headline));
    if !report.verdict.reasons.is_empty() {
        o.push_str("Почему:\n\n");
        for r in &report.verdict.reasons {
            o.push_str(&format!("- {r}\n"));
        }
        o.push('\n');
    }
    if !report.verdict.plan.is_empty() {
        o.push_str("План:\n\n");
        for p in &report.verdict.plan {
            // Plan items already carry their own numbering.
            let text = p.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ').to_string();
            o.push_str(&format!("- {text}\n"));
        }
        o.push('\n');
    }
    if !report.verdict.cautions.is_empty() {
        o.push_str("Осторожно:\n\n");
        for c in &report.verdict.cautions {
            o.push_str(&format!("- ⚠️ {c}\n"));
        }
        o.push('\n');
    }
    o.push_str("## Каналы данных\n\n| # | Канал | Балл | Доступ | Резюме |\n|---|---|---|---|---|\n");
    for (i, c) in report.channels.iter().enumerate() {
        o.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            i + 1,
            c.name,
            if c.available { c.score.to_string() } else { "—".into() },
            if c.available { "✔" } else { "✖" },
            c.summary.replace('|', "\\|")
        ));
    }
    o.push_str(&format!("## CORS\n\n- {}\n- `Access-Control-Allow-Origin`: {}\n\n", report.cors.verdict, report.cors.allow_origin.as_deref().unwrap_or("не указан")));
    o.push_str("## Стек и защита\n\n");
    if let Some(s) = &report.http.server {
        o.push_str(&format!("- **Server:** {s}\n"));
    }
    if !report.tech.is_empty() {
        let list: Vec<String> = report.tech.iter().map(|t| format!("{} ({})", t.name, t.category)).collect();
        o.push_str(&format!("- **Технологии:** {}\n", list.join(", ")));
    }
    if !report.security.cdn_waf.is_empty() {
        o.push_str(&format!("- **CDN/WAF:** {}\n", report.security.cdn_waf.join(", ")));
    }
    let head: Vec<String> = report
        .security
        .headers
        .iter()
        .map(|h| format!("{} {}", h.name, if h.present { "✔" } else { "✖" }))
        .collect();
    o.push_str(&format!("- **Заголовки:** {} — оценка {} ({}/100)\n", head.join(", "), report.security.grade, report.security.score));
    if !report.security.bot_protection.is_empty() {
        o.push_str(&format!("- **Антибот:** {}\n", report.security.bot_protection.join("; ")));
    }
    o.push_str("\n## robots.txt\n\n");
    match &report.robots {
        Some(r) if r.found => {
            o.push_str(&format!("- {}\n", r.notes.join("; ")));
            if !r.sitemaps.is_empty() {
                o.push_str(&format!("- Sitemap: {}\n", r.sitemaps.join(", ")));
            }
            if !r.notable.is_empty() {
                o.push_str(&format!("- Прячет: {}\n", r.notable.join(", ")));
            }
        }
        _ => o.push_str("Не найден.\n"),
    }
    o.push_str("\n## sitemap.xml\n\n");
    if report.sitemaps.found() {
        o.push_str(&format!(
            "- {} URL, {}, lastmod: {}\n",
            report.sitemaps.total_urls,
            count(report.sitemaps.docs.len(), "документ", "документа", "документов"),
            if report.sitemaps.has_lastmod { "да" } else { "нет" }
        ));
        for d in report.sitemaps.docs.iter().take(10) {
            o.push_str(&format!("  - `{}` — {} ({} URL)\n", d.url, d.kind, d.urls));
        }
    } else {
        o.push_str("Не найден.\n");
    }
    o.push_str("\n## ФИДЫ\n\n");
    if report.feeds.is_empty() {
        o.push_str("Не найдено.\n");
    } else {
        for f in &report.feeds {
            o.push_str(&format!(
                "- `{}` — {} записей, {} {} {}\n",
                f.url,
                f.items,
                f.kind,
                if f.declared { "(объявлен)" } else { "" },
                f.latest.clone().unwrap_or_default()
            ));
        }
    }
    o.push_str("\n## JSON-LD\n\n");
    if report.jsonld.valid > 0 {
        o.push_str(&format!("- {} валидны\n- Типы: {}\n", count(report.jsonld.valid, "блок", "блока", "блоков"), report.jsonld.types.join(", ")));
        if !report.jsonld.props.is_empty() {
            o.push_str(&format!("- Поля: {}\n", report.jsonld.props.join(", ")));
        }
    } else {
        o.push_str("Нет валидных блоков.\n");
    }
    o.push_str("\n## JSON API / эндпоинты\n\n");
    if report.js.endpoints.is_empty() {
        o.push_str("Ничего не найдено.\n");
    } else {
        o.push_str("| Балл | Путь | Тип | Проверка | Найдено в |\n|---|---|---|---|---|\n");
        for e in report.js.endpoints.iter().take(40) {
            o.push_str(&format!(
                "| {} | `{}` | {} | {} | {} |\n",
                e.score,
                e.path,
                e.kind,
                match (&e.status, e.verified) {
                    (Some(s), true) => format!("HTTP {s} JSON ✔"),
                    (Some(s), false) => format!("HTTP {s}"),
                    _ => "—".into(),
                },
                e.evidence
            ));
        }
    }
    if !report.js.inline_states.is_empty() {
        o.push_str(&format!("\nInline-JSON на странице: {}\n", report.js.inline_states.join(", ")));
    }
    if let Some(sub) = &report.subdomains {
        o.push_str(&format!("\n## Поддомены: {}\n\n", sub.domain.as_deref().unwrap_or("домен не определён")));
        for source in &sub.sources {
            let message = source.message.as_deref().map(|m| format!(" — {m}")).unwrap_or_default();
            o.push_str(&format!("- {}: {}, {} записей{}\n", source.name, source.status, source.records, message));
        }
        o.push_str(&format!("- DNS-словарь: проверено {}/{}\n", sub.dictionary_checked, sub.dictionary_total));
        for finding in &sub.subdomains {
            o.push_str(&format!("- {} — {}\n", md_code(&finding.name), finding.sources.join(", ")));
        }
        if !sub.subdomains.is_empty() {
            o.push_str("\nИмена из публичных источников могут не существовать; `*.` обозначает wildcard сертификата.\n");
        }
        for warning in &sub.warnings { o.push_str(&format!("- ⚠️ {warning}\n")); }
    }
    if let Some(hidden) = &report.hidden {
        o.push_str(&format!("\n## Скрытые пути\n\nПолучено ответов: {}/{}.\n\n", hidden.checked, hidden.total));
        for finding in &hidden.findings {
            let location = finding.location.as_deref().map(|l| format!(" → {}", md_code(l))).unwrap_or_default();
            o.push_str(&format!("- {} — HTTP {}{}\n", md_code(&finding.path), finding.status, location));
        }
        if hidden.checked > 0 { o.push_str("\nЭто кандидаты, а не подтверждённые утечки; содержимое не сохраняется.\n"); }
        for warning in &hidden.warnings { o.push_str(&format!("- ⚠️ {warning}\n")); }
    }
    if let Some(php) = &report.php {
        o.push_str("\n## Формы и параметры\n\n");
        for form in &php.forms {
            o.push_str(&format!("- Форма {} {}{}\n", form.method, md_code(&form.action), if form.same_origin { "" } else { " (внешняя)" }));
        }
        for p in &php.parameters {
            let state = if p.tested { "проверен".to_string() } else { format!("не проверен: {}", p.skip_reason.as_deref().unwrap_or("нет ответа")) };
            let idor = if p.idor_candidate { "; ID-параметр" } else { "" };
            o.push_str(&format!("- {} {} параметр {} — {}{}\n", p.method, md_code(&p.endpoint), md_code(&p.name), state, idor));
        }
        for finding in &php.sql_errors {
            o.push_str(&format!("- ⚠️ Возможная SQL-ошибка: {} параметр {}, HTTP {}, сигнатура {}\n", md_code(&finding.endpoint), md_code(&finding.parameter), finding.status, md_code(&finding.signature)));
        }
        o.push_str("\nSQL-ошибка не доказывает SQLi; IDOR требует проверки прав с разными пользователями.\n");
        for warning in &php.warnings { o.push_str(&format!("- ⚠️ {warning}\n")); }
    }
    o.push_str("\n---\n\n_Сгенерировано site-xray. Уважай robots.txt, ToS и лимиты сайта._\n");
    o
}

/// Backslashes do not escape backticks inside Markdown code spans. Use a fence
/// longer than any backtick run in the (untrusted) value instead.
fn md_code(s: &str) -> String {
    let text = s.replace(['\r', '\n'], " ");
    let longest_run = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest_run + 1);
    let padding = if text.starts_with('`') || text.ends_with('`')
        || (text.starts_with(' ') && text.ends_with(' ')) { " " } else { "" };
    format!("{fence}{padding}{text}{padding}{fence}")
}

#[cfg(test)]
mod tests {
    use super::md_code;

    #[test]
    fn markdown_code_spans_contain_untrusted_backticks() {
        assert_eq!(md_code("id"), "`id`");
        assert_eq!(md_code("a`b"), "``a`b``");
        assert_eq!(md_code("`a`"), "`` `a` ``");
        assert_eq!(md_code("a\nb"), "`a b`");
    }
}
