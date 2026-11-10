//! Russian pluralisation helper: 1 кандидат / 2 кандидата / 5 кандидатов.
pub fn plural<'a>(n: usize, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let n100 = n % 100;
    let n10 = n % 10;
    if (11..=14).contains(&n100) {
        many
    } else if n10 == 1 {
        one
    } else if (2..=4).contains(&n10) {
        few
    } else {
        many
    }
}

/// "5 документов", "1 документ", "2 документа"
pub fn count(n: usize, one: &'static str, few: &'static str, many: &'static str) -> String {
    format!("{} {}", n, plural(n, one, few, many))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_plurals() {
        assert_eq!(count(1, "документ", "документа", "документов"), "1 документ");
        assert_eq!(count(3, "документ", "документа", "документов"), "3 документа");
        assert_eq!(count(12, "документ", "документа", "документов"), "12 документов");
        assert_eq!(count(21, "документ", "документа", "документов"), "21 документ");
    }
}
