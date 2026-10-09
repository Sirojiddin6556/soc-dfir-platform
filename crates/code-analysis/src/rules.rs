//! Rules and findings.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// One kind of defect.
#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub cwe: u32,
    pub severity: Severity,
    pub title: &'static str,
    /// The `ctx` bit user data must be safe for at the sink; 0 for rules
    /// that do not depend on data flow.
    pub context: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Location {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub rule: String,
    pub cwe: u32,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub snippet: String,
    /// Where the user data entered, for data-flow findings.
    pub source: Option<Location>,
    /// Source, the calls leading to the sink, and the sink itself.
    pub trace: Vec<Location>,
    /// Other inputs that reach the same sink, such as the pages that pass
    /// request data to one database helper (at most 50).
    pub other_sources: Vec<Location>,
}

macro_rules! rule {
    ($name:ident, $id:literal, $cwe:literal, $sev:ident, $title:literal, $ctx:expr) => {
        pub static $name: Rule = Rule {
            id: $id,
            cwe: $cwe,
            severity: Severity::$sev,
            title: $title,
            context: $ctx,
        };
    };
}

use crate::value::ctx;

rule!(
    SQLI,
    "sql-injection",
    89,
    Critical,
    "SQL-инъекция",
    ctx::SQL
);
rule!(
    CMDI,
    "command-injection",
    78,
    Critical,
    "Внедрение команд ОС",
    ctx::SHELL
);
rule!(
    CODEI,
    "code-injection",
    94,
    Critical,
    "Внедрение кода",
    ctx::CODE
);
rule!(
    DESER,
    "unsafe-deserialization",
    502,
    Critical,
    "Небезопасная десериализация",
    ctx::DESER
);
rule!(
    PATH,
    "path-traversal",
    22,
    High,
    "Обход каталогов",
    ctx::PATH
);
rule!(
    XSS,
    "xss",
    79,
    High,
    "Межсайтовый скриптинг (XSS)",
    ctx::HTML
);
rule!(
    FILE_INCLUSION,
    "file-inclusion",
    98,
    Critical,
    "Включение файла, выбранного пользователем (LFI/RFI)",
    ctx::PATH
);
rule!(
    LDAPI,
    "ldap-injection",
    90,
    High,
    "LDAP-инъекция",
    ctx::LDAP
);
rule!(
    XPATHI,
    "xpath-injection",
    643,
    High,
    "XPath-инъекция",
    ctx::XPATH
);
rule!(
    XXE,
    "xxe",
    611,
    High,
    "Внешние сущности XML (XXE)",
    ctx::XML
);
rule!(
    SSTI,
    "template-injection",
    1336,
    Critical,
    "Внедрение в шаблон",
    ctx::TEMPLATE
);
rule!(
    REDIRECT,
    "open-redirect",
    601,
    Medium,
    "Открытое перенаправление",
    ctx::URL
);
rule!(
    TRUST,
    "trust-boundary",
    501,
    Low,
    "Нарушение границы доверия (данные пользователя в сессии)",
    ctx::SESSION
);
rule!(
    HEADER,
    "header-injection",
    113,
    Medium,
    "Внедрение в HTTP-заголовок",
    ctx::HEADER
);
rule!(
    CORS,
    "cors-any-origin",
    942,
    Medium,
    "CORS: доверие к любому Origin из запроса",
    ctx::ORIGIN
);
rule!(
    SSRF,
    "ssrf",
    918,
    High,
    "Подделка серверных запросов (SSRF)",
    ctx::URL
);
rule!(
    LOGI,
    "log-injection",
    117,
    Low,
    "Внедрение в журнал",
    ctx::LOG
);
rule!(WEAK_HASH, "weak-hash", 328, Medium, "Слабая хеш-функция", 0);
rule!(
    WEAK_RANDOM,
    "weak-random",
    330,
    Medium,
    "Секрет из предсказуемого генератора случайных чисел",
    ctx::SECRET
);
rule!(
    WEAK_CIPHER,
    "weak-cipher",
    327,
    High,
    "Слабый или устаревший шифр",
    0
);
rule!(
    INSECURE_COOKIE,
    "insecure-cookie",
    614,
    Medium,
    "Cookie без флага Secure",
    0
);
rule!(
    TLS_NO_VERIFY,
    "tls-no-verify",
    295,
    High,
    "Отключена проверка TLS-сертификата",
    0
);
rule!(
    DEBUG_MODE,
    "debug-enabled",
    489,
    Medium,
    "Включён режим отладки",
    0
);
rule!(
    HARDCODED_SECRET,
    "hardcoded-secret",
    798,
    High,
    "Секрет в исходном коде",
    0
);
rule!(
    BUFFER_OVERFLOW,
    "buffer-overflow",
    787,
    Critical,
    "Переполнение буфера",
    0
);
rule!(
    BUFFER_OVERREAD,
    "buffer-overread",
    125,
    High,
    "Чтение за границей буфера",
    0
);
rule!(
    NULL_DEREF,
    "null-dereference",
    476,
    Medium,
    "Разыменование нулевого указателя",
    0
);
rule!(
    NULL_RETURN,
    "unchecked-null",
    690,
    Medium,
    "Результат не проверен на NULL",
    0
);
rule!(
    FORMAT_STRING,
    "format-string",
    134,
    High,
    "Неконтролируемая строка формата",
    ctx::CODE
);

/// Splits an identifier or key into lowercase words: `resetToken`,
/// `RESET_TOKEN` and `reset-token` all give `reset`, `token`.
pub fn name_words(name: &str) -> impl Iterator<Item = String> + '_ {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphabetic() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words.into_iter()
}

/// Whether a variable, field, key or function with this name holds a value
/// that must be unpredictable.
pub fn secret_name(name: &str) -> bool {
    thread_local! {
        static KNOWN: std::cell::RefCell<std::collections::HashMap<Box<str>, bool>> =
            Default::default();
    }
    if let Some(known) = KNOWN.with(|k| k.borrow().get(name).copied()) {
        return known;
    }
    let answer = secret_name_uncached(name);
    KNOWN.with(|k| {
        let mut k = k.borrow_mut();
        if k.len() > 100_000 {
            k.clear();
        }
        k.insert(name.into(), answer);
    });
    answer
}

fn secret_name_uncached(name: &str) -> bool {
    const WORDS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "nonce",
        "salt",
        "otp",
        "totp",
        "hotp",
        "csrf",
        "xsrf",
        "sessionid",
        "sessid",
        "apikey",
        "captcha",
        "pin",
        "iv",
        "remember",
    ];
    // Words that make a secret only after these qualifiers: `api_key`,
    // `reset_code`, `session_id`.
    const PAIRS: &[(&str, &[&str])] = &[
        (
            "key",
            &[
                "api",
                "secret",
                "private",
                "signing",
                "encryption",
                "access",
                "session",
                "auth",
                "otp",
                "hmac",
            ],
        ),
        (
            "code",
            &[
                "reset",
                "verification",
                "verify",
                "confirm",
                "confirmation",
                "auth",
                "activation",
                "otp",
                "sms",
                "invite",
                "recovery",
                "login",
            ],
        ),
        ("id", &["session", "sess"]),
    ];
    // Run-together lowercase names: `resettoken`, `apikey`, `rememberme`.
    const INNER: &[&str] = &[
        "token",
        "secret",
        "passw",
        "nonce",
        "csrf",
        "xsrf",
        "apikey",
        "sessionid",
        "remember",
    ];
    let words: Vec<String> = name_words(name).collect();
    if words.iter().any(|w| WORDS.contains(&w.as_str())) {
        return true;
    }
    for pair in words.windows(2) {
        if PAIRS
            .iter()
            .any(|(last, firsts)| pair[1] == *last && firsts.contains(&pair[0].as_str()))
        {
            return true;
        }
    }
    words
        .iter()
        .any(|w| w.len() > 5 && INNER.iter().any(|i| w.contains(i)))
}

/// Whether a function with this name makes a secret: `generate_token`,
/// `new_otp`, `make_password`. A view named `password_reset` is not one.
pub fn makes_secret(name: &str) -> bool {
    const VERBS: &[&str] = &[
        "gen", "generate", "make", "create", "new", "random", "rand", "get", "build", "issue",
        "mint", "compute",
    ];
    secret_name(name) && {
        let first = name_words(name).next().unwrap_or_default();
        VERBS.contains(&first.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names() {
        for yes in [
            "token",
            "resetToken",
            "RESET_TOKEN",
            "api_key",
            "apikey",
            "session_id",
            "rememberMe00025",
            "new_password",
            "otp",
            "verification_code",
            "csrfmiddlewaretoken",
        ] {
            assert!(secret_name(yes), "{yes}");
        }
        for no in [
            "seed",
            "test_pk",
            "key",
            "code",
            "id",
            "author",
            "options",
            "filelist",
            "passenger",
            "sentence",
            "spinner",
        ] {
            assert!(!secret_name(no), "{no}");
        }
        assert!(makes_secret("generate_token"));
        assert!(makes_secret("newOtp"));
        assert!(!makes_secret("otp"));
        assert!(!makes_secret("password_reset"));
    }
}
