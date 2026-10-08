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
    "Предсказуемый генератор случайных чисел",
    0
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
    120,
    Critical,
    "Переполнение буфера",
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
