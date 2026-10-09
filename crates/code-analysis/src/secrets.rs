//! Secrets written into files: passwords, keys and tokens in code of any
//! language, in configuration, scripts, templates and `.env` files.
//!
//! The checks read text, not syntax trees, so they apply to every file a
//! project holds. A value counts as a secret by what names it (the head
//! noun of `admin_password`, `SECRET_KEY`, `api_key`) and by its shape: not
//! empty, not a placeholder, a reference or a field name. Known key formats
//! (AWS, GitHub, private key blocks) count wherever they appear.

use crate::files::TextKind;
use crate::rules::{name_words, Rule, ENV_SECRET, HARDCODED_SECRET};
use regex::Regex;
use std::sync::OnceLock;

/// Where the text comes from, which decides the checks that apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Source code of an analyzed language.
    Code,
    Text(TextKind),
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub rule: &'static Rule,
    pub line: u32,
    pub column: u32,
    pub what: String,
    /// Byte range of the secret in its line, hidden in the snippet.
    pub hide: (usize, usize),
}

/// What the scan of one file needs to know besides its text.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    pub origin: Origin,
    /// A sample or documentation file: only real key formats count.
    pub sample: bool,
    /// A `.env` file that `.gitignore` keeps out of git.
    pub ignored: bool,
    /// Lines are `key = value` settings (see `files::line_settings`).
    pub lines: bool,
}

pub fn scan(text: &str, cx: Context) -> Vec<Hit> {
    let mut hits = Vec::new();
    let settings = matches!(cx.origin, Origin::Text(k) if k.is_settings()) && cx.lines;
    let env_file = cx.origin == Origin::Text(TextKind::Env);
    if env_file && cx.ignored {
        return hits;
    }
    let lines: Vec<&str> = text.lines().collect();
    // Keys and values are read from each line; secrets never span lines
    // except private key blocks, which start on one.
    for (i, &line) in lines.iter().enumerate() {
        if line.len() > 4000 {
            continue;
        }
        let ln = i as u32 + 1;
        let mut push = |rule: &'static Rule, start: usize, end: usize, what: String| {
            if !hits
                .iter()
                .any(|h: &Hit| h.line == ln && h.rule.id == rule.id)
            {
                hits.push(Hit {
                    rule,
                    line: ln,
                    column: column(line, start),
                    what,
                    hide: (start, end),
                });
            }
        };
        for (re, what) in known_formats() {
            let Some(m) = re.find(line) else { continue };
            if m.as_str().contains("EXAMPLE") || m.as_str().contains("example") {
                continue;
            }
            // A key block, not the header text a parser looks for. Keys of
            // samples and test data are made for them.
            if m.as_str().starts_with("-----BEGIN")
                && (cx.sample || !key_body(&line[m.end()..], lines.get(i + 1)))
            {
                continue;
            }
            push(
                &HARDCODED_SECRET,
                m.start(),
                m.end(),
                format!("{what} записан в файле"),
            );
        }
        if cx.sample || matches!(cx.origin, Origin::Text(TextKind::Doc)) {
            continue;
        }
        // Markup shown as text (`&lt;user password="..."&gt;`) is an
        // example for the reader.
        if line.contains("&lt;") || line.contains("&quot;") {
            continue;
        }
        if let Some(c) = connection_url().captures(line) {
            let pass = c.get(2).expect("group");
            if secret_value("password", pass.as_str(), true) {
                push(
                    &HARDCODED_SECRET,
                    pass.start(),
                    pass.end(),
                    format!(
                        "пароль в адресе подключения {}",
                        mask_url(c.get(0).expect("match").as_str(), pass.as_str())
                    ),
                );
            }
        }
        if matches!(cx.origin, Origin::Text(TextKind::Other)) {
            continue;
        }
        let rule = if env_file {
            &ENV_SECRET
        } else {
            &HARDCODED_SECRET
        };
        // `NAME = "value"`, `'name' => 'value'`, `"name": "value"`,
        // `name="value"` in any language.
        for c in assignment().captures_iter(line) {
            let Some(key) = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3)) else {
                continue;
            };
            let Some(v) = c.get(4).or_else(|| c.get(5)) else {
                continue;
            };
            if credential_name(key.as_str())
                && whole_literal(line, v.start(), v.end())
                && secret_value(key.as_str(), v.as_str(), settings)
            {
                push(
                    rule,
                    v.start(),
                    v.end(),
                    assigned(key.as_str(), v.as_str(), env_file),
                );
            }
        }
        // `KEY=value` lines of `.env`, INI, properties and YAML files.
        if settings {
            if let Some((key, start, end)) = setting(line) {
                let v = &line[start..end];
                if credential_name(key) && secret_value(key, v, true) {
                    push(rule, start, end, assigned(key, v, env_file));
                }
            }
        }
        if cx.origin != Origin::Code
            && !matches!(
                cx.origin,
                Origin::Text(TextKind::Script | TextKind::Template)
            )
        {
            continue;
        }
        // `os.getenv("ADMIN_PASS", "...")`: the default is in the code.
        for c in key_call().captures_iter(line) {
            let callee = c.get(1).expect("callee").as_str().to_ascii_lowercase();
            let key = c.get(2).expect("key").as_str();
            let v = c.get(3).expect("value");
            if !(credential_name(key)
                && whole_literal(line, v.start(), v.end())
                && secret_value(key, v.as_str(), true))
            {
                continue;
            }
            // `define('DB_PASSWORD', '...')`, `props.put("password", ...)`
            // set the value; `getenv(name, default)` falls back to it.
            let sets = callee.starts_with("set") && !callee.starts_with("setdefault")
                || matches!(callee.as_str(), "define" | "put" | "add" | "const" | "with");
            let what = if sets {
                assigned(key, v.as_str(), false)
            } else {
                format!(
                    "значение по умолчанию для {key} записано в коде ({}): оно действует, когда переменная не задана",
                    mask(v.as_str())
                )
            };
            push(&HARDCODED_SECRET, v.start(), v.end(), what);
        }
        // `mysqli_connect($host, $user, '...')`, `hmac.new(b'...', ...)`:
        // a literal where a call takes its password or key.
        for (re, index, what) in credential_calls() {
            for m in re.find_iter(line) {
                let args = call_args(line, m.end());
                let Some(&(start, end)) = args.get(*index) else {
                    continue;
                };
                let Some((vs, ve)) = literal_arg(line, start, end) else {
                    continue;
                };
                let name = if what.starts_with("пароль") {
                    "password"
                } else {
                    "secret_key"
                };
                if secret_value(name, &line[vs..ve], true) {
                    push(
                        &HARDCODED_SECRET,
                        vs,
                        ve,
                        format!("{what} передан строкой из кода ({})", mask(&line[vs..ve])),
                    );
                }
            }
        }
        // `"host=db user=app password=..."`: a connection string.
        for c in string_literal().captures_iter(line) {
            let Some(body) = c.get(1).or_else(|| c.get(2)) else {
                continue;
            };
            for p in inline_password().captures_iter(body.as_str()) {
                let v = p.get(1).expect("value");
                let (vs, ve) = (body.start() + v.start(), body.start() + v.end());
                if secret_value("password", v.as_str(), true) {
                    push(
                        &HARDCODED_SECRET,
                        vs,
                        ve,
                        format!("пароль в строке подключения ({})", mask(v.as_str())),
                    );
                }
            }
        }
        // `os.getenv("Welcome2024!")`: the secret itself where the name of
        // a variable belongs.
        for c in env_name().captures_iter(line) {
            let v = c.get(1).expect("name");
            if value_in_place_of_name(v.as_str()) {
                push(
                    &HARDCODED_SECRET,
                    v.start(),
                    v.end(),
                    format!(
                        "вместо имени переменной окружения передано значение, похожее на пароль ({}): такой переменной нет, а секрет остаётся в коде",
                        mask(v.as_str())
                    ),
                );
            }
        }
        // `password == "admin"`: the password is checked against a string
        // in the code.
        for c in comparison().captures_iter(line) {
            let (key, v) = match (c.get(1), c.get(2), c.get(3), c.get(4)) {
                (Some(k), Some(v), _, _) => (k, v),
                (_, _, Some(v), Some(k)) => {
                    // `'math' === $token->namespace` compares the field.
                    if line[k.end()..].starts_with(['.', '-', '[', '(']) {
                        continue;
                    }
                    (k, v)
                }
                _ => continue,
            };
            let key = key.as_str();
            if credential_name(key)
                && whole_literal(line, v.start(), v.end())
                && secret_value(key, v.as_str(), true)
            {
                push(
                    &HARDCODED_SECRET,
                    v.start(),
                    v.end(),
                    format!(
                        "{key} сравнивается со строкой из кода ({})",
                        mask(v.as_str())
                    ),
                );
            }
        }
    }
    hits
}

/// Base64 text after a `-----BEGIN ... PRIVATE KEY-----` header, on the
/// same line (`"...-----\nMIIE..."`) or the next.
fn key_body(rest: &str, next: Option<&&str>) -> bool {
    let b64 = |s: &str| {
        let t = s
            .trim_start_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
            .trim_start_matches("\\n")
            .trim_start_matches("\\r\\n");
        t.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count()
            >= 40
    };
    b64(rest) || next.is_some_and(|n| b64(n))
}

/// Whether the quoted text at `start..end` is a whole string literal, not
/// the start of `"--password=" . $value` or `"x" + id`.
fn whole_literal(line: &str, start: usize, end: usize) -> bool {
    let value = &line[start..end];
    if value.contains(['"', '\'', '`']) || value.contains('(') {
        return false;
    }
    let after = line.get(end + 1..).unwrap_or("").trim_start();
    !(after.starts_with('+') && !after.starts_with("+=")
        || after.starts_with('.') && !after.starts_with("..")
        || after.starts_with("||")
        || after.starts_with('%'))
}

fn assigned(key: &str, value: &str, env_file: bool) -> String {
    if env_file {
        format!(
            "{key} = {} лежит в .env, а .gitignore этот файл не исключает: его легко закоммитить или выложить вместе с кодом",
            mask(value)
        )
    } else {
        format!("{key} = {} записан прямо в файле", mask(value))
    }
}

/// The line text with each secret replaced by its first characters.
pub fn masked_line(line: &str, hides: &[(usize, usize)]) -> String {
    let mut out = String::new();
    let mut at = 0;
    let mut sorted = hides.to_vec();
    sorted.sort();
    for (s, e) in sorted {
        if s < at || e > line.len() || !line.is_char_boundary(s) || !line.is_char_boundary(e) {
            continue;
        }
        out.push_str(&line[at..s]);
        out.push_str(&mask(&line[s..e]));
        at = e;
    }
    out.push_str(&line[at..]);
    out
}

/// The first two characters of a secret, enough to recognize it.
pub fn mask(value: &str) -> String {
    let head: String = value.chars().take(2).collect();
    format!("{head}••••••")
}

fn mask_url(url: &str, pass: &str) -> String {
    url.replacen(pass, &mask(pass), 1)
}

fn column(line: &str, byte: usize) -> u32 {
    line[..byte.min(line.len())].chars().count() as u32 + 1
}

/// Whether a key, variable or field with this name holds a credential: its
/// last word is `password`, `secret`, `token` or a qualified `key`
/// (`api_key`, `SECRET_KEY`). `password_field`, `token_url` and
/// `secret_name` name something else.
pub fn credential_name(name: &str) -> bool {
    const NOUNS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "credential",
        "credentials",
    ];
    // Run together: `dbpassword`, `SECRETKEY`, `accesstoken`.
    const ENDINGS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "secretkey",
        "privatekey",
        "accesskey",
    ];
    const KEY_QUALIFIERS: &[&str] = &[
        "api",
        "secret",
        "private",
        "signing",
        "encryption",
        "access",
        "auth",
        "hmac",
        "master",
        "app",
        "client",
        "jwt",
        "aes",
        "crypt",
        "crypto",
        "license",
        "consumer",
        "server",
        "service",
        "account",
    ];
    let words: Vec<String> = name_words(name).collect();
    let Some(last) = words.last() else {
        return false;
    };
    if NOUNS.contains(&last.as_str()) {
        // `csrf_token` and `xsrf_token` are form fields, not credentials.
        return !(words.len() >= 2
            && matches!(
                words[words.len() - 2].as_str(),
                "csrf" | "xsrf" | "reset" | "remember"
            ));
    }
    if last == "key" && words.len() >= 2 {
        return KEY_QUALIFIERS.contains(&words[words.len() - 2].as_str());
    }
    ENDINGS
        .iter()
        .any(|e| last.len() > e.len() && last.ends_with(e) && !last.starts_with("csrf"))
}

/// Whether `value`, named by `key`, looks like a real secret rather than a
/// placeholder, a reference, a field name or a label. `settings` is for
/// `key = value` files, where every value is a setting: a single word
/// there is a password too.
pub fn secret_value(key: &str, value: &str, settings: bool) -> bool {
    let v = value.trim();
    let n = v.chars().count();
    // Secrets are ASCII: text in other scripts is a message.
    if !(4..=500).contains(&n) || v.chars().any(char::is_whitespace) || !v.is_ascii() {
        return false;
    }
    // Tokens and keys are long random strings; a password can be short.
    let words: Vec<String> = name_words(key).collect();
    let last = words.last().map(String::as_str).unwrap_or("");
    let min = if last.ends_with("token") {
        10
    } else if last.ends_with("secret") || last.ends_with("key") {
        6
    } else {
        4
    };
    if n < min || v.contains('(') {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    const STARTS: &[&str] = &[
        "${",
        "$(",
        "%(",
        "{{",
        "{%",
        "<%",
        "<",
        "[",
        "$",
        "%",
        "@",
        "#{",
        "__",
        "env:",
        "env(",
        "process.env",
        "os.environ",
        "getenv",
        "vault:",
        "secret:",
        "arn:",
        "ref+",
        ".",
        "+",
        ")",
        ",",
        ";",
        "&",
        "=",
        "{",
    ];
    if STARTS.iter().any(|s| lower.starts_with(s)) {
        return false;
    }
    if ["${", "{{", "%s", "{}", "{0}", "%(", "%d"]
        .iter()
        .any(|s| v.contains(s))
    {
        return false;
    }
    const PLACEHOLDERS: &[&str] = &[
        "example",
        "sample",
        "dummy",
        "placeholder",
        "changeme",
        "change_me",
        "change-me",
        "changethis",
        "your_",
        "your-",
        "yourpass",
        "yoursecret",
        "yourtoken",
        "xxxx",
        "****",
        "....",
        "todo",
        "fixme",
        "replace",
        "insert",
        "_here",
        "-here",
        "redacted",
        "secret_key_base",
        "notasecret",
        "not-a-secret",
        "not_a_secret",
        "fake",
        "mock",
    ];
    if PLACEHOLDERS.iter().any(|p| lower.contains(p)) {
        return false;
    }
    // Labels that name an algorithm (`wp-sha384`) and names of other
    // credentials (`@sensitive_variables("password1", "password2")`).
    if ["sha1", "sha2", "sha3", "sha5", "md5", "hmac-", "-hmac"]
        .iter()
        .any(|a| lower.contains(a))
    {
        return false;
    }
    if v.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && credential_name(v)
    {
        return false;
    }
    const WORDS: &[&str] = &[
        "password",
        "passwd",
        "pass",
        "secret",
        "token",
        "key",
        "apikey",
        "api_key",
        "none",
        "null",
        "nil",
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "required",
        "optional",
        "string",
        "text",
        "hidden",
        "bearer",
        "basic",
        "digest",
        "oauth",
        "oauth2",
        "jwt",
        "hs256",
        "hs512",
        "rs256",
        "sha256",
        "sha1",
        "md5",
        "bcrypt",
        "argon2",
        "utf-8",
        "utf8",
        "ascii",
        "base64",
        "hex",
        "json",
        "test",
        "default",
        "unknown",
        "empty",
        "secure",
        "insecure",
        "plain",
        "plaintext",
        "sha512",
        "hashed",
        "confirmed",
        "undefined",
        "nullable",
    ];
    if WORDS.contains(&lower.as_str()) {
        return false;
    }
    // The key itself, or one of its words: `"password": "password"`.
    let key_lower = key.to_ascii_lowercase();
    if lower == key_lower || words.last() == Some(&lower) || words.concat() == lower {
        return false;
    }
    // Identifiers and setting names: `password_confirmation`, `newPassword`,
    // `DB_PASSWORD`, `auth.password`, `App\\Models\\User`.
    let ident = |s: &str| {
        s.chars().all(|c| {
            c.is_ascii_alphabetic() || c == '_' || c == '.' || c == '-' || c == '\\' || c == ':'
        })
    };
    // `org.apache.manager2.CSRF_NONCE`: a dotted name with digits.
    let dotted = v.split('.').count() >= 3
        && v.split('.').all(|p| {
            p.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    if dotted {
        return false;
    }
    // An address: `anon@anon.com` for anonymous FTP.
    if let Some((user, host)) = v.split_once('@') {
        if !user.is_empty()
            && host.contains('.')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return false;
        }
    }
    let has_sep =
        v.contains(['_', '.', '\\', ':']) || (v.contains('-') && !v.contains(char::is_numeric));
    if ident(v) && has_sep {
        return false;
    }
    let camel = v.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && v.chars().any(|c| c.is_ascii_uppercase())
        && v.chars().all(|c| c.is_ascii_alphabetic());
    if camel {
        return false;
    }
    // Paths, file names and URLs.
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.contains("://") {
        return false;
    }
    if v.contains(['/', '\\'])
        && (v.starts_with(['/', '.', '~', '\\'])
            || has_extension(&lower)
            || v.chars().nth(1) == Some(':'))
    {
        return false;
    }
    if has_extension(&lower) && !v.contains(char::is_numeric) {
        return false;
    }
    // Validation rules (`required|min:8`), MIME types, numbers.
    if v.contains('|')
        && lower
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "|:,_-".contains(c))
    {
        return false;
    }
    if v.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
        && n < 6
    {
        return false;
    }
    if v.chars().all(|c| c == v.chars().next().unwrap_or(' ')) {
        return false;
    }
    // A single word of letters: not a label (`Password`) or a constant
    // (`YEAR`). A token is random, so a word in one is a lexer token type
    // (`token == "comment"`). A password or a signing key can be a word
    // (`admin_password = "admin"`, `signing_key = "snowman"`) when the
    // name says whose it is or the file holds settings; a bare `password`
    // key elsewhere is more often a form field or a label.
    if v.chars().all(|c| c.is_ascii_alphabetic()) {
        let ends = |nouns: &[&str]| {
            nouns
                .iter()
                .any(|p| last == *p || (last.len() > p.len() && last.ends_with(p)))
        };
        let password = ends(&[
            "password",
            "passwd",
            "pwd",
            "pass",
            "passphrase",
            "credential",
            "credentials",
        ]);
        let key_like = ends(&["secret", "key", "apikey"]);
        let title = v.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && v.chars().skip(1).all(|c| c.is_ascii_lowercase());
        let caps = v.chars().all(|c| c.is_ascii_uppercase());
        let qualified = words.len() >= 2;
        return !title
            && !caps
            && ((password && (qualified || settings)) || (key_like && qualified));
    }
    true
}

fn has_extension(lower: &str) -> bool {
    const EXT: &[&str] = &[
        ".pem", ".key", ".crt", ".cer", ".txt", ".json", ".yml", ".yaml", ".xml", ".p12", ".pfx",
        ".jks", ".html", ".php", ".py", ".js", ".conf", ".cfg", ".ini", ".env", ".log", ".png",
        ".jpg", ".gif", ".svg", ".css", ".db", ".sqlite", ".csv", ".gpg", ".asc", ".pub",
    ];
    EXT.iter().any(|e| lower.ends_with(e))
}

/// A value passed where the name of an environment variable belongs:
/// names are identifiers (`ADMIN_PASS`, `db.url`); `Welcome2024!` is not.
fn value_in_place_of_name(v: &str) -> bool {
    let n = v.chars().count();
    if !(6..=128).contains(&n) || v.chars().any(char::is_whitespace) {
        return false;
    }
    let odd = v
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':' | '/')));
    let mixed = v.chars().any(|c| c.is_ascii_digit())
        && v.chars().any(|c| c.is_ascii_lowercase())
        && v.chars().any(|c| c.is_ascii_uppercase());
    (odd || mixed)
        && !v.starts_with(['$', '%', '{', '<'])
        && !v.contains("${")
        && secret_value("password", v, true)
}

/// `KEY=value`, `key: value`, `export KEY="value"` lines; the key and the
/// byte range of the value, without quotes and trailing comments.
fn setting(line: &str) -> Option<(&str, usize, usize)> {
    let c = setting_line().captures(line)?;
    let key = c.get(1)?.as_str();
    let m = c.get(2)?;
    let raw = m.as_str();
    let mut start = m.start();
    let mut end = m.end();
    let trimmed = raw.trim_end();
    end -= raw.len() - trimmed.len();
    let t = &line[start..end];
    if let Some(q) = t.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let close = t[1..].find(q)? + 1;
        return Some((key, start + 1, start + close));
    }
    // ` # comment` after an unquoted value.
    if let Some(i) = t
        .find(" #")
        .or_else(|| t.find("\t#"))
        .or_else(|| t.find(" ;"))
    {
        end = start + i;
    }
    let t = line[start..end].trim();
    start += line[start..end].find(t).unwrap_or(0);
    Some((key, start, start + t.len()))
}

fn known_formats() -> &'static [(Regex, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        [
            (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "ключ доступа AWS"),
            (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", "токен GitHub"),
            (r"\bgithub_pat_[A-Za-z0-9_]{60,}", "токен GitHub"),
            (r"\bglpat-[A-Za-z0-9_\-]{20}\b", "токен GitLab"),
            (r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", "токен Slack"),
            (r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}", "секретный ключ Stripe"),
            (r"\bAIza[0-9A-Za-z_\-]{35}\b", "ключ Google API"),
            (r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "ключ Anthropic API"),
            (r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}", "ключ OpenAI API"),
            (r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b", "токен Telegram-бота"),
            (r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "ключ SendGrid"),
            (r"\bnpm_[A-Za-z0-9]{36}\b", "токен npm"),
            (r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "токен PyPI"),
            (
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
                "закрытый ключ",
            ),
            (
                r"\bAccountKey=[A-Za-z0-9+/]{80,}={0,2}",
                "ключ хранилища Azure",
            ),
        ]
        .into_iter()
        .map(|(p, w)| (Regex::new(p).expect("pattern"), w))
        .collect()
    })
}

fn connection_url() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://([^\s:/@'"`<>]{1,64}):([^\s@/'"`<>]{3,128})@[A-Za-z0-9.\-_\[\]]+"#)
            .expect("pattern")
    })
}

fn assignment() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?:"([A-Za-z_][A-Za-z0-9_.\-]*)"|'([A-Za-z_][A-Za-z0-9_.\-]*)'|\$?\b([A-Za-z_][A-Za-z0-9_]*))\s*(?:\[\s*\d*\s*\]\s*)?(?:\]\s*)?(?:=>|:=|=|:)\s*(?:[rRbBuU]{1,2})?(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')"#,
        )
        .expect("pattern")
    })
}

fn setting_line() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^\s*(?:export\s+|set\s+|\$env:)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*(?:=|:)\s*(\S.*)$"#)
            .expect("pattern")
    })
}

/// `getenv("NAME", "default")`, `define('NAME', 'value')`,
/// `getenv('NAME') ?: 'default'`: the callee, the key and the value.
fn key_call() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_.\-]*)["']\s*(?:,\s*[rRbBuU]?|\)\s*(?:or|\?:|\?\?|\|\|)\s*)["']([^"'\n]*)["']"#,
        )
        .expect("pattern")
    })
}

/// Calls that take a password or a key, with its argument position.
fn credential_calls() -> &'static [(Regex, usize, &'static str)] {
    static R: OnceLock<Vec<(Regex, usize, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        const DB: &str = "пароль базы данных";
        const KEY: &str = "ключ шифрования";
        const HMAC: &str = "ключ HMAC";
        const JWT: &str = "ключ подписи JWT";
        [
            // PHP
            (r"\bmysqli_connect\s*\(", 2, DB),
            (r"\bmysql_connect\s*\(", 2, DB),
            (r"\bmysqli_real_connect\s*\(", 3, DB),
            (r"\bnew\s+mysqli\s*\(", 2, DB),
            (r"\bnew\s+\\?PDO\s*\(", 2, DB),
            (r"\bpg_connect\s*\(", 0, DB),
            (r"\bldap_bind\s*\(", 2, "пароль LDAP"),
            (r"\bftp_login\s*\(", 2, "пароль FTP"),
            (r"\bssh2_auth_password\s*\(", 2, "пароль SSH"),
            (r"\bhash_hmac\s*\(", 2, HMAC),
            (r"\bopenssl_(?:encrypt|decrypt)\s*\(", 2, KEY),
            (r"\bJWT::(?:encode|decode)\s*\(", 1, JWT),
            // Python
            (r"\bhmac\.new\s*\(", 0, HMAC),
            (r"\bjwt\.(?:encode|decode)\s*\(", 1, JWT),
            (r"\bHTTPBasicAuth\s*\(", 1, "пароль"),
            (r"\bHTTPDigestAuth\s*\(", 1, "пароль"),
            (r"\bFernet\s*\(", 0, KEY),
            (r"\bAES\.new\s*\(", 0, KEY),
            (
                r"\b(?:URLSafe)?(?:Timed)?Serializer\s*\(",
                0,
                "ключ подписи",
            ),
            (r"\.login\s*\(", 1, "пароль"),
            // Java
            (r"\bDriverManager\.getConnection\s*\(", 2, DB),
            (r"\bnew\s+SecretKeySpec\s*\(", 0, KEY),
            (r"\bAlgorithm\.HMAC(?:256|384|512)\s*\(", 0, JWT),
            (r"\bKeys\.hmacShaKeyFor\s*\(", 0, JWT),
            (r"\.signWith\s*\(", 1, JWT),
            (r"\.setSigningKey\s*\(", 0, JWT),
            (r"\bnew\s+PasswordAuthentication\s*\(", 1, "пароль"),
            // C
            (r"\bmysql_real_connect\s*\(", 3, DB),
            (r"\bHMAC\s*\(", 1, HMAC),
            (r"\bPQconnectdb\s*\(", 0, DB),
        ]
        .into_iter()
        .map(|(p, i, w)| (Regex::new(p).expect("pattern"), i, w))
        .collect()
    })
}

/// Byte ranges of the arguments of a call whose `(` ends at `open`, on
/// its line: commas at depth zero, outside strings, split them.
fn call_args(line: &str, open: usize) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0;
    let mut quote: Option<u8> = None;
    let mut start = open;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 1;
                } else if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' if depth > 0 => depth -= 1,
                b')' => {
                    args.push((start, i));
                    return args;
                }
                b',' if depth == 0 => {
                    args.push((start, i));
                    start = i + 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    args.push((start, bytes.len()));
    args
}

/// The text of an argument that is a string literal, possibly as bytes:
/// `"x"`, `b'x'`, `"x".getBytes()`, `'x'.encode()`, `"x".toCharArray()`.
fn literal_arg(line: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let arg = &line[start..end];
    let lead = arg.len() - arg.trim_start().len();
    let mut t = arg.trim();
    let mut s = start + lead;
    for suffix in [".getBytes()", ".toCharArray()", ".encode()", ".as_bytes()"] {
        if let Some(rest) = t.strip_suffix(suffix) {
            t = rest;
        }
    }
    if let Some(i) = t.find(".getBytes(").or_else(|| t.find(".encode(")) {
        if t.ends_with(')') {
            t = &t[..i];
        }
    }
    let prefix = t.len() - t.trim_start_matches(['b', 'r', 'u', 'B', 'R', 'U']).len();
    if prefix <= 2 {
        t = &t[prefix..];
        s += prefix;
    }
    let q = t.chars().next()?;
    if !(q == '"' || q == '\'') || t.len() < 2 || !t.ends_with(q) {
        return None;
    }
    let inner = &t[1..t.len() - 1];
    if inner.contains(q) {
        return None;
    }
    Some((s + 1, s + 1 + inner.len()))
}

fn string_literal() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#""((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'"#).expect("pattern"))
}

/// `password=...` inside a connection string or a URL query.
fn inline_password() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)(?:^|[;\s?&])(?:password|pwd|passwd)\s*=\s*([^;&\s'"]+)"#)
            .expect("pattern")
    })
}

fn env_name() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?:\bgetenv|environ\.get|environ\s*\[|\$_ENV\s*\[|\$_SERVER\s*\[|System\.getenv|GetEnvironmentVariable|process\.env\[)\s*\(?\s*["']([^"'\n]+)["']"#,
        )
        .expect("pattern")
    })
}

fn comparison() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:===?|!==?|\.equals\(|\.equalsIgnoreCase\()\s*["']([^"'\n]+)["']|["']([^"'\n]+)["']\s*(?:===?|!==?|\.equals\()\s*\$?(?:self\.|this\.|\$this->)?([A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("pattern")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(src: &str) -> Vec<(u32, String)> {
        scan(
            src,
            Context {
                origin: Origin::Code,
                sample: false,
                ignored: false,
                lines: true,
            },
        )
        .into_iter()
        .map(|h| (h.line, h.what))
        .collect()
    }

    #[test]
    fn credential_names() {
        for yes in [
            "password",
            "ADMIN_PASS",
            "db_password",
            "SECRET_KEY",
            "api_key",
            "apiKey",
            "client_secret",
            "access_token",
            "DBPASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "mysqlPassword",
        ] {
            assert!(credential_name(yes), "{yes}");
        }
        for no in [
            "password_field",
            "token_url",
            "secret_name",
            "csrf_token",
            "key",
            "TOKEN_HEADER",
            "passwordReset",
            "PASSWORD_MIN_LENGTH",
            "bypass",
            "primary_key",
        ] {
            assert!(!credential_name(no), "{no}");
        }
    }

    #[test]
    fn secret_values() {
        for yes in [
            "ShifoAdmin2026!",
            "s3cr3t-v4lue",
            "hunter22",
            "123456",
            "dQw4w9WgXcQ",
            "MySecret123",
        ] {
            assert!(secret_value("admin_password", yes, false), "{yes}");
        }
        assert!(secret_value("ADMIN_PASSWORD", "admin", false));
        assert!(secret_value("lSigningKey", "snowman", false));
        assert!(!secret_value("defaultToken", "comment", false));
        assert!(!secret_value("password", "admin", false));
        for no in [
            "",
            "abc",
            "${DB_PASSWORD}",
            "changeme",
            "your-secret-here",
            "password",
            "Password",
            "Пароль",
            "password_confirmation",
            "newPassword",
            "DB_PASSWORD",
            "required|min:8",
            "/etc/secret.key",
            "certs/server.pem",
            "https://example.org/token",
            "********",
            "two words",
            "{{ password }}",
            "%(password)s",
        ] {
            assert!(!secret_value("password", no, false), "{no}");
        }
    }

    #[test]
    fn assignments_in_any_language() {
        let found = code(
            r#"ADMIN_PASS = os.getenv("ADMIN_PASS", "ShifoAdmin2026!")
SECRET = os.getenv("Welcome2024!")
password = "s3cr3t-v4lue"
$db_password = 'hunter22x';
private static final String API_KEY = "k8s7D6f5G4h3";
'password' => 'required|min:8',
form = {"password": "password"}
if password == "letmein1":
token = request.cookies.get("admin_session")
user = os.getenv("ADMIN_USER", "admin")
"#,
        );
        let lines: Vec<u32> = found.iter().map(|f| f.0).collect();
        assert_eq!(lines, vec![1, 2, 3, 4, 5, 8], "{found:?}");
        assert!(found[0].1.contains("ADMIN_PASS"), "{found:?}");
        assert!(found[1].1.contains("вместо имени"), "{found:?}");
        assert!(
            !found.iter().any(|f| f.1.contains("ShifoAdmin2026")),
            "masked: {found:?}"
        );
    }

    #[test]
    fn credentials_passed_to_calls() {
        let found = code(
            r#"$db = mysqli_connect('localhost', 'shop', 'Sh0p!2026', 'shop');
$db = mysqli_connect('localhost', 'shop', 'secret', 'shop');
$pdo = new PDO($dsn, $user, getenv('DB_PASS'));
sig = hmac.new(b'k3y-f0r-s1gning', msg, hashlib.sha256)
SecretKeySpec key = new SecretKeySpec("A1b2C3d4E5f6G7h8".getBytes(), "AES");
conn = psycopg2.connect("host=db user=app password=Xy7pQ2zz")
define('DB_PASSWORD', 'r00tPa55');
props.setProperty("mail.password", "M4ilP4ss");
"#,
        );
        let lines: Vec<u32> = found.iter().map(|f| f.0).collect();
        assert_eq!(lines, vec![1, 4, 5, 6, 7, 8], "{found:?}");
        assert!(found[5].1.starts_with("mail.password = "), "{found:?}");
    }

    #[test]
    fn lookalikes_in_real_projects_are_not_secrets() {
        let found = code(
            r#"sql = "SELECT * FROM t WHERE user='"+name+"' AND password='"+password+"'"
debug.append("Token: ").append(token).append("\n");
'password' => '--password='.$connection['password'],
$variables['MERCURE_KEY'] = 'base64:'.base64_encode(random_bytes(32));
if (token.type == "comment" || "keyword" === token.type) {}
if ("time-taken".equals(token)) {}
if ('math' === $current_token->namespace) {}
{defaultToken : "comment", caseInsensitive: true}
{ .name = "fp32", .type = REDISMODULE_ARG_TYPE_PURE_TOKEN, .token = "FP32" },
"token": "AUTH2",
@sensitive_variables("password1", "password2")
$h = hash_hmac( 'sha384', $password, 'wp-sha384', true );
conn = 'dbname={database} user={user} password={password} host={host}'
sql = "SELECT * FROM users WHERE password=?"
private static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----
";
public static final String CSRF_TOKEN_SESSION_KEY = "org.apache.tomcat.manager2.CSRF_TOKEN";
$this->_password="anon@anon.com";
<filter token="YEAR" value="${year}"/>
&lt;user username="tomcat" password="s3cret" roles="admin-gui"/&gt;
String apiKey = "APIKEY-" + UUID.randomUUID();
"#,
        );
        assert!(found.is_empty(), "{found:?}");
        let props = scan(
            "corsFilter.invalidSupportsCredentials=当allowedOrigins为通配符时不支持\nspring.datasource.password=woshiniba\n",
            Context {
                origin: Origin::Text(TextKind::Config),
                sample: false,
                ignored: false,
                lines: true,
            },
        );
        assert_eq!(props.len(), 1, "{props:?}");
        let pem = code("KEY = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun'\n");
        assert_eq!(pem.len(), 1, "{pem:?}");
    }

    #[test]
    fn env_files_count_unless_git_ignores_them() {
        let cx = |ignored| Context {
            origin: Origin::Text(TextKind::Env),
            sample: false,
            ignored,
            lines: true,
        };
        let text = "SESSION_SECRET=9f8e7d6c5b4a\nDEBUG=true\nADMIN_PASS=\n";
        let found = scan(text, cx(false));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule.id, "env-secret");
        assert!(scan(text, cx(true)).is_empty());
    }

    #[test]
    fn known_formats_and_connection_strings() {
        let found = code(
            "KEY = 'AKIAABCDEFGHIJKLMNOP'\nDOC = 'AKIAIOSFODNN7EXAMPLE'\nDB = 'postgres://app:Xy7pQ2zz@db:5432/app'\nDB2 = 'postgres://app:${PASS}@db/app'\n",
        );
        let lines: Vec<u32> = found.iter().map(|f| f.0).collect();
        assert_eq!(lines, vec![1, 3], "{found:?}");
    }

    #[test]
    fn snippets_hide_the_secret() {
        assert_eq!(
            masked_line("PASS = \"hunter22\"", &[(8, 16)]),
            "PASS = \"hu••••••\""
        );
    }
}
