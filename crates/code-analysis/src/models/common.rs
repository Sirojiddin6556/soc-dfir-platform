//! String handling and condition rules shared by the language models.

use crate::interp::{arg, args_taint, ArgVal, Fact, FactOn};
use crate::value::*;
use std::rc::Rc;

pub fn literal(segs: &[Seg]) -> Option<String> {
    Value::Str(Rc::new(segs.to_vec())).as_str()
}

/// Applies `f` to the known text; unknown pieces stay as they are.
pub fn map_lits(segs: &[Seg], f: impl Fn(&str) -> String) -> Value {
    Value::segs(
        segs.iter()
            .map(|s| match s {
                Seg::Lit(t) => Seg::Lit(f(t)),
                d => d.clone(),
            })
            .collect(),
    )
}

/// `s.replace(old, new)`. Removing a quote character makes the unknown
/// pieces safe inside literals quoted with it.
pub fn replace_segs(segs: &[Seg], old: &str, new: &Value) -> Value {
    let Some(new_s) = new.as_str() else {
        let t = Value::Str(Rc::new(segs.to_vec()))
            .taint()
            .union(&new.taint());
        return Value::tainted_str(t);
    };
    if old.is_empty() {
        return Value::Str(Rc::new(segs.to_vec()));
    }
    let mut bits = 0;
    if old.contains('\'') && !new_s.contains('\'') {
        bits |= ctx::NO_SQUOTE;
    }
    if old.contains('"') && !new_s.contains('"') {
        bits |= ctx::NO_DQUOTE;
    }
    Value::segs(
        segs.iter()
            .map(|s| match s {
                Seg::Lit(t) => Seg::Lit(t.replace(old, &new_s)),
                Seg::Dyn(t) => Seg::Dyn(t.clone().with_safe(bits)),
            })
            .collect(),
    )
}

/// `"{0} {name} {0[key]}".format(...)`.
pub fn brace_format(segs: &[Seg], args: &[ArgVal]) -> Value {
    let Some(fmt) = literal(segs) else {
        let t = Value::Str(Rc::new(segs.to_vec()))
            .taint()
            .union(&args_taint(args));
        return Value::tainted_str(t);
    };
    let positional: Vec<&Value> = args
        .iter()
        .filter(|a| a.name.is_none() && !a.spread)
        .map(|a| &a.value)
        .collect();
    let mut out = Vec::new();
    let mut auto = 0usize;
    let mut chars = fmt.chars().peekable();
    let mut text = String::new();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                text.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                text.push('}');
            }
            '{' => {
                let mut field = String::new();
                for d in chars.by_ref() {
                    if d == '}' {
                        break;
                    }
                    field.push(d);
                }
                out.push(Seg::Lit(std::mem::take(&mut text)));
                let spec_free = field.split([':', '!']).next().unwrap_or("").to_string();
                let (head, rest) = match spec_free.find(['[', '.']) {
                    Some(i) => (spec_free[..i].to_string(), spec_free[i..].to_string()),
                    None => (spec_free.clone(), String::new()),
                };
                let mut v = if head.is_empty() {
                    auto += 1;
                    positional.get(auto - 1).map(|v| (*v).clone())
                } else if let Ok(i) = head.parse::<usize>() {
                    positional.get(i).map(|v| (*v).clone())
                } else {
                    crate::interp::kwarg(args, &head).cloned()
                }
                .unwrap_or_else(|| Value::Unknown(args_taint(args)));
                for part in split_accessors(&rest) {
                    v = match (&v, part) {
                        (Value::Dict(pairs), Accessor::Key(k)) => {
                            let key = k
                                .parse::<i64>()
                                .map(Value::Int)
                                .unwrap_or_else(|_| Value::str(k.clone()));
                            pairs
                                .iter()
                                .find(|(pk, _)| *pk == key)
                                .map(|(_, x)| x.clone())
                                .unwrap_or_else(Value::clean)
                        }
                        (Value::List(items), Accessor::Key(k)) => k
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| items.get(i).cloned())
                            .unwrap_or_else(Value::clean),
                        (Value::Obj(o), Accessor::Attr(a)) => o
                            .field(&a)
                            .cloned()
                            .unwrap_or_else(|| Value::Unknown(o.taint.clone())),
                        (other, _) => Value::Unknown(other.taint()),
                    };
                }
                out.extend(v.to_segs());
            }
            _ => text.push(c),
        }
    }
    out.push(Seg::Lit(text));
    Value::segs(out)
}

enum Accessor {
    Key(String),
    Attr(String),
}

fn split_accessors(s: &str) -> Vec<Accessor> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']').unwrap_or(r.len());
            out.push(Accessor::Key(r[..end].to_string()));
            rest = r.get(end + 1..).unwrap_or("");
        } else if let Some(r) = rest.strip_prefix('.') {
            let end = r.find(['[', '.']).unwrap_or(r.len());
            out.push(Accessor::Attr(r[..end].to_string()));
            rest = &r[end..];
        } else {
            break;
        }
    }
    out
}

/// printf-style `fmt % args`.
pub fn percent_format(segs: &[Seg], args: &Value) -> Value {
    let Some(fmt) = literal(segs) else {
        let t = Value::Str(Rc::new(segs.to_vec()))
            .taint()
            .union(&args.taint());
        return Value::tainted_str(t);
    };
    let positional: Vec<Value> = match args {
        Value::List(items) => items.as_ref().clone(),
        Value::Dict(_) => Vec::new(),
        other => vec![other.clone()],
    };
    let mut out = Vec::new();
    let mut text = String::new();
    let mut next = 0usize;
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            text.push(c);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            text.push('%');
            continue;
        }
        let mut key = None;
        if chars.peek() == Some(&'(') {
            chars.next();
            let mut k = String::new();
            for d in chars.by_ref() {
                if d == ')' {
                    break;
                }
                k.push(d);
            }
            key = Some(k);
        }
        let mut conv = 's';
        for d in chars.by_ref() {
            if d.is_ascii_alphabetic() {
                conv = d;
                break;
            }
        }
        out.push(Seg::Lit(std::mem::take(&mut text)));
        let v = match (&key, args) {
            (Some(k), Value::Dict(pairs)) => pairs
                .iter()
                .find(|(pk, _)| pk.as_str().as_deref() == Some(k.as_str()))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(Value::clean),
            (Some(_), other) => Value::Unknown(other.taint()),
            (None, _) => {
                next += 1;
                positional
                    .get(next - 1)
                    .cloned()
                    .unwrap_or_else(|| Value::Unknown(args.taint()))
            }
        };
        match conv {
            's' | 'r' | 'a' => out.extend(v.to_segs()),
            _ => match v {
                Value::Int(i) => out.push(Seg::Lit(i.to_string())),
                other => out.push(Seg::Dyn(other.taint().with_safe(ctx::ALL))),
            },
        }
    }
    out.push(Seg::Lit(text));
    Value::segs(out)
}

/// Safety a user function's name promises (`escape_html`, `sanitize_html`).
pub fn name_sanitizer(name: &str) -> u32 {
    let n = name.to_ascii_lowercase();
    let escapes = n.contains("escape")
        || n.contains("encode")
        || n.contains("sanitiz")
        || n.contains("clean")
        || n.contains("htmlspecialchars");
    let mut bits = 0;
    if escapes
        && (n.contains("html") || n.contains("xml") || n.contains("xss") || n == "htmlspecialchars")
    {
        bits |= ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE;
    }
    if escapes && n.contains("sql") {
        bits |= ctx::SQL;
    }
    if escapes && (n.contains("shell") || n.contains("cmd") || n.contains("arg")) {
        bits |= ctx::SHELL;
    }
    if escapes && n.contains("ldap") {
        bits |= ctx::LDAP;
    }
    bits
}

/// Facts from string methods used as conditions.
pub fn refine_str_method(name: &str, args: &[Value], truth: bool) -> Vec<(FactOn, Fact)> {
    let lit = args.first().and_then(|a| a.as_str());
    let on_recv = |f: Fact| vec![(FactOn::Recv, f)];
    match (name, truth) {
        ("startswith" | "startsWith", true) => match lit {
            Some(p) => on_recv(Fact::StartsWith(p)),
            None => on_recv(Fact::StartsWithValue),
        },
        ("endswith" | "endsWith", true) => {
            lit.map(|p| on_recv(Fact::EndsWith(p))).unwrap_or_default()
        }
        ("isdigit" | "isnumeric" | "isdecimal" | "isalnum" | "isalpha" | "isidentifier", true) => {
            on_recv(Fact::Safe(ctx::ALL & !ctx::SESSION))
        }
        _ => Vec::new(),
    }
}

/// Characters a regular expression can match, for the simple patterns used
/// as validators and filters: a sequence of character classes, escapes and
/// literals with quantifiers. `None` for anything more complex.
pub fn regex_chars(pattern: &str) -> Option<CharSet> {
    let mut set = CharSet::default();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '^' | '$' if i == 0 || i == chars.len() - 1 => i += 1,
            '+' | '*' | '?' => i += 1,
            '{' => {
                let end = chars[i..].iter().position(|c| *c == '}')? + i;
                if !chars[i + 1..end]
                    .iter()
                    .all(|c| c.is_ascii_digit() || *c == ',')
                {
                    return None;
                }
                i = end + 1;
            }
            '[' => {
                let (class, next) = parse_class(&chars, i)?;
                set.union(&class);
                i = next;
            }
            '\\' => {
                let e = *chars.get(i + 1)?;
                match e {
                    'A' | 'Z' | 'z' if i == 0 || i + 2 >= chars.len() => {}
                    _ => set.union(&escape_class(e)?),
                }
                i += 2;
            }
            '.' | '(' | ')' | '|' => return None,
            other => {
                set.add(other);
                i += 1;
            }
        }
    }
    Some(set)
}

/// Whether a pattern must match the whole string (anchored at both ends).
pub fn regex_anchored(pattern: &str, full: bool) -> bool {
    let start = full || pattern.starts_with('^') || pattern.starts_with("\\A");
    let end =
        full || pattern.ends_with('$') || pattern.ends_with("\\Z") || pattern.ends_with("\\z");
    start && end
}

#[derive(Debug, Clone)]
pub struct CharSet {
    ascii: [bool; 128],
    /// `\w` and similar classes also match non-ASCII letters.
    unicode_letters: bool,
    /// A negated class matches everything outside it, including non-ASCII.
    other: bool,
}

impl Default for CharSet {
    fn default() -> Self {
        CharSet {
            ascii: [false; 128],
            unicode_letters: false,
            other: false,
        }
    }
}

impl CharSet {
    pub fn add(&mut self, c: char) {
        if (c as u32) < 128 {
            self.ascii[c as usize] = true;
        } else {
            self.other = true;
        }
    }

    fn union(&mut self, o: &CharSet) {
        for i in 0..128 {
            self.ascii[i] |= o.ascii[i];
        }
        self.unicode_letters |= o.unicode_letters;
        self.other |= o.other;
    }

    fn negate(&self) -> CharSet {
        let mut n = CharSet::default();
        for i in 0..128 {
            n.ascii[i] = !self.ascii[i];
        }
        n.other = true;
        n
    }

    pub fn has(&self, c: char) -> bool {
        (c as u32) < 128 && self.ascii[c as usize]
    }

    fn has_any(&self, s: &str) -> bool {
        s.chars().any(|c| self.has(c))
    }

    /// Contexts in which a string made only of these characters is safe.
    /// Non-ASCII characters are not metacharacters in any of them.
    pub fn safety(&self) -> u32 {
        let mut bits = 0;
        let none = |s: &str| !self.has_any(s);
        if none("'") {
            bits |= ctx::NO_SQUOTE;
        }
        if none("\"") {
            bits |= ctx::NO_DQUOTE;
        }
        if none("<>&\"'") {
            bits |= ctx::HTML;
        }
        if none(";|&$`\n\r()<>'\"\\ \t*?[]{}~!#^") {
            bits |= ctx::SHELL;
        }
        if none("/\\.") {
            bits |= ctx::PATH;
        }
        if none("'\";`()=<>*/\\# \t\n\r") {
            bits |= ctx::SQL;
        }
        if none("*()\\&|=!<>~\0") {
            bits |= ctx::LDAP;
        }
        if none("'\"[]()/@|=<>*:") {
            bits |= ctx::XPATH;
        }
        if none("()'\"`[]{}") {
            bits |= ctx::CODE | ctx::TEMPLATE;
        }
        if none("/\\:") {
            bits |= ctx::URL;
        }
        if none("\r\n") {
            bits |= ctx::HEADER | ctx::LOG;
        }
        bits
    }
}

fn escape_class(e: char) -> Option<CharSet> {
    let mut s = CharSet::default();
    match e {
        'd' => ('0'..='9').for_each(|c| s.add(c)),
        'w' => {
            ('0'..='9')
                .chain('a'..='z')
                .chain('A'..='Z')
                .for_each(|c| s.add(c));
            s.add('_');
            s.unicode_letters = true;
        }
        's' => " \t\n\r\x0b\x0c".chars().for_each(|c| s.add(c)),
        'D' | 'W' | 'S' => return Some(escape_class(e.to_ascii_lowercase())?.negate()),
        '.' | '-' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '/' | '\\' | '^'
        | '$' | '|' | '@' | '#' | ' ' | '\'' | '"' | ':' | ',' | '=' | '&' | '%' | '!' | '<'
        | '>' | '~' => s.add(e),
        'n' => s.add('\n'),
        't' => s.add('\t'),
        'r' => s.add('\r'),
        _ => return None,
    }
    Some(s)
}

/// Parses `[...]` starting at `start`; returns the set and the index after it.
fn parse_class(chars: &[char], start: usize) -> Option<(CharSet, usize)> {
    let mut i = start + 1;
    let negated = chars.get(i) == Some(&'^');
    if negated {
        i += 1;
    }
    let mut set = CharSet::default();
    let mut first = true;
    let mut prev: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        if c == ']' && !first {
            let set = if negated { set.negate() } else { set };
            return Some((set, i + 1));
        }
        first = false;
        if c == '\\' {
            let e = *chars.get(i + 1)?;
            match escape_class(e) {
                Some(cls) if "dwsDWS".contains(e) => set.union(&cls),
                _ => {
                    let lit = match e {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => other,
                    };
                    set.add(lit);
                    prev = Some(lit);
                    i += 2;
                    continue;
                }
            }
            prev = None;
            i += 2;
            continue;
        }
        if c == '-' && prev.is_some() && chars.get(i + 1).map(|n| *n != ']').unwrap_or(false) {
            let lo = prev.unwrap();
            let hi = chars[i + 1];
            if (lo as u32) > (hi as u32) {
                return None;
            }
            for code in lo as u32..=hi as u32 {
                if let Some(ch) = char::from_u32(code) {
                    set.add(ch);
                }
            }
            prev = None;
            i += 2;
            continue;
        }
        set.add(c);
        prev = Some(c);
        i += 1;
    }
    None
}

/// Safety from checks such as "starts and ends with a quote and has no
/// quote inside" (a plain string literal) or "has no `'`".
pub fn literal_check_safety(facts: &[Fact]) -> u32 {
    let mut bits = 0;
    for q in ["'", "\""] {
        let starts = facts
            .iter()
            .any(|f| matches!(f, Fact::StartsWith(s) if s == q));
        let ends = facts
            .iter()
            .any(|f| matches!(f, Fact::EndsWith(s) if s == q));
        let inner = facts
            .iter()
            .any(|f| matches!(f, Fact::NotContainsInner(s) if s == q));
        if starts && ends && inner {
            bits |= ctx::CODE;
        }
    }
    for f in facts {
        if let Fact::NotContains(s) = f {
            match s.as_str() {
                "'" => bits |= ctx::NO_SQUOTE,
                "\"" => bits |= ctx::NO_DQUOTE,
                ".." | "../" | "..\\" | "/" => bits |= ctx::PATH,
                "<" => bits |= ctx::HTML,
                _ => {}
            }
        }
    }
    bits
}

#[allow(dead_code)]
pub fn first_arg(args: &[ArgVal]) -> Value {
    arg(args, 0, "").cloned().unwrap_or_else(Value::clean)
}
