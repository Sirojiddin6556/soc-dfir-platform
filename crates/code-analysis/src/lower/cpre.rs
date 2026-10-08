//! A small C preprocessor for the C and C++ front ends: conditional
//! sections, `#define` and `#undef`, object- and function-like macros, and
//! the macros of project headers a file includes.
//!
//! Every input line gives exactly one output line (directives and skipped
//! sections become empty lines, a macro call expands on its own line), so
//! spans in the parsed text still point into the original file. The build
//! is assumed to be Linux: `_WIN32` is not defined.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Macro {
    /// Parameter names of a function-like macro; None for object-like.
    pub params: Option<Vec<String>>,
    pub variadic: bool,
    pub body: String,
}

pub type Macros = HashMap<String, Macro>;

/// How deep macro expansions may nest; real code stays far below.
const MAX_EXPANSION_DEPTH: usize = 32;

/// Macros every compiler defines for a Linux build.
pub fn predefined(cpp: bool) -> Macros {
    let mut m = Macros::new();
    let mut def = |name: &str, body: &str| {
        m.insert(
            name.to_string(),
            Macro {
                params: None,
                variadic: false,
                body: body.to_string(),
            },
        );
    };
    def("__linux__", "1");
    def("__unix__", "1");
    def("__GNUC__", "4");
    def("__STDC__", "1");
    if cpp {
        def("__cplusplus", "201703L");
    }
    drop(def);
    // Macros taking a type, which the grammars cannot parse as a call.
    define("va_arg(ap, type) ((type) __c_va_arg(ap))", &mut m);
    define("offsetof(type, member) 0", &mut m);
    m
}

/// Runs the directives of `src` and returns its code with macros expanded,
/// one line per input line. `include` is called for `#include "name"` and
/// adds that header's macros (it may call [`preprocess`] on the header).
pub fn preprocess(
    src: &str,
    macros: &mut Macros,
    include: &mut dyn FnMut(&str, &mut Macros),
) -> String {
    let mut out = String::with_capacity(src.len());
    // Conditional sections: (parent active, a branch was taken, this branch active).
    let mut conds: Vec<(bool, bool, bool)> = Vec::new();
    let mut in_comment = false;
    let lines: Vec<&str> = src.split('\n').collect();
    let mut i = 0;
    while i < lines.len() {
        // A logical line: physical lines joined at a trailing backslash.
        let mut logical = lines[i].trim_end_matches('\r').to_string();
        let mut extra = 0;
        while logical.ends_with('\\') && i + extra + 1 < lines.len() {
            logical.pop();
            extra += 1;
            logical.push(' ');
            logical.push_str(lines[i + extra].trim_end_matches('\r'));
        }
        let active = conds.last().map(|c| c.2).unwrap_or(true);
        let directive = if in_comment {
            None
        } else {
            logical
                .trim_start()
                .strip_prefix('#')
                .map(|d| d.trim_start().to_string())
        };
        match directive {
            Some(d) => {
                let (word, rest) = split_word(&d);
                let rest = strip_comments(rest);
                match word {
                    "if" | "ifdef" | "ifndef" => {
                        let taken = active
                            && match word {
                                "ifdef" => macros.contains_key(first_ident(&rest)),
                                "ifndef" => !macros.contains_key(first_ident(&rest)),
                                _ => eval_condition(&rest, macros),
                            };
                        conds.push((active, taken, taken));
                    }
                    "elif" | "elifdef" | "elifndef" => {
                        if let Some(c) = conds.last_mut() {
                            let now = c.0
                                && !c.1
                                && match word {
                                    "elifdef" => macros.contains_key(first_ident(&rest)),
                                    "elifndef" => !macros.contains_key(first_ident(&rest)),
                                    _ => eval_condition(&rest, macros),
                                };
                            c.2 = now;
                            c.1 |= now;
                        }
                    }
                    "else" => {
                        if let Some(c) = conds.last_mut() {
                            c.2 = c.0 && !c.1;
                            c.1 = true;
                        }
                    }
                    "endif" => {
                        conds.pop();
                    }
                    "define" if active => define(&rest, macros),
                    "undef" if active => {
                        macros.remove(first_ident(&rest));
                    }
                    "include" if active => {
                        let r = rest.trim();
                        if let Some(name) = r.strip_prefix('"').and_then(|r| r.split('"').next()) {
                            include(name, macros);
                        }
                    }
                    _ => {}
                }
                // `#define X 1 /* a comment going on below`
                scan_comments(&logical, &mut in_comment);
                if in_comment {
                    out.push_str("/*");
                }
                for _ in 0..=extra {
                    out.push('\n');
                }
            }
            None if !active => {
                // Comments may open or close in skipped code too; the
                // output is in a comment at the same places as the input.
                let was = in_comment;
                scan_comments(&logical, &mut in_comment);
                match (was, in_comment) {
                    (true, false) => out.push_str("*/"),
                    (false, true) => out.push_str("/*"),
                    _ => {}
                }
                for _ in 0..=extra {
                    out.push('\n');
                }
            }
            None => {
                let expanded = expand_line(&logical, macros, &mut in_comment);
                out.push_str(&expanded);
                for _ in 0..=extra {
                    out.push('\n');
                }
            }
        }
        i += extra + 1;
    }
    // `split` yields one more piece than there are newlines.
    out.pop();
    out
}

fn split_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

fn first_ident(s: &str) -> &str {
    split_word(s).0
}

/// `/* ... */` and `// ...` removed from a directive's text.
fn strip_comments(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                quote = Some(c);
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => break,
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

fn define(rest: &str, macros: &mut Macros) {
    let rest = rest.trim_start();
    let (name, after) = split_word(rest);
    if name.is_empty() {
        return;
    }
    // A function-like macro has `(` right after its name.
    if let Some(p) = after.strip_prefix('(') {
        let Some(close) = p.find(')') else {
            return;
        };
        let mut params = Vec::new();
        let mut variadic = false;
        for raw in p[..close].split(',') {
            let raw = raw.trim();
            if raw == "..." {
                variadic = true;
            } else if let Some(n) = raw.strip_suffix("...") {
                // GNU named variadic parameter: `args...`.
                variadic = true;
                params.push(n.trim().to_string());
            } else if !raw.is_empty() {
                params.push(raw.to_string());
            }
        }
        macros.insert(
            name.to_string(),
            Macro {
                params: Some(params),
                variadic,
                body: p[close + 1..].trim().to_string(),
            },
        );
    } else {
        macros.insert(
            name.to_string(),
            Macro {
                params: None,
                variadic: false,
                body: after.trim().to_string(),
            },
        );
    }
}

/// Tracks whether a block comment is still open after `line`.
fn scan_comments(line: &str, in_comment: &mut bool) {
    let mut quote: Option<char> = None;
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if *in_comment {
            if c == '*' && b.get(i + 1) == Some(&b'/') {
                *in_comment = false;
                i += 1;
            }
        } else if let Some(q) = quote {
            if c == '\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
        } else if c == '/' && b.get(i + 1) == Some(&b'*') {
            *in_comment = true;
            i += 1;
        } else if c == '/' && b.get(i + 1) == Some(&b'/') {
            return;
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        }
        i += 1;
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// Anything else, kept verbatim: numbers, strings, punctuation, spaces
    /// and comments.
    Other(String),
}

impl Tok {
    fn text(&self) -> &str {
        match self {
            Tok::Ident(s) | Tok::Other(s) => s,
        }
    }
    fn is_space(&self) -> bool {
        matches!(self, Tok::Other(s) if s.chars().all(char::is_whitespace))
    }
}

/// Splits a line into tokens. Comments, strings and character literals are
/// single `Other` tokens, so names inside them are never expanded.
fn tokenize(line: &str, in_comment: &mut bool) -> Vec<Tok> {
    let chars: Vec<char> = line.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    let mut cur = String::new();
    let flush = |cur: &mut String, toks: &mut Vec<Tok>| {
        if !cur.is_empty() {
            toks.push(Tok::Other(std::mem::take(cur)));
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if *in_comment {
            cur.push(c);
            if c == '*' && chars.get(i + 1) == Some(&'/') {
                cur.push('/');
                i += 1;
                *in_comment = false;
            }
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            *in_comment = true;
            cur.push_str("/*");
            i += 2;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            cur.extend(&chars[i..]);
            break;
        }
        if c == '"' || c == '\'' {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i] != c {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(chars.len());
            cur.extend(&chars[start..i]);
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            // String prefixes: L"..", u8"..", u'..'.
            if matches!(word.as_str(), "L" | "u" | "U" | "u8")
                && matches!(chars.get(i), Some('"' | '\''))
            {
                cur.push_str(&word);
                continue;
            }
            flush(&mut cur, &mut toks);
            toks.push(Tok::Ident(word));
            continue;
        }
        if c.is_ascii_digit() {
            // A number with its suffix (`10UL`, `0x1F`) is not a name.
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            cur.extend(&chars[start..i]);
            continue;
        }
        if c.is_whitespace() {
            flush(&mut cur, &mut toks);
            let start = i;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            toks.push(Tok::Other(chars[start..i].iter().collect()));
            continue;
        }
        // Punctuation: one token each, so `(`, `,` and `#` stand alone.
        flush(&mut cur, &mut toks);
        toks.push(Tok::Other(c.to_string()));
        i += 1;
    }
    flush(&mut cur, &mut toks);
    toks
}

fn expand_line(line: &str, macros: &Macros, in_comment: &mut bool) -> String {
    let toks = tokenize(line, in_comment);
    if !toks
        .iter()
        .any(|t| matches!(t, Tok::Ident(n) if macros.contains_key(n)))
    {
        return line.to_string();
    }
    let mut disabled = Vec::new();
    let out = expand_toks(&toks, macros, &mut disabled, 0);
    out.iter().map(Tok::text).collect()
}

fn expand_toks(
    toks: &[Tok],
    macros: &Macros,
    disabled: &mut Vec<String>,
    depth: usize,
) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        let Tok::Ident(name) = t else {
            out.push(t.clone());
            i += 1;
            continue;
        };
        let m = match macros.get(name) {
            Some(m) if depth < MAX_EXPANSION_DEPTH && !disabled.contains(name) => m,
            _ => {
                out.push(t.clone());
                i += 1;
                continue;
            }
        };
        match &m.params {
            None => {
                let mut c = false;
                let body = tokenize(&m.body, &mut c);
                disabled.push(name.clone());
                out.extend(expand_toks(&body, macros, disabled, depth + 1));
                disabled.pop();
                i += 1;
            }
            Some(params) => {
                // Needs `(` after the name, possibly after spaces.
                let mut j = i + 1;
                while j < toks.len() && toks[j].is_space() {
                    j += 1;
                }
                if toks.get(j).map(Tok::text) != Some("(") {
                    out.push(t.clone());
                    i += 1;
                    continue;
                }
                let Some((args, end)) = collect_args(toks, j) else {
                    // The call continues on another line: left as it is.
                    out.push(t.clone());
                    i += 1;
                    continue;
                };
                let body = substitute(m, params, &args, macros, disabled, depth);
                disabled.push(name.clone());
                out.extend(expand_toks(&body, macros, disabled, depth + 1));
                disabled.pop();
                i = end + 1;
            }
        }
    }
    out
}

/// Arguments of a macro call whose `(` is at `open`, and the index of the
/// closing `)`.
fn collect_args(toks: &[Tok], open: usize) -> Option<(Vec<Vec<Tok>>, usize)> {
    let mut args: Vec<Vec<Tok>> = vec![Vec::new()];
    let mut depth = 0;
    for (k, t) in toks.iter().enumerate().skip(open + 1) {
        match t.text() {
            "(" | "[" | "{" => {
                depth += 1;
                args.last_mut()?.push(t.clone());
            }
            ")" if depth == 0 => {
                if args.len() == 1 && args[0].iter().all(Tok::is_space) {
                    args[0].clear();
                }
                return Some((args, k));
            }
            ")" | "]" | "}" => {
                depth -= 1;
                args.last_mut()?.push(t.clone());
            }
            "," if depth == 0 => args.push(Vec::new()),
            _ => args.last_mut()?.push(t.clone()),
        }
    }
    None
}

fn trim_toks(t: &[Tok]) -> &[Tok] {
    let start = t.iter().position(|x| !x.is_space()).unwrap_or(t.len());
    let end = t
        .iter()
        .rposition(|x| !x.is_space())
        .map(|e| e + 1)
        .unwrap_or(start);
    &t[start..end.max(start)]
}

/// The body of a function-like macro with its arguments in place.
fn substitute(
    m: &Macro,
    params: &[String],
    args: &[Vec<Tok>],
    macros: &Macros,
    disabled: &mut Vec<String>,
    depth: usize,
) -> Vec<Tok> {
    let mut c = false;
    let body = tokenize(&m.body, &mut c);
    let raw = |name: &str| -> Option<Vec<Tok>> {
        if let Some(p) = params.iter().position(|p| p == name) {
            return Some(trim_toks(args.get(p).map(|a| a.as_slice()).unwrap_or(&[])).to_vec());
        }
        if m.variadic && name == "__VA_ARGS__" {
            let mut v = Vec::new();
            for (k, a) in args.iter().enumerate().skip(params.len()) {
                if k > params.len() {
                    v.push(Tok::Other(",".into()));
                }
                v.extend(a.iter().cloned());
            }
            return Some(trim_toks(&v).to_vec());
        }
        None
    };
    let mut out: Vec<Tok> = Vec::new();
    let mut k = 0;
    while k < body.len() {
        let t = &body[k];
        // `#param`: the argument as a string literal.
        if t.text() == "#" {
            let mut n = k + 1;
            while n < body.len() && body[n].is_space() {
                n += 1;
            }
            if let Some(Tok::Ident(p)) = body.get(n) {
                if let Some(a) = raw(p) {
                    let text: String = a.iter().map(Tok::text).collect();
                    out.push(Tok::Other(format!("{:?}", text)));
                    k = n + 1;
                    continue;
                }
            }
        }
        // `a ## b`: the two tokens pasted together.
        if t.text() == "#" && body.get(k + 1).map(Tok::text) == Some("#") {
            while out.last().is_some_and(Tok::is_space) {
                out.pop();
            }
            let mut n = k + 2;
            while n < body.len() && body[n].is_space() {
                n += 1;
            }
            let right: Vec<Tok> = match body.get(n) {
                Some(Tok::Ident(p)) => raw(p).unwrap_or_else(|| vec![body[n].clone()]),
                Some(other) => vec![other.clone()],
                None => Vec::new(),
            };
            let left = out.pop().map(|t| t.text().to_string()).unwrap_or_default();
            let joined = format!("{left}{}", right.iter().map(Tok::text).collect::<String>());
            let mut c = false;
            out.extend(tokenize(&joined, &mut c));
            k = n + 1;
            continue;
        }
        match t {
            Tok::Ident(name) => match raw(name) {
                Some(a) => {
                    // Arguments are expanded before they are put in place,
                    // unless pasted (handled above).
                    if body.get(k + 1).map(Tok::text) == Some("#")
                        && body.get(k + 2).map(Tok::text) == Some("#")
                    {
                        out.extend(a);
                    } else {
                        out.extend(expand_toks(&a, macros, disabled, depth + 1));
                    }
                }
                None => out.push(t.clone()),
            },
            _ => out.push(t.clone()),
        }
        k += 1;
    }
    out
}

/// Value of an `#if` condition. Unknown names count as 0, as in C.
fn eval_condition(text: &str, macros: &Macros) -> bool {
    // `defined X` and `defined(X)` first, so their names are not expanded.
    let mut c = false;
    let toks = tokenize(text, &mut c);
    let mut replaced: Vec<Tok> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if toks[i].text() == "defined" {
            let mut j = i + 1;
            while j < toks.len() && toks[j].is_space() {
                j += 1;
            }
            let paren = toks.get(j).map(Tok::text) == Some("(");
            if paren {
                j += 1;
                while j < toks.len() && toks[j].is_space() {
                    j += 1;
                }
            }
            let name = toks.get(j).map(Tok::text).unwrap_or("");
            let yes = macros.contains_key(name);
            if paren {
                while j < toks.len() && toks[j].text() != ")" {
                    j += 1;
                }
            }
            replaced.push(Tok::Other(if yes { "1".into() } else { "0".into() }));
            i = j + 1;
            continue;
        }
        replaced.push(toks[i].clone());
        i += 1;
    }
    let mut disabled = Vec::new();
    let expanded = expand_toks(&replaced, macros, &mut disabled, 0);
    let text: String = expanded.iter().map(Tok::text).collect();
    let mut p = CondParser {
        toks: cond_tokens(&text),
        pos: 0,
    };
    p.ternary() != 0
}

fn cond_tokens(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if c == '\'' {
            // A character constant: its code.
            let start = i;
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                i += 1;
            }
            let inner: String = chars[start + 1..i.min(chars.len())].iter().collect();
            out.push(
                inner
                    .chars()
                    .next()
                    .map(|c| c as u32)
                    .unwrap_or(0)
                    .to_string(),
            );
            i += 1;
        } else {
            let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
            if matches!(
                two.as_str(),
                "&&" | "||" | "==" | "!=" | "<=" | ">=" | "<<" | ">>"
            ) {
                out.push(two);
                i += 2;
            } else {
                out.push(c.to_string());
                i += 1;
            }
        }
    }
    out
}

struct CondParser {
    toks: Vec<String>,
    pos: usize,
}

impl CondParser {
    fn peek(&self) -> &str {
        self.toks.get(self.pos).map(|s| s.as_str()).unwrap_or("")
    }

    fn eat(&mut self, t: &str) -> bool {
        if self.peek() == t {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn ternary(&mut self) -> i64 {
        let c = self.binary(0);
        if self.eat("?") {
            let a = self.ternary();
            self.eat(":");
            let b = self.ternary();
            if c != 0 {
                a
            } else {
                b
            }
        } else {
            c
        }
    }

    fn binary(&mut self, min: u8) -> i64 {
        let mut left = self.unary();
        loop {
            let op = self.peek().to_string();
            let prec = match op.as_str() {
                "||" => 1,
                "&&" => 2,
                "|" => 3,
                "^" => 4,
                "&" => 5,
                "==" | "!=" => 6,
                "<" | ">" | "<=" | ">=" => 7,
                "<<" | ">>" => 8,
                "+" | "-" => 9,
                "*" | "/" | "%" => 10,
                _ => return left,
            };
            if prec < min {
                return left;
            }
            self.pos += 1;
            let right = self.binary(prec + 1);
            left = match op.as_str() {
                "||" => ((left != 0) || (right != 0)) as i64,
                "&&" => ((left != 0) && (right != 0)) as i64,
                "|" => left | right,
                "^" => left ^ right,
                "&" => left & right,
                "==" => (left == right) as i64,
                "!=" => (left != right) as i64,
                "<" => (left < right) as i64,
                ">" => (left > right) as i64,
                "<=" => (left <= right) as i64,
                ">=" => (left >= right) as i64,
                "<<" => left.checked_shl(right as u32).unwrap_or(0),
                ">>" => left.checked_shr(right as u32).unwrap_or(0),
                "+" => left.wrapping_add(right),
                "-" => left.wrapping_sub(right),
                "*" => left.wrapping_mul(right),
                "/" => left.checked_div(right).unwrap_or(0),
                _ => left.checked_rem(right).unwrap_or(0),
            };
        }
    }

    fn unary(&mut self) -> i64 {
        if self.eat("!") {
            return (self.unary() == 0) as i64;
        }
        if self.eat("-") {
            return self.unary().wrapping_neg();
        }
        if self.eat("+") {
            return self.unary();
        }
        if self.eat("~") {
            return !self.unary();
        }
        if self.eat("(") {
            let v = self.ternary();
            self.eat(")");
            return v;
        }
        let t = self.peek().to_string();
        self.pos += 1;
        parse_int(&t).unwrap_or(0)
    }
}

/// A C integer literal: decimal, hex, octal or binary, with any suffix.
pub fn parse_int(t: &str) -> Option<i64> {
    let t = t.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).ok();
    }
    if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        return i64::from_str_radix(b, 2).ok();
    }
    if t.len() > 1 && t.starts_with('0') && t.chars().all(|c| c.is_ascii_digit()) {
        return i64::from_str_radix(&t[1..], 8).ok();
    }
    t.parse().ok()
}

/// The `#include "..."` names of a file, for finding the headers it uses.
pub fn local_includes(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in src.lines() {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("include") else {
            continue;
        };
        if let Some(name) = rest
            .trim()
            .strip_prefix('"')
            .and_then(|r| r.split('"').next())
        {
            if seen.insert(name.to_string()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> String {
        let mut m = predefined(false);
        preprocess(src, &mut m, &mut |_, _| {})
    }

    #[test]
    fn keeps_one_line_per_input_line() {
        let src = "#ifdef _WIN32\n#define CMD \"dir \"\n#else\n#define CMD \"ls \"\n#endif\nchar b[] = CMD;\nint x = 1; /* CMD */\n";
        let out = run(src);
        assert_eq!(out.lines().count(), src.lines().count());
        assert_eq!(out.lines().nth(5), Some("char b[] = \"ls \";"));
        assert_eq!(out.lines().nth(6), Some("int x = 1; /* CMD */"));
    }

    #[test]
    fn expands_function_like_macros_and_conditions() {
        let src = "#define SQ(x) ((x) * (x))\n#define STR(s) #s\n#define CAT(a, b) a ## b\n#if defined(__linux__) && !defined(_WIN32) && 2 > 1\nint y = SQ(n + 1); char *s = STR(hi); int CAT(ab, cd);\n#elif 1\nint z;\n#endif\n";
        let out = run(src);
        assert_eq!(
            out.lines().nth(4),
            Some("int y = ((n + 1) * (n + 1)); char *s = \"hi\"; int abcd;")
        );
        assert_eq!(out.lines().nth(6), Some(""));
    }

    #[test]
    fn continuation_lines_and_comments() {
        let src = "#define LONG(a) \\\n  call(a, \\\n       2)\nLONG(1);\n/* start\n#define X 1\n*/ int q = X;\n";
        let out = run(src);
        assert_eq!(out.lines().count(), src.lines().count());
        let call: Vec<&str> = out
            .lines()
            .nth(3)
            .unwrap_or("")
            .split_whitespace()
            .collect();
        assert_eq!(call, vec!["call(1,", "2);"]);
        // The define inside the comment is not a directive.
        assert_eq!(out.lines().nth(6), Some("*/ int q = X;"));
    }
}
