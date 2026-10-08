//! Abstract values for the interpreter.
//!
//! A value is either known exactly (a constant, a string assembled from known
//! and unknown pieces, a container with known slots) or unknown. Every unknown
//! part carries a [`Taint`]: where user-controlled data came from and which
//! output contexts it has been made safe for.

use crate::ir::{Class, Function, Span};
use std::collections::HashMap;
use std::rc::Rc;

/// Output contexts that data can be safe for, as bit flags.
pub mod ctx {
    pub const HTML: u32 = 1 << 0;
    pub const SQL: u32 = 1 << 1;
    pub const SHELL: u32 = 1 << 2;
    pub const PATH: u32 = 1 << 3;
    pub const URL: u32 = 1 << 4;
    pub const LDAP: u32 = 1 << 5;
    pub const XPATH: u32 = 1 << 6;
    pub const CODE: u32 = 1 << 7;
    pub const DESER: u32 = 1 << 8;
    pub const XML: u32 = 1 << 9;
    pub const HEADER: u32 = 1 << 10;
    pub const SESSION: u32 = 1 << 11;
    pub const TEMPLATE: u32 = 1 << 12;
    pub const LOG: u32 = 1 << 13;
    /// Holds no single quote: safe inside a single-quoted literal.
    pub const NO_SQUOTE: u32 = 1 << 20;
    /// Holds no double quote: safe inside a double-quoted literal.
    pub const NO_DQUOTE: u32 = 1 << 21;
    /// A number or a value restricted to a known safe alphabet.
    pub const ALL: u32 = 0x3FFF | NO_SQUOTE | NO_DQUOTE;
}

const MAX_SOURCES: usize = 3;
const MAX_ALTERNATIVES: usize = 8;
const MAX_ITEMS: usize = 64;

/// Where user-controlled data entered the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub what: Rc<str>,
    pub module: usize,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Taint {
    /// Empty for data the user does not control.
    pub sources: Vec<Source>,
    /// `ctx` bits this data is safe for.
    pub safe: u32,
}

impl Taint {
    pub fn clean() -> Self {
        Taint::default()
    }

    pub fn from_source(source: Source) -> Self {
        Taint {
            sources: vec![source],
            safe: 0,
        }
    }

    pub fn is_tainted(&self) -> bool {
        !self.sources.is_empty()
    }

    /// Tainted and not made safe for `context`.
    pub fn reaches(&self, context: u32) -> bool {
        self.is_tainted() && self.safe & context == 0
    }

    pub fn union(&self, other: &Taint) -> Taint {
        match (self.is_tainted(), other.is_tainted()) {
            (false, false) => Taint::clean(),
            (true, false) => self.clone(),
            (false, true) => other.clone(),
            (true, true) => {
                let mut sources = self.sources.clone();
                for s in &other.sources {
                    if sources.len() >= MAX_SOURCES {
                        break;
                    }
                    if !sources.contains(s) {
                        sources.push(s.clone());
                    }
                }
                Taint {
                    sources,
                    safe: self.safe & other.safe,
                }
            }
        }
    }

    pub fn with_safe(mut self, bits: u32) -> Self {
        if self.is_tainted() {
            self.safe |= bits;
        }
        self
    }

    pub fn without_safe(mut self, bits: u32) -> Self {
        self.safe &= !bits;
        self
    }
}

/// A piece of a string: known text, or unknown text with its taint.
#[derive(Debug, Clone, PartialEq)]
pub enum Seg {
    Lit(String),
    Dyn(Taint),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Unknown(Taint),
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<Vec<Seg>>),
    /// List, tuple or set with known slots.
    List(Rc<Vec<Value>>),
    /// Mapping with constant keys.
    Dict(Rc<Vec<(Value, Value)>>),
    /// A named thing outside the analyzed code: a module, a library function,
    /// a framework object such as `flask.request.args`.
    Ref(Rc<str>, Taint),
    Obj(Rc<Obj>),
    Func(Rc<FuncVal>),
    Class(Rc<ClassVal>),
    /// One of several values, depending on the path taken.
    OneOf(Rc<Vec<Value>>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Obj {
    /// Qualified class name (`configparser.ConfigParser`, `helpers.Thing`).
    pub class: Rc<str>,
    /// The class definition when it is part of the analyzed code.
    pub def: Option<Rc<ClassVal>>,
    pub fields: Vec<(Rc<str>, Value)>,
    /// Taint of the object as a whole, e.g. a path object built from input.
    pub taint: Taint,
}

impl Obj {
    pub fn new(class: &str) -> Obj {
        Obj {
            class: class.into(),
            def: None,
            fields: Vec::new(),
            taint: Taint::clean(),
        }
    }

    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(k, _)| &**k == name)
            .map(|(_, v)| v)
    }

    pub fn set_field(&mut self, name: &str, value: Value) {
        if let Some(slot) = self.fields.iter_mut().find(|(k, _)| &**k == name) {
            slot.1 = value;
        } else if self.fields.len() < MAX_ITEMS {
            self.fields.push((name.into(), value));
        }
    }

    pub fn with_field(mut self, name: &str, value: Value) -> Obj {
        self.set_field(name, value);
        self
    }
}

/// Lexical scope of a nested definition: the functions and classes defined
/// next to it, so a handler can call a sibling defined later in the file.
#[derive(Debug, Default)]
pub struct Scope {
    pub defs: HashMap<String, Def>,
    pub parent: Option<Rc<Scope>>,
}

#[derive(Debug, Clone)]
pub enum Def {
    Func(Rc<Function>),
    Class(Rc<Class>),
}

impl Scope {
    /// The scope of a function body: its own definitions, then the parent's.
    /// Bodies without definitions share the parent scope.
    pub fn of_body(body: &[crate::ir::Stmt], parent: Option<Rc<Scope>>) -> Option<Rc<Scope>> {
        let mut defs = HashMap::new();
        for s in body {
            match s {
                crate::ir::Stmt::FuncDef(f) => {
                    defs.insert(f.name.clone(), Def::Func(f.clone()));
                }
                crate::ir::Stmt::ClassDef(c) => {
                    defs.insert(c.name.clone(), Def::Class(c.clone()));
                }
                _ => {}
            }
        }
        if defs.is_empty() {
            return parent;
        }
        Some(Rc::new(Scope { defs, parent }))
    }
}

pub type Env = HashMap<Rc<str>, Value>;

#[derive(Debug)]
pub struct FuncVal {
    pub def: Rc<Function>,
    pub module: usize,
    pub qualname: Rc<str>,
    /// `self` for a bound method.
    pub bound: Option<Value>,
    /// Variables of the enclosing function when the definition ran.
    pub closure: Option<Rc<Env>>,
    pub scope: Option<Rc<Scope>>,
}

impl PartialEq for FuncVal {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.def, &other.def) && self.bound == other.bound
    }
}

#[derive(Debug)]
pub struct ClassVal {
    pub def: Rc<Class>,
    pub module: usize,
    pub qualname: Rc<str>,
    pub scope: Option<Rc<Scope>>,
}

impl PartialEq for ClassVal {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.def, &other.def)
    }
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(Rc::new(vec![Seg::Lit(s.into())]))
    }

    pub fn segs(segs: Vec<Seg>) -> Value {
        Value::Str(Rc::new(normalize(segs)))
    }

    pub fn tainted_str(t: Taint) -> Value {
        Value::Str(Rc::new(vec![Seg::Dyn(t)]))
    }

    pub fn list(items: Vec<Value>) -> Value {
        if items.len() > MAX_ITEMS {
            let t = items
                .iter()
                .fold(Taint::clean(), |t, v| t.union(&v.taint()));
            return Value::Unknown(t);
        }
        Value::List(Rc::new(items))
    }

    pub fn clean() -> Value {
        Value::Unknown(Taint::clean())
    }

    /// Everything user-controlled this value holds.
    pub fn taint(&self) -> Taint {
        match self {
            Value::Unknown(t) | Value::Ref(_, t) => t.clone(),
            Value::Str(segs) => segs.iter().fold(Taint::clean(), |acc, s| match s {
                Seg::Dyn(t) => acc.union(t),
                Seg::Lit(_) => acc,
            }),
            Value::List(items) | Value::OneOf(items) => items
                .iter()
                .fold(Taint::clean(), |acc, v| acc.union(&v.taint())),
            Value::Dict(pairs) => pairs.iter().fold(Taint::clean(), |acc, (k, v)| {
                acc.union(&k.taint()).union(&v.taint())
            }),
            Value::Obj(o) => o
                .fields
                .iter()
                .fold(o.taint.clone(), |acc, (_, v)| acc.union(&v.taint())),
            Value::Func(f) => f.bound.as_ref().map(|b| b.taint()).unwrap_or_default(),
            _ => Taint::clean(),
        }
    }

    pub fn is_tainted(&self) -> bool {
        self.taint().is_tainted()
    }

    /// The value with its known structure forgotten.
    pub fn opaque(&self) -> Value {
        Value::Unknown(self.taint())
    }

    /// Literal text when the value is a fully known string.
    pub fn as_str(&self) -> Option<String> {
        match self {
            Value::Str(segs) => {
                let mut out = String::new();
                for s in segs.iter() {
                    match s {
                        Seg::Lit(t) => out.push_str(t),
                        Seg::Dyn(_) => return None,
                    }
                }
                Some(out)
            }
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    /// Python-style truthiness, when known.
    pub fn truthy(&self) -> Option<bool> {
        match self {
            Value::None => Some(false),
            Value::Bool(b) => Some(*b),
            Value::Int(i) => Some(*i != 0),
            Value::Float(f) => Some(*f != 0.0),
            Value::Str(segs) => {
                if segs
                    .iter()
                    .any(|s| matches!(s, Seg::Lit(t) if !t.is_empty()))
                {
                    Some(true)
                } else if segs.iter().all(|s| matches!(s, Seg::Lit(_))) {
                    Some(false)
                } else {
                    None
                }
            }
            Value::List(items) => Some(!items.is_empty()),
            Value::Dict(pairs) => Some(!pairs.is_empty()),
            Value::Func(_) | Value::Class(_) | Value::Obj(_) => Some(true),
            Value::OneOf(alts) => {
                let first = alts.first()?.truthy()?;
                alts.iter()
                    .all(|a| a.truthy() == Some(first))
                    .then_some(first)
            }
            Value::Unknown(_) | Value::Ref(..) => None,
        }
    }

    /// The string a value turns into when formatted (`str(x)`, f-strings).
    pub fn to_segs(&self) -> Vec<Seg> {
        match self {
            Value::Str(segs) => segs.as_ref().clone(),
            Value::Int(i) => vec![Seg::Lit(i.to_string())],
            Value::Bool(b) => vec![Seg::Lit(if *b { "True" } else { "False" }.into())],
            Value::None => vec![Seg::Lit("None".into())],
            Value::Float(f) => vec![Seg::Lit(format!("{f:?}"))],
            Value::OneOf(alts) if alts.iter().all(|a| a.as_str().is_some()) => {
                vec![Seg::Dyn(self.taint().with_safe(numeric_like(alts)))]
            }
            other => vec![Seg::Dyn(other.taint())],
        }
    }

    /// A value standing for any element of this container.
    pub fn element(&self) -> Value {
        match self {
            Value::List(items) => join_all(items.iter().cloned()).unwrap_or_else(Value::clean),
            Value::Dict(pairs) => {
                join_all(pairs.iter().map(|(k, _)| k.clone())).unwrap_or_else(Value::clean)
            }
            Value::Str(_) => Value::tainted_str(self.taint()),
            Value::OneOf(alts) => {
                join_all(alts.iter().map(|a| a.element())).unwrap_or_else(Value::clean)
            }
            other => Value::Unknown(other.taint()),
        }
    }

    /// Applies a sanitizer: every user-controlled part becomes safe for `bits`.
    pub fn sanitized(&self, bits: u32) -> Value {
        self.map_taint(&|t: &Taint| t.clone().with_safe(bits))
    }

    /// Removes safety, e.g. after URL decoding re-introduces special characters.
    pub fn unsanitized(&self, bits: u32) -> Value {
        self.map_taint(&|t: &Taint| t.clone().without_safe(bits))
    }

    fn map_taint(&self, f: &dyn Fn(&Taint) -> Taint) -> Value {
        match self {
            Value::Unknown(t) => Value::Unknown(f(t)),
            Value::Ref(p, t) => Value::Ref(p.clone(), f(t)),
            Value::Str(segs) => Value::Str(Rc::new(
                segs.iter()
                    .map(|s| match s {
                        Seg::Dyn(t) => Seg::Dyn(f(t)),
                        lit => lit.clone(),
                    })
                    .collect(),
            )),
            Value::List(items) => {
                Value::List(Rc::new(items.iter().map(|v| v.map_taint(f)).collect()))
            }
            Value::OneOf(items) => {
                Value::OneOf(Rc::new(items.iter().map(|v| v.map_taint(f)).collect()))
            }
            Value::Dict(pairs) => Value::Dict(Rc::new(
                pairs
                    .iter()
                    .map(|(k, v)| (k.map_taint(f), v.map_taint(f)))
                    .collect(),
            )),
            Value::Obj(o) => {
                let mut o = (**o).clone();
                o.taint = f(&o.taint);
                for (_, v) in o.fields.iter_mut() {
                    *v = v.map_taint(f);
                }
                Value::Obj(Rc::new(o))
            }
            other => other.clone(),
        }
    }

    pub fn alternatives(&self) -> Vec<Value> {
        match self {
            Value::OneOf(alts) => alts.as_ref().clone(),
            other => vec![other.clone()],
        }
    }
}

fn numeric_like(alts: &[Value]) -> u32 {
    let all_safe = alts.iter().all(|a| {
        a.as_str()
            .map(|s| {
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            })
            .unwrap_or(false)
    });
    if all_safe {
        ctx::ALL
    } else {
        0
    }
}

/// Joins the values that reach one point along different paths.
pub fn join(a: &Value, b: &Value) -> Value {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (Value::List(x), Value::List(y)) if x.len() == y.len() => Value::List(Rc::new(
            x.iter().zip(y.iter()).map(|(p, q)| join(p, q)).collect(),
        )),
        (Value::Obj(x), Value::Obj(y)) if x.class == y.class => {
            let mut o = (**x).clone();
            o.taint = x.taint.union(&y.taint);
            for (k, v) in &y.fields {
                match o.fields.iter_mut().find(|(n, _)| n == k) {
                    Some(slot) => slot.1 = join(&slot.1, v),
                    None => o.fields.push((k.clone(), v.clone())),
                }
            }
            Value::Obj(Rc::new(o))
        }
        (Value::Dict(x), Value::Dict(y)) => {
            let mut pairs = x.as_ref().clone();
            for (k, v) in y.iter() {
                match pairs.iter_mut().find(|(n, _)| n == k) {
                    Some(slot) => slot.1 = join(&slot.1, v),
                    None => pairs.push((k.clone(), v.clone())),
                }
            }
            Value::Dict(Rc::new(pairs))
        }
        (Value::Unknown(x), Value::Unknown(y)) => Value::Unknown(x.union(y)),
        _ => {
            let mut alts: Vec<Value> = Vec::new();
            for v in a.alternatives().into_iter().chain(b.alternatives()) {
                if !alts.contains(&v) {
                    alts.push(v);
                }
            }
            if alts.len() > MAX_ALTERNATIVES {
                let t = alts.iter().fold(Taint::clean(), |t, v| t.union(&v.taint()));
                return Value::Unknown(t);
            }
            Value::OneOf(Rc::new(alts))
        }
    }
}

pub fn join_all(values: impl Iterator<Item = Value>) -> Option<Value> {
    values.fold(None, |acc, v| {
        Some(match acc {
            None => v,
            Some(a) => join(&a, &v),
        })
    })
}

/// Merges adjacent pieces and bounds the length.
pub fn normalize(segs: Vec<Seg>) -> Vec<Seg> {
    let mut out: Vec<Seg> = Vec::with_capacity(segs.len());
    for s in segs {
        match (out.last_mut(), s) {
            (_, Seg::Lit(t)) if t.is_empty() => {}
            (Some(Seg::Lit(prev)), Seg::Lit(t)) => prev.push_str(&t),
            (Some(Seg::Dyn(prev)), Seg::Dyn(t)) => *prev = prev.union(&t),
            (_, s) => out.push(s),
        }
    }
    if out.len() > MAX_ITEMS {
        // Keep both ends, which carry the quoting context, and fold the middle.
        let tail = out.split_off(out.len() - MAX_ITEMS / 2);
        let middle = out.split_off(MAX_ITEMS / 2);
        let t = middle.iter().fold(Taint::clean(), |acc, s| match s {
            Seg::Dyn(t) => acc.union(t),
            Seg::Lit(_) => acc,
        });
        out.push(Seg::Dyn(t));
        out.extend(tail);
    }
    out
}

pub fn concat(parts: &[Value]) -> Value {
    let mut segs = Vec::new();
    for p in parts {
        segs.extend(p.to_segs());
    }
    Value::segs(segs)
}

/// `s[lower:upper]` for strings with known and unknown parts.
pub fn slice_str(
    segs: &[Seg],
    lower: Option<i64>,
    upper: Option<i64>,
    lower_known: bool,
    upper_known: bool,
) -> Value {
    if segs.iter().all(|s| matches!(s, Seg::Lit(_))) {
        if !(lower_known && upper_known) {
            return Value::clean();
        }
        let text: Vec<char> = segs
            .iter()
            .flat_map(|s| match s {
                Seg::Lit(t) => t.chars().collect::<Vec<_>>(),
                Seg::Dyn(_) => Vec::new(),
            })
            .collect();
        let n = text.len() as i64;
        let fix = |i: i64| if i < 0 { (n + i).max(0) } else { i.min(n) };
        let a = fix(lower.unwrap_or(0));
        let b = fix(upper.unwrap_or(n));
        if a >= b {
            return Value::str("");
        }
        return Value::str(text[a as usize..b as usize].iter().collect::<String>());
    }
    let prefix: String = match segs.first() {
        Some(Seg::Lit(t)) => t.clone(),
        _ => String::new(),
    };
    let suffix: String = match segs.last() {
        Some(Seg::Lit(t)) if segs.len() > 1 => t.clone(),
        _ => String::new(),
    };
    let middle: Vec<Seg> = {
        let start = usize::from(!prefix.is_empty());
        let end = segs.len() - usize::from(!suffix.is_empty() && segs.len() > 1);
        segs[start..end].to_vec()
    };
    let all_taint = segs.iter().fold(Taint::clean(), |acc, s| match s {
        Seg::Dyn(t) => acc.union(t),
        Seg::Lit(_) => acc,
    });
    let p: Vec<char> = prefix.chars().collect();
    let s: Vec<char> = suffix.chars().collect();
    // Position of an index: inside the known prefix, inside the known
    // suffix (counted from the end), or somewhere unknown.
    enum Pos {
        Prefix(usize),
        Suffix(usize),
        Unknown,
    }
    let pos = |i: Option<i64>, known: bool, is_upper: bool| -> Pos {
        if !known {
            return Pos::Unknown;
        }
        match i {
            None if is_upper => Pos::Suffix(s.len()),
            None => Pos::Prefix(0),
            Some(i) if i >= 0 && (i as usize) <= p.len() => Pos::Prefix(i as usize),
            Some(i) if i < 0 && ((-i) as usize) <= s.len() => Pos::Suffix(s.len() - (-i) as usize),
            Some(_) => Pos::Unknown,
        }
    };
    let a = pos(lower, lower_known, false);
    let b = pos(upper, upper_known, true);
    let mut out = Vec::new();
    match (&a, &b) {
        (Pos::Prefix(x), Pos::Prefix(y)) => {
            return Value::str(p[*x..(*y).max(*x)].iter().collect::<String>())
        }
        (Pos::Suffix(x), Pos::Suffix(y)) => {
            return Value::str(s[*x..(*y).max(*x)].iter().collect::<String>())
        }
        (Pos::Prefix(x), Pos::Suffix(y)) => {
            out.push(Seg::Lit(p[*x..].iter().collect()));
            out.extend(middle);
            out.push(Seg::Lit(s[..*y].iter().collect()));
        }
        (Pos::Prefix(x), Pos::Unknown) => {
            out.push(Seg::Lit(p[*x..].iter().collect()));
            out.push(Seg::Dyn(all_taint));
        }
        (Pos::Unknown, Pos::Suffix(y)) => {
            out.push(Seg::Dyn(all_taint));
            out.push(Seg::Lit(s[..*y].iter().collect()));
        }
        _ => out.push(Seg::Dyn(all_taint)),
    }
    Value::segs(out)
}

/// Whether `needle` occurs in the string, when that can be decided.
pub fn str_contains(segs: &[Seg], needle: &str) -> Option<bool> {
    let mut dynamic = false;
    let mut excluded = true;
    for s in segs {
        match s {
            Seg::Lit(t) if t.contains(needle) => return Some(true),
            Seg::Lit(_) => {}
            Seg::Dyn(t) => {
                dynamic = true;
                let quote_free = (needle.contains('\'') && t.safe & ctx::NO_SQUOTE != 0)
                    || (needle.contains('"') && t.safe & ctx::NO_DQUOTE != 0);
                excluded &= t.is_tainted() && quote_free;
            }
        }
    }
    if !dynamic || excluded {
        Some(false)
    } else {
        None
    }
}

/// Quote context of each unknown piece: whether it sits inside a
/// single- or double-quoted literal of the surrounding text.
pub fn quote_contexts(segs: &[Seg]) -> Vec<(Taint, Option<char>)> {
    let mut out = Vec::new();
    let mut open: Option<char> = None;
    for s in segs {
        match s {
            Seg::Lit(t) => {
                let mut prev = '\0';
                for c in t.chars() {
                    if (c == '\'' || c == '"') && prev != '\\' {
                        match open {
                            None => open = Some(c),
                            Some(q) if q == c => open = None,
                            _ => {}
                        }
                    }
                    prev = c;
                }
            }
            Seg::Dyn(t) => out.push((t.clone(), open)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> Taint {
        Taint::from_source(Source {
            what: "test".into(),
            module: 0,
            span: Span::default(),
        })
    }

    #[test]
    fn slicing_drops_known_padding_but_keeps_input() {
        let s = vec![
            Seg::Lit("help".into()),
            Seg::Dyn(src()),
            Seg::Lit("snapes on a plane".into()),
        ];
        let v = slice_str(&s, Some(4), Some(-17), true, true);
        assert!(v.is_tainted());
        assert_eq!(v.as_str(), None);
        let head = slice_str(&s, Some(1), Some(3), true, true);
        assert_eq!(head.as_str().as_deref(), Some("el"));
        let tail = slice_str(&s, Some(-5), None, true, true);
        assert_eq!(tail.as_str().as_deref(), Some("plane"));
    }

    #[test]
    fn join_keeps_alternatives_and_list_slots() {
        let a = Value::list(vec![Value::str("sh"), Value::str("-c")]);
        let b = Value::list(vec![Value::str("cmd.exe"), Value::str("-c")]);
        match join(&a, &b) {
            Value::List(items) => {
                assert_eq!(items[1], Value::str("-c"));
                assert_eq!(items[0].alternatives().len(), 2);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            join(&Value::str("x"), &Value::tainted_str(src())).truthy(),
            None
        );
    }

    #[test]
    fn sanitizing_applies_per_context() {
        let v = Value::segs(vec![Seg::Lit("a".into()), Seg::Dyn(src())]).sanitized(ctx::HTML);
        assert!(!v.taint().reaches(ctx::HTML));
        assert!(v.taint().reaches(ctx::SQL));
        // Mixing safe and unsafe data keeps only the common safety.
        let both = concat(&[v, Value::tainted_str(src())]);
        assert!(both.taint().reaches(ctx::HTML));
    }

    #[test]
    fn quote_context_of_pieces() {
        let s = vec![
            Seg::Lit("SELECT * FROM t WHERE a = '".into()),
            Seg::Dyn(src()),
            Seg::Lit("' AND b = ".into()),
            Seg::Dyn(src()),
        ];
        let q = quote_contexts(&s);
        assert_eq!(q[0].1, Some('\''));
        assert_eq!(q[1].1, None);
    }
}
