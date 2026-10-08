//! Sizes of C arrays and allocations, and the writes and reads that go
//! past their ends: copies longer than the buffer (`memcpy`, `strcpy`,
//! `strcat`, `snprintf`), stores and loads at indexes outside it, and
//! lengths or indexes a user controls that nothing checked.
//!
//! A buffer is a [`Buf`] value: its size in bytes, the size of an element,
//! where a pointer into it points, and the range the length of the string
//! it holds is known to lie in. Pointers are values, so `data = buf;`
//! makes `data` the same buffer and a call passes it on. Integers that
//! loops count through or checks bound are [`Value::Range`]s.

use crate::interp::{ArgVal, Interp};
use crate::ir::{BinOp, Span};
use crate::lower::c::size_of_type;
use crate::rules::{Rule, BUFFER_OVERFLOW, BUFFER_OVERREAD};
use crate::value::*;
use std::rc::Rc;

const MIN: i64 = i64::MIN;
const MAX: i64 = i64::MAX;

fn arg(args: &[ArgVal], i: usize) -> Value {
    args.get(i).map(|a| a.value.clone()).unwrap_or(Value::None)
}

/// The buffers a pointer may point into.
fn bufs(v: &Value) -> Vec<Rc<Buf>> {
    match v {
        Value::Buf(b) => vec![b.clone()],
        Value::OneOf(alts) => alts.iter().flat_map(bufs).collect(),
        _ => Vec::new(),
    }
}

fn holds_buf(v: &Value) -> bool {
    !bufs(v).is_empty()
}

/// Bytes of a C type on a 64-bit Linux build: basic types, pointers,
/// arrays with a constant size and the structs and classes of the project.
pub fn type_size(it: &mut Interp, ty: &str) -> Option<i64> {
    type_layout(it, ty, 0).map(|(size, _)| size)
}

/// Size and alignment.
fn type_layout(it: &mut Interp, ty: &str, depth: usize) -> Option<(i64, i64)> {
    if depth > 8 {
        return None;
    }
    let t = ty.trim();
    if let Some(open) = t.find('[') {
        let close = t[open..].find(']')? + open;
        let n: i64 = t[open + 1..close].trim().parse().ok()?;
        let (size, align) = type_layout(it, &t[..open], depth + 1)?;
        return Some((size.checked_mul(n)?, align));
    }
    if t.ends_with('*') || t.ends_with('&') {
        return Some((8, 8));
    }
    let base = t
        .split_whitespace()
        .filter(|w| {
            !matches!(
                *w,
                "const" | "volatile" | "static" | "struct" | "class" | "union" | "register"
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(n) = size_of_type(&base) {
        return Some((n, n.min(8)));
    }
    let name = base.rsplit("::").next().unwrap_or(&base).to_string();
    let Some(Value::Class(cv)) = it.lookup_name(&name) else {
        return None;
    };
    let mut size = 0i64;
    let mut align = 1i64;
    for f in &cv.def.fields {
        let crate::ir::Stmt::Declare { ty, .. } = f else {
            continue;
        };
        let (fs, fa) = type_layout(it, ty, depth + 1)?;
        size = (size + fa - 1) / fa * fa + fs;
        align = align.max(fa);
    }
    if size == 0 {
        return None;
    }
    Some(((size + align - 1) / align * align, align))
}

/// The length of the string a value holds, in elements from where it
/// points: at least `.0`, at most `.1` ([`UNBOUNDED`] when unknown).
pub fn str_len(v: &Value) -> (i64, i64) {
    str_len_with(v, true)
}

/// [`str_len`] without assuming the string ends inside its buffer:
/// UNBOUNDED when nothing is known.
fn str_len_raw(v: &Value) -> (i64, i64) {
    str_len_with(v, false)
}

fn str_len_with(v: &Value, inside: bool) -> (i64, i64) {
    match v {
        Value::Buf(b) => {
            let (lo, hi) = match b.off {
                Some(o) if o >= 0 && o <= b.len.0 => (
                    b.len.0 - o,
                    if b.len.1 == UNBOUNDED {
                        UNBOUNDED
                    } else {
                        b.len.1 - o
                    },
                ),
                Some(o) if o >= 0 && b.len.1 != UNBOUNDED && o <= b.len.1 => (0, b.len.1 - o),
                _ => (0, UNBOUNDED),
            };
            // A string ends inside its buffer: running past the end is
            // reported where it was written.
            let room = b.size / b.elem.max(1) - 1 - b.off.filter(|o| *o >= 0).unwrap_or(0);
            if inside && room >= 0 && room < hi {
                (lo, lo.max(room))
            } else {
                (lo, hi)
            }
        }
        Value::Str(segs) => {
            let mut lo = 0i64;
            let mut known = true;
            for s in segs.iter() {
                match s {
                    Seg::Lit(t) => lo += t.chars().count() as i64,
                    Seg::Dyn(_) => known = false,
                }
            }
            (lo, if known { lo } else { UNBOUNDED })
        }
        Value::OneOf(alts) => alts.iter().fold((MAX, 0), |(lo, hi), a| {
            let (l, h) = str_len_with(a, inside);
            (lo.min(l), hi.max(h))
        }),
        _ => (0, UNBOUNDED),
    }
}

/// Whether both the shortest and the longest of [`str_len`] occur.
pub fn str_len_sure(v: &Value) -> bool {
    match v {
        Value::Buf(b) => b.len_is_sure(),
        Value::Str(_) => {
            let (lo, hi) = str_len(v);
            lo == hi
        }
        Value::OneOf(alts) => alts.iter().all(str_len_sure),
        _ => false,
    }
}

/// `strlen(s)`: a constant or a range when the string's length is known,
/// a number carrying the string's taint otherwise.
pub fn strlen(v: &Value) -> Value {
    let t = v.taint().with_safe(ctx::ALL & !ctx::SESSION | ctx::NUMBER);
    match str_len(v) {
        (0, UNBOUNDED) => Value::Unknown(t),
        (lo, hi) if str_len_sure(v) => Value::range_reached(lo, hi, t),
        (lo, hi) => Value::range(lo, hi, t),
    }
}

/// Bounds of a number, `MIN..=MAX` for an unknown one; None for values
/// that are not numbers.
fn num_bounds(v: &Value) -> Option<(i64, i64)> {
    match v {
        Value::Unknown(_) => Some((MIN, MAX)),
        other => other.bounds(),
    }
}

fn scaled(n: i64, by: i64) -> i64 {
    match n {
        MIN | MAX => n,
        n => n.saturating_mul(by),
    }
}

/// `char b[N];` (N None for `char s[] = "..."`): the array holding the
/// value it was declared with.
pub fn array(it: &mut Interp, args: &[ArgVal], span: Span) -> Value {
    let content = match arg(args, 0) {
        Value::Buf(b) => b.content.clone(),
        other => other,
    };
    let Some(elem) = arg(args, 2).as_int().filter(|e| *e > 0) else {
        return content;
    };
    let count = match arg(args, 1) {
        Value::Int(n) => n,
        Value::None => match &content {
            Value::List(items) => items.len() as i64,
            v => match str_len(v) {
                (lo, hi) if lo == hi => lo + 1,
                _ => return content,
            },
        },
        _ => return content,
    };
    if count <= 0 {
        return content;
    }
    let len = match &content {
        // `char b[N] = "..."` and `wchar_t b[N] = L"..."`
        Value::Str(_) => str_len(&content),
        // `char b[N] = {0}`: the elements not listed are zero.
        Value::List(items) => match items.iter().position(|v| matches!(v, Value::Int(0))) {
            Some(i) => (i as i64, i as i64),
            None if (items.len() as i64) < count
                && items.iter().all(|v| matches!(v, Value::Int(_))) =>
            {
                (items.len() as i64, items.len() as i64)
            }
            None => (0, UNBOUNDED),
        },
        _ => (0, UNBOUNDED),
    };
    let module = it.module();
    let b = Value::Buf(Rc::new(Buf {
        size: count.saturating_mul(elem),
        elem,
        off: Some(0),
        len,
        len_sure: false,
        content,
        module,
        at: span,
        nullable: false,
    }));
    if let Some(place) = args.first().and_then(|a| a.place.clone()) {
        it.assign_expr(&place, b.clone(), span);
    }
    b
}

/// A block from an allocator, when its size is a constant.
pub fn alloc(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Option<Value> {
    let (bytes, elem, zeroed, content) = match name {
        "malloc" | "alloca" | "_alloca" | "__builtin_alloca" | "operator new" | "valloc" => {
            (arg(args, 0).as_int()?, 1, false, Value::clean())
        }
        "calloc" => {
            let n = arg(args, 0).as_int()?;
            let m = arg(args, 1).as_int()?;
            // Elements take the type of the pointer the memory is kept in.
            (n.checked_mul(m)?, 1, true, Value::clean())
        }
        "__c_new_array" => {
            let ty = arg(args, 0).as_str()?;
            let elem = type_size(it, &ty)?;
            (
                arg(args, 1).as_int()?.checked_mul(elem)?,
                elem,
                false,
                Value::clean(),
            )
        }
        "realloc" => {
            let old = arg(args, 0);
            (
                arg(args, 1).as_int()?,
                1,
                false,
                Value::Unknown(old.taint()),
            )
        }
        _ => return None,
    };
    if bytes <= 0 {
        return None;
    }
    let module = it.module();
    Some(Value::Buf(Rc::new(Buf {
        size: bytes,
        elem,
        off: Some(0),
        len: if zeroed { (0, 0) } else { (0, UNBOUNDED) },
        len_sure: false,
        content,
        module,
        at: span,
        nullable: !matches!(
            name,
            "alloca" | "_alloca" | "__builtin_alloca" | "operator new" | "__c_new_array"
        ),
    })))
}

/// The element a pointer points to, read as a number: `*p`.
pub fn element(it: &mut Interp, b: &Buf) -> Value {
    let Some(o) = b.off.filter(|o| *o >= 0) else {
        return Value::Unknown(b.content.taint());
    };
    if let Some(s) = b.content.as_str() {
        return match s.as_bytes().get(o as usize) {
            Some(c) => Value::Int(i64::from(*c)),
            None if o as usize == s.len() => Value::Int(0),
            None => Value::Unknown(b.content.taint()),
        };
    }
    match &b.content {
        Value::List(_) => it.index(&b.content, &Value::Int(o)),
        c => Value::Unknown(c.taint()),
    }
}

/// A value read or stored as a small integer type: `(u_char) x` is 0 to
/// 255, and so is a byte read through a `u_char *`.
pub fn as_small_int(it: &mut Interp, v: &Value, lo: i64, hi: i64) -> Value {
    match v {
        Value::Int(k) if (lo..=hi).contains(k) => v.clone(),
        Value::Int(k) => Value::Int((k - lo).rem_euclid(hi - lo + 1) + lo),
        Value::Bool(_) | Value::None => v.clone(),
        Value::Buf(b) => {
            let e = element(it, b);
            as_small_int(it, &e, lo, hi)
        }
        // A string stands for its first character.
        Value::Str(_) => match v.as_str() {
            Some(s) => as_small_int(
                it,
                &Value::Int(s.bytes().next().map_or(0, i64::from)),
                lo,
                hi,
            ),
            None => Value::range(lo, hi, v.taint()),
        },
        _ => match v.bounds() {
            Some((a, b)) if a >= lo && b <= hi => v.clone(),
            Some(_) => Value::range(lo, hi, v.taint()),
            None if matches!(v, Value::Unknown(_)) => Value::range(lo, hi, v.taint()),
            None => v.clone(),
        },
    }
}

/// A pointer converted to `T *`: its elements are now `T`s.
pub fn retyped(it: &mut Interp, ty: &str, b: &Rc<Buf>) -> Value {
    let t = ty.trim();
    let Some(pointee) = t.strip_suffix('*') else {
        return Value::Buf(b.clone());
    };
    if t.contains('[') || pointee.trim_end().ends_with('*') {
        return Value::Buf(b.clone());
    }
    let pointee = pointee.trim();
    let bare = pointee.trim_start_matches("const ").trim();
    if bare == "void" || bare.is_empty() {
        return Value::Buf(b.clone());
    }
    let Some(elem) = type_size(it, pointee).filter(|e| *e > 0) else {
        return Value::Buf(b.clone());
    };
    if elem == b.elem {
        return Value::Buf(b.clone());
    }
    let off = b.off.and_then(|o| {
        let bytes = o.checked_mul(b.elem)?;
        (bytes % elem == 0).then_some(bytes / elem)
    });
    Value::Buf(Rc::new(Buf {
        elem,
        off,
        len: (0, UNBOUNDED),
        len_sure: false,
        ..(**b).clone()
    }))
}

/// Pointer arithmetic, C integer division and arithmetic on ranges.
pub fn binop(op: BinOp, l: &Value, r: &Value) -> Option<Value> {
    use BinOp::*;
    let numeric = |v: &Value| matches!(v, Value::Int(_) | Value::Range(..) | Value::Unknown(_));
    match (op, l, r) {
        (Add, Value::Buf(b), k) | (Add, k, Value::Buf(b)) if numeric(k) => {
            return Some(moved(b, k, 1))
        }
        (Sub, Value::Buf(b), k) if numeric(k) => return Some(moved(b, k, -1)),
        // An array or a checked allocation is not NULL.
        (Eq | NotEq, Value::Buf(b), Value::None | Value::Int(0))
        | (Eq | NotEq, Value::None | Value::Int(0), Value::Buf(b))
            if !b.nullable =>
        {
            return Some(Value::Bool(op == NotEq))
        }
        // Two pointers into one buffer: their distance, and which is first.
        (Sub | Lt | LtE | Gt | GtE | Eq | NotEq, Value::Buf(x), Value::Buf(y)) => {
            let (Some(a), Some(b)) = (x.off, y.off) else {
                return Some(Value::clean());
            };
            if !x.same(y) || x.elem != y.elem {
                return Some(Value::clean());
            }
            return Some(match op {
                Sub => Value::Int(a - b),
                Lt => Value::Bool(a < b),
                LtE => Value::Bool(a <= b),
                Gt => Value::Bool(a > b),
                GtE => Value::Bool(a >= b),
                Eq => Value::Bool(a == b),
                _ => Value::Bool(a != b),
            });
        }
        (Div, Value::Int(a), Value::Int(b)) => {
            return Some(
                a.checked_div(*b)
                    .map(Value::Int)
                    .unwrap_or_else(Value::clean),
            )
        }
        (Mod, Value::Int(a), Value::Int(b)) => {
            return Some(
                a.checked_rem(*b)
                    .map(Value::Int)
                    .unwrap_or_else(Value::clean),
            )
        }
        // `x & ~0` keeps every bit.
        (BitAnd, v, Value::Int(-1)) | (BitAnd, Value::Int(-1), v) if numeric(v) => {
            return Some(v.clone())
        }
        _ => {}
    }
    let ranged = matches!(l, Value::Range(..)) || matches!(r, Value::Range(..));
    if !ranged {
        // An unknown number masked or reduced to a range: `x & 0xff`, `x % n`.
        return match (op, l, r) {
            (BitAnd, Value::Unknown(t), Value::Int(m))
            | (BitAnd, Value::Int(m), Value::Unknown(t))
                if *m >= 0 =>
            {
                Some(Value::range(0, *m, t.clone()))
            }
            (Mod, Value::Unknown(t), Value::Int(k)) if *k > 0 => Some(if t.is_tainted() {
                Value::range(-(k - 1), k - 1, t.clone())
            } else {
                Value::range(0, k - 1, t.clone())
            }),
            _ => None,
        };
    }
    if !numeric(l) && !matches!(l, Value::Bool(_)) || !numeric(r) && !matches!(r, Value::Bool(_)) {
        return None;
    }
    let t = l.taint().union(&r.taint());
    let (a, b) = num_bounds(l)?;
    let (c, d) = num_bounds(r)?;
    // `i + 1`, `i * 4` over every value of `i` still reach both ends.
    let reached = l.reached() && r.reached();
    let range = |lo: i64, hi: i64, t: Taint| {
        if reached {
            Value::range_reached(lo, hi, t)
        } else {
            Value::range(lo, hi, t)
        }
    };
    let truth = |v: Option<bool>| Some(v.map(Value::Bool).unwrap_or_else(Value::clean));
    match op {
        Lt => truth(if b < c {
            Some(true)
        } else if a >= d {
            Some(false)
        } else {
            None
        }),
        LtE => truth(if b <= c {
            Some(true)
        } else if a > d {
            Some(false)
        } else {
            None
        }),
        Gt => truth(if a > d {
            Some(true)
        } else if b <= c {
            Some(false)
        } else {
            None
        }),
        GtE => truth(if a >= d {
            Some(true)
        } else if b < c {
            Some(false)
        } else {
            None
        }),
        Eq | NotEq => {
            let eq = if a == b && c == d && a == c {
                Some(true)
            } else if b < c || d < a {
                Some(false)
            } else {
                None
            };
            truth(eq.map(|e| e == (op == Eq)))
        }
        Add => {
            let lo = if a == MIN || c == MIN {
                MIN
            } else {
                a.saturating_add(c)
            };
            let hi = if b == MAX || d == MAX {
                MAX
            } else {
                b.saturating_add(d)
            };
            Some(range(lo, hi, t))
        }
        Sub => {
            let lo = if a == MIN || d == MAX {
                MIN
            } else {
                a.saturating_sub(d)
            };
            let hi = if b == MAX || c == MIN {
                MAX
            } else {
                b.saturating_sub(c)
            };
            Some(range(lo, hi, t))
        }
        Mul => {
            let k = match (l, r) {
                (Value::Int(k), _) => Some((*k, c, d)),
                (_, Value::Int(k)) => Some((*k, a, b)),
                _ => None,
            };
            match k {
                Some((0, _, _)) => Some(Value::Int(0)),
                Some((k, lo, hi)) if k > 0 => Some(range(scaled(lo, k), scaled(hi, k), t)),
                _ if [a, b, c, d].iter().all(|x| *x != MIN && *x != MAX) => {
                    let corners = [a * c, a * d, b * c, b * d];
                    let lo = corners.iter().min().copied().unwrap_or(0);
                    let hi = corners.iter().max().copied().unwrap_or(0);
                    Some(Value::range(lo, hi, t))
                }
                _ => Some(Value::Unknown(t)),
            }
        }
        Div => match r {
            Value::Int(k) if *k > 0 => {
                let lo = if a == MIN { MIN } else { a / k };
                let hi = if b == MAX { MAX } else { b / k };
                Some(range(lo, hi, t))
            }
            _ => Some(Value::Unknown(t)),
        },
        Mod => match r {
            Value::Int(k) if *k > 0 => Some(if a >= 0 {
                Value::range(0, b.min(k - 1), t)
            } else if b <= 0 {
                Value::range(-(k - 1), 0, t)
            } else {
                Value::range(-(k - 1), k - 1, t)
            }),
            _ => Some(Value::Unknown(t)),
        },
        BitAnd => match (l, r) {
            (_, Value::Int(m)) | (Value::Int(m), _) if *m >= 0 => {
                let hi = if a >= 0 && matches!(r, Value::Int(_)) {
                    b.min(*m)
                } else {
                    *m
                };
                Some(Value::range(0, hi, t))
            }
            _ => Some(Value::Unknown(t)),
        },
        Shr => match r {
            Value::Int(s) if (0..63).contains(s) && a >= 0 => {
                let hi = if b == MAX { MAX } else { b >> s };
                Some(Value::range(a >> s, hi, t))
            }
            _ => Some(Value::Unknown(t)),
        },
        _ => Some(Value::Unknown(t)),
    }
}

/// `p + k` and `p - k`.
fn moved(b: &Rc<Buf>, k: &Value, sign: i64) -> Value {
    let off = match (b.off, k) {
        (Some(o), Value::Int(n)) => n.checked_mul(sign).and_then(|d| o.checked_add(d)),
        _ => None,
    };
    Value::Buf(Rc::new(Buf {
        off,
        ..(**b).clone()
    }))
}

/// Where a finding about `b` should send the reader.
fn declared(it: &Interp, b: &Buf) -> String {
    if b.module == it.module() && b.at.line > 0 {
        format!(" (строка {})", b.at.line)
    } else {
        String::new()
    }
}

/// Reports an access of `lo..=hi` bytes (MAX: unknown, controlled by
/// `taint` when it holds user data) at where `dst` points.
#[allow(clippy::too_many_arguments)]
fn check_bytes(
    it: &mut Interp,
    dst: &Value,
    lo: i64,
    hi: i64,
    reached: bool,
    taint: &Taint,
    write: bool,
    what: &str,
    span: Span,
) {
    let rule: &'static Rule = if write {
        &BUFFER_OVERFLOW
    } else {
        &BUFFER_OVERREAD
    };
    let verb = if write {
        "записывает"
    } else {
        "читает"
    };
    for b in bufs(dst) {
        let Some(off) = b.off else {
            continue;
        };
        let start = off.saturating_mul(b.elem);
        let at = declared(it, &b);
        if hi <= 0 {
            continue;
        }
        if start < 0 {
            let place = if write {
                "перед началом"
            } else {
                "до начала"
            };
            let msg = format!(
                "{what} {verb} {place} буфера размером {}{at}: указатель смещён на {}",
                counted(b.size, BYTES),
                counted(start, BYTES)
            );
            it.flag(rule, span, &msg);
            continue;
        }
        let room = b.size - start;
        if hi == MAX {
            if taint.is_tainted() {
                let msg = format!(
                    "{what}: размер не проверен, а в буфере {}{at}",
                    counted(room, BYTES)
                );
                it.flag_tainted(rule, span, &msg, taint);
            }
            continue;
        }
        // A size that only may be too large is reported when the user
        // chooses it, or when its largest value certainly occurs.
        if hi > room && (taint.is_tainted() || reached || lo > room) {
            let n = if lo == hi {
                counted(hi, BYTES)
            } else {
                format!("до {}", counted(hi, OF_BYTES))
            };
            let into = if write {
                "в буфер"
            } else {
                "из буфера"
            };
            let from = if start > 0 {
                format!(", начиная с байта {start}")
            } else {
                String::new()
            };
            let msg = format!(
                "{what} {verb} {n} {into} размером {}{from}{at}",
                counted(b.size, BYTES)
            );
            if taint.is_tainted() {
                it.flag_tainted(rule, span, &msg, taint);
            } else {
                it.flag(rule, span, &msg);
            }
        }
    }
}

/// Checks an amount that is a count of `width`-byte elements.
#[allow(clippy::too_many_arguments)]
fn check_count(
    it: &mut Interp,
    dst: &Value,
    count: &Value,
    width: i64,
    write: bool,
    what: &str,
    span: Span,
) {
    let Some((lo, hi)) = num_bounds(count) else {
        return;
    };
    check_bytes(
        it,
        dst,
        scaled(lo.max(0), width),
        scaled(hi, width),
        count.reached(),
        &count.taint(),
        write,
        what,
        span,
    );
}

/// Checks writing a string of `len` elements and its NUL.
/// `reached`: the longest length certainly occurs.
#[allow(clippy::too_many_arguments)]
fn check_string(
    it: &mut Interp,
    dst: &Value,
    len: (i64, i64),
    reached: bool,
    src: &Value,
    width: i64,
    what: &str,
    span: Span,
) {
    let hi = if len.1 == UNBOUNDED {
        MAX
    } else {
        scaled(len.1 + 1, width)
    };
    check_bytes(
        it,
        dst,
        scaled(len.0 + 1, width),
        hi,
        len.0 == len.1 || reached,
        &src.taint(),
        true,
        what,
        span,
    );
}

/// Reports a string function reading from where `src` points when that
/// is outside its buffer (`strcpy(dst, buf - 8)`).
fn check_source(it: &mut Interp, src: &Value, what: &str, span: Span) {
    check_bytes(it, src, 1, 1, true, &Taint::clean(), false, what, span);
}

/// Bytes per character of a string function: 4 for the `wcs` and `wmem`
/// families.
fn width(name: &str) -> i64 {
    if name.starts_with("wcs")
        || name.starts_with("wmem")
        || name.starts_with("_wcs")
        || name.starts_with("swprintf")
        || name.starts_with("vswprintf")
        || name.starts_with("_snw")
        || name.starts_with("_vsnw")
        || name.starts_with("fgetws")
        || name.ends_with('W')
    {
        4
    } else {
        1
    }
}

/// Bounds of the length of the text `sprintf(fmt, args...)` makes, and
/// the taint of the parts whose length is not bounded.
pub fn format_len(fmt: &Value, args: &[ArgVal]) -> (i64, i64, Taint) {
    let Some(f) = fmt.as_str() else {
        let t = fmt.taint();
        return (0, UNBOUNDED, t);
    };
    let (mut lo, mut hi) = (0i64, 0i64);
    let mut open = Taint::clean();
    let mut unbounded = false;
    let mut next = 0usize;
    let mut chars = f.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            lo += 1;
            hi += 1;
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            lo += 1;
            hi += 1;
            continue;
        }
        let mut width: Option<i64> = None;
        let mut precision: Option<i64> = None;
        let mut in_precision = false;
        let mut conv = ' ';
        for n in chars.by_ref() {
            match n {
                '0'..='9' => {
                    let d = n as i64 - '0' as i64;
                    let slot = if in_precision {
                        &mut precision
                    } else {
                        &mut width
                    };
                    *slot = Some(slot.unwrap_or(0).saturating_mul(10).saturating_add(d));
                }
                '.' => {
                    in_precision = true;
                    precision = Some(0);
                }
                '*' => {
                    // The width or precision is an argument.
                    let v = args.get(next).map(|a| a.value.clone());
                    next += 1;
                    let k = v.and_then(|v| v.as_int());
                    if in_precision {
                        precision = k;
                    } else {
                        width = k.or(Some(MAX));
                    }
                }
                '-' | '+' | ' ' | '#' | '\'' => {}
                'h' | 'l' | 'L' | 'q' | 'j' | 'z' | 't' => {}
                other => {
                    conv = other;
                    break;
                }
            }
        }
        let v = args
            .get(next)
            .map(|a| a.value.clone())
            .unwrap_or(Value::None);
        if conv != 'n' {
            next += 1;
        }
        let (l, mut h) = match conv {
            's' | 'S' => {
                let (l, h) = str_len(&v);
                match precision {
                    Some(p) => (l.min(p), h.min(p)),
                    None => (l, h),
                }
            }
            'c' | 'C' => (1, 1),
            'd' | 'i' | 'u' | 'x' | 'X' | 'o' => match v.bounds() {
                Some((a, b)) if a == b => {
                    let n = if conv == 'x' || conv == 'X' {
                        format!("{a:x}").len()
                    } else {
                        a.to_string().len()
                    } as i64;
                    (n, n)
                }
                _ => (1, 20),
            },
            'p' => (3, 18),
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => (1, 317),
            'n' => (0, 0),
            _ => (0, 0),
        };
        if h == UNBOUNDED {
            unbounded = true;
            open = open.union(&v.taint());
        }
        let w = width.unwrap_or(0);
        if w == MAX {
            unbounded = true;
            h = UNBOUNDED;
        }
        lo = lo.saturating_add(l.max(w));
        if h != UNBOUNDED {
            hi = hi.saturating_add(h.max(w));
        }
    }
    (lo, if unbounded { UNBOUNDED } else { hi }, open)
}

/// The length of the string `dst` holds after a copy of `n` elements
/// (n None: up to and with the NUL) from a string of length `src`, at
/// `off` elements into a buffer whose string had length `old`.
fn copied_len(off: i64, old: (i64, i64), src: (i64, i64), n: Option<(i64, i64)>) -> (i64, i64) {
    let (slo, shi) = src;
    let terminated = match n {
        None => true,
        Some((nlo, _)) => shi != UNBOUNDED && shi < nlo,
    };
    if terminated {
        let hi = if shi == UNBOUNDED {
            UNBOUNDED
        } else {
            off + shi
        };
        return (off + slo, hi);
    }
    // Only characters before the NUL were copied: the string now runs at
    // least to their end.
    match n {
        Some((nlo, nhi)) if nlo == nhi && slo >= nlo => {
            let end = off + nlo;
            if old.0 > end {
                (old.0, old.1)
            } else {
                (end, UNBOUNDED)
            }
        }
        _ => (off.min(old.0).max(0), UNBOUNDED),
    }
}

/// Size checks of a library call that writes or reads memory. The call's
/// own model stores what it writes.
pub fn check_call(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) {
    let w = width(name);
    let what = format!("{name}()");
    match name {
        "memcpy" | "memmove" | "wmemcpy" | "wmemmove" | "CopyMemory" | "RtlCopyMemory"
        | "MoveMemory" | "bcopy" => {
            let (dst, src) = if name == "bcopy" {
                (arg(args, 1), arg(args, 0))
            } else {
                (arg(args, 0), arg(args, 1))
            };
            let n = arg(args, 2);
            check_count(it, &dst, &n, w, true, &what, span);
            check_count(it, &src, &n, w, false, &what, span);
        }
        "memset" | "wmemset" => {
            check_count(it, &arg(args, 0), &arg(args, 2), w, true, &what, span);
        }
        "bzero" | "explicit_bzero" | "ZeroMemory" | "SecureZeroMemory" => {
            check_count(it, &arg(args, 0), &arg(args, 1), 1, true, &what, span);
        }
        "memcpy_s" | "memmove_s" | "wmemcpy_s" | "wmemmove_s" | "strcpy_s" | "wcscpy_s"
        | "strcat_s" | "wcscat_s" | "strncpy_s" | "wcsncpy_s" | "strncat_s" | "wcsncat_s"
        | "snprintf_s" | "sprintf_s" | "swprintf_s" | "_snprintf_s" | "_snwprintf_s" | "gets_s"
        | "_getws_s" => {
            // The size argument must not exceed the buffer.
            check_count(it, &arg(args, 0), &arg(args, 1), w, true, &what, span);
        }
        "strcpy" | "wcscpy" | "lstrcpyA" | "lstrcpyW" | "_mbscpy" | "stpcpy" | "lstrcpy" => {
            let (dst, src) = (arg(args, 0), arg(args, 1));
            check_source(it, &src, &what, span);
            let len = str_len(&src);
            check_string(it, &dst, len, str_len_sure(&src), &src, w, &what, span);
        }
        "strncpy" | "wcsncpy" | "stpncpy" | "lstrcpynA" | "lstrcpynW" => {
            check_source(it, &arg(args, 1), &what, span);
            check_count(it, &arg(args, 0), &arg(args, 2), w, true, &what, span);
        }
        "strlcpy" | "wcslcpy" | "strlcat" | "wcslcat" => {
            check_count(it, &arg(args, 0), &arg(args, 2), w, true, &what, span);
        }
        "strcat" | "wcscat" | "lstrcatA" | "lstrcatW" | "_mbscat" | "lstrcat" => {
            let (dst, src) = (arg(args, 0), arg(args, 1));
            check_source(it, &src, &what, span);
            let d = str_len(&dst);
            let s = str_len(&src);
            let len = (
                d.0.saturating_add(s.0),
                if d.1 == UNBOUNDED || s.1 == UNBOUNDED {
                    UNBOUNDED
                } else {
                    d.1 + s.1
                },
            );
            // Only a length the user controls counts when the
            // destination's own length is unknown.
            if str_len_raw(&dst).1 == UNBOUNDED && str_len_raw(&src).1 != UNBOUNDED {
                return;
            }
            let reached = str_len_sure(&dst) && str_len_sure(&src);
            check_string(it, &dst, len, reached, &src, w, &what, span);
        }
        "strncat" | "wcsncat" => {
            let (dst, src) = (arg(args, 0), arg(args, 1));
            check_source(it, &src, &what, span);
            let d = str_len(&dst);
            let s = str_len(&src);
            let n = num_bounds(&arg(args, 2)).unwrap_or((MIN, MAX));
            if str_len_raw(&dst).1 == UNBOUNDED {
                return;
            }
            let add = (s.0.min(n.0.max(0)), s.1.min(n.1));
            let len = (
                d.0.saturating_add(add.0),
                if add.1 == UNBOUNDED || add.1 == MAX {
                    UNBOUNDED
                } else {
                    d.1 + add.1
                },
            );
            let taint = if s.1 == UNBOUNDED && n.1 == MAX {
                src.taint().union(&arg(args, 2).taint())
            } else {
                arg(args, 2).taint()
            };
            let hi = if len.1 == UNBOUNDED {
                MAX
            } else {
                scaled(len.1 + 1, w)
            };
            let reached = len.0 == len.1
                || str_len_sure(&dst) && (str_len_sure(&src) || n.0 == n.1 && n.1 < s.0);
            check_bytes(
                it,
                &dst,
                scaled(len.0 + 1, w),
                hi,
                reached,
                &taint,
                true,
                &what,
                span,
            );
        }
        "snprintf" | "vsnprintf" | "swprintf" | "vswprintf" | "_snprintf" | "_vsnprintf"
        | "_snwprintf" | "_vsnwprintf" => {
            check_count(it, &arg(args, 0), &arg(args, 1), w, true, &what, span);
        }
        "sprintf" | "vsprintf" | "_swprintf" | "_vswprintf" => {
            let (lo, hi, open) = format_len(&arg(args, 1), args.get(2..).unwrap_or(&[]));
            let dst = arg(args, 0);
            if hi == UNBOUNDED {
                check_bytes(
                    it,
                    &dst,
                    scaled(lo + 1, w),
                    MAX,
                    false,
                    &open,
                    true,
                    &what,
                    span,
                );
            } else {
                check_bytes(
                    it,
                    &dst,
                    scaled(lo + 1, w),
                    scaled(hi + 1, w),
                    lo == hi,
                    &open,
                    true,
                    &what,
                    span,
                );
            }
        }
        "gets" | "_getws" => {
            let msg = format!("{what} читает строку любой длины: используйте fgets()");
            it.flag(&BUFFER_OVERFLOW, span, &msg);
        }
        "fgets" | "fgetws" => {
            check_count(it, &arg(args, 0), &arg(args, 1), w, true, &what, span);
        }
        "recv" | "recvfrom" | "read" | "_read" | "pread" | "SSL_read" | "BIO_read" => {
            check_count(it, &arg(args, 1), &arg(args, 2), 1, true, &what, span);
        }
        "fread" => {
            let n = binop(BinOp::Mul, &arg(args, 1), &arg(args, 2)).unwrap_or_else(|| {
                crate::interp::generic_binop(BinOp::Mul, &arg(args, 1), &arg(args, 2))
            });
            check_count(it, &arg(args, 0), &n, 1, true, &what, span);
        }
        "scanf" | "wscanf" | "fscanf" | "fwscanf" | "sscanf" | "swscanf" => {
            let first =
                if name.contains("scanf") && (name.starts_with('f') || name.starts_with('s')) {
                    1
                } else {
                    0
                };
            let input = (first == 1 && name.starts_with('s')).then(|| arg(args, 0));
            scanf_checks(
                it,
                &arg(args, first),
                args.get(first + 1..).unwrap_or(&[]),
                input,
                w,
                &what,
                span,
            );
        }
        _ => {}
    }
}

/// `scanf("%s", buf)`: a `%s` or `%[` without a width writes as much as
/// the input holds.
fn scanf_checks(
    it: &mut Interp,
    fmt: &Value,
    args: &[ArgVal],
    input: Option<Value>,
    w: i64,
    what: &str,
    span: Span,
) {
    let Some(f) = fmt.as_str() else {
        return;
    };
    let mut next = 0usize;
    let mut chars = f.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            continue;
        }
        let mut skip = false;
        let mut width: Option<i64> = None;
        let mut conv = ' ';
        while let Some(n) = chars.next() {
            match n {
                '*' => skip = true,
                '0'..='9' => {
                    width = Some(width.unwrap_or(0) * 10 + (n as i64 - '0' as i64));
                }
                'h' | 'l' | 'L' | 'q' | 'j' | 'z' | 't' | 'm' => {}
                '[' => {
                    // The scan set runs to the next `]` (a leading `]` belongs to it).
                    let mut first = true;
                    for s in chars.by_ref() {
                        if s == ']' && !first {
                            break;
                        }
                        first = false;
                    }
                    conv = '[';
                    break;
                }
                other => {
                    conv = other;
                    break;
                }
            }
        }
        if skip {
            continue;
        }
        let dst = args
            .get(next)
            .map(|a| a.value.clone())
            .unwrap_or(Value::None);
        next += 1;
        if !matches!(conv, 's' | 'S' | '[' | 'c') {
            continue;
        }
        match width {
            Some(n) => {
                let bytes = if conv == 'c' { n } else { n + 1 };
                check_bytes(
                    it,
                    &dst,
                    scaled(bytes, w),
                    scaled(bytes, w),
                    true,
                    &Taint::clean(),
                    true,
                    what,
                    span,
                );
            }
            None if conv == 'c' => {}
            None => match &input {
                Some(src) => {
                    let len = str_len(src);
                    check_string(it, &dst, len, str_len_sure(src), src, w, what, span);
                }
                None if holds_buf(&dst) => {
                    let msg = format!("{what}: %{conv} без ширины читает строку любой длины");
                    it.flag(&BUFFER_OVERFLOW, span, &msg);
                }
                None => {}
            },
        }
    }
}

/// `b[k]` read.
pub fn read_at(it: &mut Interp, b: &Rc<Buf>, key: &Value) -> Value {
    let span = it.span();
    check_index(it, b, key, false, span);
    let content = b.content.clone();
    it.index(&content, key)
}

/// `b[k] = v`.
pub fn write_at(it: &mut Interp, b: &Rc<Buf>, key: &Value, value: &Value, span: Span) -> Value {
    check_index(it, b, key, true, span);
    let content = match &b.content {
        Value::List(_) | Value::Dict(_) => {
            crate::interp::store_index(&b.content, key, value.clone())
                .unwrap_or_else(|| Value::Unknown(b.content.taint().union(&value.taint())))
        }
        Value::Str(_) if !value.taint().is_tainted() => b.content.clone(),
        other => Value::Unknown(other.taint().union(&value.taint())),
    };
    let len = match (b.off, key.bounds()) {
        (Some(o), Some((klo, khi))) if klo != MIN && khi != MAX => {
            let (klo, khi) = (klo.saturating_add(o), khi.saturating_add(o));
            let (lo, hi) = b.len;
            match value {
                // A NUL ends the string there, or earlier.
                Value::Int(0) if klo == khi => (lo.min(klo), hi.min(klo)),
                Value::Int(0) => (lo.min(klo).max(0), hi),
                // A character after the NUL or before the shortest end
                // leaves the length as it was.
                Value::Int(_) if khi < lo || (hi != UNBOUNDED && klo > hi) => (lo, hi),
                _ if khi < lo || (hi != UNBOUNDED && klo > hi) => (lo.min(klo.max(0)), hi),
                _ => (lo.min(klo.max(0)), UNBOUNDED),
            }
        }
        _ => (0, UNBOUNDED),
    };
    Value::Buf(Rc::new(Buf {
        content,
        len,
        len_sure: false,
        ..(**b).clone()
    }))
}

fn check_index(it: &mut Interp, b: &Buf, key: &Value, write: bool, span: Span) {
    let Some(off) = b.off else {
        return;
    };
    let rule: &'static Rule = if write {
        &BUFFER_OVERFLOW
    } else {
        &BUFFER_OVERREAD
    };
    let count = b.size / b.elem.max(1);
    let at = declared(it, b);
    let taint = key.taint();
    let Some((klo, khi)) = num_bounds(key) else {
        return;
    };
    let lo = if klo == MIN {
        MIN
    } else {
        klo.saturating_add(off)
    };
    let hi = if khi == MAX {
        MAX
    } else {
        khi.saturating_add(off)
    };
    if hi == MAX || lo == MIN {
        if taint.is_tainted() {
            let side = match (lo == MIN, hi == MAX) {
                (true, true) => "не проверен",
                (true, false) => "не проверен снизу",
                _ => "не проверен сверху",
            };
            let msg = format!(
                "индекс {side}, а в массиве {}{at}",
                counted(count, ELEMENTS)
            );
            it.flag_tainted(rule, span, &msg, &taint);
        }
        if lo == MIN && hi == MAX {
            return;
        }
    }
    // An index that only may be outside is reported when the user
    // chooses it, or when that value certainly occurs.
    let sure = taint.is_tainted() || key.reached();
    if hi != MAX && hi >= count && (sure || lo >= count) {
        let el = match (write, lo == hi) {
            (true, true) => format!("запись в элемент {hi}"),
            (true, false) => format!("запись в элементы до {hi}"),
            (false, true) => format!("чтение элемента {hi}"),
            (false, false) => format!("чтение элементов до {hi}"),
        };
        let msg = format!("{el} массива из {}{at}", counted(count, OF_ELEMENTS));
        if taint.is_tainted() {
            it.flag_tainted(rule, span, &msg, &taint);
        } else {
            it.flag(rule, span, &msg);
        }
    } else if lo != MIN && lo < 0 && (sure || hi < 0) {
        let el = if write {
            format!("запись в элемент {lo}")
        } else {
            format!("чтение элемента {lo}")
        };
        let msg = format!(
            "{el}: до начала массива из {}{at}",
            counted(count, OF_ELEMENTS)
        );
        if taint.is_tainted() {
            it.flag_tainted(rule, span, &msg, &taint);
        } else {
            it.flag(rule, span, &msg);
        }
    }
}

/// Stores `value` (a string of `len` elements from where the pointer
/// points) where pointer argument `i` points, keeping the buffer it
/// points into. False when the place holds no buffer.
pub fn put(
    it: &mut Interp,
    args: &[ArgVal],
    i: usize,
    value: &Value,
    len: (i64, i64),
    span: Span,
) -> bool {
    let Some(a) = args.get(i) else {
        return false;
    };
    let Some(place) = a.place.clone() else {
        return false;
    };
    let views = bufs(&a.value);
    if views.is_empty() {
        return false;
    }
    let root = it.eval(&place);
    let content = match value {
        Value::Buf(b) => b.content.clone(),
        v => v.clone(),
    };
    let updated = |r: &Value| -> Value {
        match r {
            Value::Buf(rb) => match views.iter().find(|v| v.same(rb)) {
                Some(v) => {
                    let abs = match v.off {
                        Some(o) if o >= 0 => (
                            len.0.saturating_add(o),
                            if len.1 == UNBOUNDED {
                                UNBOUNDED
                            } else {
                                len.1.saturating_add(o)
                            },
                        ),
                        _ => (0, UNBOUNDED),
                    };
                    Value::Buf(Rc::new(Buf {
                        content: content.clone(),
                        len: abs,
                        len_sure: false,
                        ..(**rb).clone()
                    }))
                }
                None => r.clone(),
            },
            _ => content.clone(),
        }
    };
    let new = match &root {
        Value::OneOf(alts) => join_all(alts.iter().map(updated)).unwrap_or_else(|| content.clone()),
        r if holds_buf(r) => updated(r),
        // The place is not the buffer (`*pp`, a field): store the buffer
        // the argument pointed to.
        _ => match views.first() {
            Some(v) => updated(&Value::Buf(v.clone())),
            None => content.clone(),
        },
    };
    it.assign_expr(&place, new, span);
    true
}

/// The length a buffer's string gets from a copy by `name`.
pub fn copy_len(name: &str, args: &[ArgVal]) -> (i64, i64) {
    let dst = arg(args, 0);
    let old = match &dst {
        Value::Buf(b) => {
            let o = b.off.unwrap_or(0);
            (
                (b.len.0 - o).max(0),
                if b.len.1 == UNBOUNDED {
                    UNBOUNDED
                } else {
                    (b.len.1 - o).max(0)
                },
            )
        }
        _ => (0, UNBOUNDED),
    };
    let n = |i: usize| num_bounds(&arg(args, i)).filter(|(lo, hi)| *lo != MIN && *hi != MAX);
    match name {
        "strcpy" | "wcscpy" | "lstrcpyA" | "lstrcpyW" | "_mbscpy" | "stpcpy" | "lstrcpy" => {
            str_len(&arg(args, 1))
        }
        "strcpy_s" | "wcscpy_s" => str_len(&arg(args, 2)),
        "strncpy" | "wcsncpy" | "stpncpy" => copied_len(
            0,
            old,
            str_len(&arg(args, 1)),
            Some(n(2).unwrap_or((0, MAX))),
        ),
        "memcpy" | "memmove" | "wmemcpy" | "wmemmove" => match n(2) {
            Some((lo, hi)) => {
                let w = width(name);
                let el = if w == 1 {
                    // A byte count: in elements of the destination.
                    match &dst {
                        Value::Buf(b) if b.elem > 1 => (lo / b.elem, hi / b.elem),
                        _ => (lo, hi),
                    }
                } else {
                    (lo, hi)
                };
                copied_len(0, old, str_len(&arg(args, 1)), Some(el))
            }
            None => (0, UNBOUNDED),
        },
        "strcat" | "wcscat" | "lstrcatA" | "lstrcatW" | "_mbscat" | "lstrcat" => {
            let s = str_len(&arg(args, 1));
            (
                old.0.saturating_add(s.0),
                if old.1 == UNBOUNDED || s.1 == UNBOUNDED {
                    UNBOUNDED
                } else {
                    old.1 + s.1
                },
            )
        }
        "strncat" | "wcsncat" => {
            let s = str_len(&arg(args, 1));
            let cap = n(2).map(|(_, hi)| hi).unwrap_or(MAX);
            let add_hi = if s.1 == UNBOUNDED { cap } else { s.1.min(cap) };
            (
                old.0.saturating_add(s.0.min(cap)),
                if old.1 == UNBOUNDED || add_hi == MAX {
                    UNBOUNDED
                } else {
                    old.1 + add_hi
                },
            )
        }
        _ => (0, UNBOUNDED),
    }
}

/// The length a buffer's string gets from `memset(b, c, n)`.
pub fn memset_len(name: &str, args: &[ArgVal]) -> (i64, i64) {
    let dst = arg(args, 0);
    let Value::Buf(b) = &dst else {
        return (0, UNBOUNDED);
    };
    let o = b.off.unwrap_or(0);
    let old = (
        (b.len.0 - o).max(0),
        if b.len.1 == UNBOUNDED {
            UNBOUNDED
        } else {
            (b.len.1 - o).max(0)
        },
    );
    // `wmemset` counts characters, `memset` bytes.
    let n = match arg(args, 2).as_int() {
        Some(n) if n >= 0 && width(name) > 1 => n,
        Some(n) if n >= 0 => n / b.elem.max(1),
        _ => return (0, UNBOUNDED),
    };
    match arg(args, 1).as_int() {
        Some(0) if n > 0 => (0, 0),
        Some(0) => old,
        Some(_) if old.0 >= n => (old.0, old.1),
        Some(_) => (n, UNBOUNDED),
        None => (0, UNBOUNDED),
    }
}

/// Forms of a noun counted in Russian: for 1, for 2 to 4, for 5 or more.
type Forms = [&'static str; 3];
const BYTES: Forms = ["байт", "байта", "байт"];
/// After `до` and `из`.
const OF_BYTES: Forms = ["байта", "байт", "байт"];
const ELEMENTS: Forms = ["элемент", "элемента", "элементов"];
const OF_ELEMENTS: Forms = ["элемента", "элементов", "элементов"];

/// `n` with the form of the noun that goes with it: 1 байт, 3 байта,
/// 12 байт, 21 байт.
fn counted(n: i64, forms: Forms) -> String {
    let k = n.unsigned_abs();
    let form = match (k % 10, k % 100) {
        (_, 11..=14) => forms[2],
        (1, _) => forms[0],
        (2..=4, _) => forms[1],
        _ => forms[2],
    };
    format!("{n} {form}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_take_the_form_of_their_number() {
        let bytes = |n| counted(n, BYTES);
        assert_eq!(bytes(1), "1 байт");
        assert_eq!(bytes(4), "4 байта");
        assert_eq!(bytes(16), "16 байт");
        assert_eq!(bytes(12), "12 байт");
        assert_eq!(bytes(22), "22 байта");
        assert_eq!(bytes(-1), "-1 байт");
        assert_eq!(counted(1, OF_ELEMENTS), "1 элемента");
        assert_eq!(counted(9, OF_ELEMENTS), "9 элементов");
        assert_eq!(counted(3, ELEMENTS), "3 элемента");
        assert_eq!(counted(111, ELEMENTS), "111 элементов");
    }
}
