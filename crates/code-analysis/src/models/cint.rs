//! Integer overflow and underflow in C (CWE-190 and CWE-191): a sum,
//! difference or product, `++` or `--`, whose result does not fit the type
//! C computes it in (`int`, `unsigned int`, `int64_t`), or the signed
//! `char` or `short` variable it is stored in (`char c = data + 1;`).
//!
//! The type of each side comes from declarations, literals, casts and a few
//! library functions; a side of unknown type (a struct field, most calls)
//! leaves the operation unchecked. A result that only may not fit is
//! reported when it comes from a number the user gave. Without one, only
//! constants are: a signed result out of range (`INT_MAX + 1`), which C
//! leaves undefined. Unsigned arithmetic wraps by definition, and code
//! relies on it (`while (n--)`, hashes, `x - 1` of a counter at 0), so
//! there it takes the user's number.
//!
//! The user's number counts where it first enters arithmetic: the result is
//! marked [`ctx::COMPUTED`], like a string's length, so a hash or a sum
//! built from input bytes (`h = h * 33 + c`) is not reported at every step.
//! Unsigned `char` and `short` variables are not checked: storing into them
//! wraps by definition, which checksums rely on.

use crate::interp::Interp;
use crate::ir::{BinOp, Const, Expr, UnOp};
use crate::lower::c::{is_unsigned32, plain_type, small_int_range};
use crate::rules::{INT_OVERFLOW, INT_UNDERFLOW};
use crate::value::*;
use std::rc::Rc;

/// A C integer type.
#[derive(Debug, Clone, PartialEq)]
pub struct IntType {
    pub bits: u32,
    pub signed: bool,
    /// As declared (`int64_t`), or `int` after promotion.
    pub name: Rc<str>,
}

impl IntType {
    fn of(bits: u32, signed: bool, name: &str) -> IntType {
        IntType {
            bits,
            signed,
            name: name.into(),
        }
    }

    pub fn min(&self) -> i128 {
        if self.signed {
            -(1i128 << (self.bits - 1))
        } else {
            0
        }
    }

    pub fn max(&self) -> i128 {
        if self.signed {
            (1i128 << (self.bits - 1)) - 1
        } else {
            (1i128 << self.bits) - 1
        }
    }

    /// Types narrower than `int` compute as `int`.
    fn promoted(&self) -> IntType {
        if self.bits < 32 {
            IntType::of(32, true, "int")
        } else {
            self.clone()
        }
    }
}

/// The integer type a declared C type names; None for pointers, floating
/// point, and types the project defines.
pub fn int_type(ty: &str) -> Option<IntType> {
    if ty.contains(['*', '[', '(', '&', '<']) {
        return None;
    }
    let t = plain_type(ty);
    if let Some((lo, hi)) = small_int_range(&t) {
        let bits = if lo < -128 || hi > 255 { 16 } else { 8 };
        return Some(IntType::of(bits, lo < 0, &t));
    }
    let (bits, signed) = match t.as_str() {
        "int" | "signed" | "signed int" | "int32_t" | "gint" | "gint32" | "s32" | "__s32"
        | "INT" | "INT32" | "LONG" | "wchar_t" => (32, true),
        _ if is_unsigned32(&t) => (32, false),
        "long" | "long int" | "signed long" | "signed long int" | "long long" | "long long int"
        | "signed long long" | "int64_t" | "ssize_t" | "off_t" | "off64_t" | "loff_t"
        | "ptrdiff_t" | "intptr_t" | "intmax_t" | "time_t" | "gint64" | "gssize" | "s64"
        | "__s64" | "INT64" | "LONGLONG" | "__int64" => (64, true),
        "unsigned long"
        | "unsigned long int"
        | "long unsigned int"
        | "unsigned long long"
        | "unsigned long long int"
        | "uint64_t"
        | "u_int64_t"
        | "size_t"
        | "uintptr_t"
        | "uintmax_t"
        | "u_long"
        | "ulong"
        | "guint64"
        | "gsize"
        | "u64"
        | "__u64"
        | "UINT64"
        | "ULONGLONG"
        | "DWORD64"
        | "SIZE_T" => (64, false),
        _ => return None,
    };
    Some(IntType::of(bits, signed, &t))
}

/// The type C computes `a op b` in: both promoted, then the wider, unsigned
/// when it is at least as wide as the signed one.
fn common(a: &IntType, b: &IntType) -> IntType {
    let (a, b) = (a.promoted(), b.promoted());
    if a.signed == b.signed {
        return if b.bits > a.bits { b } else { a };
    }
    let (u, s) = if a.signed { (b, a) } else { (a, b) };
    if u.bits >= s.bits {
        u
    } else {
        s
    }
}

/// The type of what a library function returns.
fn call_type(name: &str) -> Option<IntType> {
    Some(match name {
        "sizeof" | "strlen" | "wcslen" | "strnlen" | "wcsnlen" => IntType::of(64, false, "size_t"),
        "atoi" | "_wtoi" | "abs" => IntType::of(32, true, "int"),
        "atol" | "atoll" | "strtol" | "strtoll" | "wcstol" | "_wtol" | "labs" | "llabs" => {
            IntType::of(64, true, "long")
        }
        "strtoul" | "strtoull" | "wcstoul" => IntType::of(64, false, "unsigned long"),
        _ => return None,
    })
}

/// The integer type of `e`, when the program says what it is.
pub fn type_of(it: &Interp, e: &Expr) -> Option<IntType> {
    match e {
        Expr::Name(n) => int_type(&it.c_type(n)?),
        Expr::Attr(o, f) => int_type(&it.c_field_type(o, f)?),
        Expr::Lit(Const::Int(k)) => Some(if i32::try_from(*k).is_ok() {
            IntType::of(32, true, "int")
        } else {
            IntType::of(64, true, "long")
        }),
        Expr::Cast(ty, _) => int_type(ty),
        Expr::Un(UnOp::Neg | UnOp::Pos | UnOp::BitNot, x) => type_of(it, x).map(|t| t.promoted()),
        Expr::Bin(op, l, r) => match op {
            BinOp::Add
            | BinOp::Sub
            | BinOp::Mul
            | BinOp::Div
            | BinOp::Mod
            | BinOp::BitAnd
            | BinOp::BitOr
            | BinOp::BitXor => Some(common(&type_of(it, l)?, &type_of(it, r)?)),
            BinOp::Shl | BinOp::Shr => type_of(it, l).map(|t| t.promoted()),
            _ => None,
        },
        Expr::Call { func, .. } => match &**func {
            Expr::Name(n) => call_type(n),
            _ => None,
        },
        _ => None,
    }
}

/// What an operand of type `t` may hold: its known bounds, or any value of
/// its type. None for pointers and other values that are not numbers.
fn operand(v: &Value, t: &IntType) -> Option<(i128, i128)> {
    let (lo, hi) = match (v, v.bounds()) {
        // An open end of a range.
        (Value::Range(..), Some((lo, hi))) => (
            if lo == i64::MIN { t.min() } else { lo as i128 },
            if hi == i64::MAX { t.max() } else { hi as i128 },
        ),
        (_, Some((lo, hi))) => (lo as i128, hi as i128),
        (_, None) if number(v) => (t.min(), t.max()),
        (_, None) => return None,
    };
    let (lo, hi) = (lo.max(t.min()), hi.min(t.max()));
    (lo <= hi).then_some((lo, hi))
}

fn number(v: &Value) -> bool {
    match v {
        Value::Unknown(_) => true,
        Value::OneOf(alts) => alts.iter().all(|a| number(a) || a.bounds().is_some()),
        _ => false,
    }
}

/// `lo..=hi` of type `from` converted to `to`, and whether its ends are
/// still its ends. A negative signed value made unsigned counts from 0:
/// `h * 33 + c` with a `char c` is a hash, not a huge number.
fn convert((lo, hi): (i128, i128), to: &IntType) -> ((i128, i128), bool) {
    if lo >= to.min() && hi <= to.max() {
        return ((lo, hi), true);
    }
    if lo == hi && lo < 0 && !to.signed {
        let k = lo + (1i128 << to.bits);
        if k >= 0 {
            return ((k, k), true);
        }
    }
    let (a, b) = (lo.max(to.min()), hi.min(to.max()));
    if a <= b {
        ((a, b), false)
    } else {
        ((to.min(), to.max()), false)
    }
}

/// The values `l op r` takes; `square` when both sides are one variable.
fn combined(op: BinOp, (a, b): (i128, i128), (c, d): (i128, i128), square: bool) -> (i128, i128) {
    match op {
        BinOp::Add => (a.saturating_add(c), b.saturating_add(d)),
        BinOp::Sub => (a.saturating_sub(d), b.saturating_sub(c)),
        _ if square => {
            let (x, y) = (a.saturating_mul(a), b.saturating_mul(b));
            if a >= 0 {
                (x, y)
            } else if b <= 0 {
                (y, x)
            } else {
                (0, x.max(y))
            }
        }
        _ => {
            let p = [
                a.saturating_mul(c),
                a.saturating_mul(d),
                b.saturating_mul(c),
                b.saturating_mul(d),
            ];
            (*p.iter().min().unwrap_or(&0), *p.iter().max().unwrap_or(&0))
        }
    }
}

/// A number the user gave, not one computed from it.
fn users(v: &Value) -> bool {
    v.taint().reaches(ctx::COMPUTED)
}

/// `l op r` (a sum, difference or product) evaluated to `v` from `lv` and
/// `rv`: reports a result that does not fit its type, or the signed small
/// type `into` of the variable it is stored in. Gives the value the program
/// goes on with.
#[allow(clippy::too_many_arguments)]
pub fn arith(
    it: &mut Interp,
    op: BinOp,
    l: &Expr,
    r: &Expr,
    lv: &Value,
    rv: &Value,
    v: Value,
    into: Option<(&str, &str)>,
) -> Value {
    let v = if v.is_tainted() {
        v.sanitized(ctx::COMPUTED)
    } else {
        v
    };
    let (Some(lt), Some(rt)) = (type_of(it, l), type_of(it, r)) else {
        return v;
    };
    let (Some(a), Some(b)) = (operand(lv, &lt), operand(rv, &rt)) else {
        return v;
    };
    // An untainted operand the analysis knows nothing of (`st->value << 8`)
    // overflows with any number added: the user's number is not to blame.
    let unknown =
        |v: &Value, r: (i128, i128), t: &IntType| !v.is_tainted() && r == (t.min(), t.max());
    let blamed = !unknown(lv, a, &lt) && !unknown(rv, b, &rt);
    let ty = common(&lt, &rt);
    let (a, a_ends) = convert(a, &ty);
    let (b, b_ends) = convert(b, &ty);
    let square = matches!((l, r), (Expr::Name(x), Expr::Name(y)) if x == y);
    let (mut lo, hi) = combined(op, a, b, square);
    // `len -= MIN(chunk, len)`: what is taken is at most `len`.
    if op == BinOp::Sub
        && matches!(rv, Value::OneOf(_))
        && !matches!(lv, Value::Int(_))
        && rv.alternatives().iter().any(|x| x == lv)
    {
        lo = lo.max(0);
    }
    let tainted: Vec<&Value> = [lv, rv].into_iter().filter(|v| v.is_tainted()).collect();
    let user = blamed && !tainted.is_empty() && tainted.iter().all(|v| users(v));
    let constant = |v: &Value| matches!(v.bounds(), Some((x, y)) if x == y);
    let sure = constant(lv) && constant(rv) && a_ends && b_ends;
    let found = Found {
        lo,
        hi,
        user,
        sure,
        taint: lv.taint().union(&rv.taint()),
    };
    let text = show(it, &Expr::Bin(op, Box::new(l.clone()), Box::new(r.clone())))
        .unwrap_or_else(|| "вычисление".into());
    report(it, op, &found, &ty, None, &text);
    // Stored into a signed `char` or `short` from `char` and `short` values
    // that `int` holds whatever they are.
    if let Some((var, t)) = into {
        let small = |e: &Expr, t: &IntType| t.bits < 32 || matches!(e, Expr::Lit(_));
        if let Some(st) = int_type(t).filter(|s| s.bits < 32 && s.signed) {
            if small(l, &lt) && small(r, &rt) {
                report(it, op, &found, &st, Some(var), &text);
            }
        }
    }
    let fits = lo >= ty.min() && hi <= ty.max();
    match v {
        // `c + 1` of a `char c` read from input: whatever `c` is, the sum
        // is at most 128.
        Value::Unknown(t) if fits && (lo > ty.min() || hi < ty.max()) => {
            Value::range(lo as i64, hi as i64, t)
        }
        // A constant out of range wraps.
        Value::Int(k) if !fits && lo == hi => {
            let span = 1i128 << ty.bits;
            let w = (k as i128 - ty.min()).rem_euclid(span) + ty.min();
            i64::try_from(w)
                .map(Value::Int)
                .unwrap_or_else(|_| Value::clean())
        }
        v => v,
    }
}

struct Found {
    lo: i128,
    hi: i128,
    /// From numbers the user gave.
    user: bool,
    /// From constants.
    sure: bool,
    taint: Taint,
}

/// Reports a result `f` of `text` that does not fit `ty`, the type of the
/// variable `var` when it is stored there.
fn report(it: &mut Interp, op: BinOp, f: &Found, ty: &IntType, var: Option<&str>, text: &str) {
    let over = f.hi > ty.max();
    let under = f.lo < ty.min();
    // `x - y` goes wrong below, `x + y` and `x * y` above.
    let above = if op == BinOp::Sub {
        over && !under
    } else {
        over
    };
    if !above && !under {
        return;
    }
    if !f.user && !(f.sure && ty.signed) {
        return;
    }
    let (rule, limit, bound, edge) = if above {
        (&INT_OVERFLOW, "максимум", ty.max(), f.hi)
    } else {
        (&INT_UNDERFLOW, "минимум", ty.min(), f.lo)
    };
    let into = var
        .map(|v| format!(" при записи в {v}"))
        .unwrap_or_default();
    // A user's number: the finding names where it comes from, then this.
    let what = if f.user {
        let past = if above {
            "превысить максимум"
        } else {
            "оказаться меньше минимума"
        };
        format!(
            "{text}: результат может {past} {} ({bound}){into}, а проверки нет",
            ty.name
        )
    } else {
        format!(
            "Результат {text} равен {edge}, а {limit} {} — {bound}{into}",
            ty.name
        )
    };
    let span = it.span();
    if f.user {
        it.flag_tainted(rule, span, &what, &f.taint);
    } else {
        it.flag(rule, span, &what);
    }
}

/// `data + 1` for findings; None for expressions too long to read.
fn show(it: &Interp, e: &Expr) -> Option<String> {
    let s = shown(it, e, 0)?;
    (s.chars().count() <= 60).then_some(s)
}

fn shown(it: &Interp, e: &Expr, depth: u32) -> Option<String> {
    if depth > 4 {
        return None;
    }
    let sub = |x: &Expr| -> Option<String> {
        let s = shown(it, x, depth + 1)?;
        Some(if matches!(x, Expr::Bin(..)) {
            format!("({s})")
        } else {
            s
        })
    };
    Some(match e {
        Expr::Name(n) => n.clone(),
        Expr::Lit(Const::Int(k)) => k.to_string(),
        Expr::Cast(_, x) => shown(it, x, depth)?,
        Expr::Un(UnOp::Deref, x) => format!("*{}", sub(x)?),
        Expr::Un(UnOp::Neg, x) => format!("-{}", sub(x)?),
        Expr::Index(a, i) => format!("{}[{}]", sub(a)?, shown(it, i, depth + 1)?),
        // `img.width` of a struct variable, `p->width` of a pointer.
        Expr::Attr(a, f) => {
            let value = matches!(&**a, Expr::Name(n)
                if it.c_type(n).is_some_and(|t| !t.contains(['*', '['])));
            format!("{}{}{f}", sub(a)?, if value { "." } else { "->" })
        }
        Expr::Call { func, args, .. } if args.len() <= 1 => match &**func {
            Expr::Name(n) => format!(
                "{n}({})",
                match args.first() {
                    Some(a) => shown(it, &a.value, depth + 1)?,
                    None => String::new(),
                }
            ),
            _ => return None,
        },
        Expr::Bin(op, l, r) => {
            let sym = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                BinOp::Mod => "%",
                BinOp::Shl => "<<",
                BinOp::Shr => ">>",
                BinOp::BitAnd => "&",
                BinOp::BitOr => "|",
                BinOp::BitXor => "^",
                _ => return None,
            };
            format!("{} {sym} {}", sub(l)?, sub(r)?)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_combine_as_c_does() {
        let int = int_type("int").unwrap();
        let uint = int_type("unsigned int").unwrap();
        let ch = int_type("char").unwrap();
        let i64t = int_type("int64_t").unwrap();
        let size = int_type("size_t").unwrap();
        assert_eq!(common(&ch, &ch).bits, 32);
        assert!(common(&ch, &ch).signed);
        assert!(!common(&int, &uint).signed);
        assert_eq!(common(&uint, &i64t), i64t);
        assert!(!common(&int, &size).signed);
        assert_eq!(uint.max(), 4294967295);
        assert_eq!(ch.min(), -128);
        assert_eq!(int_type("const unsigned short").unwrap().max(), 65535);
        assert_eq!(int_type("char *"), None);
        assert_eq!(int_type("my_count_t"), None);
    }

    #[test]
    fn squares_are_not_negative() {
        assert_eq!(combined(BinOp::Mul, (-5, 3), (-5, 3), true), (0, 25));
        assert_eq!(combined(BinOp::Mul, (-5, 3), (-5, 3), false), (-15, 25));
        assert_eq!(combined(BinOp::Sub, (0, 10), (1, 1), false), (-1, 9));
    }
}
