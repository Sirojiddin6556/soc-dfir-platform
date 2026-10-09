//! Memory used or freed again after `free` or `delete` released it (CWE-416
//! and CWE-415): `free(p); p->n`, `free(p); free(p)`, and a freed pointer
//! returned from a function or passed to one that reads it.
//!
//! `free(p)` leaves in `p` a [`Value::Ref`] that names the call (see
//! [`freed`]); assigning `p` replaces it, and a function that frees its
//! parameter gives it back to the caller like any change it makes there.
//! Memory freed on some paths only is not reported, as with NULL (see
//! `cnull`): such code usually frees and uses it under related
//! conditions. Nor is memory freed in code that runs on a guess: in a
//! branch taken on what a field holds, which code not followed may have
//! changed (`if (--o->refs == 0) free(o);`).
//!
//! Only pointers held in variables are followed: a field or an element
//! may be set again by code the analysis did not follow.

use crate::interp::{ArgVal, Interp};
use crate::ir::{Expr, Span};
use crate::rules::{DOUBLE_FREE, USE_AFTER_FREE};
use crate::value::*;
use std::rc::Rc;

const FREED: &str = "\u{1}freed:";
/// Freed memory already reported as used: later uses are not reported
/// again, a second `free` is.
const USED: &str = "\u{1}freed!:";

/// The call that first passed freed memory down to a function that misuses
/// it, where the misuse is reported: in the caller the mistake is.
#[derive(Debug)]
pub struct FreedArg {
    pub module: usize,
    pub span: Span,
    /// The function called.
    pub callee: Rc<str>,
    /// The caller's variable holding the memory.
    pub var: Rc<str>,
}

/// Where the memory was freed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Freed {
    pub module: usize,
    pub line: u32,
    /// Already reported as used.
    pub used: bool,
}

/// The memory a variable holds once freed at `line` of `module`.
fn freed_value(f: Freed, t: Taint) -> Value {
    let prefix = if f.used { USED } else { FREED };
    Value::Ref(format!("{prefix}{}:{}", f.module, f.line).into(), t)
}

fn parse(name: &str) -> Option<Freed> {
    let (rest, used) = match name.strip_prefix(FREED) {
        Some(r) => (r, false),
        None => (name.strip_prefix(USED)?, true),
    };
    let (m, l) = rest.split_once(':')?;
    Some(Freed {
        module: m.parse().ok()?,
        line: l.parse().ok()?,
        used,
    })
}

/// Where `v` was freed, when it is freed memory on every path here.
pub fn freed(v: &Value) -> Option<Freed> {
    match v {
        Value::Ref(name, _) => parse(name),
        Value::OneOf(alts) => {
            let mut all = alts.iter().map(freed);
            let first = all.next()??;
            all.all(|f| f.is_some()).then_some(first)
        }
        _ => None,
    }
}

/// Whether `v` is freed memory on some path.
pub fn maybe_freed(v: &Value) -> bool {
    match v {
        Value::Ref(name, _) => parse(name).is_some(),
        Value::OneOf(alts) => alts.iter().any(maybe_freed),
        _ => false,
    }
}

/// ` в строке N` when the memory was freed in the module reported in.
fn at_line(f: Freed, module: usize) -> String {
    if f.module == module {
        format!(" в строке {}", f.line)
    } else {
        String::new()
    }
}

/// `free(p)`, `delete p`: reports memory freed before, and leaves `p`
/// freed.
pub fn release(it: &mut Interp, args: &[ArgVal], span: Span) {
    let Some(a) = args.first() else {
        return;
    };
    let Some(var) = a.pointer.clone() else {
        return;
    };
    if matches!(a.value, Value::None) {
        return;
    }
    if let Some(before) = freed(&a.value) {
        match it.freed_arg(&var) {
            Some(o) => {
                let msg = format!(
                    "Указатель {} освобождён{} и передан в {}(), которая освобождает его повторно",
                    o.var,
                    at_line(before, o.module),
                    o.callee
                );
                it.flag_at(&DOUBLE_FREE, o.module, o.span, &msg);
            }
            None => {
                let msg = format!(
                    "Память по указателю {var} освобождается повторно: она уже освобождена{}",
                    at_line(before, it.module())
                );
                it.flag(&DOUBLE_FREE, span, &msg);
            }
        }
    }
    let now = freed_value(
        Freed {
            module: it.module(),
            line: span.line,
            used: false,
        },
        a.value.taint(),
    );
    // Freed on a guess: as far as the analysis knows the memory.
    let now = if it.on_guess() {
        join(&now, &a.value)
    } else {
        now
    };
    it.assign_expr(&Expr::Name(var.to_string()), now, span);
}

/// `e`, holding `v`, read or written through by the program or by the
/// library function `by`: reports freed memory, and gives the value the
/// program goes on with when it was reported.
pub fn used(it: &mut Interp, e: Option<&Expr>, v: &Value, by: Option<&str>) -> Option<Value> {
    let f = freed(v).filter(|f| !f.used)?;
    let Some(Expr::Name(n)) = e.map(uncast) else {
        return None;
    };
    // `&x` passed to a parameter: what it points to is `x`, not memory
    // `x` points to.
    if it.addressed(n) {
        return None;
    }
    match it.freed_arg(n) {
        Some(o) => {
            let msg = format!(
                "Указатель {} освобождён{} и передан в {}(), которая его использует",
                o.var,
                at_line(f, o.module),
                o.callee
            );
            it.flag_at(&USE_AFTER_FREE, o.module, o.span, &msg);
        }
        None => {
            let line = at_line(f, it.module());
            let msg = match by {
                None => format!("Указатель {n} используется после освобождения{line}"),
                Some(func) => format!(
                    "Указатель {n} освобождён{line} и передан в {func}(), которая его читает"
                ),
            };
            let span = it.span();
            it.flag(&USE_AFTER_FREE, span, &msg);
        }
    }
    let span = it.span();
    let used = freed_value(Freed { used: true, ..f }, v.taint());
    it.assign_expr(&Expr::Name(n.clone()), used, span);
    Some(Value::Unknown(v.taint()))
}

/// Checks the pointers a library call reads or writes through: those
/// `cnull` checks for NULL, and the strings `printf` prints.
pub fn check_call(it: &mut Interp, func: &str, args: &[ArgVal], format: Option<usize>) {
    let mut read: Vec<usize> = crate::models::cnull::deref_args(func).to_vec();
    if let Some(fi) = format {
        if let Some(fmt) = args.get(fi).and_then(|a| a.value.as_str()) {
            read.extend(string_args(&fmt).into_iter().map(|i| fi + 1 + i));
        }
    }
    for i in read {
        let Some(a) = args.get(i).filter(|a| !a.addressed) else {
            continue;
        };
        if freed(&a.value).is_none() {
            continue;
        }
        let e = a.pointer.as_ref().map(|v| Expr::Name(v.to_string()));
        used(it, e.as_ref(), &a.value, Some(func));
    }
}

/// The arguments after a `printf` format that its `%s` conversions read,
/// counted from the first one.
fn string_args(fmt: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut next = 0usize;
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            continue;
        }
        for n in chars.by_ref() {
            match n {
                // `%*d` takes its width from an argument.
                '*' => next += 1,
                'h'
                | 'l'
                | 'L'
                | 'q'
                | 'j'
                | 'z'
                | 't'
                | 'I'
                | '#'
                | '-'
                | '+'
                | ' '
                | '.'
                | '\''
                | '0'..='9' => {}
                conv => {
                    if matches!(conv, 's' | 'S') {
                        out.push(next);
                    }
                    next += 1;
                    break;
                }
            }
        }
    }
    out
}

fn uncast(e: &Expr) -> &Expr {
    match e {
        Expr::Cast(_, x) => uncast(x),
        e => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_conversions_are_counted_past_widths() {
        assert_eq!(string_args("%s"), vec![0]);
        assert_eq!(string_args("%d %s %%s %*s %ls"), vec![1, 3, 4]);
        assert_eq!(string_args("%5.2f %-10s"), vec![1]);
    }

    #[test]
    fn freed_memory_on_every_path_only() {
        let a = freed_value(
            Freed {
                module: 1,
                line: 7,
                used: false,
            },
            Taint::clean(),
        );
        assert_eq!(freed(&a).map(|f| f.line), Some(7));
        let some = Value::OneOf(Rc::new(vec![a.clone(), Value::clean()]));
        assert_eq!(freed(&some), None);
        assert!(maybe_freed(&some));
        // A field read from it is not freed memory itself.
        let field = Value::Ref(format!("{FREED}1:7.next").into(), Taint::clean());
        assert_eq!(freed(&field), None);
    }
}
