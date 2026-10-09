//! NULL pointers in C: reads through a pointer that is NULL on the path
//! taken (`p = NULL; p->n`, a read inside `if (!p)`), and through the
//! result of a function that returns NULL when it fails, before the
//! program checks it (`malloc`, `calloc`, `realloc`, `fopen`).
//!
//! An allocation of known size is a [`Buf`] whose `nullable` names its
//! allocator until a check (`if (p)`, `p != NULL`) clears it. Other such
//! results, a stream or an allocation of a size not known, are a
//! [`Value::Ref`] named for the function (see [`maybe_null`]) that a check
//! turns into what the function gives.
//!
//! A pointer is reported as NULL only when it is NULL on every path to the
//! read: one that is NULL on some paths only is usually set and used under
//! related conditions the analysis does not relate.

use crate::interp::{ArgVal, Interp};
use crate::ir::{Expr, UnOp};
use crate::rules::{NULL_DEREF, NULL_RETURN};
use crate::value::*;
use std::rc::Rc;

const MAYBE_NULL: &str = "NULL?";

/// What `func` returns before the program checks it for NULL; `t` is the
/// taint of what it gives once checked.
pub fn maybe_null(func: &str, t: Taint) -> Value {
    Value::Ref(format!("{MAYBE_NULL}{func}").into(), t)
}

/// The function an unchecked result named `name` came from.
pub fn unchecked(name: &str) -> Option<&str> {
    name.strip_prefix(MAYBE_NULL)
}

/// The name an allocator's unchecked result keeps, for allocators that
/// return NULL when they fail (not `alloca` or `new`).
pub fn allocator(name: &str) -> Option<&'static str> {
    match name {
        "malloc" | "valloc" => Some("malloc"),
        "calloc" => Some("calloc"),
        "realloc" => Some("realloc"),
        _ => None,
    }
}

/// The value once the program knows it is not NULL.
pub fn not_null(v: &Value) -> Value {
    match v {
        Value::None => Value::clean(),
        Value::Buf(b) if b.nullable.is_some() => Value::Buf(Rc::new(Buf {
            nullable: None,
            ..(**b).clone()
        })),
        Value::Ref(name, t) if unchecked(name).is_some() => Value::Unknown(t.clone()),
        Value::OneOf(alts) => join_all(
            alts.iter()
                .filter(|a| !matches!(a, Value::None))
                .map(not_null),
        )
        .unwrap_or_else(Value::clean),
        other => other.clone(),
    }
}

/// Why a pointer may be NULL where the program reads through it.
enum Null {
    /// NULL on every path here.
    Is,
    /// An unchecked result of the function, made in the module at the line
    /// when known.
    From(String, Option<(usize, u32)>),
}

fn null_of(v: &Value) -> Option<Null> {
    match v {
        Value::None => Some(Null::Is),
        Value::Buf(b) => b
            .nullable
            .map(|f| Null::From(f.to_string(), Some((b.module, b.at.line)))),
        Value::Ref(name, _) => unchecked(name).map(|f| Null::From(f.to_string(), None)),
        // A result one of the paths here did not check.
        Value::OneOf(alts) => alts.iter().find_map(|a| match null_of(a) {
            Some(Null::Is) | None => None,
            from => from,
        }),
        _ => None,
    }
}

/// `e` (when it names the pointer) with the value `v`, read or written
/// through by the program, or by the library function `by`: reports it
/// when it is NULL or a result not checked for NULL. Gives the value the
/// program goes on with, which is no longer NULL, and keeps it in `e`.
pub fn deref(it: &mut Interp, e: Option<&Expr>, v: Value, by: Option<&str>) -> Value {
    let Some(null) = null_of(&v) else {
        return v;
    };
    // `&x` passed to a parameter points to `x`, whatever `x` holds.
    if matches!(e, Some(Expr::Name(n)) if it.addressed(n)) {
        return v;
    }
    // NULL is reported in a local variable the code set to NULL, or found
    // NULL, on every path here: a field or a global may have been set
    // since by code the analysis did not follow.
    if matches!(null, Null::Is) && !matches!(e, Some(Expr::Name(n)) if it.null_here(n)) {
        return v;
    }
    let span = it.span();
    let name = match e.and_then(describe) {
        Some(n) => format!("Указатель {n}"),
        None => "Указатель".to_string(),
    };
    let (rule, msg) = match null {
        Null::Is => (
            &NULL_DEREF,
            match by {
                None => format!("{name} равен NULL и разыменовывается"),
                Some(f) => format!("{name} равен NULL, а {f}() его разыменовывает"),
            },
        ),
        Null::From(f, at) => {
            let line = match at {
                Some((m, line)) if m == it.module() => format!(" в строке {line}"),
                _ => String::new(),
            };
            (
                &NULL_RETURN,
                match by {
                    None => format!("{name} получен от {f}(){line} и разыменовывается"),
                    Some(u) => format!(
                        "{name} получен от {f}(){line} и передан в {u}(), которая его \
                         разыменовывает"
                    ),
                },
            )
        }
    };
    it.flag(rule, span, &msg);
    let checked = not_null(&v);
    if let Some(e) = e.filter(|e| is_place(e)) {
        it.assign_expr(e, checked.clone(), span);
    }
    checked
}

/// Checks the pointers a library call reads or writes through, and gives
/// the arguments the call goes on with when one was reported.
pub fn check_call(it: &mut Interp, func: &str, args: &[ArgVal]) -> Option<Vec<ArgVal>> {
    // `memcpy(d, NULL, 0)` reads nothing.
    if let Some(n) = count_arg(func) {
        if args
            .get(n)
            .is_some_and(|a| matches!(a.value, Value::Int(0)))
        {
            return None;
        }
    }
    let mut out: Option<Vec<ArgVal>> = None;
    for &i in deref_args(func) {
        // `memset(&p, 0, sizeof(p))` writes the pointer, not through it.
        let Some(a) = args.get(i).filter(|a| !a.addressed) else {
            continue;
        };
        if null_of(&a.value).is_none() {
            continue;
        }
        let e = a.var.as_ref().map(|v| Expr::Name(v.to_string()));
        let checked = deref(it, e.as_ref(), a.value.clone(), Some(func));
        out.get_or_insert_with(|| args.to_vec())[i].value = checked;
    }
    out
}

/// Pointer arguments a library function reads or writes through, which
/// must not be NULL.
fn deref_args(func: &str) -> &'static [usize] {
    match func {
        "strcpy" | "wcscpy" | "strncpy" | "wcsncpy" | "strcat" | "wcscat" | "strncat"
        | "wcsncat" | "stpcpy" | "stpncpy" | "lstrcpyA" | "lstrcpyW" | "lstrcatA" | "lstrcatW"
        | "memcpy" | "memmove" | "wmemcpy" | "wmemmove" | "memcmp" | "wmemcmp" | "strcmp"
        | "wcscmp" | "strncmp" | "wcsncmp" | "strcasecmp" | "strncasecmp" | "strstr" | "wcsstr"
        | "strspn" | "wcsspn" | "strcspn" | "wcscspn" | "strpbrk" | "wcspbrk" | "strcoll" => {
            &[0, 1]
        }
        "memset" | "wmemset" | "bzero" | "explicit_bzero" | "strlen" | "wcslen" | "strdup"
        | "_strdup" | "wcsdup" | "_wcsdup" | "strchr" | "wcschr" | "strrchr" | "wcsrchr"
        | "atoi" | "atol" | "atoll" | "atof" | "strtol" | "strtoul" | "strtoll" | "strtoull"
        | "strtod" | "strtof" | "wcstol" | "wcstoul" | "_wtoi" | "_wtol" | "sprintf"
        | "vsprintf" | "sscanf" | "swscanf" | "vsscanf" | "fclose" | "fprintf" | "fwprintf"
        | "vfprintf" | "vfwprintf" | "fscanf" | "fwscanf" | "vfscanf" | "fgetc" | "getc"
        | "fgetwc" | "getwc" | "feof" | "ferror" | "clearerr" | "fseek" | "fseeko" | "ftell"
        | "ftello" | "rewind" | "fileno" | "setbuf" | "setvbuf" | "fgetpos" | "fsetpos" => &[0],
        "fgets" | "fgetws" => &[0, 2],
        "fputs" | "fputws" => &[0, 1],
        "fputc" | "putc" | "fputwc" | "putwc" | "ungetc" | "ungetwc" => &[1],
        "fread" | "fwrite" => &[0, 3],
        _ => &[],
    }
}

/// The argument that says how many bytes or characters a library function
/// reads or writes through its pointers.
fn count_arg(func: &str) -> Option<usize> {
    match func {
        "memcpy" | "memmove" | "wmemcpy" | "wmemmove" | "memcmp" | "wmemcmp" | "memset"
        | "wmemset" | "strncpy" | "wcsncpy" | "strncat" | "wcsncat" | "strncmp" | "wcsncmp"
        | "strncasecmp" | "stpncpy" => Some(2),
        "bzero" | "explicit_bzero" => Some(1),
        _ => None,
    }
}

/// A variable or a field of one, which a check or a read can narrow.
fn is_place(e: &Expr) -> bool {
    match e {
        Expr::Name(_) => true,
        Expr::Attr(b, _) => is_place(b),
        _ => false,
    }
}

/// `p`, `req->path`, `*pp`, `argv[…]` for a message.
fn describe(e: &Expr) -> Option<String> {
    match e {
        Expr::Name(n) => Some(n.clone()),
        Expr::Attr(b, f) => Some(format!("{}->{f}", describe(b)?)),
        Expr::Index(b, _) => Some(format!("{}[…]", describe(b)?)),
        Expr::Un(UnOp::Deref, x) => Some(format!("*{}", describe(x)?)),
        Expr::Cast(_, x) => describe(x),
        _ => None,
    }
}
