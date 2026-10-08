//! C and C++: input from sockets, standard input, the command line and the
//! environment; the C library's string functions; and the calls that run
//! commands, take a format string, open files or query a database.
//!
//! Functions that fill a buffer (`recv(s, buf, ...)`, `strcpy(dst, src)`)
//! assign to the variable the pointer argument is rooted at, as the front
//! end does not model addresses.
//!
//! Data from the network and CGI request variables are always untrusted.
//! The command line, the environment, standard input and files are
//! untrusted only with `external_sources`: a command-line tool doing what
//! its user typed (`ssh` running `$SSH_ASKPASS`, `curl -o FILE`) is not a
//! flaw unless the program runs with rights its user lacks or is fed
//! another party's data.

use crate::interp::{args_taint, ArgVal, Fact, FactOn, Interp, Model};
use crate::ir::{BinOp, Function, Param, Span};
use crate::models::cmem;
use crate::rules::*;
use crate::value::*;

pub struct C;

/// A number: safe in every context.
const NUMERIC: u32 = ctx::ALL & !ctx::SESSION;

fn a(args: &[ArgVal], i: usize) -> Value {
    args.get(i).map(|a| a.value.clone()).unwrap_or(Value::None)
}

/// Writes `value` where pointer argument `i` points.
fn store(it: &mut Interp, args: &[ArgVal], i: usize, value: Value, span: Span) {
    let len = cmem::str_len(&value);
    store_len(it, args, i, value, len, span);
}

/// Writes `value`, a string of `len` elements, where pointer argument `i`
/// points: into the array it points into when its size is known.
fn store_len(
    it: &mut Interp,
    args: &[ArgVal],
    i: usize,
    value: Value,
    len: (i64, i64),
    span: Span,
) {
    if cmem::put(it, args, i, &value, len, span) {
        return;
    }
    if let Some(place) = args.get(i).and_then(|a| a.place.clone()) {
        it.assign_expr(&place, value, span);
    }
}

/// What `recv(s, buf, n)` and `read(fd, buf, n)` return: -1 to n.
fn received(n: &Value) -> Value {
    match n.as_int() {
        Some(n) if n >= 0 => Value::range(-1, n, Taint::clean()),
        _ => number(Taint::clean()),
    }
}

fn number(t: Taint) -> Value {
    Value::Unknown(t.with_safe(NUMERIC | ctx::NUMBER))
}

/// Whether a stream argument is the process's standard input.
fn is_stdin(v: &Value) -> bool {
    matches!(v, Value::Ref(p, _) if matches!(&**p, "stdin" | "cin" | "wcin" | "std::cin"))
}

/// A descriptor or stream from `socket()` or `accept()`.
fn is_socket(v: &Value) -> bool {
    matches!(v, Value::Ref(p, _) if &**p == "socket")
}

/// Input read from `stream`: the network's from a socket, the local
/// user's from standard input, a file's otherwise.
fn read_from(it: &Interp, stream: &Value, what: &str) -> Value {
    if is_socket(stream) || stream.taint().is_tainted() {
        // A socket, or a file or pipe the remote user named.
        return Value::Unknown(it.source(what));
    }
    if is_stdin(stream) {
        return external(it, "stdin");
    }
    external(it, what)
}

/// CGI request data a web server passes in the environment.
fn cgi_variable(name: &str) -> bool {
    name.starts_with("HTTP_")
        || matches!(
            name,
            "QUERY_STRING"
                | "REQUEST_URI"
                | "PATH_INFO"
                | "PATH_TRANSLATED"
                | "CONTENT_TYPE"
                | "REMOTE_USER"
                | "REMOTE_IDENT"
                | "AUTH_TYPE"
                | "SCRIPT_URL"
                | "REDIRECT_URL"
                | "REDIRECT_QUERY_STRING"
        )
}

fn external(it: &Interp, what: &str) -> Value {
    if it.external_sources {
        Value::Unknown(it.source(what))
    } else {
        Value::clean()
    }
}

/// The text a value holds, as a string value.
fn text(v: &Value) -> Value {
    match v {
        Value::Buf(b) => text(&b.content),
        Value::Str(_) => v.clone(),
        Value::None => Value::str(""),
        Value::Int(_) | Value::Float(_) | Value::Bool(_) => v.clone(),
        other => Value::tainted_str(other.taint()),
    }
}

/// `"sh" -c CMD`: whether an `exec*` call runs a shell on its arguments.
fn runs_shell(path: &Value) -> bool {
    path.as_str()
        .map(|p| {
            let base = p
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&p)
                .to_ascii_lowercase();
            matches!(
                base.as_str(),
                "sh" | "bash"
                    | "dash"
                    | "zsh"
                    | "ksh"
                    | "csh"
                    | "tcsh"
                    | "cmd"
                    | "cmd.exe"
                    | "powershell"
                    | "powershell.exe"
                    | "pwsh"
            )
        })
        .unwrap_or(false)
}

/// Arguments of `execl(path, arg0, arg1, ...)` or the array of
/// `execv(path, argv)`.
fn exec_args(name: &str, args: &[ArgVal]) -> Vec<Value> {
    if name.contains('v') {
        let argv = match a(args, 1) {
            Value::Buf(b) => b.content.clone(),
            other => other,
        };
        match argv {
            Value::List(items) => items.to_vec(),
            other => vec![other],
        }
    } else {
        args.iter().skip(1).map(|x| x.value.clone()).collect()
    }
}

fn exec_sink(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) {
    let path = a(args, 0);
    // The program to run chosen by the user.
    if it.sink(&CMDI, &path, span, name) {
        return;
    }
    let argv = exec_args(name, args);
    if runs_shell(&path) || argv.first().is_some_and(runs_shell) {
        // `sh -c CMD`: the command string is code for the shell.
        let mut after_c = false;
        for v in argv.iter().skip(1) {
            let flag = v.as_str().unwrap_or_default();
            if after_c && it.sink(&CMDI, v, span, name) {
                return;
            }
            if matches!(flag.as_str(), "-c" | "/c" | "/C" | "-Command") {
                after_c = true;
            }
        }
    }
}

/// The format argument of printf-like functions, by name, and whether
/// they print into their first argument.
fn format_index(name: &str) -> Option<(usize, bool)> {
    Some(match name {
        "printf" | "vprintf" | "wprintf" | "vwprintf" | "printf_s" | "wprintf_s" | "vprintf_s"
        | "vwprintf_s" | "warn" | "warnx" | "vwarn" | "vwarnx" => (0, false),
        "fprintf" | "vfprintf" | "fwprintf" | "vfwprintf" | "fprintf_s" | "fwprintf_s"
        | "vfprintf_s" | "vfwprintf_s" | "dprintf" | "vdprintf" | "syslog" | "vsyslog" | "err"
        | "errx" | "verr" | "verrx" => (1, false),
        "sprintf" | "vsprintf" | "_swprintf" | "_vswprintf" | "asprintf" | "vasprintf" => (1, true),
        "snprintf" | "vsnprintf" | "swprintf" | "vswprintf" | "_snprintf" | "_vsnprintf"
        | "_snwprintf" | "_vsnwprintf" | "sprintf_s" | "vsprintf_s" | "swprintf_s"
        | "vswprintf_s" => (2, true),
        "_snprintf_s" | "_vsnprintf_s" | "_snwprintf_s" | "_vsnwprintf_s" => (3, true),
        _ => return None,
    })
}

/// The text `sprintf(fmt, args...)` produces: the format with each
/// conversion replaced by its argument.
fn format_result(fmt: &Value, args: &[ArgVal]) -> Value {
    let Some(f) = fmt.as_str() else {
        return Value::Unknown(fmt.taint().union(&args_taint(args)));
    };
    let mut out: Vec<Value> = Vec::new();
    let mut lit = String::new();
    let mut next = 0;
    let mut chars = f.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            lit.push(c);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            lit.push('%');
            continue;
        }
        // Flags, width, precision and length, then the conversion.
        let mut conv = ' ';
        for n in chars.by_ref() {
            if n.is_ascii_alphabetic() && !matches!(n, 'h' | 'l' | 'L' | 'q' | 'j' | 'z' | 't') {
                conv = n;
                break;
            }
        }
        out.push(Value::str(std::mem::take(&mut lit)));
        let v = args
            .get(next)
            .map(|x| x.value.clone())
            .unwrap_or(Value::None);
        next += 1;
        out.push(match conv {
            's' | 'S' => text(&v),
            'c' | 'C' => Value::tainted_str(v.taint()),
            _ => match v {
                Value::Int(_) | Value::Float(_) => v,
                other => number(other.taint()),
            },
        });
    }
    out.push(Value::str(lit));
    concat(&out)
}

/// Opening, reading or changing a file by name: arguments that are paths.
fn path_args(name: &str) -> &'static [usize] {
    match name {
        "fopen" | "_wfopen" | "fopen_s" | "freopen" | "open" | "open64" | "_open" | "_wopen"
        | "creat" | "unlink" | "_unlink" | "remove" | "_wremove" | "rmdir" | "mkdir" | "_mkdir"
        | "opendir" | "chdir" | "chmod" | "chown" | "access" | "_access" | "stat" | "lstat"
        | "truncate" | "realpath_unchecked" | "readlink" | "ifstream" | "ofstream" | "fstream"
        | "basic_ifstream" | "basic_ofstream" | "CreateFileA" | "CreateFileW" | "CreateFile"
        | "DeleteFileA" | "DeleteFileW" => &[0],
        "rename" | "link" | "symlink" | "copy_file" => &[0, 1],
        "openat" => &[1],
        _ => &[],
    }
}

impl Model for C {
    fn ref_attr(&self, _it: &mut Interp, path: &str, taint: &Taint, name: &str) -> Value {
        Value::Ref(format!("{path}.{name}").into(), taint.clone())
    }

    fn builtin(&self, _it: &mut Interp, name: &str) -> Value {
        Value::Ref(name.into(), Taint::clean())
    }

    fn entry_param(
        &self,
        it: &mut Interp,
        _module: usize,
        func: &Function,
        _route: Option<&crate::interp::Route>,
        index: usize,
        _param: &Param,
    ) -> Value {
        // `int main(int argc, char *argv[])`
        if (func.name == "main" || func.name == "wmain") && index == 1 {
            return external(it, "argv");
        }
        Value::clean()
    }

    fn coerce(&self, it: &mut Interp, ty: &str, value: Value) -> Value {
        // `(u_char) c`, `u_char ch = *p;`: an integer of that type.
        if !ty.contains(['*', '[', '&', '(']) {
            if let Some((lo, hi)) = crate::lower::c::small_int_range(ty) {
                return cmem::as_small_int(it, &value, lo, hi);
            }
            if let Value::Buf(b) = &value {
                if crate::lower::c::is_int_type(ty) {
                    return cmem::element(it, b);
                }
            }
            if let Value::Int(k) = value {
                if (-(1 << 32)..0).contains(&k) && crate::lower::c::is_unsigned32(ty) {
                    return Value::Int(k + (1 << 32));
                }
            }
        }
        if let Value::Buf(b) = &value {
            return cmem::retyped(it, ty, b);
        }
        if matches!(value, Value::List(_) | Value::Dict(_)) {
            return initialized(it, ty, value);
        }
        let t = ty.trim();
        let t = t.strip_prefix("const ").unwrap_or(t).trim();
        let base = t.split('<').next().unwrap_or(t);
        let base = base.rsplit("::").next().unwrap_or(base);
        // File streams: their methods open and read files.
        if matches!(
            base,
            "ifstream" | "ofstream" | "fstream" | "wifstream" | "wofstream"
        ) && matches!(&value, Value::Unknown(x) if !x.is_tainted())
        {
            return Value::Ref(base.into(), Taint::clean());
        }
        // A struct variable starts as an object, so its fields can be set.
        let plain = !t.contains('*') && !t.contains('[') && !t.contains('&');
        let is_struct = t.starts_with("struct ")
            || (t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && !t.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
        if plain && is_struct && matches!(&value, Value::Unknown(x) if !x.is_tainted()) {
            let class = t.trim_start_matches("struct ").trim();
            return Value::Obj(std::rc::Rc::new(Obj {
                class: class.into(),
                def: None,
                fields: Vec::new(),
                taint: Taint::clean(),
            }));
        }
        value
    }

    fn call_ref(
        &self,
        it: &mut Interp,
        path: &str,
        _taint: &Taint,
        args: &[ArgVal],
        span: Span,
    ) -> Value {
        let name = path.rsplit("::").next().unwrap_or(path);
        let name = name.rsplit('.').next().unwrap_or(name);
        function(it, name, args, span)
    }

    fn call_method(
        &self,
        it: &mut Interp,
        recv: &Value,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>) {
        // `std::cin.getline(buf, n)`, `in.read(buf, n)`
        if matches!(name, "getline" | "get" | "read" | "readsome") && !args.is_empty() {
            let v = read_from(it, recv, "istream");
            store(it, args, 0, v.clone(), span);
            return (Value::clean(), None);
        }
        let all = recv.taint().union(&args_taint(args));
        match name {
            // Containers and strings that take data in.
            "push_back" | "push_front" | "emplace_back" | "emplace_front" | "insert"
            | "emplace" | "append" | "assign" | "push" | "add" | "set" | "operator+=" => {
                let joined = Value::Unknown(all);
                (Value::clean(), Some(joined))
            }
            "c_str" | "data" | "str" | "front" | "back" | "at" | "top" | "substr" | "get"
            | "value" | "first" | "second" | "begin" | "end" | "find" | "operator[]" => {
                (Value::Unknown(recv.taint()), None)
            }
            "size" | "length" | "count" | "empty" | "capacity" | "compare" => {
                (Value::clean(), None)
            }
            "clear" => (Value::clean(), Some(Value::clean())),
            _ => (Value::Unknown(all), None),
        }
    }

    fn index(&self, it: &mut Interp, base: &Value, key: &Value) -> Option<Value> {
        match base {
            Value::Buf(b) => Some(cmem::read_at(it, b, key)),
            Value::Ref(..) | Value::Unknown(_) => Some(Value::Unknown(base.taint())),
            _ => None,
        }
    }

    fn store_index(
        &self,
        it: &mut Interp,
        base: &Value,
        key: &Value,
        value: &Value,
        span: Span,
    ) -> Option<Value> {
        match base {
            Value::Buf(b) => Some(cmem::write_at(it, b, key, value, span)),
            Value::OneOf(alts) if alts.iter().any(|a| matches!(a, Value::Buf(_))) => {
                let vals: Vec<Value> = alts
                    .iter()
                    .map(|a| {
                        self.store_index(it, a, key, value, span)
                            .or_else(|| crate::interp::store_index(a, key, value.clone()))
                            .unwrap_or_else(|| a.clone())
                    })
                    .collect();
                Some(join_all(vals.into_iter()).unwrap_or_else(Value::clean))
            }
            Value::List(_) | Value::Dict(_) => None,
            // A character written into a string, or an element into an
            // array or container the analysis does not track by element.
            Value::Str(_) if !value.taint().is_tainted() => Some(base.clone()),
            _ => Some(Value::Unknown(base.taint().union(&value.taint()))),
        }
    }

    fn binop(&self, _it: &mut Interp, op: BinOp, l: &Value, r: &Value) -> Option<Value> {
        cmem::binop(op, l, r)
    }

    fn quiet_entries(&self) -> bool {
        true
    }

    /// Projects that bring their own copy of a C library function
    /// (OpenSSH's `openbsd-compat/strlcat.c`) get the library's
    /// behaviour: the copy's pointer loops are beyond the analysis.
    fn library_over_project(&self, name: &str) -> bool {
        LIBC_OVER_PROJECT.contains(&name)
    }

    fn facts_safety(&self, facts: &[Fact], _value: &Value) -> u32 {
        crate::models::common::literal_check_safety(facts)
    }

    /// A prefix check of a canonical path (`strncmp(real, base, n) == 0`,
    /// `starts_with(real, base)`): the path it was made from, and the data
    /// it was built from, stay inside the directory.
    fn refine_call(&self, name: &str, args: &[Value], truth: bool) -> Vec<(FactOn, Fact)> {
        // `strstr(p, "..") == NULL`, `!strchr(p, '/')`
        if matches!(name, "strstr" | "wcsstr" | "strchr" | "wcschr" | "strpbrk") && !truth {
            let needle = match args.get(1) {
                Some(Value::Int(c)) => u32::try_from(*c)
                    .ok()
                    .and_then(char::from_u32)
                    .map(String::from),
                Some(v) => v.as_str(),
                None => None,
            };
            return match needle {
                Some(n) if name == "strpbrk" => n
                    .chars()
                    .map(|c| (FactOn::Arg(0), Fact::NotContains(c.to_string())))
                    .collect(),
                Some(n) => vec![(FactOn::Arg(0), Fact::NotContains(n))],
                None => Vec::new(),
            };
        }
        let prefix_holds = match name {
            "strncmp" | "wcsncmp" | "memcmp" | "strncasecmp" | "_strnicmp" | "_wcsnicmp" => !truth,
            "starts_with" | "str_starts_with" | "g_str_has_prefix" | "has_prefix"
            | "startswith" | "str_has_prefix" => truth,
            _ => return Vec::new(),
        };
        if !prefix_holds {
            return Vec::new();
        }
        let canonical = |v: &Value| {
            let t = v.taint();
            t.is_tainted() && t.safe & ctx::CANONICAL != 0
        };
        match args.iter().position(canonical) {
            Some(i) => vec![(FactOn::Arg(i), Fact::SafeSources(ctx::PATH))],
            None => Vec::new(),
        }
    }
}

/// `struct S s = {a, .f = b};` and arrays of such: objects of the project
/// struct `S` with the members set, so `s.f` and `tbl[i].f()` find them.
fn initialized(it: &mut Interp, ty: &str, value: Value) -> Value {
    let array = ty.contains('[');
    let base: String = ty
        .split(['[', '*', '&'])
        .next()
        .unwrap_or("")
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "struct" | "union" | "static" | "volatile"))
        .collect::<Vec<_>>()
        .join(" ");
    let Some(Value::Class(cv)) = it.lookup_name(&base) else {
        return value;
    };
    let fields: Vec<&str> = cv
        .def
        .fields
        .iter()
        .filter_map(|f| match f {
            crate::ir::Stmt::Declare { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    if fields.is_empty() {
        return value;
    }
    let one = |v: &Value| -> Value {
        let set: Vec<(std::rc::Rc<str>, Value)> = match v {
            Value::List(items) => fields
                .iter()
                .zip(items.iter())
                .map(|(f, v)| ((*f).into(), v.clone()))
                .collect(),
            Value::Dict(pairs) => pairs
                .iter()
                .filter_map(|(k, v)| {
                    let name = match k {
                        Value::Str(_) => k.as_str()?,
                        Value::Int(i) => fields.get(usize::try_from(*i).ok()?)?.to_string(),
                        _ => return None,
                    };
                    Some((name.into(), v.clone()))
                })
                .collect(),
            other => return other.clone(),
        };
        let mut o = Obj::new(&cv.qualname);
        o.def = Some(cv.clone());
        for (f, v) in set {
            o.set_field(&f, v);
        }
        Value::Obj(std::rc::Rc::new(o))
    };
    match (&value, array) {
        (Value::List(items), true) => Value::list(items.iter().map(one).collect()),
        (_, false) => one(&value),
        _ => value,
    }
}

fn function(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Value {
    let a0 = a(args, 0);
    cmem::check_call(it, name, args, span);
    // printf family: the format must be a fixed string.
    if let Some((fi, into_buffer)) = format_index(name) {
        let fmt = a(args, fi);
        it.sink(&FORMAT_STRING, &fmt, span, name);
        if into_buffer {
            let rest = args.get(fi + 1..).unwrap_or(&[]);
            let result = format_result(&fmt, rest);
            let (lo, hi, _) = cmem::format_len(&fmt, rest);
            // `snprintf` stops one short of its size.
            let cap = match fi {
                2 => a(args, 1).as_int().map(|n| n - 1),
                _ => None,
            };
            let len = match cap {
                Some(c) if c >= 0 => (lo.min(c), hi.min(c)),
                _ => (lo, hi),
            };
            store_len(it, args, 0, result, len, span);
        }
        return Value::clean();
    }
    let paths = path_args(name);
    if !paths.is_empty() {
        for &i in paths {
            it.sink(&PATH, &a(args, i), span, name);
        }
        // A stream from a name the user chose reads what they chose.
        return Value::Unknown(a0.taint());
    }
    match name {
        // ----- input -----
        "recv" | "recvfrom" | "recvmsg" | "read" | "_read" | "pread" | "SSL_read" | "BIO_read" => {
            let v = if name == "read" || name == "_read" || name == "pread" {
                // A descriptor may be a socket, a file or standard input (0).
                match a0 {
                    Value::Int(0) => external(it, "stdin"),
                    fd => read_from(it, &fd, &format!("{name}()")),
                }
            } else {
                Value::Unknown(it.source(&format!("{name}()")))
            };
            store_len(it, args, 1, v, (0, UNBOUNDED), span);
            received(&a(args, 2))
        }
        "fgets" | "fgetws" | "gets" | "_getws" | "gets_s" => {
            let stream = if matches!(name, "gets" | "_getws" | "gets_s") {
                Value::Ref("stdin".into(), Taint::clean())
            } else {
                a(args, 2)
            };
            let v = read_from(it, &stream, name);
            let len = match a(args, 1).as_int() {
                Some(n) if n > 0 && !matches!(name, "gets" | "_getws") => (0, n - 1),
                _ => (0, UNBOUNDED),
            };
            store_len(it, args, 0, v.clone(), len, span);
            v
        }
        "fread" => {
            let v = read_from(it, &a(args, 3), name);
            store_len(it, args, 0, v, (0, UNBOUNDED), span);
            match a(args, 2).as_int() {
                Some(n) if n >= 0 => Value::range(0, n, Taint::clean()),
                _ => number(Taint::clean()),
            }
        }
        "getline" | "getdelim" | "__getline" => {
            // C `getline(&line, &n, stream)` and C++ `getline(stream, s)`.
            if args.len() >= 3 && !is_stdin(&a0) {
                let v = read_from(it, &a(args, args.len() - 1), name);
                store(it, args, 0, v, span);
            } else {
                let v = read_from(it, &a0, name);
                store(it, args, 1, v, span);
            }
            number(Taint::clean())
        }
        "scanf" | "wscanf" | "scanf_s" | "vscanf" => {
            let v = external(it, "stdin");
            for i in 1..args.len() {
                store(it, args, i, v.clone(), span);
            }
            number(Taint::clean())
        }
        "fscanf" | "fwscanf" | "fscanf_s" | "sscanf" | "swscanf" | "sscanf_s" => {
            let v = if name.starts_with('s') {
                Value::Unknown(a0.taint())
            } else {
                read_from(it, &a0, name)
            };
            for i in 2..args.len() {
                store(it, args, i, v.clone(), span);
            }
            number(Taint::clean())
        }
        "getenv" | "_wgetenv" | "secure_getenv" | "getenv_s" | "_wgetenv_s" => {
            // `getenv_s(&size, buf, n, name)` fills `buf`.
            let filled = name.ends_with("_s");
            let var = a(args, if filled { 3 } else { 0 }).as_str();
            let v = if var.as_deref().is_some_and(cgi_variable) {
                Value::Unknown(it.source(&format!("{name}()")))
            } else {
                external(it, &format!("{name}()"))
            };
            if filled {
                store(it, args, 1, v, span);
                return Value::clean();
            }
            v
        }
        "__c_stdin" => external(it, "cin"),
        "socket" | "accept" | "accept4" | "WSASocketA" | "WSASocketW" => {
            Value::Ref("socket".into(), Taint::clean())
        }
        "fdopen" | "_fdopen" if is_socket(&a0) => a0,
        "fgetc" | "getc" | "getchar" | "_getch" | "getwc" | "getwchar" => {
            let stream = if matches!(name, "getchar" | "_getch" | "getwchar") {
                Value::Ref("stdin".into(), Taint::clean())
            } else {
                a0
            };
            read_from(it, &stream, name)
        }

        // ----- strings -----
        "strcpy" | "wcscpy" | "strncpy" | "wcsncpy" | "memcpy" | "memmove" | "wmemcpy"
        | "wmemmove" | "strcpy_s" | "strncpy_s" | "wcscpy_s" | "memcpy_s" | "lstrcpyA"
        | "lstrcpyW" | "_mbscpy" | "stpcpy" | "strlcpy" => {
            let src = if name.ends_with("_s") && args.len() >= 3 {
                a(args, 2)
            } else {
                a(args, 1)
            };
            store_len(it, args, 0, text(&src), cmem::copy_len(name, args), span);
            text(&src)
        }
        "strcat" | "wcscat" | "strncat" | "wcsncat" | "strcat_s" | "strncat_s" | "wcscat_s"
        | "lstrcatA" | "lstrcatW" | "strlcat" => {
            let src = if name.ends_with("_s") && args.len() >= 3 {
                a(args, 2)
            } else {
                a(args, 1)
            };
            let joined = concat(&[text(&a0), text(&src)]);
            store_len(
                it,
                args,
                0,
                joined.clone(),
                cmem::copy_len(name, args),
                span,
            );
            joined
        }
        "strdup" | "_strdup" | "wcsdup" | "_wcsdup" | "strndup" | "strchr" | "strrchr"
        | "wcschr" | "wcsrchr" | "strstr" | "wcsstr" | "strpbrk" | "wcspbrk" | "strtok"
        | "wcstok" | "strtok_r" | "memchr" | "basename" | "dirname" => text(&a0),
        "strlen" | "wcslen" | "lstrlenA" | "lstrlenW" => cmem::strlen(&a0),
        "strnlen" | "wcsnlen" => match (cmem::strlen(&a0), a(args, 1).as_int()) {
            (len, Some(n)) => match len.bounds() {
                Some((lo, hi)) => Value::range(lo.min(n), hi.min(n), len.taint()),
                None => Value::range(0, n, len.taint()),
            },
            (len, None) => len,
        },
        "strcmp" | "strncmp" | "wcscmp" | "wcsncmp" | "strcasecmp" | "strncasecmp" | "memcmp"
        | "strspn" | "strcspn" | "wcsspn" | "wcscspn" | "isdigit" | "isalpha" | "isalnum"
        | "isspace" | "isupper" | "islower" | "iswdigit" | "toupper" | "tolower" | "towupper"
        | "towlower" => Value::clean(),
        "atoi" | "atol" | "atoll" | "atof" | "strtol" | "strtoul" | "strtoll" | "strtoull"
        | "strtod" | "strtof" | "wcstol" | "wcstoul" | "_wtoi" | "_wtol" | "abs" | "labs" => {
            number(a0.taint())
        }
        "memset" | "wmemset" | "bzero" | "explicit_bzero" | "SecureZeroMemory" => {
            if !matches!(a0, Value::Obj(_)) {
                let len = if name.ends_with("memset") {
                    cmem::memset_len(name, args)
                } else {
                    (0, 0)
                };
                store_len(it, args, 0, Value::clean(), len, span);
            }
            Value::clean()
        }
        // C++ string and stream objects built from data.
        "string" | "wstring" | "basic_string" | "string_view" | "stringstream"
        | "istringstream" | "ostringstream" => {
            if args.is_empty() {
                Value::str("")
            } else {
                text(&a0)
            }
        }
        "to_string" | "to_wstring" | "stoi" | "stol" | "stoll" | "stoul" | "stod" => {
            number(a0.taint())
        }
        "vector" | "list" | "deque" | "map" | "set" | "unordered_map" | "unordered_set"
        | "multimap" => Value::Unknown(args_taint(args)),
        "__c_array" => cmem::array(it, args, span),
        // `char *p[N];`: N pointers, so `p[2] = buf` keeps what it points to.
        "__c_slots" => {
            if let (Value::Unknown(t), Some(n)) = (&a0, a(args, 1).as_int()) {
                if !t.is_tainted() && (1..=64).contains(&n) {
                    let slots = Value::list(vec![Value::clean(); n as usize]);
                    store(it, args, 0, slots, span);
                }
            }
            Value::clean()
        }
        "__c_new_array" | "malloc" | "calloc" | "_alloca" | "alloca" | "operator new"
        | "__builtin_alloca" | "valloc" => {
            cmem::alloc(it, name, args, span).unwrap_or_else(Value::clean)
        }
        "realloc" => {
            cmem::alloc(it, name, args, span).unwrap_or_else(|| Value::Unknown(a0.taint()))
        }
        // `delete p` and the end of the block declaring an object run its
        // destructor.
        "__c_delete" | "__c_destroy" => {
            if let Value::Obj(o) = &a0 {
                if let Some(cv) = &o.def {
                    let dtor = format!("~{}", cv.def.name);
                    if cv.def.methods.iter().any(|m| m.name == dtor) {
                        it.call_method(&a0, &dtor, &[], span);
                    }
                }
            }
            Value::clean()
        }
        "free" | "close" | "fclose" | "closesocket" => Value::clean(),

        // ----- commands -----
        "system" | "_system" | "_wsystem" | "popen" | "_popen" | "_wpopen" | "wordexp" => {
            it.sink(&CMDI, &a0, span, name);
            Value::clean()
        }
        "execl" | "execlp" | "execle" | "execv" | "execvp" | "execve" | "execvpe" | "_execl"
        | "_execlp" | "_execv" | "_execvp" | "_wexecl" | "_wexeclp" | "_wexecv" | "_wexecvp"
        | "_spawnl" | "_spawnlp" | "_spawnv" | "_spawnvp" | "_spawnle" | "_spawnve"
        | "_wspawnl" | "_wspawnlp" | "_wspawnv" | "_wspawnvp" | "_wspawnle" | "_wspawnve"
        | "posix_spawn" | "posix_spawnp" => {
            let shifted: Vec<ArgVal>;
            let (args, name) = if name.starts_with("posix_spawn") {
                // `posix_spawn(&pid, path, actions, attrs, argv, envp)`
                shifted = [1, 4]
                    .iter()
                    .filter_map(|&i| args.get(i).cloned())
                    .collect();
                (&shifted[..], "execv")
            } else if name.starts_with("_spawn") || name.starts_with("_wspawn") {
                // `_spawnl(mode, path, ...)`
                shifted = args.iter().skip(1).cloned().collect();
                (&shifted[..], name)
            } else {
                (args, name)
            };
            exec_sink(it, name, args, span);
            Value::clean()
        }
        "ShellExecuteA" | "ShellExecuteW" | "WinExec" | "CreateProcessA" | "CreateProcessW" => {
            for i in 0..args.len().min(3) {
                if it.sink(&CMDI, &a(args, i), span, name) {
                    break;
                }
            }
            Value::clean()
        }
        "dlopen" | "LoadLibraryA" | "LoadLibraryW" | "LoadLibrary" | "LoadLibraryExA"
        | "LoadLibraryExW" => {
            it.sink(&CODEI, &a0, span, name);
            Value::clean()
        }

        // ----- databases and directories -----
        "mysql_query" | "mysql_real_query" | "PQexec" | "PQsendQuery" => {
            it.sink(&SQLI, &a(args, 1), span, name);
            Value::clean()
        }
        "sqlite3_exec"
        | "sqlite3_prepare"
        | "sqlite3_prepare_v2"
        | "sqlite3_prepare_v3"
        | "sqlite3_prepare16"
        | "sqlite3_prepare16_v2" => {
            it.sink(&SQLI, &a(args, 1), span, name);
            Value::clean()
        }
        "SQLExecDirect" | "SQLExecDirectA" | "SQLExecDirectW" | "SQLPrepare" | "SQLPrepareA"
        | "SQLPrepareW" => {
            it.sink(&SQLI, &a(args, 1), span, name);
            Value::clean()
        }
        "ldap_search_s" | "ldap_search_ext_s" | "ldap_search" | "ldap_search_ext"
        | "ldap_search_sA" | "ldap_search_sW" | "ldap_search_ext_sA" | "ldap_search_ext_sW" => {
            it.sink(&LDAPI, &a(args, 3), span, name);
            Value::clean()
        }

        // The canonical path: a prefix check of it confines the path.
        "realpath" | "canonicalize_file_name" | "canonical" | "weakly_canonical" => {
            let v = Value::Unknown(a0.taint().with_safe(ctx::CANONICAL));
            if name == "realpath" {
                store(it, args, 1, v.clone(), span);
            }
            v
        }
        "_fullpath" | "_wfullpath" => {
            let v = Value::Unknown(a(args, 1).taint().with_safe(ctx::CANONICAL));
            store(it, args, 0, v.clone(), span);
            v
        }
        // `sizeof(T)` of a struct or class of the project.
        "sizeof" => {
            // `sizeof(wchar_t)` and `sizeof(S)` parse as a name in parentheses.
            let ty = match &a0 {
                Value::Ref(p, _) => Some(p.to_string()),
                Value::Class(cv) => Some(cv.def.name.clone()),
                other => other.as_str(),
            };
            ty.and_then(|t| cmem::type_size(it, &t))
                .map(Value::Int)
                .unwrap_or_else(Value::clean)
        }
        "alignof" | "offsetof" | "time" | "rand" | "random" | "getpid" => Value::clean(),
        // Anything else: its result depends on its arguments.
        _ => Value::Unknown(args_taint(args)),
    }
}

/// C library functions the model knows; see `Model::library_over_project`.
const LIBC_OVER_PROJECT: &[&str] = &[
    "bzero",
    "explicit_bzero",
    "memchr",
    "memcmp",
    "memcpy",
    "memmove",
    "memset",
    "snprintf",
    "sprintf",
    "asprintf",
    "vasprintf",
    "vsnprintf",
    "strcat",
    "strchr",
    "strcpy",
    "strcspn",
    "strdup",
    "strlcat",
    "strlcpy",
    "strlen",
    "strncat",
    "strncpy",
    "strndup",
    "strnlen",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
    "strtok_r",
    "wcslen",
    "wcsnlen",
    "wcslcat",
    "wcslcpy",
];
