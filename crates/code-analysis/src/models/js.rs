//! JavaScript / TypeScript: Node's standard library, the Express and NestJS
//! web frameworks, common database clients and the browser/React sinks.
//!
//! Request data enters through Express handler parameters (`req`), NestJS
//! parameter decorators (`@Body`, `@Query`, `@Param`, `@Headers`) and
//! `process.argv`. It is tracked to SQL queries, OS command execution, file
//! paths, `eval`-family code execution, redirects, outbound requests (SSRF)
//! and HTML responses (XSS).

use super::common::*;
use crate::interp::*;
use crate::ir::*;
use crate::rules::*;
use crate::value::*;

pub struct Js;

/// HTTP request verbs that register a handler on an Express app or router.
const HANDLER_VERBS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "options", "head", "all", "use", "param",
];

/// Fields of `req` that do not carry attacker-controlled data.
const REQ_CLEAN: &[&str] = &[
    "method",
    "protocol",
    "secure",
    "httpVersion",
    "httpVersionMajor",
    "httpVersionMinor",
    "complete",
    "aborted",
    "app",
    "route",
    "res",
    "socket",
    "connection",
];

/// `fs` functions whose first argument is a file path.
const FS_PATH: &[&str] = &[
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "createReadStream",
    "createWriteStream",
    "open",
    "openSync",
    "opendir",
    "readdir",
    "readdirSync",
    "stat",
    "statSync",
    "lstat",
    "lstatSync",
    "realpath",
    "realpathSync",
    "readlink",
    "unlink",
    "unlinkSync",
    "rm",
    "rmdir",
    "rmdirSync",
    "mkdir",
    "mkdirSync",
    "access",
    "accessSync",
    "truncate",
    "chmod",
    "chmodSync",
    "exists",
    "existsSync",
    "watch",
    "watchFile",
];

/// `fs` functions whose second argument is also a path.
const FS_PATH2: &[&str] = &[
    "copyFile",
    "copyFileSync",
    "rename",
    "renameSync",
    "link",
    "symlink",
];

/// Methods that run an outbound HTTP request; a tainted URL is an SSRF.
const SSRF_REFS: &[&str] = &[
    "axios",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.patch",
    "axios.delete",
    "axios.request",
    "axios.head",
    "fetch",
    "builtins.fetch",
    "fetch-module",
    "http.get",
    "http.request",
    "got",
    "got.get",
    "got.post",
    "superagent.get",
    "request",
];

impl Js {
    fn request(&self, it: &Interp, field: &str) -> Value {
        Value::Ref(
            format!("express.req.{field}").into(),
            it.source(&format!("request.{field}")),
        )
    }
}

impl Model for Js {
    fn ref_attr(&self, it: &mut Interp, path: &str, taint: &Taint, name: &str) -> Value {
        let full = format!("{path}.{name}");
        match path {
            "express.req" => {
                if REQ_CLEAN.contains(&name) {
                    Value::Ref(full.into(), Taint::clean())
                } else {
                    Value::Ref(full.into(), it.source(&format!("request.{name}")))
                }
            }
            "express.res" => Value::Ref(full.into(), Taint::clean()),
            "express.app" | "express.router" => {
                if HANDLER_VERBS.contains(&name) {
                    Value::Ref(format!("express.handler.{name}").into(), Taint::clean())
                } else if name == "route" {
                    Value::Ref("express.router".into(), Taint::clean())
                } else {
                    Value::Ref("express.app".into(), Taint::clean())
                }
            }
            "express" => match name {
                "Router" => Value::Ref("express.Router".into(), Taint::clean()),
                "static" | "json" | "urlencoded" | "raw" | "text" => {
                    Value::Ref("express.middleware".into(), Taint::clean())
                }
                _ => Value::Ref("express.app".into(), Taint::clean()),
            },
            "child_process" => Value::Ref(format!("child_process.{name}").into(), Taint::clean()),
            "fs" => Value::Ref(format!("fs.{name}").into(), Taint::clean()),
            "path" => Value::Ref(format!("path.{name}").into(), Taint::clean()),
            "vm" => Value::Ref(format!("vm.{name}").into(), Taint::clean()),
            "axios" => Value::Ref(format!("axios.{name}").into(), Taint::clean()),
            "http" => Value::Ref(format!("http.{name}").into(), Taint::clean()),
            "process" if name == "argv" || name == "env" => {
                Value::Ref(full.into(), it.source(&format!("process.{name}")))
            }
            _ => Value::Ref(full.into(), taint.clone()),
        }
    }

    fn call_ref(
        &self,
        it: &mut Interp,
        path: &str,
        taint: &Taint,
        args: &[ArgVal],
        span: Span,
    ) -> Value {
        if taint.is_tainted() {
            return Value::Unknown(taint.union(&args_taint(args)));
        }
        let a0 = || arg(args, 0, "").cloned().unwrap_or_else(Value::clean);
        let propagate = || Value::Unknown(args_taint(args));
        let short = path.rsplit('.').next().unwrap_or(path);

        // ---- sanitizers that convert data to a safe form ----
        if matches!(
            short,
            "Number" | "parseInt" | "parseFloat" | "BigInt" | "Boolean"
        ) && !path.contains("express.")
        {
            return Value::clean();
        }
        if matches!(short, "encodeURIComponent" | "encodeURI") {
            return Value::Unknown(a0().taint().with_safe(ctx::URL | ctx::HTML));
        }

        // ---- database queries (receiver held in a variable or unknown) ----
        if matches!(short, "query" | "execute" | "raw")
            && !path.starts_with("express.")
            && !path.starts_with("fs.")
        {
            it.sink(&SQLI, &a0(), span, short);
            return propagate();
        }

        // ---- code execution ----
        if matches!(path, "eval" | "builtins.eval" | "globalThis.eval") {
            it.sink(&CODEI, &a0(), span, "eval");
            return Value::clean();
        }
        if matches!(path, "Function" | "builtins.Function" | "GeneratorFunction") {
            for a in args {
                it.sink(&CODEI, &a.value, span, "Function");
            }
            return Value::clean();
        }
        if matches!(
            path,
            "vm.runInContext"
                | "vm.runInNewContext"
                | "vm.runInThisContext"
                | "vm.compileFunction"
                | "vm.Script"
        ) {
            it.sink(&CODEI, &a0(), span, path);
            return Value::clean();
        }
        if matches!(
            path,
            "setTimeout" | "setInterval" | "builtins.setTimeout" | "builtins.setInterval"
        ) {
            // Only the string form (`setTimeout("code", 0)`) runs code.
            if a0().as_str().is_none() && a0().taint().is_tainted() {
                it.sink(&CODEI, &a0(), span, short);
            }
            return Value::clean();
        }
        if path == "__jsx_dangerous_html" {
            it.sink(&XSS, &a0(), span, "dangerouslySetInnerHTML");
            return Value::clean();
        }

        // ---- command execution ----
        if matches!(
            path,
            "child_process.exec"
                | "child_process.execSync"
                | "child_process.execFile"
                | "child_process.execFileSync"
                | "child_process.spawn"
                | "child_process.spawnSync"
                | "child_process.fork"
        ) {
            it.sink(&CMDI, &a0(), span, short);
            return propagate();
        }

        // ---- files ----
        if path.starts_with("fs.") && FS_PATH.contains(&short) {
            it.sink(&PATH, &a0(), span, short);
            return propagate();
        }
        if path.starts_with("fs.") && FS_PATH2.contains(&short) {
            it.sink(&PATH, &a0(), span, short);
            if let Some(b) = arg(args, 1, "") {
                it.sink(&PATH, b, span, short);
            }
            return propagate();
        }

        // ---- outbound requests (SSRF) ----
        if SSRF_REFS.contains(&path) {
            it.sink(&SSRF, &a0(), span, short);
            return propagate();
        }

        // ---- module loading ----
        if matches!(path, "require" | "builtins.require" | "import") {
            if a0().taint().is_tainted() {
                it.sink(&CODEI, &a0(), span, "require");
            }
            if let Some(spec) = a0().as_str() {
                return module_ref(&spec);
            }
            return Value::Unknown(args_taint(args));
        }

        match path {
            // ---- paths ----
            "path.join" | "path.resolve" | "path.normalize" => {
                let parts: Vec<Value> = args.iter().map(|a| a.value.clone()).collect();
                concat_paths(&parts)
            }
            "path.basename" | "path.extname" => {
                // A base name cannot climb out of its directory.
                Value::Unknown(a0().taint().with_safe(ctx::PATH))
            }
            // ---- express app / router ----
            "express" => Value::Ref("express.app".into(), Taint::clean()),
            "express.Router" => Value::Ref("express.router".into(), Taint::clean()),
            "express.middleware" => Value::Ref("express.middleware".into(), Taint::clean()),
            p if p.starts_with("express.handler.") => {
                self.register_handlers(it, args, span);
                Value::Ref("express.app".into(), Taint::clean())
            }
            // ---- response sinks ----
            "express.res.send" | "express.res.write" | "express.res.end" => {
                it.sink(&XSS, &a0(), span, short);
                Value::Ref("express.res".into(), Taint::clean())
            }
            "express.res.redirect" => {
                // `redirect(status, url)` or `redirect(url)`.
                let target = if args.len() > 1 {
                    arg(args, 1, "")
                } else {
                    arg(args, 0, "")
                };
                if let Some(t) = target {
                    it.sink(&REDIRECT, t, span, "redirect");
                }
                Value::Ref("express.res".into(), Taint::clean())
            }
            "express.res.sendFile" | "express.res.download" => {
                it.sink(&PATH, &a0(), span, short);
                Value::Ref("express.res".into(), Taint::clean())
            }
            "express.res.set"
            | "express.res.setHeader"
            | "express.res.header"
            | "express.res.append" => {
                // The header value (second argument, or first for an object).
                if let Some(v) = arg(args, 1, "") {
                    it.sink(&HEADER, v, span, short);
                }
                Value::Ref("express.res".into(), Taint::clean())
            }
            p if p.starts_with("express.res.") => Value::Ref("express.res".into(), Taint::clean()),
            _ => propagate(),
        }
    }

    fn call_method(
        &self,
        it: &mut Interp,
        recv: &Value,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>) {
        let a0 = || arg(args, 0, "").cloned().unwrap_or_else(Value::clean);
        let propagate = || Value::Unknown(recv.taint().union(&args_taint(args)));
        // `app.get(path, handler)` / `router.use(mw)` where the app or router
        // is held in a variable: analyze each handler with a tainted request.
        if HANDLER_VERBS.contains(&name) && args.iter().any(|a| matches!(a.value, Value::Func(_))) {
            self.register_handlers(it, args, span);
            return (propagate(), None);
        }
        match name {
            // Database queries: the SQL text is the first argument. A
            // parameterized call keeps user data in a separate array, so only
            // a built-up query string is flagged.
            "query" | "execute" => {
                it.sink(&SQLI, &a0(), span, name);
                (propagate(), None)
            }
            "raw" => {
                it.sink(&SQLI, &a0(), span, name);
                (propagate(), None)
            }
            // `childProcess.exec(cmd)` where the module is held in a variable.
            "exec" | "execSync" => {
                it.sink(&CMDI, &a0(), span, name);
                (Value::clean(), None)
            }
            // jQuery / cheerio: `$(sel).html(userHtml)`.
            "html" => {
                it.sink(&XSS, &a0(), span, name);
                (propagate(), None)
            }
            _ => (propagate(), None),
        }
    }

    fn attr(&self, _it: &mut Interp, base: &Value, _name: &str) -> Option<Value> {
        base.taint()
            .is_tainted()
            .then(|| Value::Unknown(base.taint()))
    }

    fn index(&self, _it: &mut Interp, base: &Value, _key: &Value) -> Option<Value> {
        base.taint()
            .is_tainted()
            .then(|| Value::Unknown(base.taint()))
    }

    fn entry_param(
        &self,
        it: &mut Interp,
        _module: usize,
        _func: &Function,
        _route: Option<&Route>,
        _index: usize,
        param: &Param,
    ) -> Value {
        // NestJS parameter decorators mark exactly which request data a
        // parameter receives.
        if let Some(dec) = param.ty.as_deref().and_then(|t| t.strip_prefix('@')) {
            let d = dec.split('(').next().unwrap_or(dec).trim();
            return match d {
                "Body" => self.request(it, "body"),
                "Query" => self.request(it, "query"),
                "Param" | "Params" => self.request(it, "params"),
                "Headers" | "Header" => self.request(it, "headers"),
                "Cookies" => self.request(it, "cookies"),
                "Session" => self.request(it, "session"),
                "UploadedFile" | "UploadedFiles" => self.request(it, "file"),
                "Ip" => Value::tainted_str(it.source("request.ip")),
                "Req" | "Request" => Value::Ref("express.req".into(), it.source("request")),
                _ => Value::clean(),
            };
        }
        // An Express-style handler names its request and response parameters.
        match param.name.as_str() {
            "req" | "request" => Value::Ref("express.req".into(), it.source("request")),
            "res" | "response" => Value::Ref("express.res".into(), Taint::clean()),
            _ => Value::clean(),
        }
    }

    fn sanitizer_of(&self, qualname: &str) -> u32 {
        name_sanitizer(last_name(qualname))
    }

    fn builtin(&self, _it: &mut Interp, name: &str) -> Value {
        Value::Ref(format!("builtins.{name}").into(), Taint::clean())
    }
}

impl Js {
    /// Invokes every function argument of an Express route or middleware with
    /// a tainted request, so the handler body is analyzed as an entry point.
    fn register_handlers(&self, it: &mut Interp, args: &[ArgVal], span: Span) {
        let req = Value::Ref("express.req".into(), it.source("request"));
        let res = Value::Ref("express.res".into(), Taint::clean());
        let handler_args = [
            ArgVal::plain(req),
            ArgVal::plain(res),
            ArgVal::plain(Value::clean()),
        ];
        for a in args {
            if matches!(a.value, Value::Func(_)) {
                if let Some(f) = it.callable(&a.value) {
                    it.call_value(&f, &handler_args, span);
                }
            }
        }
    }
}

/// The last dotted segment of a qualified name.
fn last_name(s: &str) -> &str {
    s.rsplit(['.', ':']).next().unwrap_or(s)
}

/// A value for `require('spec')` / `import ... from 'spec'`.
fn module_ref(spec: &str) -> Value {
    let s = spec.trim_start_matches("node:");
    let root = match s {
        "child_process" => "child_process",
        "fs" | "fs/promises" => "fs",
        "path" => "path",
        "vm" => "vm",
        "express" => "express",
        "axios" => "axios",
        "http" | "https" => "http",
        "node-fetch" => "fetch-module",
        _ => return Value::Ref(format!("module.{s}").into(), Taint::clean()),
    };
    Value::Ref(root.into(), Taint::clean())
}

/// Joins path segments, keeping each segment's data. `path.join(dir, name)`
/// is as unsafe as `name` when `name` can climb out with `..`.
fn concat_paths(parts: &[Value]) -> Value {
    let mut segs: Vec<Value> = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            segs.push(Value::str("/"));
        }
        segs.push(p.clone());
    }
    concat(&segs)
}
