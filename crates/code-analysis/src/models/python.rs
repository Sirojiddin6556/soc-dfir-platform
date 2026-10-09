//! Python: the standard library, Flask, Django and FastAPI, common database,
//! XML, LDAP and crypto libraries.

use super::common::*;
use crate::interp::*;
use crate::ir::*;
use crate::rules::*;
use crate::value::*;
use std::rc::Rc;

pub struct Python;

/// Attributes of `flask.request` that carry client data.
const FLASK_REQUEST: &[&str] = &[
    "args",
    "form",
    "values",
    "cookies",
    "headers",
    "data",
    "json",
    "files",
    "query_string",
    "full_path",
    "url",
    "base_url",
    "url_root",
    "host",
    "host_url",
    "stream",
    "environ",
    "authorization",
    "user_agent",
    "referrer",
    "access_route",
    "get_json",
    "get_data",
    "view_args",
    "content_type",
    "mimetype",
    "input_stream",
    "origin",
];

const DJANGO_REQUEST: &[&str] = &[
    "GET",
    "POST",
    "COOKIES",
    "META",
    "FILES",
    "body",
    "headers",
    "data",
    "query_params",
    "path",
    "path_info",
    "get_full_path",
    "build_absolute_uri",
    "get_host",
    "content_type",
];

/// Request attributes with client data across Django, DRF, aiohttp,
/// Starlette, Pyramid, Falcon, Sanic and Tornado.
const WEB_REQUEST: &[&str] = &[
    "GET",
    "POST",
    "COOKIES",
    "META",
    "FILES",
    "body",
    "headers",
    "data",
    "query_params",
    "path_params",
    "query",
    "match_info",
    "post",
    "json",
    "text",
    "read",
    "content",
    "form",
    "args",
    "cookies",
    "params",
    "get_param",
    "get_header",
    "url",
    "rel_url",
    "stream",
    "arguments",
    "query_arguments",
    "body_arguments",
    "uri",
    "path",
    "path_info",
    "full_path",
    "query_string",
    "raw_path",
    "get_full_path",
    "build_absolute_uri",
    "get_host",
    "files",
    "values",
    "multipart",
    "media",
    "get_media",
    "matchdict",
    "json_body",
];

const WEB_FRAMEWORKS: &[&str] = &[
    "django",
    "rest_framework",
    "aiohttp",
    "starlette",
    "fastapi",
    "pyramid",
    "falcon",
    "sanic",
    "tornado",
    "quart",
    "bottle",
    "litestar",
];

/// Safety of base64/hex output: an alphabet without quotes or markup.
const ENCODED_SAFE: u32 = ctx::HTML
    | ctx::SQL
    | ctx::SHELL
    | ctx::LDAP
    | ctx::XPATH
    | ctx::CODE
    | ctx::HEADER
    | ctx::TEMPLATE
    | ctx::LOG
    | ctx::NO_SQUOTE
    | ctx::NO_DQUOTE;

/// Percent-encoding keeps `/` but escapes quotes, markup and spaces.
const QUOTED_SAFE: u32 = ENCODED_SAFE & !ctx::CODE;

const WEAK_HASHES: &[&str] = &["md5", "md4", "md2", "sha1", "sha", "ripemd160", "md5-sha1"];

const RANDOM_FUNCS: &[&str] = &[
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "getrandbits",
    "randbytes",
    "uniform",
    "normalvariate",
    "gauss",
    "sample",
    "shuffle",
    "triangular",
    "betavariate",
    "expovariate",
    "gammavariate",
    "lognormvariate",
    "vonmisesvariate",
    "paretovariate",
    "weibullvariate",
    "binomialvariate",
];

const PATH_FUNCS: &[&str] = &[
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.mkdir",
    "os.makedirs",
    "os.listdir",
    "os.scandir",
    "os.stat",
    "os.lstat",
    "os.chmod",
    "os.chown",
    "os.open",
    "os.walk",
    "os.truncate",
    "os.utime",
    "os.access",
    "os.path.exists",
    "os.path.lexists",
    "os.path.isfile",
    "os.path.isdir",
    "os.path.getsize",
    "os.path.getmtime",
    "os.path.getatime",
    "os.path.getctime",
    "io.open",
    "codecs.open",
    "glob.glob",
    "glob.iglob",
    "flask.send_file",
    "fileinput.input",
    "linecache.getlines",
    "linecache.getline",
];

const PATH_FUNCS_2: &[&str] = &[
    "os.rename",
    "os.replace",
    "os.link",
    "os.symlink",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "shutil.rmtree",
    "shutil.copymode",
    "shutil.copystat",
];

const SHELL_FUNCS: &[&str] = &[
    "os.system",
    "os.popen",
    "os.popen2",
    "os.popen3",
    "os.popen4",
    "commands.getoutput",
    "commands.getstatusoutput",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "pty.spawn",
];

const SUBPROCESS_FUNCS: &[&str] = &[
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "asyncio.create_subprocess_exec",
];

const HTML_ESCAPERS: &[&str] = &[
    "html.escape",
    "markupsafe.escape",
    "flask.escape",
    "jinja2.escape",
    "django.utils.html.escape",
    "django.utils.html.conditional_escape",
    "werkzeug.utils.escape",
];

/// Short names some code imports these under.
fn canonical(path: &str) -> String {
    let p = path
        .strip_prefix("builtins.")
        .map(|b| format!("builtins.{b}"))
        .unwrap_or_else(|| path.to_string());
    let aliases: &[(&str, &str)] = &[
        ("flask.globals.request", "flask.request"),
        ("flask.helpers.", "flask."),
        ("flask.wrappers.Response", "flask.Response"),
        ("werkzeug.wrappers.Response", "flask.Response"),
        ("werkzeug.utils.redirect", "flask.redirect"),
        ("werkzeug.utils.send_file", "flask.send_file"),
        ("cPickle.", "pickle."),
        ("_pickle.", "pickle."),
        ("Cryptodome.", "Crypto."),
        ("defusedxml.", "defusedxml."),
        ("xml.etree.cElementTree.", "xml.etree.ElementTree."),
        ("pathlib.PosixPath", "pathlib.Path"),
        ("pathlib.WindowsPath", "pathlib.Path"),
        ("pathlib.PurePath", "pathlib.Path"),
        ("pathlib.PurePosixPath", "pathlib.Path"),
        ("pathlib.PureWindowsPath", "pathlib.Path"),
        ("django.http.response.", "django.http."),
    ];
    for (from, to) in aliases {
        if let Some(rest) = p.strip_prefix(from) {
            return format!("{to}{rest}");
        }
    }
    p
}

impl Model for Python {
    fn ref_attr(&self, it: &mut Interp, path: &str, taint: &Taint, name: &str) -> Value {
        let path = canonical(path);
        let full = format!("{path}.{name}");
        match path.as_str() {
            "flask.request" => {
                if name == "path" || name == "script_root" {
                    if let Some(r) = it.current_route() {
                        if r.fixed_path && name == "path" {
                            return Value::str(r.path.clone());
                        }
                    }
                    return Value::tainted_str(it.source("request.path"));
                }
                if FLASK_REQUEST.contains(&name) {
                    return Value::Ref(full.into(), it.source(&format!("request.{name}")));
                }
                Value::Ref(full.into(), Taint::clean())
            }
            "web.request" => {
                if WEB_REQUEST.contains(&name) || DJANGO_REQUEST.contains(&name) {
                    return Value::Ref(full.into(), it.source(&format!("request.{name}")));
                }
                Value::Ref(full.into(), Taint::clean())
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
            return source_accessor(path, taint, args);
        }
        let path = canonical(path);
        let p = path.as_str();
        let a0 = || arg(args, 0, "").cloned().unwrap_or_else(Value::clean);
        let propagate = || Value::Unknown(args_taint(args));
        let short = p.rsplit('.').next().unwrap_or(p);

        // ---- builtins ----
        if let Some(b) = p.strip_prefix("builtins.") {
            return builtin(it, b, args, span);
        }

        // ---- command execution ----
        if SHELL_FUNCS.contains(&p) {
            it.sink(&CMDI, &a0(), span, p);
            return Value::clean();
        }
        if SUBPROCESS_FUNCS.contains(&p) {
            check_subprocess(it, args, span, p);
            return Value::Obj(Rc::new(Obj::new("subprocess.CompletedProcess")));
        }
        if p.starts_with("os.exec") || p.starts_with("os.spawn") || p.starts_with("os.posix_spawn")
        {
            check_exec_args(it, args, span, p);
            return Value::clean();
        }

        // ---- files ----
        if PATH_FUNCS.contains(&p) {
            it.sink(&PATH, &a0(), span, p);
            return if p.starts_with("os.path.") {
                Value::clean()
            } else {
                file_of(&a0())
            };
        }
        if PATH_FUNCS_2.contains(&p) {
            it.sink(&PATH, &a0(), span, p);
            if let Some(b) = arg(args, 1, "dst") {
                it.sink(&PATH, b, span, p);
            }
            return Value::clean();
        }

        match p {
            // ---- paths ----
            "os.path.join" | "posixpath.join" | "ntpath.join" => {
                let mut parts = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        parts.push(Value::str("/"));
                    }
                    parts.push(a.value.clone());
                }
                concat(&parts)
            }
            "os.path.basename"
            | "werkzeug.utils.secure_filename"
            | "ntpath.basename"
            | "posixpath.basename" => a0().sanitized(ctx::PATH),
            // Join that refuses results outside the base directory.
            "werkzeug.security.safe_join"
            | "werkzeug.utils.safe_join"
            | "flask.safe_join"
            | "django.utils._os.safe_join" => {
                concat(&args.iter().map(|a| a.value.clone()).collect::<Vec<_>>())
                    .sanitized(ctx::PATH)
            }
            "os.path.realpath" | "os.path.abspath" | "os.path.normpath" | "os.path.expanduser"
            | "os.path.dirname" => a0(),
            "os.getenv" | "os.environ.get" => Value::clean(),
            "pathlib.Path" => {
                let mut parts = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        parts.push(Value::str("/"));
                    }
                    parts.push(path_string(&a.value));
                }
                make_path(concat(&parts), false)
            }
            "flask.send_from_directory" => {
                it.sink(&PATH, &a0(), span, p);
                Value::Obj(Rc::new(Obj::new("flask.Response")))
            }
            "io.StringIO" | "io.BytesIO" => {
                let init = arg(args, 0, "initial_value")
                    .cloned()
                    .unwrap_or_else(|| Value::str(""));
                Value::Obj(Rc::new(Obj::new("io.StringIO").with_field("buf", init)))
            }

            // ---- encodings ----
            "base64.b64encode"
            | "base64.urlsafe_b64encode"
            | "base64.b32encode"
            | "base64.b16encode"
            | "base64.encodebytes"
            | "base64.standard_b64encode"
            | "binascii.hexlify"
            | "binascii.b2a_hex"
            | "binascii.b2a_base64" => encoded(&a0()),
            "base64.b64decode"
            | "base64.urlsafe_b64decode"
            | "base64.b32decode"
            | "base64.b16decode"
            | "base64.decodebytes"
            | "base64.standard_b64decode"
            | "binascii.unhexlify"
            | "binascii.a2b_hex"
            | "binascii.a2b_base64" => Value::tainted_str(a0().taint().without_safe(ctx::ALL)),
            "urllib.parse.unquote"
            | "urllib.parse.unquote_plus"
            | "urllib.parse.unquote_to_bytes"
            | "urllib.unquote"
            | "html.unescape" => {
                let v = a0();
                match v.as_str() {
                    Some(_) => v,
                    None => v.unsanitized(ctx::ALL),
                }
            }
            "urllib.parse.quote"
            | "urllib.parse.quote_plus"
            | "urllib.quote"
            | "urllib.parse.urlencode" => a0().sanitized(QUOTED_SAFE),
            "shlex.quote" | "pipes.quote" => a0().sanitized(ctx::SHELL),
            "shlex.split" => Value::Unknown(a0().taint()),
            "json.dumps" | "json.dump" => Value::tainted_str(a0().taint()),
            "json.loads" | "json.load" | "ujson.loads" | "orjson.loads" => {
                Value::Unknown(a0().taint())
            }
            "ast.literal_eval" => Value::Unknown(a0().taint()),
            "re.escape" => a0().sanitized(ctx::XPATH),
            "re.compile" => Value::Obj(Rc::new(Obj::new("re.Pattern").with_field("pattern", a0()))),
            "re.sub" | "re.subn" => {
                let pattern = a0().as_str().unwrap_or_default();
                regex_sub(
                    &pattern,
                    arg(args, 1, "repl"),
                    &arg(args, 2, "string").cloned().unwrap_or_else(Value::clean),
                )
            }
            "ldap3.utils.conv.escape_filter_chars"
            | "ldap.filter.escape_filter_chars"
            | "ldap.dn.escape_dn_chars" => a0().sanitized(ctx::LDAP),
            "bleach.clean" | "xml.sax.saxutils.escape" => a0().sanitized(ctx::HTML),
            "cgi.escape" => {
                let quote = kwarg(args, "quote")
                    .and_then(|q| q.truthy())
                    .unwrap_or(false);
                a0().sanitized(ctx::HTML | if quote { ctx::NO_DQUOTE } else { 0 })
            }
            _ if HTML_ESCAPERS.contains(&p) => {
                a0().sanitized(ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE)
            }

            // ---- URL parsing ----
            "urllib.parse.urlparse" | "urllib.parse.urlsplit" | "urlparse.urlparse" => {
                let v = a0();
                let mut o = Obj::new("urllib.parse.ParseResult");
                o.taint = v.taint();
                if let Some(var) = args.first().and_then(|a| a.var.clone()) {
                    o.set_field("__of", Value::str(var.to_string()));
                }
                if let Some(s) = v.as_str() {
                    let (scheme, netloc, rest) = split_url(&s);
                    o.set_field("scheme", Value::str(scheme));
                    o.set_field("netloc", Value::str(netloc.clone()));
                    o.set_field("hostname", Value::str(netloc));
                    o.set_field("path", Value::str(rest));
                }
                Value::Obj(Rc::new(o))
            }
            "urllib.parse.urljoin" => propagate(),

            // ---- deserialization ----
            "pickle.loads"
            | "pickle.load"
            | "pickle.Unpickler"
            | "dill.loads"
            | "dill.load"
            | "marshal.loads"
            | "marshal.load"
            | "jsonpickle.decode"
            | "jsonpickle.loads"
            | "shelve.open"
            | "yaml.unsafe_load"
            | "yaml.unsafe_load_all"
            | "yaml.full_load"
            | "yaml.full_load_all"
            | "joblib.load"
            | "torch.load"
            | "numpy.load"
            | "pandas.read_pickle" => {
                let unsafe_numpy = p != "numpy.load"
                    || kwarg(args, "allow_pickle").and_then(|v| v.truthy()) == Some(true);
                if unsafe_numpy {
                    it.sink(&DESER, &a0(), span, p);
                }
                Value::Unknown(a0().taint())
            }
            "yaml.load" | "yaml.load_all" => {
                let loader = arg(args, 1, "Loader");
                let safe = matches!(loader, Some(Value::Ref(l, _)) if l.ends_with("SafeLoader") || l.ends_with("BaseLoader"));
                if !safe {
                    it.sink(&DESER, &a0(), span, p);
                }
                Value::Unknown(a0().taint())
            }
            "yaml.safe_load" | "yaml.safe_load_all" => Value::Unknown(a0().taint()),

            // ---- code execution ----
            "code.InteractiveInterpreter" | "importlib.import_module" | "__import__" => {
                it.sink(&CODEI, &a0(), span, p);
                Value::clean()
            }

            // ---- templates ----
            "flask.render_template_string"
            | "jinja2.Template"
            | "mako.template.Template"
            | "jinja2.Environment.from_string" => {
                it.sink(&SSTI, &a0(), span, p);
                Value::Obj(Rc::new(Obj::new("template")))
            }
            "flask.render_template" => {
                it.sink(&PATH, &a0(), span, p);
                Value::clean()
            }

            // ---- HTTP responses ----
            "flask.make_response" => {
                let body = match a0() {
                    Value::List(items) => items.first().cloned().unwrap_or_else(Value::clean),
                    other => other,
                };
                check_body(it, &body, span, "make_response");
                Value::Obj(Rc::new(Obj::new("flask.Response")))
            }
            "flask.Response"
            | "django.http.HttpResponse"
            | "django.http.HttpResponseBadRequest"
            | "django.http.HttpResponseNotFound"
            | "starlette.responses.HTMLResponse"
            | "fastapi.responses.HTMLResponse" => {
                let ty = arg(args, 2, "mimetype")
                    .or_else(|| kwarg(args, "content_type"))
                    .and_then(|v| v.as_str());
                let html = ty.map(|t| t.contains("html")).unwrap_or(true);
                if html {
                    let body = arg(args, 0, "response")
                        .or_else(|| kwarg(args, "content"))
                        .cloned()
                        .unwrap_or_else(Value::clean);
                    check_body(it, &body, span, short);
                }
                Value::Obj(Rc::new(Obj::new("flask.Response")))
            }
            "flask.jsonify" | "django.http.JsonResponse" => {
                Value::Obj(Rc::new(Obj::new("flask.Response")))
            }
            "flask.redirect"
            | "django.shortcuts.redirect"
            | "django.http.HttpResponseRedirect"
            | "django.http.HttpResponsePermanentRedirect"
            | "starlette.responses.RedirectResponse"
            | "fastapi.responses.RedirectResponse" => {
                it.sink(&REDIRECT, &a0(), span, short);
                Value::Obj(Rc::new(Obj::new("flask.Response")))
            }
            "markupsafe.Markup"
            | "flask.Markup"
            | "django.utils.safestring.mark_safe"
            | "django.utils.html.format_html" => {
                it.sink(&XSS, &a0(), span, short);
                a0().sanitized(ctx::HTML)
            }
            "flask.Flask" => Value::Obj(Rc::new(Obj::new("flask.Flask"))),
            "starlette.templating.Jinja2Templates" | "fastapi.templating.Jinja2Templates" => {
                Value::Obj(Rc::new(Obj::new("starlette.Jinja2Templates")))
            }

            // ---- outbound requests ----
            "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.delete"
            | "requests.head"
            | "requests.patch"
            | "requests.options"
            | "httpx.get"
            | "httpx.post"
            | "httpx.put"
            | "httpx.delete"
            | "urllib.request.urlopen"
            | "urllib.request.Request"
            | "urllib.urlopen"
            | "urllib2.urlopen" => {
                let url = arg(args, 0, "url").cloned().unwrap_or_else(Value::clean);
                it.sink(&SSRF, &url, span, p);
                check_verify(it, args, span, p);
                // Whoever controls the URL controls the response.
                response_of(&url)
            }
            "requests.request" | "httpx.request" => {
                let url = arg(args, 1, "url").cloned().unwrap_or_else(Value::clean);
                it.sink(&SSRF, &url, span, p);
                check_verify(it, args, span, p);
                response_of(&url)
            }
            "requests.Session" | "httpx.Client" => {
                Value::Obj(Rc::new(Obj::new("requests.Session")))
            }
            "ssl._create_unverified_context" => {
                it.flag(&TLS_NO_VERIFY, span, p);
                Value::clean()
            }
            "ssl.wrap_socket" => {
                if matches!(kwarg(args, "cert_reqs"), Some(Value::Ref(r, _)) if r.ends_with("CERT_NONE"))
                {
                    it.flag(&TLS_NO_VERIFY, span, p);
                }
                Value::clean()
            }

            // ---- crypto ----
            "hashlib.md5"
            | "hashlib.sha1"
            | "hashlib.md4"
            | "Crypto.Hash.MD5.new"
            | "Crypto.Hash.SHA1.new"
            | "Crypto.Hash.MD4.new"
            | "Crypto.Hash.MD2.new"
            | "cryptography.hazmat.primitives.hashes.MD5"
            | "cryptography.hazmat.primitives.hashes.SHA1" => {
                if kwarg(args, "usedforsecurity").and_then(|v| v.truthy()) != Some(false) {
                    it.flag(&WEAK_HASH, span, p);
                }
                Value::Obj(Rc::new(Obj::new("hashlib.hash")))
            }
            "hashlib.new" => {
                let algo = a0();
                let weak = !algo.alternatives().is_empty()
                    && algo.alternatives().iter().all(|a| {
                        a.as_str()
                            .map(|s| WEAK_HASHES.contains(&s.to_ascii_lowercase().as_str()))
                            .unwrap_or(false)
                    });
                if weak && kwarg(args, "usedforsecurity").and_then(|v| v.truthy()) != Some(false) {
                    it.flag(
                        &WEAK_HASH,
                        span,
                        &format!(
                            "hashlib.new('{}')",
                            algo.alternatives()[0].as_str().unwrap_or_default()
                        ),
                    );
                }
                Value::Obj(Rc::new(Obj::new("hashlib.hash")))
            }
            "Crypto.Cipher.DES.new"
            | "Crypto.Cipher.DES3.new"
            | "Crypto.Cipher.ARC2.new"
            | "Crypto.Cipher.ARC4.new"
            | "Crypto.Cipher.Blowfish.new"
            | "Crypto.Cipher.CAST.new"
            | "Crypto.Cipher.XOR.new"
            | "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES"
            | "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish"
            | "cryptography.hazmat.primitives.ciphers.algorithms.ARC4"
            | "cryptography.hazmat.primitives.ciphers.algorithms.IDEA"
            | "cryptography.hazmat.primitives.ciphers.algorithms.CAST5"
            | "cryptography.hazmat.primitives.ciphers.algorithms.SEED"
            | "cryptography.hazmat.primitives.ciphers.modes.ECB" => {
                it.flag(&WEAK_CIPHER, span, p);
                Value::clean()
            }
            "Crypto.Cipher.AES.new" => {
                if matches!(arg(args, 1, "mode"), Some(Value::Ref(m, _)) if m.ends_with("MODE_ECB"))
                {
                    it.flag(&WEAK_CIPHER, span, "AES в режиме ECB");
                }
                Value::clean()
            }
            "random.Random" => Value::Obj(Rc::new(Obj::new("random.Random"))),
            "random.SystemRandom" => Value::Obj(Rc::new(Obj::new("random.SystemRandom"))),
            _ if p.starts_with("random.")
                && RANDOM_FUNCS.contains(&short)
                && p.matches('.').count() == 1 =>
            {
                it.weak_random(&format!("{p}()"), span, args)
            }
            _ if p.starts_with("secrets.") => Value::clean(),

            // ---- databases ----
            "sqlite3.connect"
            | "psycopg2.connect"
            | "pymysql.connect"
            | "MySQLdb.connect"
            | "mysql.connector.connect"
            | "cx_Oracle.connect"
            | "oracledb.connect"
            | "pyodbc.connect"
            | "sqlite3.Connection" => Value::Obj(Rc::new(Obj::new("db.Connection"))),
            "sqlalchemy.text"
            | "sqlalchemy.sql.text"
            | "sqlalchemy.sql.expression.text"
            | "django.db.models.expressions.RawSQL" => {
                it.sink(&SQLI, &a0(), span, p);
                Value::Obj(Rc::new(Obj::new("sql.Text")))
            }
            "pandas.read_sql" | "pandas.read_sql_query" => {
                it.sink(&SQLI, &a0(), span, p);
                Value::clean()
            }

            // ---- LDAP ----
            "ldap3.Connection" => Value::Obj(Rc::new(Obj::new("ldap3.Connection"))),
            "ldap.initialize" | "ldap.open" => Value::Obj(Rc::new(Obj::new("ldap.LDAPObject"))),

            // ---- XML and XPath ----
            "xml.sax.make_parser" => Value::Obj(Rc::new(
                Obj::new("xml.sax.XMLReader").with_field("external", Value::Bool(false)),
            )),
            "xml.dom.minidom.parseString"
            | "xml.dom.minidom.parse"
            | "xml.dom.pulldom.parseString"
            | "xml.dom.pulldom.parse" => {
                if let Some(Value::Obj(parser)) = arg(args, 1, "parser") {
                    if parser.field("external") == Some(&Value::Bool(true)) {
                        it.sink(&XXE, &a0(), span, p);
                    }
                }
                Value::Obj(Rc::new(Obj::new("xml.dom.Document")))
            }
            "xml.sax.parseString" | "xml.sax.parse" => Value::clean(),
            "lxml.etree.XMLParser" | "lxml.etree.XMLPullParser" => {
                let resolve = kwarg(args, "resolve_entities").and_then(|v| v.truthy())
                    == Some(true)
                    || kwarg(args, "no_network").and_then(|v| v.truthy()) == Some(false);
                Value::Obj(Rc::new(
                    Obj::new("lxml.etree.XMLParser").with_field("external", Value::Bool(resolve)),
                ))
            }
            "lxml.etree.parse"
            | "lxml.etree.fromstring"
            | "lxml.etree.XML"
            | "lxml.etree.iterparse"
            | "lxml.objectify.parse"
            | "lxml.objectify.fromstring" => {
                if let Some(Value::Obj(parser)) = arg(args, 1, "parser") {
                    if parser.field("external") == Some(&Value::Bool(true)) {
                        it.sink(&XXE, &a0(), span, p);
                    }
                }
                Value::Obj(Rc::new(Obj::new("lxml.etree._Element")))
            }
            "lxml.etree.XPath" | "lxml.etree.ETXPath" | "lxml.etree.XPathEvaluator" => {
                it.sink(&XPATHI, &a0(), span, p);
                Value::Obj(Rc::new(Obj::new("lxml.etree.XPath")))
            }
            "elementpath.select" | "elementpath.iter_select" => {
                it.sink(
                    &XPATHI,
                    &arg(args, 1, "path").cloned().unwrap_or_else(Value::clean),
                    span,
                    p,
                );
                Value::clean()
            }
            "elementpath.Selector" => {
                it.sink(&XPATHI, &a0(), span, p);
                Value::clean()
            }
            "xml.etree.ElementTree.parse"
            | "xml.etree.ElementTree.fromstring"
            | "xml.etree.ElementTree.XML" => Value::Obj(Rc::new(Obj::new("xml.etree.Element"))),

            // ---- configuration ----
            "configparser.ConfigParser"
            | "configparser.RawConfigParser"
            | "configparser.SafeConfigParser"
            | "ConfigParser.ConfigParser" => {
                Value::Obj(Rc::new(Obj::new("configparser.ConfigParser")))
            }
            "logging.getLogger" => Value::Obj(Rc::new(Obj::new("logging.Logger"))),
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
        match recv {
            Value::Str(segs) => {
                if matches!(name, "format" | "format_map") && literal(segs).is_none() {
                    it.sink(&FORMAT_STRING, recv, span, "str.format");
                }
                (str_method(segs, name, args), None)
            }
            Value::Unknown(t) if t.is_tainted() && matches!(name, "format" | "format_map") => {
                it.sink(&FORMAT_STRING, recv, span, "str.format");
                (str_method(&[Seg::Dyn(t.clone())], name, args), None)
            }
            Value::List(items) => list_method(items, name, args),
            Value::Dict(pairs) => dict_method(pairs, name, args),
            Value::Obj(o) => obj_method(it, recv, o, name, args, span),
            Value::Unknown(t) if t.is_tainted() && is_str_method(name) => {
                (str_method(&[Seg::Dyn(t.clone())], name, args), None)
            }
            _ => (generic_method(it, recv, name, args, span), None),
        }
    }

    fn attr(&self, it: &mut Interp, base: &Value, name: &str) -> Option<Value> {
        let Value::Obj(o) = base else { return None };
        if o.def.is_some() {
            return handler_attr(it, o, name);
        }
        match &*o.class {
            "pathlib.Path" => {
                let s = o
                    .field("path")
                    .cloned()
                    .unwrap_or_else(|| Value::Unknown(o.taint.clone()));
                Some(match name {
                    "name" | "stem" | "suffix" => {
                        Value::tainted_str(s.taint()).sanitized(ctx::PATH)
                    }
                    "parent" => make_path(Value::tainted_str(s.taint()), false),
                    _ => Value::Unknown(s.taint()),
                })
            }
            "urllib.parse.ParseResult" => Some(Value::tainted_str(o.taint.clone())),
            _ => None,
        }
    }

    fn index(&self, _it: &mut Interp, base: &Value, key: &Value) -> Option<Value> {
        match base {
            Value::Ref(_, t) if t.is_tainted() => Some(Value::tainted_str(t.clone())),
            Value::Ref(p, _) if &**p == "os.environ" => Some(Value::clean()),
            Value::Obj(o) if &*o.class == "configparser.ConfigParser" => {
                let section = key.as_str().unwrap_or_default();
                let prefix = format!("{section}\u{1}");
                let mut sec = Obj::new("configparser.Section");
                for (k, v) in &o.fields {
                    if let Some(name) = k.strip_prefix(&prefix) {
                        sec.set_field(name, v.clone());
                    }
                }
                Some(Value::Obj(Rc::new(sec)))
            }
            Value::Obj(o) if &*o.class == "configparser.Section" => Some(
                key.as_str()
                    .and_then(|k| o.field(&k).cloned())
                    .unwrap_or_else(Value::clean),
            ),
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
            Value::Ref(p, _) if p.ends_with("flask.session") || p.ends_with("request.session") => {
                if !it.sink(&TRUST, key, span, "session[...]") {
                    it.sink(&TRUST, value, span, "session[...]");
                }
                it.sink(&WEAK_RANDOM, value, span, "session[...]");
                Some(base.clone())
            }
            _ => None,
        }
    }

    fn binop(&self, _it: &mut Interp, op: BinOp, l: &Value, r: &Value) -> Option<Value> {
        match (op, l) {
            (BinOp::Mod, Value::Str(segs)) => Some(percent_format(segs, r)),
            (BinOp::Div, Value::Obj(o)) if &*o.class == "pathlib.Path" => {
                let base = o
                    .field("path")
                    .cloned()
                    .unwrap_or_else(|| Value::Unknown(o.taint.clone()));
                Some(make_path(
                    concat(&[base, Value::str("/"), path_string(r)]),
                    false,
                ))
            }
            _ => None,
        }
    }

    fn builtin(&self, _it: &mut Interp, name: &str) -> Value {
        Value::Ref(format!("builtins.{name}").into(), Taint::clean())
    }

    fn route(&self, it: &mut Interp, module: usize, func: &Function) -> Option<Route> {
        for d in &func.decorators {
            let Expr::Call {
                func: callee, args, ..
            } = d
            else {
                continue;
            };
            let Expr::Attr(_, method) = &**callee else {
                continue;
            };
            if !matches!(
                method.as_str(),
                "route"
                    | "get"
                    | "post"
                    | "put"
                    | "delete"
                    | "patch"
                    | "api_route"
                    | "head"
                    | "options"
                    | "websocket"
            ) {
                continue;
            }
            let Some(Arg {
                value: Expr::Lit(Const::Str(path)),
                ..
            }) = args.first()
            else {
                continue;
            };
            let mut params = Vec::new();
            let mut numeric = Vec::new();
            let fastapi = path.contains('{') || imports(it, module, "fastapi");
            let mut rest = path.as_str();
            while let Some(start) = rest.find(['<', '{']) {
                let close = if rest.as_bytes()[start] == b'<' {
                    '>'
                } else {
                    '}'
                };
                let Some(end) = rest[start..].find(close) else {
                    break;
                };
                let inner = &rest[start + 1..start + end];
                let (name, converter) = if close == '>' {
                    match inner.split_once(':') {
                        Some((conv, n)) => (n, conv),
                        None => (inner, ""),
                    }
                } else {
                    match inner.split_once(':') {
                        Some((n, conv)) => (n, conv),
                        None => (inner, ""),
                    }
                };
                if matches!(converter, "int" | "float" | "uuid") {
                    numeric.push(name.to_string());
                }
                params.push(name.to_string());
                rest = &rest[start + end + 1..];
            }
            return Some(Route {
                path: path.clone(),
                fixed_path: params.is_empty(),
                params,
                typed_params: numeric,
                framework: if fastapi { "fastapi" } else { "flask" },
            });
        }
        None
    }

    fn entry_param(
        &self,
        it: &mut Interp,
        module: usize,
        _func: &Function,
        route: Option<&Route>,
        index: usize,
        param: &Param,
    ) -> Value {
        let ty = param.ty.as_deref().unwrap_or("");
        let numeric_type = matches!(
            ty,
            "int" | "float" | "bool" | "UUID" | "uuid.UUID" | "datetime" | "date"
        );
        if let Some(r) = route {
            if r.params.contains(&param.name) {
                let t = it.source(&format!("параметр маршрута {}", param.name));
                if r.typed_params.contains(&param.name) || numeric_type {
                    return Value::Unknown(t.with_safe(ctx::ALL & !ctx::SESSION));
                }
                return Value::tainted_str(t);
            }
            if r.framework == "fastapi" {
                let ty = param.ty.as_deref().unwrap_or("");
                if ty.ends_with("Request") {
                    return Value::Ref("web.request".into(), Taint::clean());
                }
                let injected = matches!(&param.default, Some(Expr::Call { func, .. }) if matches!(&**func, Expr::Name(n) | Expr::Attr(_, n) if n == "Depends" || n == "Security"));
                if !injected && !matches!(ty, "Session" | "BackgroundTasks" | "Response") {
                    let t = it.source(&format!("параметр запроса {}", param.name));
                    if numeric_type {
                        return Value::Unknown(t.with_safe(ctx::ALL & !ctx::SESSION));
                    }
                    return Value::tainted_str(t);
                }
            }
        }
        let named = matches!(param.name.as_str(), "request" | "req") && index <= 2;
        let typed = ty.ends_with("Request") && !ty.contains("Flask");
        if (named || typed) && WEB_FRAMEWORKS.iter().any(|f| imports(it, module, f)) {
            return Value::Ref("web.request".into(), Taint::clean());
        }
        Value::clean()
    }

    fn on_return(&self, it: &mut Interp, _route: &Route, value: &Value, span: Span) {
        let body = match value {
            Value::List(items) => items.first().cloned().unwrap_or_else(Value::clean),
            other => other.clone(),
        };
        check_body(it, &body, span, "ответ обработчика");
    }

    fn sanitizer_of(&self, qualname: &str) -> u32 {
        name_sanitizer(qualname.rsplit('.').next().unwrap_or(qualname))
    }

    fn refine_method(
        &self,
        recv: &Value,
        name: &str,
        args: &[Value],
        truth: bool,
    ) -> Vec<(FactOn, Fact)> {
        if !truth {
            return Vec::new();
        }
        let (pattern, target) = match recv {
            Value::Ref(p, _)
                if &**p == "re" && matches!(name, "match" | "fullmatch" | "search") =>
            {
                (args.first().and_then(|v| v.as_str()), 1)
            }
            Value::Obj(o)
                if &*o.class == "re.Pattern"
                    && matches!(name, "match" | "fullmatch" | "search") =>
            {
                (o.field("pattern").and_then(|v| v.as_str()), 0)
            }
            _ => return refine_str_method(name, args, truth),
        };
        let Some(pattern) = pattern else {
            return Vec::new();
        };
        let anchored = regex_anchored(&pattern, name == "fullmatch")
            || (name == "match" && regex_anchored(&format!("^{pattern}"), false));
        match (anchored, regex_chars(&pattern)) {
            (true, Some(set)) => {
                let mut bits = set.safety();
                if !pattern.ends_with("\\Z") && !pattern.ends_with("\\z") && name != "fullmatch" {
                    // `$` also matches before a final newline.
                    bits &= !(ctx::HEADER | ctx::LOG);
                }
                vec![(FactOn::Arg(target), Fact::Safe(bits))]
            }
            _ => Vec::new(),
        }
    }

    fn refine_attr(&self, obj: &Obj, field: &str, fact: &Fact) -> Vec<(Rc<str>, u32)> {
        if &*obj.class == "urllib.parse.ParseResult"
            && matches!(field, "netloc" | "hostname")
            && matches!(fact, Fact::OneOf(_))
        {
            if let Some(var) = obj.field("__of").and_then(|v| v.as_str()) {
                return vec![(var.into(), ctx::URL)];
            }
        }
        Vec::new()
    }

    fn facts_safety(&self, facts: &[Fact], value: &Value) -> u32 {
        let mut bits = literal_check_safety(facts);
        // A resolved path that starts with the base directory stays inside it.
        if facts
            .iter()
            .any(|f| matches!(f, Fact::StartsWithValue | Fact::StartsWith(_)))
            && is_normalized_path(value)
        {
            bits |= ctx::PATH;
        }
        bits
    }
}

/// `re.sub(pattern, repl, s)`: removing every character outside a class
/// leaves only that class.
pub(crate) fn regex_sub(pattern: &str, repl: Option<&Value>, s: &Value) -> Value {
    let repl = repl.and_then(|r| r.as_str());
    let (Some(repl), Some(removed)) = (repl, regex_chars(pattern.trim_end_matches(['+', '*'])))
    else {
        return Value::tainted_str(s.taint());
    };
    if s.as_str().is_some() {
        return Value::clean();
    }
    // Characters that survive: everything not matched, plus the replacement.
    let mut kept = CharSet::default();
    for c in (0u8..128).map(char::from) {
        if !removed.has(c) {
            kept.add(c);
        }
    }
    for c in repl.chars() {
        kept.add(c);
    }
    Value::tainted_str(s.taint()).sanitized(kept.safety())
}

fn imports(it: &Interp, module: usize, prefix: &str) -> bool {
    it.project.modules[module].ir.body.iter().any(|s| match s {
        Stmt::Import { path, .. } => path == prefix || path.starts_with(&format!("{prefix}.")),
        _ => false,
    })
}

/// Values read from a framework request object.
fn source_accessor(path: &str, taint: &Taint, args: &[ArgVal]) -> Value {
    let last = path.rsplit('.').next().unwrap_or(path);
    if matches!(kwarg(args, "type"), Some(Value::Ref(t, _)) if t.ends_with("int") || t.ends_with("float"))
    {
        return Value::Unknown(taint.clone().with_safe(ctx::ALL));
    }
    match last {
        "getlist"
        | "get_all"
        | "getall"
        | "keys"
        | "values"
        | "items"
        | "to_dict"
        | "lists"
        | "get_json"
        | "json"
        | "form"
        | "dict"
        | "copy"
        | "listvalues"
        | "split"
        | "readlines"
        | "post"
        | "multipart"
        | "query"
        | "match_info"
        | "params"
        | "arguments"
        | "get_media"
        | "media"
        | "get_arguments"
        | "get_query_arguments"
        | "get_body_arguments" => Value::Unknown(taint.clone()),
        _ => Value::tainted_str(taint.clone()),
    }
}

fn builtin(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Value {
    let a0 = arg(args, 0, "").cloned();
    match name {
        "open" | "file" => {
            let path = arg(args, 0, "file")
                .map(path_string)
                .unwrap_or_else(Value::clean);
            it.sink(&PATH, &path, span, "open");
            file_of(&path)
        }
        "eval" | "exec" | "compile" | "execfile" => {
            if let Some(v) = arg(args, 0, "source") {
                it.sink(&CODEI, v, span, name);
            }
            Value::clean()
        }
        "str" | "repr" | "ascii" | "format" | "unicode" => match a0 {
            None => Value::str(""),
            Some(v @ Value::Obj(_)) => path_string(&v),
            Some(v) => Value::segs(v.to_segs()),
        },
        "bytes" | "bytearray" => match a0 {
            Some(v @ Value::Str(_)) => v,
            Some(v) => Value::Unknown(v.taint()),
            None => Value::str(""),
        },
        "int" | "float" | "bool" | "len" | "hash" | "id" | "ord" | "abs" | "round" | "callable"
        | "hasattr" | "issubclass" | "complex" | "divmod" | "pow" | "sum" | "any" | "all" => {
            Value::clean()
        }
        "isinstance" => {
            let (Some(v), Some(Value::Ref(cls, _))) = (a0, arg(args, 1, "")) else {
                return Value::clean();
            };
            match (&v, cls.as_ref()) {
                (Value::Str(_), "builtins.str") => Value::Bool(true),
                (Value::Str(_), _) => Value::Bool(false),
                (Value::Int(_), "builtins.int") => Value::Bool(true),
                (Value::List(_), "builtins.list" | "builtins.tuple") => Value::clean(),
                (Value::Int(_) | Value::List(_) | Value::Dict(_) | Value::None, _) => {
                    Value::Bool(false)
                }
                _ => Value::clean(),
            }
        }
        "list" | "tuple" | "set" | "frozenset" | "sorted" | "reversed" => match a0 {
            Some(v @ Value::List(_)) => v,
            Some(Value::Dict(pairs)) => Value::list(pairs.iter().map(|(k, _)| k.clone()).collect()),
            Some(v) => Value::Unknown(v.taint()),
            None => Value::list(Vec::new()),
        },
        "dict" => {
            let mut pairs: Vec<(Value, Value)> = Vec::new();
            if let Some(Value::Dict(d)) = &a0 {
                pairs = d.as_ref().clone();
            } else if let Some(v) = &a0 {
                return Value::Unknown(v.taint());
            }
            for a in args.iter().filter(|a| a.name.is_some()) {
                pairs.push((Value::str(a.name.as_deref().unwrap_or("")), a.value.clone()));
            }
            Value::Dict(Rc::new(pairs))
        }
        "getattr" => {
            let (Some(obj), Some(attr)) = (a0, arg(args, 1, "").and_then(|v| v.as_str())) else {
                return Value::Unknown(args_taint(args));
            };
            it.get_attr(&obj, &attr)
        }
        "chr" | "min" | "max" | "next" | "iter" | "enumerate" | "zip" | "map" | "filter"
        | "range" | "vars" | "dir" => Value::Unknown(args_taint(args)),
        "print" | "input" | "super" | "type" | "object" | "setattr" | "delattr" | "locals"
        | "globals" | "exit" | "quit" => Value::clean(),
        _ => Value::Unknown(args_taint(args)),
    }
}

/// `str(path)` for path objects; the value itself otherwise.
fn path_string(v: &Value) -> Value {
    match v {
        Value::Obj(o) if &*o.class == "pathlib.Path" => o
            .field("path")
            .cloned()
            .unwrap_or_else(|| Value::Unknown(o.taint.clone())),
        Value::Obj(o) => Value::tainted_str(o.taint.clone()),
        other => other.clone(),
    }
}

/// A file opened by name: its content is as trusted as the name.
fn file_of(path: &Value) -> Value {
    let mut o = Obj::new("file");
    o.taint = path.taint();
    Value::Obj(Rc::new(o))
}

/// The response of a request to `url`.
fn response_of(url: &Value) -> Value {
    let mut o = Obj::new("http.Response");
    o.taint = url.taint().without_safe(ctx::ALL);
    Value::Obj(Rc::new(o))
}

fn make_path(s: Value, normalized: bool) -> Value {
    let mut o = Obj::new("pathlib.Path");
    o.taint = s.taint();
    o.set_field("path", s);
    o.set_field("normalized", Value::Bool(normalized));
    Value::Obj(Rc::new(o))
}

fn is_normalized_path(v: &Value) -> bool {
    match v {
        Value::Obj(o) => o.field("normalized") == Some(&Value::Bool(true)),
        Value::OneOf(alts) => alts.iter().all(is_normalized_path),
        _ => false,
    }
}

fn encoded(v: &Value) -> Value {
    match v.as_str() {
        Some(_) => Value::clean(),
        None => Value::tainted_str(v.taint().with_safe(ENCODED_SAFE)),
    }
}

/// Response bodies are HTML unless they are objects or JSON-like.
fn check_body(it: &mut Interp, body: &Value, span: Span, what: &str) {
    let html: Vec<Value> = body
        .alternatives()
        .into_iter()
        .filter(|v| {
            !matches!(
                v,
                Value::Obj(_) | Value::Dict(_) | Value::None | Value::Func(_)
            )
        })
        .collect();
    for v in html {
        if it.sink(&XSS, &v, span, what) {
            return;
        }
    }
}

fn check_verify(it: &mut Interp, args: &[ArgVal], span: Span, what: &str) {
    if kwarg(args, "verify").and_then(|v| v.truthy()) == Some(false) {
        it.flag(&TLS_NO_VERIFY, span, what);
    }
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "ksh",
    "dash",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

pub(crate) fn is_shell(v: &Value) -> bool {
    v.alternatives().iter().any(|a| {
        a.as_str()
            .map(|s| {
                let base = s
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&s)
                    .to_ascii_lowercase();
                SHELLS.contains(&base.as_str())
            })
            .unwrap_or(false)
    })
}

/// `subprocess.*`: a shell runs the whole string; without a shell only the
/// program name, or the script handed to `sh -c`, is dangerous.
fn check_subprocess(it: &mut Interp, args: &[ArgVal], span: Span, what: &str) {
    let cmd = arg(args, 0, "args").cloned().unwrap_or_else(Value::clean);
    let shell = kwarg(args, "shell")
        .map(|v| v.truthy())
        .unwrap_or(Some(false));
    if shell != Some(false) {
        let script = match &cmd {
            Value::List(items) => items.first().cloned().unwrap_or_else(Value::clean),
            other => other.clone(),
        };
        it.sink(&CMDI, &script, span, what);
        return;
    }
    check_argv(it, &cmd, span, what);
}

pub(crate) fn check_argv(it: &mut Interp, cmd: &Value, span: Span, what: &str) {
    match cmd {
        Value::List(items) => {
            let Some(program) = items.first() else { return };
            if it.sink(&CMDI, program, span, what) {
                return;
            }
            if is_shell(program) {
                for item in items.iter().skip(1) {
                    if it.sink(&CMDI, item, span, what) {
                        return;
                    }
                }
            }
        }
        Value::OneOf(alts) => {
            for a in alts.iter() {
                check_argv(it, a, span, what);
            }
        }
        other => {
            it.sink(&CMDI, other, span, what);
        }
    }
}

fn check_exec_args(it: &mut Interp, args: &[ArgVal], span: Span, what: &str) {
    let mut argv: Vec<Value> = Vec::new();
    for a in args.iter().skip(1) {
        match &a.value {
            Value::List(items) => argv.extend(items.iter().cloned()),
            v => argv.push(v.clone()),
        }
    }
    let program = arg(args, 0, "path").cloned().unwrap_or_else(Value::clean);
    if it.sink(&CMDI, &program, span, what) {
        return;
    }
    if is_shell(&program) {
        for v in argv.iter().skip(1) {
            if it.sink(&CMDI, v, span, what) {
                return;
            }
        }
    }
}

fn split_url(s: &str) -> (String, String, String) {
    let (scheme, rest) = match s.find("://") {
        Some(i) => (s[..i].to_string(), &s[i + 3..]),
        None => match s.strip_prefix("//") {
            Some(r) => (String::new(), r),
            None => return (String::new(), String::new(), s.to_string()),
        },
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (scheme, rest[..end].to_string(), rest[end..].to_string())
}

fn is_str_method(name: &str) -> bool {
    matches!(
        name,
        "lower"
            | "upper"
            | "strip"
            | "lstrip"
            | "rstrip"
            | "replace"
            | "encode"
            | "decode"
            | "split"
            | "rsplit"
            | "splitlines"
            | "format"
            | "join"
            | "title"
            | "capitalize"
            | "casefold"
            | "swapcase"
            | "zfill"
            | "center"
            | "ljust"
            | "rjust"
            | "translate"
            | "removeprefix"
            | "removesuffix"
            | "partition"
            | "rpartition"
            | "expandtabs"
            | "startswith"
            | "endswith"
            | "find"
            | "rfind"
            | "index"
            | "rindex"
            | "count"
            | "isdigit"
            | "isalnum"
            | "isalpha"
            | "isnumeric"
            | "isdecimal"
    )
}

pub(crate) fn str_method(segs: &[Seg], name: &str, args: &[ArgVal]) -> Value {
    let lit = literal(segs);
    let taint = Value::Str(Rc::new(segs.to_vec())).taint();
    let a = |i: usize| arg(args, i, "").and_then(|v| v.as_str());
    match name {
        "lower" | "casefold" => map_lits(segs, |s| s.to_lowercase()),
        "upper" => map_lits(segs, |s| s.to_uppercase()),
        "encode" | "decode" => Value::Str(Rc::new(segs.to_vec())),
        "strip" | "lstrip" | "rstrip" => match lit {
            Some(s) => {
                let chars: Option<Vec<char>> = a(0).map(|c| c.chars().collect());
                let pat = |c: char| {
                    chars
                        .as_ref()
                        .map(|cs| cs.contains(&c))
                        .unwrap_or(c.is_whitespace())
                };
                Value::str(match name {
                    "strip" => s.trim_matches(pat),
                    "lstrip" => s.trim_start_matches(pat),
                    _ => s.trim_end_matches(pat),
                })
            }
            None => Value::Str(Rc::new(segs.to_vec())),
        },
        "replace" => match (a(0), arg(args, 1, "")) {
            (Some(old), Some(new)) => replace_segs(segs, &old, new),
            _ => Value::tainted_str(taint.union(&args_taint(args))),
        },
        "format" => brace_format(segs, args),
        "join" => {
            let sep = lit.unwrap_or_default();
            match arg(args, 0, "") {
                Some(Value::List(items)) => {
                    let mut parts = Vec::new();
                    for (i, v) in items.iter().enumerate() {
                        if i > 0 {
                            parts.push(Value::Str(Rc::new(segs.to_vec())));
                        }
                        parts.push(v.clone());
                    }
                    concat(&parts)
                }
                Some(v) => {
                    let _ = sep;
                    Value::tainted_str(v.taint().union(&taint))
                }
                None => Value::str(""),
            }
        }
        "split" | "rsplit" => match lit {
            Some(s) => {
                let parts: Vec<Value> = match a(0) {
                    Some(sep) if !sep.is_empty() => s.split(sep.as_str()).map(Value::str).collect(),
                    _ => s.split_whitespace().map(Value::str).collect(),
                };
                Value::list(parts)
            }
            None => Value::Unknown(taint),
        },
        "splitlines" => match lit {
            Some(s) => Value::list(s.lines().map(Value::str).collect()),
            None => Value::Unknown(taint),
        },
        "partition" | "rpartition" => Value::Unknown(taint),
        "startswith" | "endswith" => match (lit, a(0)) {
            (Some(s), Some(p)) => Value::Bool(if name == "startswith" {
                s.starts_with(&p)
            } else {
                s.ends_with(&p)
            }),
            (None, Some(p)) => {
                let known = if name == "startswith" {
                    segs.first()
                } else {
                    segs.last()
                };
                match known {
                    Some(Seg::Lit(t)) if t.len() >= p.len() => {
                        Value::Bool(if name == "startswith" {
                            t.starts_with(&p)
                        } else {
                            t.ends_with(&p)
                        })
                    }
                    _ => Value::clean(),
                }
            }
            _ => Value::clean(),
        },
        "find" | "rfind" | "index" | "rindex" | "count" => match (lit, a(0)) {
            (Some(s), Some(p)) => Value::Int(match name {
                "find" | "index" => s
                    .find(&p)
                    .map(|i| s[..i].chars().count() as i64)
                    .unwrap_or(-1),
                "rfind" | "rindex" => s
                    .rfind(&p)
                    .map(|i| s[..i].chars().count() as i64)
                    .unwrap_or(-1),
                _ => s.matches(&p).count() as i64,
            }),
            _ => Value::clean(),
        },
        "isdigit" | "isalnum" | "isalpha" | "isnumeric" | "isdecimal" | "isspace" | "islower"
        | "isupper" | "isidentifier" => match lit {
            Some(s) => Value::Bool(
                !s.is_empty()
                    && s.chars().all(|c| match name {
                        "isdigit" | "isnumeric" | "isdecimal" => c.is_numeric(),
                        "isalnum" => c.is_alphanumeric(),
                        "isalpha" => c.is_alphabetic(),
                        "isspace" => c.is_whitespace(),
                        "islower" => !c.is_uppercase(),
                        "isupper" => !c.is_lowercase(),
                        _ => c.is_alphanumeric() || c == '_',
                    }),
            ),
            None => Value::clean(),
        },
        "title" | "capitalize" | "swapcase" | "zfill" | "center" | "ljust" | "rjust"
        | "expandtabs" | "translate" | "removeprefix" | "removesuffix" | "format_map" => {
            match lit {
                Some(s) if name == "removeprefix" => Value::str(
                    a(0).map(|p| s.strip_prefix(&p).unwrap_or(&s).to_string())
                        .unwrap_or(s),
                ),
                Some(s) if name == "removesuffix" => Value::str(
                    a(0).map(|p| s.strip_suffix(&p).unwrap_or(&s).to_string())
                        .unwrap_or(s),
                ),
                Some(_) if name == "format_map" => Value::tainted_str(args_taint(args)),
                Some(s) => Value::str(s),
                None => Value::tainted_str(taint),
            }
        }
        "__len__" => Value::clean(),
        _ => Value::Unknown(taint.union(&args_taint(args))),
    }
}

fn list_method(items: &Rc<Vec<Value>>, name: &str, args: &[ArgVal]) -> (Value, Option<Value>) {
    let a0 = arg(args, 0, "").cloned();
    let mut v = items.as_ref().clone();
    match name {
        "append" | "add" => {
            v.push(a0.unwrap_or_else(Value::clean));
            (Value::None, Some(Value::list(v)))
        }
        "extend" | "update" => match a0 {
            Some(Value::List(more)) => {
                v.extend(more.iter().cloned());
                (Value::None, Some(Value::list(v)))
            }
            Some(other) => {
                let t = items.iter().fold(other.taint(), |t, x| t.union(&x.taint()));
                (Value::None, Some(Value::Unknown(t)))
            }
            None => (Value::None, None),
        },
        "insert" => {
            let (Some(Value::Int(i)), Some(x)) = (a0, arg(args, 1, "").cloned()) else {
                return (
                    Value::None,
                    Some(Value::Unknown(
                        args_taint(args).union(&Value::List(items.clone()).taint()),
                    )),
                );
            };
            let n = v.len() as i64;
            let i = if i < 0 { (n + i).max(0) } else { i.min(n) } as usize;
            v.insert(i, x);
            (Value::None, Some(Value::list(v)))
        }
        "pop" => {
            if v.is_empty() {
                return (Value::clean(), None);
            }
            let i = match a0 {
                None => v.len() as i64 - 1,
                Some(Value::Int(i)) => i,
                Some(_) => {
                    let el = Value::List(items.clone()).element();
                    return (el.clone(), Some(Value::Unknown(el.taint())));
                }
            };
            let n = v.len() as i64;
            let i = if i < 0 { n + i } else { i };
            if i < 0 || i >= n {
                return (Value::clean(), None);
            }
            let x = v.remove(i as usize);
            (x, Some(Value::list(v)))
        }
        "remove" | "discard" => {
            if let Some(x) = a0 {
                if let Some(pos) = v.iter().position(|e| values_eq(e, &x) == Some(true)) {
                    v.remove(pos);
                    return (Value::None, Some(Value::list(v)));
                }
            }
            (Value::None, None)
        }
        "index" => match a0.and_then(|x| v.iter().position(|e| values_eq(e, &x) == Some(true))) {
            Some(i) => (Value::Int(i as i64), None),
            None => (Value::clean(), None),
        },
        "count" => (Value::clean(), None),
        "copy" => (Value::List(items.clone()), None),
        "reverse" => {
            v.reverse();
            (Value::None, Some(Value::list(v)))
        }
        "sort" => (Value::None, None),
        "clear" => (Value::None, Some(Value::list(Vec::new()))),
        _ => (
            Value::Unknown(Value::List(items.clone()).taint().union(&args_taint(args))),
            None,
        ),
    }
}

fn dict_method(
    pairs: &Rc<Vec<(Value, Value)>>,
    name: &str,
    args: &[ArgVal],
) -> (Value, Option<Value>) {
    let a0 = arg(args, 0, "").cloned();
    let lookup = |k: &Value| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone());
    let all_values = || join_all(pairs.iter().map(|(_, v)| v.clone()));
    match name {
        "get" => {
            let default = arg(args, 1, "default").cloned().unwrap_or(Value::None);
            match a0 {
                Some(k) if is_const(&k) => (lookup(&k).unwrap_or(default), None),
                _ => (
                    all_values().map(|v| join(&v, &default)).unwrap_or(default),
                    None,
                ),
            }
        }
        "keys" => (
            Value::list(pairs.iter().map(|(k, _)| k.clone()).collect()),
            None,
        ),
        "values" => (
            Value::list(pairs.iter().map(|(_, v)| v.clone()).collect()),
            None,
        ),
        "items" => (
            Value::list(
                pairs
                    .iter()
                    .map(|(k, v)| Value::list(vec![k.clone(), v.clone()]))
                    .collect(),
            ),
            None,
        ),
        "update" => {
            let mut out = pairs.as_ref().clone();
            if let Some(Value::Dict(more)) = a0 {
                for (k, v) in more.iter() {
                    match out.iter_mut().find(|(ok, _)| ok == k) {
                        Some(slot) => slot.1 = v.clone(),
                        None => out.push((k.clone(), v.clone())),
                    }
                }
            }
            for a in args.iter().filter(|a| a.name.is_some()) {
                out.push((Value::str(a.name.as_deref().unwrap_or("")), a.value.clone()));
            }
            (Value::None, Some(Value::Dict(Rc::new(out))))
        }
        "setdefault" => {
            let Some(k) = a0 else {
                return (Value::None, None);
            };
            match lookup(&k) {
                Some(v) => (v, None),
                None => {
                    let d = arg(args, 1, "").cloned().unwrap_or(Value::None);
                    let mut out = pairs.as_ref().clone();
                    out.push((k, d.clone()));
                    (d, Some(Value::Dict(Rc::new(out))))
                }
            }
        }
        "pop" => {
            let Some(k) = a0 else {
                return (Value::clean(), None);
            };
            let default = arg(args, 1, "").cloned().unwrap_or_else(Value::clean);
            let v = lookup(&k).unwrap_or(default);
            let out: Vec<(Value, Value)> =
                pairs.iter().filter(|(pk, _)| *pk != k).cloned().collect();
            (v, Some(Value::Dict(Rc::new(out))))
        }
        "copy" => (Value::Dict(pairs.clone()), None),
        "clear" => (Value::None, Some(Value::Dict(Rc::new(Vec::new())))),
        _ => (Value::Unknown(Value::Dict(pairs.clone()).taint()), None),
    }
}

/// Request handler base classes whose attributes carry the request.
fn handler_kind(it: &mut Interp, o: &Obj) -> Option<&'static str> {
    let cv = o.def.clone()?;
    for b in it.external_bases(&cv) {
        let b = canonical(&b);
        let short = b.rsplit('.').next().unwrap_or(&b);
        match short {
            "BaseHTTPRequestHandler"
            | "SimpleHTTPRequestHandler"
            | "CGIHTTPRequestHandler"
            | "StreamRequestHandler" => return Some("http.server"),
            "RequestHandler" if b.starts_with("tornado") || b == "RequestHandler" => {
                return Some("tornado")
            }
            _ => {}
        }
    }
    None
}

fn handler_attr(it: &mut Interp, o: &Obj, name: &str) -> Option<Value> {
    match (handler_kind(it, o)?, name) {
        ("http.server", "path" | "requestline" | "raw_requestline") => {
            Some(Value::tainted_str(it.source("self.path")))
        }
        ("http.server", "headers") => {
            Some(Value::Ref("web.headers".into(), it.source("self.headers")))
        }
        ("http.server", "rfile") => Some(Value::Ref("web.rfile".into(), it.source("тело запроса"))),
        ("http.server", "wfile") => Some(Value::Obj(Rc::new(Obj::new("http.wfile")))),
        ("tornado", "request") => Some(Value::Ref("web.request".into(), Taint::clean())),
        _ => None,
    }
}

fn handler_method(
    it: &mut Interp,
    o: &Obj,
    name: &str,
    args: &[ArgVal],
    span: Span,
) -> Option<Value> {
    let kind = handler_kind(it, o)?;
    let a = |i: usize| arg(args, i, "").cloned().unwrap_or_else(Value::clean);
    match (kind, name) {
        ("http.server" | "tornado", "send_header" | "set_header" | "add_header") => {
            let header = a(0).as_str().unwrap_or_default().to_ascii_lowercase();
            match header.as_str() {
                "location" => {
                    it.sink(&REDIRECT, &a(1), span, name);
                }
                "access-control-allow-origin" => {
                    it.sink(&CORS, &a(1), span, name);
                }
                // Tornado rejects header values with CR or LF.
                _ if kind == "tornado" => {}
                _ => {
                    it.sink(&HEADER, &a(1), span, name);
                }
            }
            if header == "set-cookie" {
                it.sink(&WEAK_RANDOM, &a(1), span, "значение cookie");
            }
            Some(Value::None)
        }
        (
            "tornado",
            "get_argument" | "get_query_argument" | "get_body_argument" | "get_cookie"
            | "decode_argument",
        ) => Some(Value::tainted_str(it.source(&format!("self.{name}")))),
        ("tornado", "get_arguments" | "get_query_arguments" | "get_body_arguments") => {
            Some(Value::Unknown(it.source(&format!("self.{name}"))))
        }
        ("tornado", "write" | "finish") => {
            if !matches!(a(0), Value::Dict(_)) {
                check_body(it, &a(0), span, name);
            }
            Some(Value::None)
        }
        ("tornado", "redirect") => {
            it.sink(&REDIRECT, &a(0), span, "redirect");
            Some(Value::None)
        }
        _ => None,
    }
}

fn obj_method(
    it: &mut Interp,
    recv: &Value,
    o: &Rc<Obj>,
    name: &str,
    args: &[ArgVal],
    span: Span,
) -> (Value, Option<Value>) {
    if o.def.is_some() {
        if let Some(v) = handler_method(it, o, name, args, span) {
            return (v, None);
        }
        return (generic_method(it, recv, name, args, span), None);
    }
    let a0 = || arg(args, 0, "").cloned().unwrap_or_else(Value::clean);
    let updated = |f: &dyn Fn(&mut Obj)| {
        let mut n = (**o).clone();
        f(&mut n);
        Some(Value::Obj(Rc::new(n)))
    };
    match &*o.class {
        // Jinja escapes what a page template prints, as `render_template`.
        "starlette.Jinja2Templates" if matches!(name, "TemplateResponse" | "get_template") => {
            let page = args
                .iter()
                .filter(|a| a.name.is_none())
                .find(|a| a.value.as_str().is_some_and(|s| s.contains('.')) || a.value.is_tainted())
                .map(|a| a.value.clone())
                .or_else(|| kwarg(args, "name").cloned())
                .unwrap_or_else(Value::clean);
            it.sink(&PATH, &page, span, name);
            (Value::Obj(Rc::new(Obj::new("flask.Response"))), None)
        }
        "configparser.ConfigParser" => match name {
            "set" => {
                let (Some(s), Some(k)) = (
                    arg(args, 0, "section").and_then(|v| v.as_str()),
                    arg(args, 1, "option").and_then(|v| v.as_str()),
                ) else {
                    let t = args_taint(args);
                    return (
                        Value::None,
                        updated(&|n: &mut Obj| n.taint = n.taint.union(&t)),
                    );
                };
                let v = arg(args, 2, "value").cloned().unwrap_or(Value::None);
                let key = format!("{s}\u{1}{}", k.to_lowercase());
                (
                    Value::None,
                    updated(&|n: &mut Obj| n.set_field(&key, v.clone())),
                )
            }
            "get" | "getint" | "getfloat" | "getboolean" => {
                let numeric = name != "get";
                let found = match (
                    arg(args, 0, "section").and_then(|v| v.as_str()),
                    arg(args, 1, "option").and_then(|v| v.as_str()),
                ) {
                    (Some(s), Some(k)) => {
                        o.field(&format!("{s}\u{1}{}", k.to_lowercase())).cloned()
                    }
                    _ => Some(Value::Unknown(Value::Obj(o.clone()).taint())),
                };
                let v = found
                    .or_else(|| kwarg(args, "fallback").cloned())
                    .unwrap_or_else(Value::clean);
                (
                    if numeric {
                        Value::Unknown(v.taint().with_safe(ctx::ALL))
                    } else {
                        v
                    },
                    None,
                )
            }
            "add_section" | "read" | "read_file" | "read_string" | "read_dict" | "has_option"
            | "has_section" | "remove_option" | "sections" | "options" | "write" => {
                (Value::clean(), None)
            }
            _ => (Value::Unknown(o.taint.clone()), None),
        },
        "io.StringIO" => match name {
            "write" | "writelines" => {
                let buf = o.field("buf").cloned().unwrap_or_else(|| Value::str(""));
                let add = match a0() {
                    Value::List(items) => concat(&items),
                    v => v,
                };
                let next = concat(&[buf, add]);
                (
                    Value::clean(),
                    updated(&|n: &mut Obj| n.set_field("buf", next.clone())),
                )
            }
            "getvalue" | "read" | "readline" => (
                o.field("buf").cloned().unwrap_or_else(|| Value::str("")),
                None,
            ),
            _ => (Value::clean(), None),
        },
        "xml.sax.XMLReader" => match name {
            "setFeature" => {
                let feature = match a0() {
                    Value::Ref(p, _) => p.to_string(),
                    v => v.as_str().unwrap_or_default(),
                };
                let external = feature.ends_with("feature_external_ges")
                    || feature.ends_with("feature_external_pes")
                    || feature.contains("external-general-entities")
                    || feature.contains("external-parameter-entities");
                if external {
                    let on = arg(args, 1, "")
                        .map(|v| v.truthy() != Some(false))
                        .unwrap_or(false);
                    return (
                        Value::None,
                        updated(&|n: &mut Obj| n.set_field("external", Value::Bool(on))),
                    );
                }
                (Value::None, None)
            }
            "parse" => {
                if o.field("external") == Some(&Value::Bool(true)) {
                    it.sink(&XXE, &a0(), span, "XMLReader.parse");
                }
                (Value::None, None)
            }
            _ => (Value::None, None),
        },
        "lxml.etree._Element" => match name {
            "xpath" => {
                it.sink(
                    &XPATHI,
                    &arg(args, 0, "_path").cloned().unwrap_or_else(Value::clean),
                    span,
                    "xpath",
                );
                (Value::clean(), None)
            }
            "getroot" | "getroottree" => (recv.clone(), None),
            _ => (Value::clean(), None),
        },
        "pathlib.Path" => {
            let s = o
                .field("path")
                .cloned()
                .unwrap_or_else(|| Value::Unknown(o.taint.clone()));
            match name {
                "resolve" | "absolute" | "expanduser" => (make_path(s, true), None),
                "joinpath" | "with_name" | "with_suffix" | "with_stem" | "relative_to" => {
                    let mut parts = vec![s];
                    for a in args {
                        parts.push(Value::str("/"));
                        parts.push(path_string(&a.value));
                    }
                    (make_path(concat(&parts), false), None)
                }
                "open" | "read_text" | "read_bytes" | "write_text" | "write_bytes" | "exists"
                | "is_file" | "is_dir" | "unlink" | "mkdir" | "rmdir" | "touch" | "stat"
                | "lstat" | "iterdir" | "glob" | "rglob" | "rename" | "replace" | "chmod"
                | "owner" | "group" | "symlink_to" | "hardlink_to" | "samefile" | "is_symlink"
                | "readlink" => {
                    it.sink(&PATH, &s, span, &format!("Path.{name}"));
                    (
                        if name == "open" {
                            Value::Obj(Rc::new(Obj::new("file")))
                        } else {
                            Value::clean()
                        },
                        None,
                    )
                }
                "as_posix" | "__str__" | "__fspath__" => (s, None),
                _ => (Value::Unknown(s.taint()), None),
            }
        }
        "db.Connection" | "db.Cursor" => match name {
            "cursor" => (Value::Obj(Rc::new(Obj::new("db.Cursor"))), None),
            "execute" | "executemany" | "executescript" | "mogrify" => {
                it.sink(
                    &SQLI,
                    &arg(args, 0, "sql").cloned().unwrap_or_else(Value::clean),
                    span,
                    name,
                );
                (Value::Obj(Rc::new(Obj::new("db.Cursor"))), None)
            }
            _ => (Value::clean(), None),
        },
        "ldap3.Connection" => match name {
            "search" | "search_paged" => {
                let base = arg(args, 0, "search_base")
                    .cloned()
                    .unwrap_or_else(Value::clean);
                let filter = arg(args, 1, "search_filter")
                    .cloned()
                    .unwrap_or_else(Value::clean);
                if !it.sink(&LDAPI, &filter, span, "Connection.search") {
                    it.sink(&LDAPI, &base, span, "Connection.search");
                }
                (Value::Bool(true), None)
            }
            _ => (Value::clean(), None),
        },
        "ldap.LDAPObject" => match name {
            "search" | "search_s" | "search_st" | "search_ext" | "search_ext_s" => {
                let filter = arg(args, 2, "filterstr")
                    .cloned()
                    .unwrap_or_else(Value::clean);
                if !it.sink(&LDAPI, &filter, span, name) {
                    it.sink(&LDAPI, &a0(), span, name);
                }
                (Value::clean(), None)
            }
            _ => (Value::clean(), None),
        },
        "random.Random" => {
            if RANDOM_FUNCS.contains(&name) {
                let what = format!("random.Random().{name}()");
                return (it.weak_random(&what, span, args), None);
            }
            (Value::clean(), None)
        }
        "file" | "http.Response" => match name {
            "read" | "readline" | "readlines" | "decode" | "text" | "json" | "content"
            | "iter_lines" | "iter_content" | "getvalue" => {
                (Value::tainted_str(o.taint.clone()), None)
            }
            _ => (Value::Unknown(o.taint.clone()), None),
        },
        "http.wfile" => {
            if matches!(name, "write" | "writelines") {
                check_body(it, &a0(), span, "wfile.write");
            }
            (Value::None, None)
        }
        "re.Pattern" => {
            let pattern = o
                .field("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            match name {
                "sub" | "subn" => (
                    regex_sub(
                        &pattern,
                        arg(args, 0, "repl"),
                        &arg(args, 1, "string").cloned().unwrap_or_else(Value::clean),
                    ),
                    None,
                ),
                "match" | "fullmatch" | "search" | "findall" | "finditer" | "split" => {
                    (Value::Unknown(a0().taint()), None)
                }
                _ => (Value::clean(), None),
            }
        }
        "random.SystemRandom"
        | "hashlib.hash"
        | "subprocess.CompletedProcess"
        | "xml.dom.Document"
        | "xml.etree.Element" => (Value::clean(), None),
        "requests.Session" => match name {
            "get" | "post" | "put" | "delete" | "head" | "patch" | "options" | "request" => {
                let url = if name == "request" {
                    arg(args, 1, "url")
                } else {
                    arg(args, 0, "url")
                };
                it.sink(
                    &SSRF,
                    &url.cloned().unwrap_or_else(Value::clean),
                    span,
                    &format!("Session.{name}"),
                );
                check_verify(it, args, span, name);
                (Value::clean(), None)
            }
            _ => (Value::clean(), None),
        },
        "flask.Response" => match name {
            "set_cookie" => {
                check_cookie(it, args, span);
                (Value::None, None)
            }
            "set_data" => {
                check_body(it, &a0(), span, "Response.set_data");
                (Value::None, None)
            }
            _ => (Value::clean(), None),
        },
        "flask.Flask" => {
            if name == "run" && kwarg(args, "debug").and_then(|v| v.truthy()) == Some(true) {
                it.flag(&DEBUG_MODE, span, "app.run(debug=True)");
            }
            (Value::clean(), None)
        }
        "template" => {
            if name == "render" {
                return (Value::tainted_str(args_taint(args)), None);
            }
            (Value::clean(), None)
        }
        _ => (generic_method(it, recv, name, args, span), None),
    }
}

/// Methods on values the analyzer knows nothing about: well-known method
/// names still identify common sinks.
fn generic_method(it: &mut Interp, recv: &Value, name: &str, args: &[ArgVal], span: Span) -> Value {
    let a0 = arg(args, 0, "").cloned().unwrap_or_else(Value::clean);
    match name {
        // http.cookiejar's set_cookie(cookie) takes a single Cookie object.
        "set_cookie"
            if args.iter().filter(|a| !a.spread).count() >= 2 && !args.iter().any(|a| a.spread) =>
        {
            check_cookie(it, args, span)
        }
        "execute" | "executemany" | "executescript" | "raw" | "extra" | "mogrify"
            if !recv.is_tainted() && matches!(a0, Value::Str(_)) =>
        {
            it.sink(&SQLI, &a0, span, name);
        }
        "xpath" if !recv.is_tainted() => {
            it.sink(&XPATHI, &a0, span, "xpath");
        }
        "search_s" | "search_ext_s" => {
            it.sink(
                &LDAPI,
                &arg(args, 2, "filterstr")
                    .cloned()
                    .unwrap_or_else(Value::clean),
                span,
                name,
            );
        }
        // An application whose object the analysis could not follow; test
        // runners and task queues also take `debug=`.
        "run"
            if kwarg(args, "debug").and_then(|v| v.truthy()) == Some(true)
                && ["flask", "werkzeug", "bottle", "quart", "sanic"]
                    .iter()
                    .any(|f| imports(it, it.module(), f)) =>
        {
            it.flag(&DEBUG_MODE, span, "run(debug=True)");
        }
        "render_template_string" | "from_string" => {
            it.sink(&SSTI, &a0, span, name);
        }
        _ => {}
    }
    Value::Unknown(recv.taint().union(&args_taint(args)))
}

fn check_cookie(it: &mut Interp, args: &[ArgVal], span: Span) {
    if let Some(value) = arg(args, 1, "value") {
        it.sink(&WEAK_RANDOM, value, span, "значение cookie");
    }
    let secure = kwarg(args, "secure").map(|v| v.truthy());
    // Flask's set_cookie(key, value, max_age, expires, path, domain, secure, ...)
    let secure = secure.or_else(|| {
        args.iter()
            .filter(|a| a.name.is_none())
            .nth(6)
            .map(|a| a.value.truthy())
    });
    match secure {
        Some(Some(true)) | Some(None) => {}
        _ => it.flag(&INSECURE_COOKIE, span, "set_cookie без secure=True"),
    }
}
