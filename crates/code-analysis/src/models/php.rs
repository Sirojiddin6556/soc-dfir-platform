//! PHP: request superglobals, the standard library, the database, XML and
//! LDAP extensions, and output to the page.
//!
//! Output is checked in its HTML context: the markup a script writes
//! before a value (inline HTML and earlier `echo`s) decides whether the
//! value lands in text, an attribute, a script or a style sheet, and each
//! context needs its own escaping.

use super::common::*;
use crate::interp::{args_taint, is_const, ArgVal, Fact, FactOn, Interp, Model};
use crate::ir::{BinOp, Function, Param, Span};
use crate::rules::*;
use crate::value::*;
use std::rc::Rc;

pub struct Php;

/// Superglobals filled from the request.
const REQUEST: &[&str] = &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"];

/// `$_SERVER` keys the client controls.
fn server_key_tainted(key: &str) -> bool {
    key.starts_with("HTTP_")
        || matches!(
            key,
            "REQUEST_URI"
                | "QUERY_STRING"
                | "PHP_SELF"
                | "PATH_INFO"
                | "PATH_TRANSLATED"
                | "ORIG_PATH_INFO"
                | "REDIRECT_URL"
                | "REDIRECT_QUERY_STRING"
                | "CONTENT_TYPE"
                | "argv"
                | "PHP_AUTH_USER"
                | "PHP_AUTH_PW"
        )
}

/// Output alphabets of base64 and hex: no quotes, markup or separators.
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

/// `urlencode`: also no `/` or `:`, so it cannot change where a URL goes.
const URLENCODED_SAFE: u32 = ENCODED_SAFE | ctx::URL;

/// Values a number can take are safe everywhere but in a session.
const NUMERIC: u32 = ctx::ALL & !ctx::SESSION;

/// `htmlspecialchars` with `ENT_QUOTES`, the default since PHP 8.1.
const HTML_QUOTES: u32 =
    ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE | ctx::HTML_ENCODED | ctx::TEMPLATE;

/// `addslashes`, `mysqli_real_escape_string` and the like.
const SLASHES: u32 = ctx::ESCAPED_QUOTES;

const ENT_QUOTES: i64 = 3;
const LIBXML_NOENT: i64 = 2;
const LIBXML_DTDLOAD: i64 = 4;
const CURLOPT_URL: i64 = 10002;
const CURLOPT_SSL_VERIFYPEER: i64 = 64;
const CURLOPT_SSL_VERIFYHOST: i64 = 81;

/// Values of the predefined constants the model looks at.
fn constant(name: &str) -> Option<Value> {
    let i = |v: i64| Some(Value::Int(v));
    match name {
        "ENT_COMPAT" => i(2),
        "ENT_QUOTES" => i(ENT_QUOTES),
        "ENT_NOQUOTES" => i(0),
        "ENT_HTML401" => i(0),
        "ENT_XML1" => i(16),
        "ENT_XHTML" => i(32),
        "ENT_HTML5" => i(48),
        "ENT_IGNORE" => i(4),
        "ENT_SUBSTITUTE" => i(8),
        "ENT_DISALLOWED" => i(128),
        "FILTER_VALIDATE_INT" => i(257),
        "FILTER_VALIDATE_BOOLEAN" | "FILTER_VALIDATE_BOOL" => i(258),
        "FILTER_VALIDATE_FLOAT" => i(259),
        "FILTER_VALIDATE_REGEXP" => i(272),
        "FILTER_VALIDATE_URL" => i(273),
        "FILTER_VALIDATE_EMAIL" => i(274),
        "FILTER_VALIDATE_IP" => i(275),
        "FILTER_VALIDATE_MAC" => i(276),
        "FILTER_VALIDATE_DOMAIN" => i(277),
        "FILTER_DEFAULT" | "FILTER_UNSAFE_RAW" => i(516),
        "FILTER_SANITIZE_STRING" | "FILTER_SANITIZE_STRIPPED" => i(513),
        "FILTER_SANITIZE_ENCODED" => i(514),
        "FILTER_SANITIZE_SPECIAL_CHARS" => i(515),
        "FILTER_SANITIZE_EMAIL" => i(517),
        "FILTER_SANITIZE_URL" => i(518),
        "FILTER_SANITIZE_NUMBER_INT" => i(519),
        "FILTER_SANITIZE_NUMBER_FLOAT" => i(520),
        "FILTER_SANITIZE_MAGIC_QUOTES" => i(521),
        "FILTER_SANITIZE_FULL_SPECIAL_CHARS" => i(522),
        "FILTER_SANITIZE_ADD_SLASHES" => i(523),
        "FILTER_CALLBACK" => i(1024),
        "INPUT_POST" => i(0),
        "INPUT_GET" => i(1),
        "INPUT_COOKIE" => i(2),
        "INPUT_ENV" => i(4),
        "INPUT_SERVER" => i(5),
        "LIBXML_NOENT" => i(LIBXML_NOENT),
        "LIBXML_DTDLOAD" => i(LIBXML_DTDLOAD),
        "LIBXML_DTDATTR" => i(8),
        "LIBXML_NONET" => i(2048),
        "CURLOPT_URL" => i(CURLOPT_URL),
        "CURLOPT_SSL_VERIFYPEER" => i(CURLOPT_SSL_VERIFYPEER),
        "CURLOPT_SSL_VERIFYHOST" => i(CURLOPT_SSL_VERIFYHOST),
        "JSON_HEX_TAG" => i(1),
        "JSON_HEX_AMP" => i(2),
        "JSON_HEX_APOS" => i(4),
        "JSON_HEX_QUOT" => i(8),
        "LDAP_ESCAPE_FILTER" => i(1),
        "LDAP_ESCAPE_DN" => i(2),
        "E_ALL" => i(32767),
        "PHP_EOL" => Some(Value::str("\n")),
        "DIRECTORY_SEPARATOR" => Some(Value::str("/")),
        "PHP_VERSION" | "PHP_OS" | "PHP_OS_FAMILY" | "__DIR__" | "__FILE__" | "__CLASS__"
        | "__FUNCTION__" | "__METHOD__" | "__NAMESPACE__" => Some(Value::clean()),
        "__LINE__" | "PHP_INT_MAX" | "PHP_INT_MIN" | "PHP_INT_SIZE" | "M_PI" => {
            Some(Value::clean())
        }
        _ => None,
    }
}

impl Model for Php {
    fn ref_attr(&self, _it: &mut Interp, path: &str, taint: &Taint, name: &str) -> Value {
        Value::Ref(format!("{path}.{name}").into(), taint.clone())
    }

    fn call_ref(
        &self,
        it: &mut Interp,
        path: &str,
        taint: &Taint,
        args: &[ArgVal],
        span: Span,
    ) -> Value {
        let name = path.trim_start_matches('\\').to_ascii_lowercase();
        if let Some((class, method)) = name.split_once('.') {
            return static_call(it, class, method, taint, args, span);
        }
        if let Some(v) = new_object(it, &name, args, span) {
            return v;
        }
        function(it, &name, args, span)
    }

    fn call_method(
        &self,
        it: &mut Interp,
        recv: &Value,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>) {
        let lname = name.to_ascii_lowercase();
        if let Value::Obj(o) = recv {
            if o.def.is_none() {
                if let Some(r) = object_method(it, o, &lname, args, span) {
                    return r;
                }
            }
        }
        (generic_method(it, recv, &lname, args, span), None)
    }

    fn index(&self, it: &mut Interp, base: &Value, key: &Value) -> Option<Value> {
        let k = key.as_str().or_else(|| key.as_int().map(|i| i.to_string()));
        match base {
            Value::Unknown(t) if t.is_tainted() => {
                // `$_GET['id']`: name the parameter in the finding.
                let first = &t.sources[0];
                // `$_FILES['f']['tmp_name']` is where PHP stored the upload,
                // and its size and error code are numbers PHP sets; the
                // client chooses only the name and type.
                if first.what.starts_with("$_FILES[")
                    && matches!(k.as_deref(), Some("tmp_name" | "size" | "error"))
                {
                    return Some(Value::clean());
                }
                if !first.weak_random && REQUEST.contains(&&*first.what) {
                    if let Some(k) = &k {
                        let mut src = it.source(&format!("{}['{k}']", first.what));
                        src.safe = t.safe;
                        return Some(Value::Unknown(src));
                    }
                }
                Some(Value::Unknown(t.clone()))
            }
            Value::Ref(p, _) if &**p == "$_SERVER" => Some(match k {
                Some(k) if server_key_tainted(&k) => {
                    let mut t = it.source(&format!("$_SERVER['{k}']"));
                    // The path of this request starts with `/` on this
                    // site: linking or redirecting to it stays here.
                    if matches!(
                        k.as_str(),
                        "REQUEST_URI"
                            | "PHP_SELF"
                            | "PATH_INFO"
                            | "ORIG_PATH_INFO"
                            | "REDIRECT_URL"
                    ) {
                        t.safe |= ctx::URL | ctx::SCHEME;
                    }
                    Value::Unknown(t)
                }
                _ => Value::clean(),
            }),
            Value::Ref(p, _) if &**p == "$_SESSION" => Some(if it.external_sources {
                Value::Unknown(it.source("$_SESSION"))
            } else {
                Value::clean()
            }),
            Value::None => Some(Value::None),
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
            Value::Ref(p, _) if &**p == "$_SESSION" => {
                let k = key.as_str().unwrap_or_default();
                it.sink(&TRUST, value, span, &format!("$_SESSION['{k}']"));
                Some(base.clone())
            }
            // Writing to an unset variable makes an array.
            Value::None => Some(match key {
                Value::Int(0) => Value::list(vec![value.clone()]),
                k if is_const_key(k) => Value::Dict(Rc::new(vec![(k.clone(), value.clone())])),
                _ => Value::Unknown(value.taint().union(&key.taint())),
            }),
            // A list given a string key, or an index past its end, becomes
            // a map with the list's indexes as keys.
            Value::List(items) => {
                let n = items.len() as i64;
                match key {
                    Value::Int(i) if (0..n).contains(i) => None,
                    Value::Int(i) if *i == n => {
                        let mut items = items.as_ref().clone();
                        items.push(value.clone());
                        Some(Value::list(items))
                    }
                    k if is_const_key(k) => {
                        let mut pairs: Vec<(Value, Value)> = items
                            .iter()
                            .enumerate()
                            .map(|(i, v)| (Value::Int(i as i64), v.clone()))
                            .collect();
                        pairs.push((k.clone(), value.clone()));
                        Some(Value::Dict(Rc::new(pairs)))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn binop(&self, _it: &mut Interp, op: BinOp, l: &Value, r: &Value) -> Option<Value> {
        match op {
            // `+` on arrays is a union; on anything else it is arithmetic.
            BinOp::Add => match (l, r) {
                (Value::Dict(a), Value::Dict(b)) => {
                    let mut pairs = a.as_ref().clone();
                    for (k, v) in b.iter() {
                        if !pairs.iter().any(|(pk, _)| pk == k) {
                            pairs.push((k.clone(), v.clone()));
                        }
                    }
                    Some(Value::Dict(Rc::new(pairs)))
                }
                (Value::List(_) | Value::Dict(_), _) | (_, Value::List(_) | Value::Dict(_)) => {
                    Some(Value::Unknown(l.taint().union(&r.taint())))
                }
                _ => Some(arithmetic(op, l, r)),
            },
            BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::Pow => {
                Some(arithmetic(op, l, r))
            }
            _ => None,
        }
    }

    fn builtin(&self, it: &mut Interp, name: &str) -> Value {
        if REQUEST.contains(&name) {
            return Value::Unknown(it.source(name));
        }
        match name {
            "$_SERVER" | "$_SESSION" => return Value::Ref(name.into(), Taint::clean()),
            "$_ENV" | "$GLOBALS" | "$this" | "$http_response_header" => return Value::clean(),
            _ => {}
        }
        if name.starts_with('$') {
            if let Some(v) = it.php_object_var(name) {
                return v;
            }
            if name == "$wpdb" {
                return obj("wpdb");
            }
            // An unset variable is null.
            return Value::None;
        }
        if let Some(v) = constant(name) {
            return v;
        }
        if let Some(v) = it.php_const(name) {
            return v;
        }
        match name.to_ascii_lowercase().as_str() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "null" => Value::None,
            _ => Value::Ref(name.into(), Taint::clean()),
        }
    }

    fn entry_param(
        &self,
        it: &mut Interp,
        _module: usize,
        _func: &Function,
        _route: Option<&crate::interp::Route>,
        _index: usize,
        param: &Param,
    ) -> Value {
        match &param.ty {
            Some(ty) => self.coerce(it, ty, Value::clean()),
            None => Value::clean(),
        }
    }

    fn sanitizer_of(&self, qualname: &str) -> u32 {
        let last = qualname.rsplit('.').next().unwrap_or(qualname);
        name_sanitizer(last)
    }

    fn refine_method(
        &self,
        _recv: &Value,
        _name: &str,
        _args: &[Value],
        _truth: bool,
    ) -> Vec<(FactOn, Fact)> {
        Vec::new()
    }

    fn refine_call(&self, name: &str, args: &[Value], truth: bool) -> Vec<(FactOn, Fact)> {
        let lname = name.trim_start_matches('\\').to_ascii_lowercase();
        let on = |i: usize, f: Fact| vec![(FactOn::Arg(i), f)];
        match (lname.as_str(), truth) {
            ("preg_match", true) => {
                let Some(re) = args.first().and_then(|a| a.as_str()) else {
                    return Vec::new();
                };
                match regex_check_safety(&re) {
                    Some(bits) => on(1, Fact::Safe(bits)),
                    None => Vec::new(),
                }
            }
            ("in_array", true) => match args.get(1) {
                Some(Value::List(items)) if items.iter().all(is_const) && !items.is_empty() => {
                    on(0, Fact::OneOf(items.as_ref().clone()))
                }
                Some(Value::Dict(pairs)) if pairs.iter().all(|(_, v)| is_const(v)) => on(
                    0,
                    Fact::OneOf(pairs.iter().map(|(_, v)| v.clone()).collect()),
                ),
                _ => Vec::new(),
            },
            (
                "is_numeric" | "is_int" | "is_integer" | "is_long" | "is_float" | "is_double"
                | "ctype_digit",
                true,
            ) => on(0, Fact::Safe(NUMERIC | ctx::NUMBER)),
            (
                "ctype_xdigit" | "ctype_alnum" | "ctype_alpha" | "ctype_upper" | "ctype_lower",
                true,
            ) => on(0, Fact::Safe(NUMERIC)),
            // WordPress: 0 for a relative path without `..`.
            ("validate_file", false) => on(0, Fact::Safe(ctx::PATH)),
            ("filter_var", true) => match args.get(1).and_then(|f| f.as_int()) {
                Some(257..=259) => on(0, Fact::Safe(NUMERIC)),
                Some(275) => on(0, Fact::Safe(NUMERIC & !ctx::PATH & !ctx::URL)),
                _ => Vec::new(),
            },
            ("strpos" | "stripos" | "str_contains", false) => {
                match args.get(1).and_then(|a| a.as_str()) {
                    Some(n) => on(0, Fact::NotContains(n)),
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }

    fn facts_safety(&self, facts: &[Fact], _value: &Value) -> u32 {
        literal_check_safety(facts)
    }

    /// Strings PHP makes from values: `null` and `false` are empty, `true`
    /// is "1", and an object needs `__toString` (without one the script
    /// stops with an error, so nothing of it reaches the string).
    /// Functions that receive no request data follow their clean calls
    /// only a few frames deep, as in Java: a function that reads the
    /// request itself is an entry of its own.
    fn quiet_entries(&self) -> bool {
        true
    }

    fn library_over_project(&self, name: &str) -> bool {
        WORDPRESS.contains(&name.to_ascii_lowercase().as_str())
    }

    fn stringify(&self, it: &mut Interp, value: Value) -> Value {
        match value {
            Value::None | Value::Bool(false) => Value::str(""),
            Value::Bool(true) => Value::str("1"),
            Value::Obj(ref o) if o.def.is_some() => {
                if !it.has_method(&value, "__toString") {
                    return Value::str("");
                }
                let span = it.span();
                let (v, _) = it.call_method(&value, "__toString", &[], span);
                match v {
                    Value::None => Value::str(""),
                    v => v,
                }
            }
            Value::OneOf(alts) => {
                let vals: Vec<Value> = alts.iter().map(|a| self.stringify(it, a.clone())).collect();
                join_all(vals.into_iter()).unwrap_or_else(Value::clean)
            }
            other => other,
        }
    }

    fn coerce(&self, it: &mut Interp, ty: &str, value: Value) -> Value {
        let t = ty.trim().trim_start_matches('?').trim_start_matches('\\');
        match t.to_ascii_lowercase().as_str() {
            "int" | "integer" | "float" | "double" | "real" | "bool" | "boolean" => numeric(&value),
            "string" | "binary" | "mixed" | "" => value,
            "array" | "iterable" => match value {
                Value::List(_) | Value::Dict(_) => value,
                Value::None => Value::list(Vec::new()),
                other => Value::Unknown(other.taint()),
            },
            "unset" => Value::None,
            lower => {
                if !matches!(value, Value::Unknown(_) | Value::None) {
                    return value;
                }
                if let Some(class) = api_class(lower) {
                    return Value::Obj(Rc::new(Obj::new(class)));
                }
                match it.java_type_class(t) {
                    Some(cv) => Value::Obj(Rc::new(Obj {
                        class: cv.qualname.clone(),
                        def: Some(cv),
                        fields: Vec::new(),
                        taint: value.taint(),
                    })),
                    None => value,
                }
            }
        }
    }
}

fn is_const_key(k: &Value) -> bool {
    matches!(k, Value::Int(_)) || k.as_str().is_some()
}

/// Library classes the model knows, by lowercase name.
fn api_class(lower: &str) -> Option<&'static str> {
    Some(match lower {
        "pdo" => "PDO",
        "pdostatement" => "PDOStatement",
        "mysqli" => "mysqli",
        "mysqli_stmt" => "mysqli_stmt",
        "sqlite3" => "SQLite3",
        "domdocument" => "DOMDocument",
        "domxpath" => "DOMXPath",
        "simplexmlelement" => "SimpleXMLElement",
        "xmlreader" => "XMLReader",
        "soapclient" => "SoapClient",
        "splfileobject" => "SplFileObject",
        "ziparchive" => "ZipArchive",
        "twig_loader_string" => "Twig_Loader_String",
        "twig_loader_array" | "arrayloader" => "Twig_Loader_Array",
        "twig_environment" | "environment" => "Twig_Environment",
        "smarty" => "Smarty",
        _ => return None,
    })
}

fn obj(class: &str) -> Value {
    Value::Obj(Rc::new(Obj::new(class)))
}

/// `array_map($f, $a)`: `$f` applied to each element.
fn map_elements(it: &mut Interp, f: &Value, arr: &Value, span: Span) -> Value {
    let call = |it: &mut Interp, v: &Value| it.call_value(f, &[ArgVal::plain(v.clone())], span);
    match arr {
        Value::List(items) => Value::list(items.iter().map(|v| call(it, v)).collect()),
        Value::Dict(pairs) => Value::Dict(Rc::new(
            pairs
                .iter()
                .map(|(k, v)| (k.clone(), call(it, v)))
                .collect(),
        )),
        other => {
            let one = call(it, &other.element());
            Value::Unknown(one.taint())
        }
    }
}

/// `count()` of an array with known slots, and type checks of a value whose
/// type is certain (`is_array($args[0])` for a string argument).
fn known_number(name: &str, args: &[ArgVal], a0: &Value) -> Option<Value> {
    if args.len() != 1 {
        return None;
    }
    let want = match name {
        "count" | "sizeof" => {
            return match a0 {
                Value::List(items) => Some(Value::Int(items.len() as i64)),
                Value::Dict(items) => Some(Value::Int(items.len() as i64)),
                _ => None,
            };
        }
        "is_numeric" => {
            return match a0 {
                Value::Unknown(t) if t.is_tainted() && t.safe & ctx::NUMBER != 0 => {
                    Some(Value::Bool(true))
                }
                Value::Int(_) | Value::Float(_) => Some(Value::Bool(true)),
                Value::None | Value::Bool(_) | Value::List(_) | Value::Dict(_) | Value::Obj(_) => {
                    Some(Value::Bool(false))
                }
                _ => None,
            };
        }
        "is_array" => 5,
        "is_string" => 4,
        "is_int" => 2,
        "is_bool" => 1,
        "is_null" => 0,
        _ => return None,
    };
    crate::interp::kind_of(a0).map(|k| Value::Bool(k == want))
}

/// A number made from `v` (`intval`, `(int)`, `$x + 0`).
fn numeric(v: &Value) -> Value {
    match v {
        Value::Int(_) | Value::Float(_) | Value::Bool(_) => v.clone(),
        Value::None => Value::Int(0),
        other => match other.as_str() {
            Some(s) => {
                let digits: String = s
                    .trim_start()
                    .chars()
                    .enumerate()
                    .take_while(|(i, c)| {
                        c.is_ascii_digit() || (*i == 0 && (*c == '-' || *c == '+'))
                    })
                    .map(|(_, c)| c)
                    .collect();
                Value::Int(digits.parse().unwrap_or(0))
            }
            None => Value::Unknown(other.taint().with_safe(NUMERIC | ctx::NUMBER)),
        },
    }
}

fn arithmetic(op: BinOp, l: &Value, r: &Value) -> Value {
    if let (Some(a), Some(b)) = (l.as_int(), r.as_int()) {
        let v = match op {
            BinOp::Add => a.checked_add(b),
            BinOp::Sub => a.checked_sub(b),
            BinOp::Mul => a.checked_mul(b),
            BinOp::Mod if b != 0 => a.checked_rem(b),
            _ => None,
        };
        if let Some(v) = v {
            return Value::Int(v);
        }
    }
    Value::Unknown(l.taint().union(&r.taint()).with_safe(NUMERIC | ctx::NUMBER))
}

fn a(args: &[ArgVal], i: usize) -> Value {
    args.iter()
        .filter(|a| a.name.is_none())
        .nth(i)
        .map(|a| a.value.clone())
        .unwrap_or(Value::None)
}

/// A by-reference argument: the variable it names is set to `value`.
fn set_ref(it: &mut Interp, args: &[ArgVal], i: usize, value: Value) {
    if let Some(var) = args
        .iter()
        .filter(|a| a.name.is_none())
        .nth(i)
        .and_then(|a| a.var.clone())
    {
        it.set_var(&var, value);
    }
}

/// Data from outside the request (a file, a command, the session): only
/// untrusted with `external_sources`.
fn external(it: &Interp, what: &str) -> Value {
    if it.external_sources {
        Value::Unknown(it.source(what))
    } else {
        Value::clean()
    }
}

fn all_taint(args: &[ArgVal]) -> Value {
    Value::Unknown(args_taint(args))
}

/// The text of a value with its unknown pieces kept.
fn as_text(v: &Value) -> Value {
    match v {
        Value::Str(_) => v.clone(),
        Value::Int(i) => Value::str(i.to_string()),
        Value::None | Value::Bool(false) => Value::str(""),
        Value::Bool(true) => Value::str("1"),
        other => Value::segs(other.to_segs()),
    }
}

/// `new Class(...)` of a library class.
fn new_object(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Option<Value> {
    let class = api_class(name)?;
    match class {
        "SimpleXMLElement" => {
            // new SimpleXMLElement($data, $options, $dataIsURL)
            check_xxe(it, &a(args, 0), &a(args, 1), span, "SimpleXMLElement");
            if a(args, 2).truthy() == Some(true) {
                it.sink(&SSRF, &a(args, 0), span, "SimpleXMLElement");
            }
        }
        "SoapClient" => {
            it.sink(&SSRF, &a(args, 0), span, "SoapClient");
        }
        "SplFileObject" => {
            it.sink(&PATH, &a(args, 0), span, "SplFileObject");
        }
        // Twig templates given as text: `new ArrayLoader(['t' => $src])`.
        "Twig_Loader_Array" => {
            if let Value::Dict(pairs) = a(args, 0) {
                for (_, v) in pairs.iter() {
                    it.sink(&SSTI, v, span, "Twig ArrayLoader");
                }
            }
        }
        "Twig_Environment" => {
            // `\Twig\Environment` is a common class name: only with a Twig
            // loader is it Twig's.
            let loader = a(args, 0);
            let Value::Obj(l) = &loader else {
                return None;
            };
            if !l.class.starts_with("Twig_Loader") {
                return None;
            }
            let string_loader = l.class.as_ref() == "Twig_Loader_String";
            return Some(Value::Obj(Rc::new(
                Obj::new(class).with_field("string_loader", Value::Bool(string_loader)),
            )));
        }
        "PDO" => {
            if let Some(dsn) = a(args, 0).as_str() {
                let mut o = Obj::new(class);
                o.set_field("dsn", Value::str(dsn));
                return Some(Value::Obj(Rc::new(o)));
            }
        }
        _ => {}
    }
    Some(obj(class))
}

/// `Class::method(...)` of a class outside the project.
fn static_call(
    it: &mut Interp,
    class: &str,
    method: &str,
    taint: &Taint,
    args: &[ArgVal],
    span: Span,
) -> Value {
    let a0 = a(args, 0);
    match (class, method) {
        // Laravel and similar query builders
        ("db", "select" | "statement" | "unprepared" | "insert" | "update" | "delete" | "raw")
        | ("db", "selectone" | "affectingstatement") => {
            it.sink(&SQLI, &a0, span, &format!("DB::{method}"));
            Value::clean()
        }
        ("pdo", "quote") => quoted_sql(&a0),
        ("esapi" | "encoder", _) => all_taint(args),
        _ => Value::Unknown(taint.union(&args_taint(args))),
    }
}

/// A value `PDO::quote` or `pg_escape_literal` wrapped in quotes.
fn quoted_sql(v: &Value) -> Value {
    match v.as_str() {
        Some(s) => Value::str(format!("'{}'", s.replace('\'', "''"))),
        None => Value::tainted_str(v.taint().with_safe(ctx::SQL | ctx::ESCAPED_QUOTES)),
    }
}

/// Library functions.
fn function(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Value {
    let a0 = a(args, 0);
    match name {
        // ----- helpers the front end emits -----
        "__php_append" => append(&a0, a(args, 1)),
        "__php_pairs" => pairs(&a0),
        "__php_global" => {
            let n = a0.as_str().unwrap_or_default();
            it.php_global(&n)
        }
        "include" | "include_once" | "require" | "require_once" => {
            include(it, &a0, span);
            Value::clean()
        }
        "define" => {
            if let Some(n) = a0.as_str() {
                it.php_define(&n, a(args, 1));
            }
            Value::Bool(true)
        }

        // ----- output -----
        "echo" | "print" => {
            for v in args {
                output(it, &v.value, span, name);
            }
            Value::Int(1)
        }
        "printf" | "vprintf" => {
            let s = if name == "printf" {
                sprintf(
                    &a0,
                    &args[1.min(args.len())..]
                        .iter()
                        .map(|a| a.value.clone())
                        .collect::<Vec<_>>(),
                )
            } else {
                sprintf(&a0, &list_items(&a(args, 1)))
            };
            output(it, &s, span, name);
            Value::clean()
        }
        "print_r" | "var_export" => {
            if a(args, 1).truthy() == Some(true) {
                return Value::Unknown(a0.taint());
            }
            output(it, &Value::Unknown(a0.taint()), span, name);
            Value::clean()
        }
        "var_dump" => {
            for v in args {
                output(it, &Value::Unknown(v.value.taint()), span, name);
            }
            Value::clean()
        }
        "die" | "exit" => {
            if !matches!(a0, Value::Int(_) | Value::None) {
                output(it, &a0, span, name);
            }
            Value::clean()
        }
        "header" => {
            header(it, &a0, span);
            Value::clean()
        }
        "http_redirect" => {
            redirect(it, &a0, span, name);
            Value::clean()
        }
        "setcookie" | "setrawcookie" => {
            cookie(it, args, span);
            Value::Bool(true)
        }

        // ----- request data -----
        "getallheaders" | "apache_request_headers" => Value::Unknown(it.source(name)),
        "filter_input" => {
            let src = match a0.as_int() {
                Some(0) => "$_POST",
                Some(1) => "$_GET",
                Some(2) => "$_COOKIE",
                Some(5) => "$_SERVER",
                _ => return Value::clean(),
            };
            let key = a(args, 1).as_str().unwrap_or_default();
            if src == "$_SERVER" && !server_key_tainted(&key) {
                return Value::clean();
            }
            let v = Value::Unknown(it.source(&format!("{src}['{key}']")));
            filter(&v, &a(args, 2), &a(args, 3))
        }
        "filter_input_array" => Value::Unknown(it.source("filter_input_array")),
        "filter_var" => filter(&a0, &a(args, 1), &a(args, 2)),
        "getenv" => Value::clean(),

        // ----- numbers and checks -----
        "intval" | "floatval" | "doubleval" | "boolval" | "abs" | "round" | "floor" | "ceil"
        | "count" | "sizeof" | "strlen" | "mb_strlen" | "crc32" | "ord" | "array_sum"
        | "array_product" | "is_numeric" | "is_int" | "is_string" | "is_array" | "isset"
        | "empty" | "in_array" | "array_key_exists" | "is_null" | "strcmp" | "strcasecmp"
        | "strncmp" | "strncasecmp" | "preg_match_all" | "substr_count" | "time" | "mktime"
        | "strtotime" | "filesize" | "max" | "min" | "hexdec" | "octdec" | "bindec" | "ip2long"
        | "date" | "checkdate" | "version_compare" | "password_verify" | "hash_equals"
        | "ctype_digit" | "ctype_alnum" | "ctype_alpha" | "is_bool" | "is_object"
        | "is_callable" | "function_exists" | "class_exists" | "method_exists" | "defined"
        | "array_search" | "strpos" | "stripos" | "strrpos" | "str_contains"
        | "str_starts_with" | "str_ends_with" | "number_format" | "random_int" | "mt_srand"
        | "srand" | "microtime" | "memory_get_usage" | "connection_status" => {
            known_number(name, args, &a0).unwrap_or_else(|| match name {
                "intval" | "floatval" | "doubleval" | "boolval" => numeric(&a0),
                "max" | "min" => numeric(&all_taint(args)),
                _ => Value::Unknown(args_taint(args).with_safe(NUMERIC)),
            })
        }
        "settype" => {
            let ty = a(args, 1).as_str().unwrap_or_default().to_ascii_lowercase();
            if matches!(
                ty.as_str(),
                "int" | "integer" | "float" | "double" | "bool" | "boolean"
            ) {
                set_ref(it, args, 0, numeric(&a0));
            }
            Value::Bool(true)
        }
        "md5" | "sha1" | "hash" | "md5_file" | "sha1_file" | "hash_file" | "hash_hmac"
        | "crypt" | "password_hash" | "bin2hex" | "dechex" | "decbin" | "decoct" | "uniqid"
        | "spl_object_hash" => {
            if matches!(name, "md5" | "sha1" | "crypt") && is_password(args, 0) {
                it.flag(&WEAK_HASH, span, &format!("{name}() для пароля"));
            }
            if name == "hash" {
                let algo = a0.as_str().unwrap_or_default().to_ascii_lowercase();
                if matches!(algo.as_str(), "md5" | "sha1" | "md4" | "md2") && is_password(args, 1) {
                    it.flag(&WEAK_HASH, span, &format!("hash('{algo}') для пароля"));
                }
            }
            if matches!(name, "md5_file" | "sha1_file") {
                it.sink(&PATH, &a0, span, name);
            }
            if name == "uniqid" {
                return it.weak_random("uniqid()", span, args);
            }
            Value::Unknown(args_taint(args).with_safe(ENCODED_SAFE | ctx::URL | ctx::PATH))
        }

        // ----- randomness -----
        "rand" | "mt_rand" | "lcg_value" | "array_rand" | "str_shuffle" | "shuffle" => {
            it.weak_random(&format!("{name}()"), span, args)
        }
        "random_bytes" | "openssl_random_pseudo_bytes" => Value::clean(),

        // ----- strings -----
        "htmlspecialchars" | "htmlentities" => {
            let flags = a(args, 1).as_int().unwrap_or(ENT_QUOTES);
            let bits = match flags & 3 {
                3 => HTML_QUOTES,
                2 => ctx::HTML | ctx::NO_DQUOTE | ctx::HTML_ENCODED | ctx::TEMPLATE,
                _ => ctx::HTML | ctx::HTML_ENCODED | ctx::TEMPLATE,
            };
            as_text(&a0).sanitized(bits)
        }
        "strip_tags" => as_text(&a0).sanitized(ctx::HTML),
        "htmlspecialchars_decode"
        | "html_entity_decode"
        | "urldecode"
        | "rawurldecode"
        | "stripslashes"
        | "stripcslashes"
        | "base64_decode"
        | "hex2bin"
        | "quoted_printable_decode"
        | "convert_uudecode"
        | "str_rot13"
        | "strrev"
        | "json_decode"
        | "gzuncompress"
        | "gzinflate"
        | "gzdecode" => Value::Unknown(a0.taint().without_safe(!0)),
        "addslashes"
        | "addcslashes"
        | "mysql_real_escape_string"
        | "mysql_escape_string"
        | "pg_escape_string"
        | "pg_escape_bytea"
        | "sqlite_escape_string"
        | "db2_escape_string"
        | "esc_sql"
        | "quotemeta" => {
            let a = if matches!(name, "pg_escape_string" | "pg_escape_bytea") && args.len() > 1 {
                a(args, 1)
            } else {
                a0
            };
            as_text(&a).sanitized(SLASHES | ctx::HEADER | ctx::LOG)
        }
        "mysqli_real_escape_string" | "mysqli_escape_string" => {
            as_text(&a(args, 1)).sanitized(SLASHES | ctx::HEADER | ctx::LOG)
        }
        "pg_escape_literal" | "pg_escape_identifier" => {
            let v = if args.len() > 1 { a(args, 1) } else { a0 };
            quoted_sql(&v)
        }
        "escapeshellarg" | "escapeshellcmd" => as_text(&a0).sanitized(ctx::SHELL),
        "ldap_escape" => as_text(&a0).sanitized(ctx::LDAP),
        "urlencode" | "rawurlencode" => encoded(&a0, URLENCODED_SAFE),
        "base64_encode" | "convert_uuencode" => encoded(&a0, ENCODED_SAFE),
        "http_build_query" => encoded(&a0, URLENCODED_SAFE),
        "json_encode" => {
            let flags = a(args, 1).as_int().unwrap_or(0);
            let mut bits = ctx::NO_DQUOTE | ctx::HEADER | ctx::LOG;
            if flags & 1 != 0 {
                bits |= ctx::HTML;
            }
            if flags & 4 != 0 {
                bits |= ctx::NO_SQUOTE;
            }
            Value::tainted_str(all_taint(args).taint()).sanitized(bits)
        }
        "serialize" | "var_export_return" => Value::Unknown(a0.taint()),
        "sprintf" | "vsprintf" => {
            if name == "sprintf" {
                sprintf(
                    &a0,
                    &args
                        .iter()
                        .skip(1)
                        .map(|a| a.value.clone())
                        .collect::<Vec<_>>(),
                )
            } else {
                sprintf(&a0, &list_items(&a(args, 1)))
            }
        }
        "trim"
        | "ltrim"
        | "rtrim"
        | "chop"
        | "strtolower"
        | "strtoupper"
        | "mb_strtolower"
        | "mb_strtoupper"
        | "ucfirst"
        | "lcfirst"
        | "ucwords"
        | "nl2br"
        | "strval"
        | "utf8_encode"
        | "utf8_decode"
        | "iconv"
        | "mb_convert_encoding"
        | "wordwrap"
        | "str_pad"
        | "mb_str_pad"
        | "str_repeat"
        | "chunk_split"
        | "trim_all"
        | "normalizer_normalize" => {
            let v = match name {
                "iconv" => a(args, 2),
                _ => a0.clone(),
            };
            match (name, v.as_str()) {
                ("strtolower" | "mb_strtolower", Some(s)) => Value::str(s.to_lowercase()),
                ("strtoupper" | "mb_strtoupper", Some(s)) => Value::str(s.to_uppercase()),
                ("trim", Some(s)) if args.len() == 1 => Value::str(s.trim()),
                _ => {
                    let t = as_text(&v);
                    if name == "nl2br" {
                        t
                    } else if matches!(name, "str_pad" | "str_repeat" | "wordwrap" | "chunk_split")
                    {
                        Value::Unknown(args_taint(args))
                    } else {
                        t
                    }
                }
            }
        }
        "substr" | "mb_substr" | "strstr" | "stristr" | "strrchr" | "substr_replace" | "strtok"
        | "basename" | "dirname" | "pathinfo" | "realpath" | "strtr" | "ltrim_slash" => {
            let v = as_text(&a0);
            match name {
                // A file name without directories cannot leave the folder.
                "basename" => match v.as_str() {
                    Some(s) => Value::str(s.rsplit('/').next().unwrap_or(&s).to_string()),
                    None => Value::tainted_str(v.taint().with_safe(ctx::PATH)),
                },
                "substr_replace" | "strtr" => Value::Unknown(args_taint(args)),
                "realpath" => {
                    it.sink(&PATH, &a0, span, name);
                    Value::Unknown(v.taint())
                }
                _ => Value::Unknown(v.taint()),
            }
        }
        "str_replace" | "str_ireplace" => str_replace(&a0, &a(args, 1), &a(args, 2)),
        "preg_replace" => preg_replace(it, &a0, &a(args, 1), &a(args, 2), span),
        "preg_replace_callback" | "preg_replace_callback_array" | "preg_filter" => {
            Value::Unknown(a(args, 2).taint())
        }
        "preg_match" => {
            let subject = a(args, 1);
            set_ref(it, args, 2, Value::Unknown(subject.taint()));
            Value::Unknown(Taint::clean())
        }
        "preg_split" | "explode" | "str_split" | "mb_str_split" | "str_getcsv" | "preg_grep" => {
            let v = if name == "explode" { a(args, 1) } else { a0 };
            Value::Unknown(v.taint())
        }
        "implode" | "join" => {
            let (glue, items) = match (&a0, &a(args, 1)) {
                (g, Value::None) => (Value::str(""), g.clone()),
                (g @ (Value::List(_) | Value::Dict(_)), s) => (s.clone(), g.clone()),
                (g, items) => (g.clone(), items.clone()),
            };
            let vals = list_items(&items);
            if vals.is_empty() {
                return Value::Unknown(items.taint().union(&glue.taint()));
            }
            let mut parts = Vec::new();
            for (i, v) in vals.iter().enumerate() {
                if i > 0 {
                    parts.push(as_text(&glue));
                }
                parts.push(as_text(v));
            }
            concat(&parts)
        }

        // ----- arrays -----
        "array_values" => match &a0 {
            Value::Dict(p) => Value::list(p.iter().map(|(_, v)| v.clone()).collect()),
            v @ Value::List(_) => v.clone(),
            other => Value::Unknown(other.taint()),
        },
        "array_keys" => match &a0 {
            Value::Dict(p) => Value::list(p.iter().map(|(k, _)| k.clone()).collect()),
            Value::List(items) => {
                Value::list((0..items.len()).map(|i| Value::Int(i as i64)).collect())
            }
            other => Value::Unknown(other.taint()),
        },
        "array"
        | "compact"
        | "array_merge"
        | "array_merge_recursive"
        | "array_combine"
        | "array_slice"
        | "array_reverse"
        | "array_unique"
        | "array_filter"
        | "array_flip"
        | "array_column"
        | "array_fill"
        | "array_pad"
        | "array_diff"
        | "array_intersect"
        | "array_chunk"
        | "iterator_to_array"
        | "func_get_args"
        | "array_replace" => match (name, &a0) {
            (
                "array_reverse" | "array_unique" | "array_filter",
                v @ (Value::List(_) | Value::Dict(_)),
            ) => v.clone(),
            _ => all_taint(args),
        },
        "array_map" if args.len() == 2 => match it.callable(&a0) {
            Some(f) => map_elements(it, &f, &a(args, 1), span),
            None => Value::Unknown(a(args, 1).taint()),
        },
        "array_map" => Value::Unknown(
            args.iter()
                .skip(1)
                .fold(Taint::clean(), |t, a| t.union(&a.value.taint())),
        ),
        "array_pop" | "array_shift" | "end" | "reset" | "current" | "next" | "prev" | "key"
        | "array_key_first" | "array_key_last" | "each" => {
            let item = match &a0 {
                Value::List(items) => match name {
                    "array_pop" | "end" => items.last().cloned(),
                    "array_shift" | "reset" | "current" => items.first().cloned(),
                    _ => None,
                },
                _ => None,
            };
            item.unwrap_or_else(|| a0.element())
        }
        "array_push" | "array_unshift" => {
            let mut cur = a0.clone();
            for v in args.iter().skip(1) {
                cur = append(&cur, v.value.clone());
            }
            set_ref(it, args, 0, cur);
            Value::clean()
        }
        "sort" | "rsort" | "usort" | "uasort" | "uksort" | "ksort" | "krsort" | "asort"
        | "arsort" | "natsort" | "natcasesort" | "array_walk" | "array_splice" => {
            if !matches!(a0, Value::List(_) | Value::Dict(_)) {
                return Value::clean();
            }
            set_ref(it, args, 0, Value::Unknown(a0.taint()));
            Value::clean()
        }
        "extract" | "parse_str" => {
            if name == "parse_str" {
                set_ref(it, args, 1, Value::Unknown(a0.taint()));
            }
            Value::clean()
        }
        "range" => Value::clean(),

        // ----- code -----
        "eval" | "assert" | "create_function" => {
            let code = if name == "create_function" {
                a(args, 1)
            } else {
                a0
            };
            if name != "assert" || matches!(code, Value::Str(_) | Value::Unknown(_)) {
                it.sink(&CODEI, &code, span, name);
            }
            Value::Unknown(code.taint())
        }
        "call_user_func" | "call_user_func_array" | "forward_static_call" => {
            it.sink(&CODEI, &a0, span, name);
            Value::Unknown(args_taint(args))
        }
        "unserialize" | "igbinary_unserialize" | "yaml_parse" => {
            let restricted = match a(args, 1) {
                Value::Dict(opts) => opts.iter().any(|(k, v)| {
                    k.as_str().as_deref() == Some("allowed_classes")
                        && !matches!(v, Value::Bool(true))
                }),
                _ => false,
            };
            if !restricted {
                it.sink(&DESER, &a0, span, name);
            }
            Value::Unknown(a0.taint().without_safe(!0))
        }

        // ----- commands -----
        "system" | "exec" | "passthru" | "shell_exec" | "popen" | "proc_open" | "pcntl_exec"
        | "expect_popen" => {
            let cmd = &a0;
            if !matches!(cmd, Value::List(_)) {
                it.sink(&CMDI, cmd, span, name);
            }
            let out = external(it, &format!("вывод {name}()"));
            match name {
                "exec" => {
                    set_ref(it, args, 1, Value::Unknown(out.taint()));
                    out
                }
                "proc_open" => {
                    set_ref(it, args, 2, Value::Unknown(out.taint()));
                    Value::Obj(Rc::new(Obj {
                        class: "process".into(),
                        def: None,
                        fields: Vec::new(),
                        taint: out.taint(),
                    }))
                }
                "popen" => Value::Obj(Rc::new(Obj {
                    class: "stream".into(),
                    def: None,
                    fields: Vec::new(),
                    taint: out.taint(),
                })),
                _ => out,
            }
        }
        "mail" => {
            it.sink(&HEADER, &a(args, 3), span, "mail(): заголовки");
            it.sink(&CMDI, &a(args, 4), span, "mail(): параметры sendmail");
            Value::Bool(true)
        }

        // ----- files -----
        "fopen"
        | "file_get_contents"
        | "readfile"
        | "file"
        | "gzopen"
        | "bzopen"
        | "fpassthru_file"
        | "parse_ini_file"
        | "highlight_file"
        | "show_source"
        | "simplexml_load_file"
        | "getimagesize"
        | "exif_read_data"
        | "opendir"
        | "scandir"
        | "glob"
        | "dir" => {
            let path = a0.clone();
            if !is_remote(&path) {
                it.sink(&PATH, &path, span, name);
            } else {
                it.sink(&SSRF, &path, span, name);
            }
            // PHP opens URLs too: a name the user writes from its start
            // can be `http://internal/`.
            let url_aware = matches!(
                name,
                "fopen"
                    | "file_get_contents"
                    | "readfile"
                    | "file"
                    | "simplexml_load_file"
                    | "getimagesize"
            );
            if url_aware && !is_remote(&path) && starts_free(&as_text(&path)) {
                it.sink(&SSRF, &path, span, name);
            }
            if name == "simplexml_load_file" {
                check_xxe(it, &path, &a(args, 2), span, name);
            }
            let content = external(it, &format!("файл ({name})"));
            match name {
                "fopen" | "gzopen" | "bzopen" | "opendir" => Value::Obj(Rc::new(Obj {
                    class: "stream".into(),
                    def: None,
                    fields: Vec::new(),
                    taint: content.taint(),
                })),
                "readfile" => Value::clean(),
                _ => content,
            }
        }
        "file_put_contents" | "unlink" | "mkdir" | "rmdir" | "touch" | "chmod" | "chown"
        | "chgrp" | "tempnam" | "is_file" | "is_dir" | "file_exists" | "is_readable"
        | "is_writable" | "fileperms" | "filemtime" | "stat" | "lstat" | "is_link" | "readlink"
        | "finfo_file" | "mime_content_type" => {
            let p = if name == "finfo_file" { a(args, 1) } else { a0 };
            it.sink(&PATH, &p, span, name);
            Value::clean()
        }
        "copy" | "rename" | "symlink" | "link" | "move_uploaded_file" => {
            if name != "move_uploaded_file" {
                it.sink(&PATH, &a0, span, name);
            }
            it.sink(&PATH, &a(args, 1), span, name);
            Value::Bool(true)
        }
        "fgets"
        | "fread"
        | "fgetc"
        | "fgetcsv"
        | "fscanf"
        | "stream_get_contents"
        | "stream_get_line"
        | "readdir"
        | "gzread"
        | "gzgets" => Value::Unknown(a0.taint()),
        "fwrite" | "fputs" | "fclose" | "pclose" | "proc_close" | "fflush" | "flock"
        | "closedir" => Value::clean(),

        // ----- network -----
        "curl_init" => {
            if !matches!(a0, Value::None) {
                it.sink(&SSRF, &a0, span, name);
            }
            obj("CurlHandle")
        }
        "curl_setopt" => {
            curl_option(it, &a(args, 1), &a(args, 2), span);
            Value::Bool(true)
        }
        "curl_setopt_array" => {
            if let Value::Dict(opts) = a(args, 1) {
                for (k, v) in opts.iter() {
                    curl_option(it, k, v, span);
                }
            }
            Value::Bool(true)
        }
        "curl_exec" => external(it, "ответ curl_exec()"),
        "fsockopen" | "pfsockopen" | "stream_socket_client" | "get_headers" => {
            it.sink(&SSRF, &a0, span, name);
            Value::clean()
        }
        "stream_context_create" => {
            if let Value::Dict(opts) = &a0 {
                let ssl = opts
                    .iter()
                    .find(|(k, _)| k.as_str().as_deref() == Some("ssl"))
                    .map(|(_, v)| v.clone());
                if let Some(Value::Dict(ssl)) = ssl {
                    let off = ssl.iter().any(|(k, v)| {
                        matches!(
                            k.as_str().as_deref(),
                            Some("verify_peer" | "verify_peer_name")
                        ) && v.truthy() == Some(false)
                    });
                    if off {
                        it.flag(
                            &TLS_NO_VERIFY,
                            span,
                            "stream_context_create(verify_peer=false)",
                        );
                    }
                }
            }
            Value::clean()
        }

        // ----- SQL -----
        "mysql_query"
        | "mysql_unbuffered_query"
        | "sqlite_query"
        | "sqlite_exec"
        | "sqlite_array_query"
        | "sqlite_unbuffered_query"
        | "mssql_query"
        | "msql_query" => {
            it.sink(&SQLI, &a0, span, name);
            external_rows(it, name)
        }
        "mysql_db_query" => {
            it.sink(&SQLI, &a(args, 1), span, name);
            external_rows(it, name)
        }
        "mysqli_query" | "mysqli_multi_query" | "mysqli_real_query" | "mysqli_prepare"
        | "pg_send_query" | "sqlsrv_query" | "sqlsrv_prepare" | "odbc_exec" | "odbc_prepare"
        | "db2_exec" | "db2_prepare" | "oci_parse" | "ifx_query" | "ingres_query"
        | "maxdb_query" | "fbsql_query" | "cubrid_query" => {
            it.sink(&SQLI, &a(args, 1), span, name);
            external_rows(it, name)
        }
        // pg_query([$conn,] $query)
        "pg_query" | "pg_exec" => {
            let q = if args.len() >= 2 { a(args, 1) } else { a0 };
            it.sink(&SQLI, &q, span, name);
            external_rows(it, name)
        }
        "pg_query_params" => {
            let q = if args.len() >= 3 { a(args, 1) } else { a0 };
            it.sink(&SQLI, &q, span, name);
            external_rows(it, name)
        }
        "pg_prepare" => {
            let q = if args.len() >= 3 {
                a(args, 2)
            } else {
                a(args, 1)
            };
            it.sink(&SQLI, &q, span, name);
            Value::clean()
        }
        "mysql_connect"
        | "mysql_pconnect"
        | "mysql_select_db"
        | "mysql_close"
        | "mysqli_connect"
        | "mysqli_close"
        | "pg_connect"
        | "pg_close"
        | "mysqli_stmt_bind_param"
        | "mysqli_stmt_execute"
        | "pg_execute" => Value::clean(),
        "mysql_fetch_array"
        | "mysql_fetch_assoc"
        | "mysql_fetch_row"
        | "mysql_fetch_object"
        | "mysqli_fetch_array"
        | "mysqli_fetch_assoc"
        | "mysqli_fetch_row"
        | "mysqli_fetch_object"
        | "mysqli_fetch_all"
        | "pg_fetch_array"
        | "pg_fetch_assoc"
        | "pg_fetch_row"
        | "pg_fetch_object"
        | "pg_fetch_all"
        | "sqlite_fetch_array"
        | "odbc_fetch_array"
        | "mysql_result"
        | "pg_fetch_result" => Value::Unknown(a0.taint()),

        // ----- LDAP and XPath -----
        "ldap_search" | "ldap_list" | "ldap_read" => {
            it.sink(&LDAPI, &a(args, 2), span, name);
            Value::clean()
        }
        "simplexml_load_string" => {
            check_xxe(it, &a0, &a(args, 2), span, name);
            obj("SimpleXMLElement")
        }

        // ----- logs and configuration -----
        "error_log" | "syslog" => {
            let msg = if name == "syslog" { a(args, 1) } else { a0 };
            it.sink(&LOGI, &msg, span, name);
            Value::Bool(true)
        }
        "ini_set" => {
            let key = a0.as_str().unwrap_or_default();
            let on = match a(args, 1) {
                Value::Str(_) => a(args, 1).as_str().map(|s| {
                    matches!(
                        s.to_ascii_lowercase().as_str(),
                        "1" | "on" | "true" | "stdout"
                    )
                }),
                v => v.truthy(),
            };
            if key == "display_errors" && on == Some(true) {
                it.flag(&DEBUG_MODE, span, "ini_set('display_errors', 1)");
            }
            Value::clean()
        }
        "openssl_encrypt" | "openssl_decrypt" => {
            let method = a(args, 1).as_str().unwrap_or_default().to_ascii_lowercase();
            if weak_cipher(&method) {
                it.flag(&WEAK_CIPHER, span, &format!("{name}('{method}')"));
            }
            Value::Unknown(a0.taint())
        }
        "mcrypt_encrypt" | "mcrypt_decrypt" | "mcrypt_module_open" => {
            let cipher = a0.as_str().unwrap_or_default().to_ascii_lowercase();
            let mode = a(args, 3).as_str().unwrap_or_default().to_ascii_lowercase();
            if weak_cipher(&cipher) || mode == "ecb" {
                it.flag(&WEAK_CIPHER, span, &format!("{name}('{cipher}')"));
            }
            Value::Unknown(a(args, 2).taint())
        }

        _ => match wordpress(it, name, args, span) {
            Some(v) => v,
            None => all_taint(args),
        },
    }
}

/// WordPress functions whose behaviour is known: they are modelled even
/// when WordPress itself is part of the scanned code (see
/// `Model::library_over_project`), so that plugins and core read alike and
/// the formatting code behind them is not re-run at every call.
pub const WORDPRESS: &[&str] = &[
    "esc_html",
    "esc_html__",
    "esc_html_x",
    "esc_html_e",
    "esc_attr",
    "esc_attr__",
    "esc_attr_x",
    "esc_attr_e",
    "esc_textarea",
    "esc_xml",
    "esc_url",
    "esc_url_raw",
    "sanitize_url",
    "esc_js",
    "esc_sql",
    "wp_kses",
    "wp_kses_post",
    "wp_kses_data",
    "wp_filter_kses",
    "wp_filter_post_kses",
    "sanitize_text_field",
    "sanitize_textarea_field",
    "sanitize_key",
    "sanitize_title",
    "sanitize_title_with_dashes",
    "sanitize_html_class",
    "sanitize_user",
    "sanitize_file_name",
    "sanitize_email",
    "sanitize_mime_type",
    "sanitize_hex_color",
    "sanitize_hex_color_no_hash",
    "tag_escape",
    "absint",
    "wp_unslash",
    "stripslashes_deep",
    "wp_slash",
    "__",
    "_x",
    "_n",
    "_nx",
    "translate",
    "_e",
    "_ex",
    "apply_filters",
    "apply_filters_ref_array",
    "do_action",
    "wp_redirect",
    "wp_safe_redirect",
    "wp_remote_get",
    "wp_remote_post",
    "wp_remote_head",
    "wp_remote_request",
    "wp_safe_remote_get",
    "wp_safe_remote_post",
    "wp_safe_remote_head",
    "wp_safe_remote_request",
    "download_url",
    "wp_json_encode",
    "wp_send_json",
    "wp_send_json_success",
    "wp_send_json_error",
    "wp_die",
    "wp_unique_filename",
    "wp_basename",
    "wp_handle_upload",
    "wp_handle_sideload",
    "media_handle_upload",
    "media_handle_sideload",
    "validate_file",
    "validate_file_to_edit",
    "plugin_basename",
    "current_user_can",
    "is_user_logged_in",
    "wp_verify_nonce",
    "check_admin_referer",
    "check_ajax_referer",
    "get_current_user_id",
    "wp_create_nonce",
    "home_url",
    "site_url",
    "admin_url",
    "network_admin_url",
    "self_admin_url",
    "get_admin_url",
    "network_home_url",
    "network_site_url",
    "plugins_url",
    "content_url",
    "includes_url",
    "get_option",
    "get_site_option",
    "get_transient",
    "get_site_transient",
    "get_post_meta",
    "get_user_meta",
    "get_term_meta",
    "get_comment_meta",
    "get_metadata",
    "get_post",
    "get_posts",
    "get_page",
    "get_post_field",
    "get_term",
    "get_terms",
    "get_the_terms",
    "get_user_by",
    "get_userdata",
    "get_users",
    "get_comment",
    "get_comments",
    "wp_get_current_user",
    "get_bloginfo",
    "get_the_title",
    "get_the_content",
    "get_the_excerpt",
    "get_permalink",
    "get_the_permalink",
    "wp_get_attachment_url",
    "wp_upload_dir",
];

fn wordpress(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Option<Value> {
    let a0 = a(args, 0);
    let text = |bits: u32| as_text(&a0).sanitized(bits);
    // Entity-encoded like htmlspecialchars with ENT_QUOTES.
    let entities = HTML_QUOTES | ctx::HEADER | ctx::LOG;
    Some(match name {
        "esc_html" | "esc_html__" | "esc_html_x" | "esc_attr" | "esc_attr__" | "esc_attr_x"
        | "esc_textarea" | "esc_xml" => text(entities),
        "esc_html_e" | "esc_attr_e" => {
            output(it, &text(entities), span, name);
            Value::None
        }
        // Characters outside a URL removed, `'` and `&` encoded, and a
        // scheme outside the allowed list (`javascript:`) dropped.
        "esc_url" | "sanitize_url" => text(entities | ctx::SCHEME),
        "esc_url_raw" => text(ctx::HTML | ctx::NO_DQUOTE | ctx::SCHEME | ctx::HEADER | ctx::LOG),
        // Quotes backslash-escaped and `<>&"` encoded, for inline scripts.
        "esc_js" => {
            text(ctx::HTML | ctx::NO_DQUOTE | ctx::ESCAPED_QUOTES | ctx::HTML_ENCODED | ctx::LOG)
        }
        "esc_sql" => text(SLASHES),
        // Markup reduced to allowed tags: safe as page content.
        "wp_kses"
        | "wp_kses_post"
        | "wp_kses_data"
        | "wp_filter_kses"
        | "wp_filter_post_kses"
        | "sanitize_text_field"
        | "sanitize_textarea_field" => text(ctx::HTML | ctx::HEADER | ctx::LOG),
        "sanitize_key"
        | "sanitize_title"
        | "sanitize_title_with_dashes"
        | "sanitize_html_class"
        | "sanitize_mime_type"
        | "sanitize_hex_color"
        | "sanitize_hex_color_no_hash"
        | "tag_escape" => text(NUMERIC),
        "sanitize_user" => {
            text(ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE | ctx::HEADER | ctx::LOG)
        }
        "sanitize_file_name" => {
            text(ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE | ctx::PATH | ctx::HEADER | ctx::LOG)
        }
        "sanitize_email" => text(ctx::HTML | ctx::NO_DQUOTE | ctx::HEADER | ctx::LOG),
        "absint" => numeric(&a0),
        "wp_unslash" | "stripslashes_deep" => a0,
        "wp_slash" => text(SLASHES),
        // Translations return their text; `_e` prints it.
        "__" | "_x" | "translate" => a0,
        "_n" | "_nx" => join(&a0, &a(args, 1)),
        "_e" | "_ex" => {
            output(it, &a0, span, name);
            Value::None
        }
        // Hooks: what a filter returns is what it was given.
        "apply_filters" | "apply_filters_ref_array" => match name {
            "apply_filters" => a(args, 1),
            _ => list_items(&a(args, 1))
                .into_iter()
                .next()
                .unwrap_or_else(Value::clean),
        },
        "do_action" => Value::None,
        "wp_redirect" => {
            redirect(it, &a0, span, name);
            Value::Bool(true)
        }
        // Checked against the allowed hosts.
        "wp_safe_redirect" => Value::Bool(true),
        "wp_remote_get" | "wp_remote_post" | "wp_remote_head" | "wp_remote_request"
        | "download_url" => {
            it.sink(&SSRF, &a0, span, name);
            external(it, &format!("ответ {name}()"))
        }
        // Refuse local and private addresses.
        "wp_safe_remote_get"
        | "wp_safe_remote_post"
        | "wp_safe_remote_head"
        | "wp_safe_remote_request" => external(it, &format!("ответ {name}()")),
        "wp_json_encode" => text(ctx::NO_DQUOTE | ctx::HEADER | ctx::LOG),
        // JSON responses are not HTML pages.
        "wp_send_json" | "wp_send_json_success" | "wp_send_json_error" => Value::None,
        // The message is printed as HTML.
        "wp_die" => {
            output(it, &a0, span, name);
            Value::None
        }
        // The name is passed through sanitize_file_name() first.
        "wp_unique_filename" => as_text(&a(args, 1)).sanitized(
            ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE | ctx::PATH | ctx::HEADER | ctx::LOG,
        ),
        "wp_basename" => as_text(&a0).sanitized(ctx::PATH),
        // The stored file gets a sanitized, unique name in the uploads folder.
        "wp_handle_upload"
        | "wp_handle_sideload"
        | "media_handle_upload"
        | "media_handle_sideload" => Value::clean(),
        // 0 for a valid relative path (see refine_call).
        "validate_file" => Value::clean(),
        // Ends the request unless the file is valid and allowed.
        "validate_file_to_edit" => {
            if let Some(var) = args.first().and_then(|a| a.var.clone()) {
                it.set_var(&var, as_text(&a0).sanitized(ctx::PATH));
            }
            as_text(&a0).sanitized(ctx::PATH)
        }
        "plugin_basename" => as_text(&a0),
        "current_user_can"
        | "is_user_logged_in"
        | "wp_verify_nonce"
        | "check_admin_referer"
        | "check_ajax_referer"
        | "get_current_user_id"
        | "wp_create_nonce" => Value::clean(),
        // URLs of this site: the path given is appended to a fixed address.
        "home_url" | "site_url" | "admin_url" | "network_admin_url" | "self_admin_url"
        | "network_home_url" | "network_site_url" | "plugins_url" | "content_url"
        | "includes_url" => concat(&[Value::str("https://site.invalid/"), as_text(&a0)]),
        "get_admin_url" => concat(&[
            Value::str("https://site.invalid/wp-admin/"),
            as_text(&a(args, 1)),
        ]),
        // Stored data: the database, not the request.
        "get_option"
        | "get_site_option"
        | "get_transient"
        | "get_site_transient"
        | "get_post_meta"
        | "get_user_meta"
        | "get_term_meta"
        | "get_comment_meta"
        | "get_metadata"
        | "get_post"
        | "get_posts"
        | "get_page"
        | "get_post_field"
        | "get_term"
        | "get_terms"
        | "get_the_terms"
        | "get_user_by"
        | "get_userdata"
        | "get_users"
        | "get_comment"
        | "get_comments"
        | "wp_get_current_user"
        | "get_bloginfo"
        | "get_the_title"
        | "get_the_content"
        | "get_the_excerpt"
        | "get_permalink"
        | "get_the_permalink"
        | "wp_get_attachment_url"
        | "wp_upload_dir" => external(it, &format!("WordPress {name}()")),
        _ => return None,
    })
}

/// `$wpdb`, WordPress's database object, whether or not WordPress is part
/// of the scanned code.
fn wpdb_method(it: &mut Interp, name: &str, args: &[ArgVal], span: Span) -> Option<Value> {
    let a0 = a(args, 0);
    Some(match name {
        "query" | "get_results" | "get_row" | "get_var" | "get_col" => {
            it.sink(&SQLI, &a0, span, &format!("$wpdb->{name}"));
            external_rows(it, name)
        }
        // Placeholders are escaped and quoted: only the query text itself
        // can carry an injection.
        "prepare" => as_text(&a0),
        "esc_like" => as_text(&a0),
        "_real_escape" | "_escape" | "escape" => as_text(&a0).sanitized(SLASHES),
        _ => Value::clean(),
    })
}

fn external_rows(it: &Interp, name: &str) -> Value {
    external(it, &format!("результат {name}()"))
}

fn weak_cipher(method: &str) -> bool {
    method.contains("des")
        || method.contains("rc4")
        || method.contains("rc2")
        || method.starts_with("bf")
        || method.contains("blowfish")
        || method.ends_with("-ecb")
        || method.contains("_ecb")
}

/// Whether an argument holds a password: by its variable or the request
/// field it came from.
fn is_password(args: &[ArgVal], i: usize) -> bool {
    let Some(a) = args.iter().filter(|a| a.name.is_none()).nth(i) else {
        return false;
    };
    let pw = |s: &str| {
        name_words(s).any(|w| {
            matches!(
                w.as_str(),
                "password" | "passwd" | "pwd" | "pass" | "passphrase"
            )
        })
    };
    a.var.as_deref().map(pw).unwrap_or(false) || a.value.taint().sources.iter().any(|s| pw(&s.what))
}

fn encoded(v: &Value, bits: u32) -> Value {
    match v.as_str() {
        Some(_) => Value::clean(),
        None => Value::tainted_str(v.taint().with_safe(bits)),
    }
}

fn list_items(v: &Value) -> Vec<Value> {
    match v {
        Value::List(items) => items.as_ref().clone(),
        Value::Dict(pairs) => pairs.iter().map(|(_, v)| v.clone()).collect(),
        _ => Vec::new(),
    }
}

/// `$a[] = $v`
fn append(arr: &Value, v: Value) -> Value {
    match arr {
        Value::List(items) => {
            let mut items = items.as_ref().clone();
            items.push(v);
            Value::list(items)
        }
        Value::Dict(pairs) => {
            let next = pairs
                .iter()
                .filter_map(|(k, _)| k.as_int())
                .max()
                .map(|m| m + 1)
                .unwrap_or(0);
            let mut pairs = pairs.as_ref().clone();
            pairs.push((Value::Int(next), v));
            Value::Dict(Rc::new(pairs))
        }
        Value::None => Value::list(vec![v]),
        other => Value::Unknown(other.taint().union(&v.taint())),
    }
}

/// The `[key, value]` pairs `foreach ($a as $k => $v)` walks.
fn pairs(arr: &Value) -> Value {
    match arr {
        Value::List(items) => Value::list(
            items
                .iter()
                .enumerate()
                .map(|(i, v)| Value::list(vec![Value::Int(i as i64), v.clone()]))
                .collect(),
        ),
        Value::Dict(pairs) => Value::list(
            pairs
                .iter()
                .map(|(k, v)| Value::list(vec![k.clone(), v.clone()]))
                .collect(),
        ),
        other => Value::Unknown(other.taint()),
    }
}

/// PHP's `sprintf`: `%s`, `%d`, `%'.10d`, `%1$s` ...
fn sprintf(fmt: &Value, args: &[Value]) -> Value {
    let Some(f) = fmt.as_str() else {
        let t = args.iter().fold(fmt.taint(), |t, a| t.union(&a.taint()));
        return Value::tainted_str(t);
    };
    let mut out = Vec::new();
    let mut text = String::new();
    let mut next = 0usize;
    let chars: Vec<char> = f.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '%' {
            text.push(c);
            continue;
        }
        if chars.get(i) == Some(&'%') {
            text.push('%');
            i += 1;
            continue;
        }
        // argnum$
        let start = i;
        let mut num = String::new();
        while i < chars.len() && chars[i].is_ascii_digit() {
            num.push(chars[i]);
            i += 1;
        }
        let mut argnum = None;
        if chars.get(i) == Some(&'$') && !num.is_empty() {
            argnum = num.parse::<usize>().ok();
            i += 1;
        } else {
            i = start;
        }
        // flags, width, precision
        while i < chars.len() {
            match chars[i] {
                '-' | '+' | ' ' | '0' => i += 1,
                '\'' => i += 2,
                _ => break,
            }
        }
        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
            i += 1;
        }
        let conv = chars.get(i).copied().unwrap_or('s');
        i += 1;
        let v = match argnum {
            Some(n) => args.get(n.saturating_sub(1)).cloned(),
            None => {
                next += 1;
                args.get(next - 1).cloned()
            }
        }
        .unwrap_or(Value::None);
        out.push(Seg::Lit(std::mem::take(&mut text)));
        match conv {
            's' => out.extend(as_text(&v).to_segs()),
            _ => match numeric(&v) {
                Value::Int(n) => out.push(Seg::Lit(n.to_string())),
                other => out.push(Seg::Dyn(other.taint().with_safe(NUMERIC))),
            },
        }
    }
    out.push(Seg::Lit(text));
    Value::segs(out)
}

/// `str_replace($search, $replace, $subject)`, with arrays of searches.
fn str_replace(search: &Value, replace: &Value, subject: &Value) -> Value {
    let searches: Vec<Value> = match search {
        Value::List(_) | Value::Dict(_) => list_items(search),
        other => vec![other.clone()],
    };
    let replaces: Vec<Value> = match replace {
        Value::List(_) | Value::Dict(_) => list_items(replace),
        other => vec![other.clone(); searches.len().max(1)],
    };
    let mut cur = as_text(subject);
    let mut removed = String::new();
    for (i, s) in searches.iter().enumerate() {
        let Some(s) = s.as_str() else {
            return Value::Unknown(cur.taint().union(&s.taint()));
        };
        let r = replaces.get(i).cloned().unwrap_or(Value::str(""));
        if s.chars().count() == 1 {
            removed.push_str(&s);
        }
        cur = match &cur {
            Value::Str(segs) => replace_segs(segs, &s, &r),
            other => other.clone(),
        };
    }
    // Escaping the LDAP filter metacharacters.
    if ['\\', '*', '(', ')'].iter().all(|c| removed.contains(*c)) {
        cur = cur.sanitized(ctx::LDAP);
    }
    cur
}

/// Splits `/body/flags` (or `#body#i`, `~body~`) into its parts.
fn split_regex(re: &str) -> Option<(String, String)> {
    let mut chars = re.trim().chars();
    let open = chars.next()?;
    if open.is_alphanumeric() || open == '\\' {
        return None;
    }
    let close = match open {
        '(' => ')',
        '{' => '}',
        '[' => ']',
        '<' => '>',
        c => c,
    };
    let rest: String = chars.collect();
    let end = rest.rfind(close)?;
    Some((rest[..end].to_string(), rest[end + 1..].to_string()))
}

/// Safety a successful `preg_match` with this pattern proves about the
/// subject: only for patterns anchored at both ends.
fn regex_check_safety(re: &str) -> Option<u32> {
    let (body, flags) = split_regex(re)?;
    if !regex_anchored(&body, false) {
        return None;
    }
    let mut set = regex_chars(&body)?;
    if flags.contains('i') {
        set = set.case_insensitive();
    }
    let mut bits = set.safety();
    // `$` also matches before a final newline unless the pattern has /D.
    if body.ends_with('$') && !flags.contains('D') {
        bits &= !(ctx::HEADER | ctx::LOG);
    }
    Some(bits)
}

/// `preg_replace`: removing a class of characters leaves the rest; the
/// `/e` modifier runs the replacement as code.
fn preg_replace(
    it: &mut Interp,
    pattern: &Value,
    replacement: &Value,
    subject: &Value,
    span: Span,
) -> Value {
    if let (Value::List(pats), _) = (pattern, replacement) {
        let reps = match replacement {
            Value::List(r) => r.as_ref().clone(),
            other => vec![other.clone(); pats.len()],
        };
        let mut cur = subject.clone();
        for (i, p) in pats.iter().enumerate() {
            let r = reps.get(i).cloned().unwrap_or(Value::str(""));
            cur = preg_replace(it, p, &r, &cur, span);
        }
        return cur;
    }
    let taint = subject.taint().union(&replacement.taint());
    let Some((body, flags)) = pattern.as_str().as_deref().and_then(split_regex) else {
        return Value::tainted_str(taint.union(&pattern.taint()));
    };
    if flags.contains('e') {
        it.sink(
            &CODEI,
            &concat(&[replacement.clone(), subject.clone()]),
            span,
            "preg_replace /e",
        );
    }
    let rep = replacement.as_str();
    let class = if body.starts_with('[') && body.ends_with(']')
        || body.starts_with('\\') && body.chars().count() == 2
        || body.chars().count() == 1 && !".^$*+?()[]{}|".contains(body.as_str())
    {
        regex_chars(&body)
    } else {
        // `[^a-z]+`, `\W+`, `\W*`
        let trimmed = body.trim_end_matches(['+', '*']);
        if trimmed != body
            && (trimmed.starts_with('[') && trimmed.ends_with(']')
                || trimmed.starts_with('\\') && trimmed.chars().count() == 2)
        {
            regex_chars(trimmed)
        } else {
            None
        }
    };
    match (class, rep) {
        (Some(removed), Some(r)) if !r.contains('$') && !r.contains('\\') => {
            let removed = if flags.contains('i') {
                removed.case_insensitive()
            } else {
                removed
            };
            let mut left = removed.negate();
            for c in r.chars() {
                left.add(c);
            }
            let s = as_text(subject);
            match s.as_str() {
                Some(_) => Value::Unknown(Taint::clean()),
                None => Value::tainted_str(s.taint().with_safe(left.safety())),
            }
        }
        _ => Value::tainted_str(taint),
    }
}

/// `filter_var($v, FILTER, $options)`.
fn filter(v: &Value, filter: &Value, _options: &Value) -> Value {
    let id = filter.as_int().unwrap_or(516);
    let bits = match id {
        257..=259 => return numeric(v),
        275 | 276 => NUMERIC & !ctx::PATH & !ctx::URL,
        // Validated e-mail: `'`, `&`, `/` and `|` are allowed, `<` is not.
        274 | 517 => ctx::HTML | ctx::NO_DQUOTE | ctx::HEADER | ctx::LOG,
        273 | 518 => ctx::HEADER | ctx::LOG,
        519 => NUMERIC,
        520 => NUMERIC & !ctx::PATH,
        513 | 515 | 522 => HTML_QUOTES | ctx::HEADER | ctx::LOG,
        521 | 523 => SLASHES,
        514 => URLENCODED_SAFE,
        _ => 0,
    };
    as_text(v).sanitized(bits)
}

/// `include $file`: a file chosen by the user runs as code. A file of the
/// project included by a fixed name brings its variables along.
fn include(it: &mut Interp, path: &Value, span: Span) {
    if let Some(p) = path.as_str() {
        it.php_include(&p);
        return;
    }
    let alts = path.alternatives();
    let fixed: Vec<String> = alts.iter().filter_map(|a| a.as_str()).collect();
    if alts.len() > 1 && fixed.len() == alts.len() {
        it.php_include_any(&fixed);
        return;
    }
    it.sink(&FILE_INCLUSION, path, span, "include");
}

/// The value's first characters are not fixed text.
fn starts_free(v: &Value) -> bool {
    match v {
        Value::Str(segs) => matches!(segs.first(), Some(Seg::Dyn(_))),
        Value::OneOf(alts) => alts.iter().any(starts_free),
        _ => true,
    }
}

fn is_remote(v: &Value) -> bool {
    match v {
        Value::Str(segs) => match segs.first() {
            Some(Seg::Lit(t)) => {
                let t = t.trim_start().to_ascii_lowercase();
                t.starts_with("http://") || t.starts_with("https://") || t.starts_with("ftp://")
            }
            _ => false,
        },
        _ => false,
    }
}

fn check_xxe(it: &mut Interp, data: &Value, options: &Value, span: Span, what: &str) {
    let opts = options.as_int().unwrap_or(0);
    if opts & (LIBXML_NOENT | LIBXML_DTDLOAD) != 0 {
        it.sink(&XXE, data, span, what);
    }
}

fn curl_option(it: &mut Interp, opt: &Value, value: &Value, span: Span) {
    match opt.as_int() {
        Some(CURLOPT_URL) => {
            it.sink(&SSRF, value, span, "curl CURLOPT_URL");
        }
        Some(CURLOPT_SSL_VERIFYPEER | CURLOPT_SSL_VERIFYHOST) => {
            let off = match value {
                Value::Int(0) | Value::Bool(false) => true,
                v => v
                    .as_str()
                    .map(|s| s == "0" || s.is_empty())
                    .unwrap_or(false),
            };
            if off {
                it.flag(&TLS_NO_VERIFY, span, "curl: проверка сертификата отключена");
            }
        }
        _ => {}
    }
}

/// `header("Name: value")`.
fn header(it: &mut Interp, h: &Value, span: Span) {
    let segs = as_text(h).to_segs();
    let head = match segs.first() {
        Some(Seg::Lit(t)) => t.clone(),
        _ => String::new(),
    };
    let Some((name, rest)) = head.split_once(':') else {
        return;
    };
    let name = name.trim().to_ascii_lowercase();
    // The value: what follows the colon, unknown pieces included.
    let mut value = vec![Seg::Lit(rest.trim_start().to_string())];
    value.extend(segs.iter().skip(1).cloned());
    let value = Value::segs(value);
    match name.as_str() {
        "location" => redirect(it, &value, span, "header('Location')"),
        "refresh" => {
            if let Some(Seg::Lit(t)) = value.to_segs().first() {
                if let Some(i) = t.to_ascii_lowercase().find("url=") {
                    let mut v = vec![Seg::Lit(t[i + 4..].to_string())];
                    v.extend(value.to_segs().into_iter().skip(1));
                    redirect(it, &Value::segs(v), span, "header('Refresh')");
                }
            }
        }
        "access-control-allow-origin" => {
            it.sink(&CORS, &value, span, "Access-Control-Allow-Origin");
        }
        "content-type" => {
            it.notes.insert("content_type", value);
        }
        // PHP refuses header values with line breaks: no header splitting.
        _ => {}
    }
}

/// A redirect to `url`: open when the user picks where it leads. Text
/// before the user's part that already fixes the site (a path, or a
/// scheme and host) makes it safe.
fn redirect(it: &mut Interp, url: &Value, span: Span, what: &str) {
    for alt in url.alternatives() {
        if !host_fixed(&alt) {
            it.sink(&REDIRECT, &alt, span, what);
            return;
        }
    }
}

/// Whether the literal start of a URL already fixes its site.
fn host_fixed(url: &Value) -> bool {
    let segs = as_text(url).to_segs();
    let prefix = match segs.first() {
        Some(Seg::Lit(t)) => t.trim_start(),
        _ => return false,
    };
    if segs.len() == 1 {
        return true;
    }
    if prefix.is_empty() {
        return false;
    }
    if let Some(rest) = prefix.strip_prefix('/') {
        // `//host` and `/\host` are other sites.
        return !rest.is_empty() && !rest.starts_with('/') && !rest.starts_with('\\');
    }
    let lower = prefix.to_ascii_lowercase();
    if let Some(i) = lower.find("://") {
        let after = &lower[i + 3..];
        return after.contains(['/', '?', '#']);
    }
    // A relative URL: a character that cannot be part of a scheme before
    // any `:` keeps it relative.
    prefix
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'))
        && !prefix.contains(':')
}

fn cookie(it: &mut Interp, args: &[ArgVal], span: Span) {
    let name = a(args, 0).as_str().unwrap_or_default();
    it.sink(&WEAK_RANDOM, &a(args, 1), span, &format!("cookie {name}"));
    let secure = match a(args, 2) {
        Value::Dict(opts) => opts
            .iter()
            .find(|(k, _)| k.as_str().as_deref() == Some("secure"))
            .map(|(_, v)| v.truthy()),
        _ => args
            .iter()
            .find(|x| x.name.as_deref() == Some("secure"))
            .map(|x| x.value.truthy())
            .or_else(|| (args.len() > 5).then(|| a(args, 5).truthy())),
    };
    let sensitive = name_words(&name).any(|w| {
        matches!(
            w.as_str(),
            "sess" | "session" | "sid" | "token" | "auth" | "remember" | "login" | "jwt" | "key"
        )
    }) || secret_name(&name);
    if sensitive && !matches!(secure, Some(Some(true)) | Some(None)) {
        it.flag(
            &INSECURE_COOKIE,
            span,
            &format!("setcookie('{name}') без secure"),
        );
    }
}

/// Methods of library objects.
fn object_method(
    it: &mut Interp,
    o: &Obj,
    name: &str,
    args: &[ArgVal],
    span: Span,
) -> Option<(Value, Option<Value>)> {
    let a0 = a(args, 0);
    let clean = || Some((Value::clean(), None));
    match (&*o.class, name) {
        ("PDO", "query" | "exec" | "prepare")
        | ("SQLite3", "query" | "exec" | "querysingle" | "prepare") => {
            it.sink(&SQLI, &a0, span, &format!("{}::{name}", o.class));
            let class = if o.class.as_ref() == "PDO" {
                "PDOStatement"
            } else {
                "SQLite3Result"
            };
            let rows = external_rows(it, name);
            Some((
                Value::Obj(Rc::new(Obj {
                    class: class.into(),
                    def: None,
                    fields: Vec::new(),
                    taint: rows.taint(),
                })),
                None,
            ))
        }
        ("PDO", "quote") => Some((quoted_sql(&a0), None)),
        ("wpdb", _) => wpdb_method(it, name, args, span).map(|v| (v, None)),
        // With Twig_Loader_String the name given to render() is the
        // template's source; createTemplate() always takes source.
        ("Twig_Environment", "render" | "display" | "loadtemplate" | "load") => {
            if o.field("string_loader") == Some(&Value::Bool(true)) {
                it.sink(&SSTI, &a0, span, &format!("Twig::{name}"));
                // The page is the user's text.
                return Some((Value::Unknown(a0.taint()), None));
            }
            clean()
        }
        ("Twig_Environment", "createtemplate") => {
            it.sink(&SSTI, &a0, span, "Twig::createTemplate");
            clean()
        }
        // `$smarty->fetch('string:' . $src)`: a template given as text.
        ("Smarty", "fetch" | "display" | "createtemplate") => {
            let text = as_text(&a0);
            let inline = match &text {
                Value::Str(segs) => matches!(segs.first(), Some(Seg::Lit(t))
                    if t.starts_with("string:") || t.starts_with("eval:")),
                _ => false,
            };
            if inline {
                it.sink(&SSTI, &a0, span, &format!("Smarty::{name}"));
            }
            clean()
        }
        ("SQLite3", "escapestring") => Some((as_text(&a0).sanitized(ctx::ESCAPED_QUOTES), None)),
        ("mysqli", "query" | "multi_query" | "real_query" | "prepare" | "send_query") => {
            it.sink(&SQLI, &a0, span, &format!("mysqli::{name}"));
            let rows = external_rows(it, name);
            Some((
                Value::Obj(Rc::new(Obj {
                    class: if name == "prepare" {
                        "mysqli_stmt"
                    } else {
                        "mysqli_result"
                    }
                    .into(),
                    def: None,
                    fields: Vec::new(),
                    taint: rows.taint(),
                })),
                None,
            ))
        }
        ("mysqli", "real_escape_string" | "escape_string") => Some((
            as_text(&a0).sanitized(SLASHES | ctx::HEADER | ctx::LOG),
            None,
        )),
        ("PDOStatement" | "mysqli_stmt" | "mysqli_result" | "SQLite3Result", _) => {
            Some((Value::Unknown(o.taint.clone()), None))
        }
        ("DOMDocument", "loadxml" | "load") => {
            if name == "load" {
                it.sink(&PATH, &a0, span, "DOMDocument::load");
            }
            check_xxe(it, &a0, &a(args, 1), span, &format!("DOMDocument::{name}"));
            clean()
        }
        ("DOMXPath", "query" | "evaluate") | ("SimpleXMLElement", "xpath") => {
            it.sink(&XPATHI, &a0, span, &format!("{}::{name}", o.class));
            clean()
        }
        ("SoapClient", _) | ("CurlHandle", _) => clean(),
        ("stream" | "process", _) => Some((Value::Unknown(o.taint.clone()), None)),
        _ => None,
    }
}

/// Methods of objects the analysis cannot see. Query methods count as SQL
/// sinks when they are given SQL text.
fn generic_method(it: &mut Interp, recv: &Value, name: &str, args: &[ArgVal], span: Span) -> Value {
    let a0 = a(args, 0);
    match name {
        "query" | "exec" | "execute" | "multi_query" | "real_query" | "unbuffered_query"
        | "prepare" | "get_results" | "get_row" | "get_var" | "get_col" | "select"
        | "statement" | "unprepared" | "executequery" | "executestatement" | "executeupdate"
        | "fetchall" | "fetchassoc" | "fetchone" | "fetchcolumn" | "fetchrow" | "getall"
        | "getrow" | "getone" | "getcol" | "sql_query" | "rawquery" | "createnativequery"
            if looks_like_sql(&a0) =>
        {
            it.sink(&SQLI, &a0, span, name);
        }
        "whereraw" | "orwhereraw" | "havingraw" | "orderbyraw" | "selectraw" | "groupbyraw"
        | "fromraw" | "raw" => {
            it.sink(&SQLI, &a0, span, name);
        }
        "xpath" => {
            it.sink(&XPATHI, &a0, span, name);
        }
        "query" | "evaluate" if a0.as_str().is_none() && starts_with_lit(&a0, "/") => {
            it.sink(&XPATHI, &a0, span, name);
        }
        _ => {}
    }
    Value::Unknown(recv.taint().union(&args_taint(args)))
}

fn starts_with_lit(v: &Value, p: &str) -> bool {
    matches!(v.to_segs().first(), Some(Seg::Lit(t)) if t.trim_start().starts_with(p))
}

/// Whether the known text of a value reads as an SQL statement.
fn looks_like_sql(v: &Value) -> bool {
    let text: String = v
        .to_segs()
        .iter()
        .map(|s| match s {
            Seg::Lit(t) => t.to_ascii_lowercase(),
            Seg::Dyn(_) => " ? ".to_string(),
        })
        .collect();
    let t = text.trim_start();
    let has = |w: &str| t.contains(w);
    (t.starts_with("select") && has(" from"))
        || (t.starts_with("insert") && has("into"))
        || (t.starts_with("update") && has(" set "))
        || (t.starts_with("delete") && has("from"))
        || t.starts_with("replace into")
        || t.starts_with("create table")
        || t.starts_with("drop table")
        || t.starts_with("alter table")
        || (t.starts_with("with ") && has("select"))
}

// ----- output and HTML contexts -----

/// Bytes of earlier markup kept to know the context of the next output.
const MAX_TAIL: usize = 8192;

/// `echo $v`: checked in the HTML context the page is in at that point.
fn output(it: &mut Interp, v: &Value, span: Span, what: &str) {
    let tail = it
        .notes
        .get("php_html")
        .and_then(|t| t.as_str())
        .unwrap_or_default();
    let html = match it.notes.get("content_type").map(|c| c.to_segs()) {
        Some(segs) => match segs.first() {
            Some(Seg::Lit(t)) => {
                let t = t.trim().to_ascii_lowercase();
                t.is_empty() || t.starts_with("text/html") || t.contains("xhtml")
            }
            _ => true,
        },
        None => true,
    };
    let mut scan = HtmlScan::default();
    scan.feed(&tail);
    let mut written = tail;
    for alt in v.alternatives() {
        let mut s = scan.clone();
        for seg in as_text(&alt).to_segs() {
            match seg {
                Seg::Lit(t) => {
                    s.feed(&t);
                }
                Seg::Dyn(t) => {
                    if html && t.sources.iter().any(|s| !s.weak_random) {
                        let need = s.context();
                        if !need.safe(t.safe) {
                            let forced = t.clone().without_safe(ctx::HTML);
                            if it.sink(
                                &XSS,
                                &Value::Unknown(forced),
                                span,
                                &format!("{what} ({})", need.name()),
                            ) {
                                break;
                            }
                        }
                    }
                    s.feed("x");
                }
            }
        }
    }
    // Remember the markup written so far; unknown text stands as `x`.
    for seg in as_text(&v.alternatives().into_iter().next().unwrap_or(Value::None)).to_segs() {
        match seg {
            Seg::Lit(t) => written.push_str(&t),
            Seg::Dyn(_) => written.push('x'),
        }
    }
    if written.len() > MAX_TAIL {
        let mut cut = written.len() - MAX_TAIL;
        while !written.is_char_boundary(cut) {
            cut += 1;
        }
        written = written[cut..].to_string();
    }
    it.notes.insert("php_html", Value::str(written));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttrKind {
    Plain,
    /// `onclick="..."`: JavaScript, run after entity decoding.
    Event,
    /// `href`, `src`, `action` ...: a URL whose scheme can run script.
    Url,
    /// `style="..."`
    Style,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Js {
    Code,
    Str(char),
    /// A string the page runs as code: `setTimeout('...')`.
    CodeStr(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Text,
    TagOpen,
    TagName,
    EndTag,
    InTag,
    AttrName,
    AfterAttrName,
    BeforeValue,
    Value,
    Comment,
    MarkupDecl,
    Script,
    Style,
}

/// Where a piece of output lands, enough to tell which escaping it needs.
#[derive(Debug, Clone, Default)]
struct HtmlScan {
    state: State,
    tag: String,
    attr: String,
    quote: Option<char>,
    /// Characters of the attribute value so far.
    value_len: usize,
    js: Option<Js>,
    /// Recent script text, to recognize `setTimeout(` before a string.
    js_recent: String,
    /// Characters of a closing tag being matched in script or style.
    raw_close: String,
    raw_tag: &'static str,
    /// Characters of `<!--` or `-->` matched so far.
    marks: String,
}

#[derive(Debug, Clone, Copy)]
enum Need {
    Text,
    Name,
    Attr {
        quote: Option<char>,
        kind: AttrKind,
        js: Js,
        at_start: bool,
    },
    Script(Js),
    Css,
}

impl Need {
    fn name(&self) -> &'static str {
        match self {
            Need::Text => "текст страницы",
            Need::Name => "имя тега или атрибута",
            Need::Attr {
                kind: AttrKind::Event,
                ..
            } => "обработчик события",
            Need::Attr {
                kind: AttrKind::Url,
                ..
            } => "URL в атрибуте",
            Need::Attr {
                kind: AttrKind::Style,
                ..
            } => "стиль в атрибуте",
            Need::Attr { quote: None, .. } => "атрибут без кавычек",
            Need::Attr { .. } => "значение атрибута",
            Need::Script(_) => "скрипт",
            Need::Css => "таблица стилей",
        }
    }

    /// Whether data with these safety bits is safe here.
    fn safe(&self, bits: u32) -> bool {
        let has = |b: u32| bits & b == b;
        let decoded = bits & ctx::HTML_ENCODED != 0;
        // A JavaScript string: its quote is absent or escaped (entity
        // escapes count only where no decoding happens).
        let js_str = |q: char, decoding: bool| {
            let no = if q == '"' {
                ctx::NO_DQUOTE
            } else {
                ctx::NO_SQUOTE
            };
            (has(no) && !(decoding && decoded)) || has(ctx::ESCAPED_QUOTES)
        };
        match *self {
            Need::Text => has(ctx::HTML),
            Need::Name => has(ctx::HTML | ctx::SHELL),
            Need::Css => has(ctx::HTML | ctx::CODE),
            Need::Script(Js::Code) | Need::Script(Js::CodeStr(_)) => has(ctx::CODE),
            Need::Script(Js::Str(q)) => js_str(q, false) && has(ctx::HTML),
            Need::Attr {
                quote,
                kind,
                js,
                at_start,
            } => {
                let delimited = match quote {
                    Some('"') => has(ctx::NO_DQUOTE),
                    Some(_) => has(ctx::NO_SQUOTE),
                    None => has(ctx::HTML | ctx::SHELL),
                };
                delimited
                    && match kind {
                        AttrKind::Plain => true,
                        AttrKind::Url => !at_start || bits & (ctx::URL | ctx::SCHEME) != 0,
                        AttrKind::Style => has(ctx::CODE),
                        AttrKind::Event => match js {
                            Js::Str(q) => js_str(q, true),
                            _ => has(ctx::CODE),
                        },
                    }
            }
        }
    }
}

const URL_ATTRS: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "data",
    "background",
    "poster",
    "codebase",
    "cite",
    "xlink:href",
    "srcdoc",
];

impl HtmlScan {
    fn context(&self) -> Need {
        match self.state {
            State::Text | State::Comment | State::MarkupDecl | State::EndTag => Need::Text,
            State::TagOpen
            | State::TagName
            | State::InTag
            | State::AttrName
            | State::AfterAttrName => Need::Name,
            State::BeforeValue | State::Value => {
                let attr = self.attr.to_ascii_lowercase();
                let kind = if attr.starts_with("on") {
                    AttrKind::Event
                } else if attr == "style" {
                    AttrKind::Style
                } else if URL_ATTRS.contains(&attr.as_str()) {
                    AttrKind::Url
                } else {
                    AttrKind::Plain
                };
                Need::Attr {
                    quote: if self.state == State::BeforeValue {
                        None
                    } else {
                        self.quote
                    },
                    kind,
                    js: self.js.unwrap_or(Js::Code),
                    at_start: self.value_len == 0,
                }
            }
            State::Script => Need::Script(self.js.unwrap_or(Js::Code)),
            State::Style => Need::Css,
        }
    }

    fn close_tag(&mut self) {
        let t = self.tag.to_ascii_lowercase();
        self.state = match t.as_str() {
            "script" => {
                self.raw_tag = "script";
                self.js = Some(Js::Code);
                self.js_recent.clear();
                State::Script
            }
            "style" => {
                self.raw_tag = "style";
                State::Style
            }
            _ => State::Text,
        };
        self.raw_close.clear();
    }

    fn js_step(&mut self, c: char) {
        let js = self.js.unwrap_or(Js::Code);
        match js {
            Js::Code => {
                if c == '\'' || c == '"' || c == '`' {
                    let recent = self.js_recent.to_ascii_lowercase();
                    let recent = recent.trim_end();
                    let runs = [
                        "settimeout(",
                        "setinterval(",
                        "eval(",
                        "function(",
                        "execscript(",
                    ]
                    .iter()
                    .any(|f| recent.ends_with(f));
                    self.js = Some(if runs { Js::CodeStr(c) } else { Js::Str(c) });
                } else {
                    self.js_recent.push(c);
                    if self.js_recent.len() > 32 {
                        self.js_recent.remove(0);
                    }
                }
            }
            Js::Str(q) | Js::CodeStr(q) => {
                if c == q {
                    self.js = Some(Js::Code);
                    self.js_recent.clear();
                }
            }
        }
    }

    fn feed(&mut self, text: &str) {
        for c in text.chars() {
            match self.state {
                State::Text => {
                    if c == '<' {
                        self.state = State::TagOpen;
                        self.tag.clear();
                    }
                }
                State::TagOpen => match c {
                    '!' => {
                        self.state = State::MarkupDecl;
                        self.marks.clear();
                    }
                    '/' => self.state = State::EndTag,
                    c if c.is_ascii_alphabetic() => {
                        self.state = State::TagName;
                        self.tag.push(c);
                    }
                    _ => self.state = State::Text,
                },
                State::MarkupDecl => {
                    self.marks.push(c);
                    if self.marks == "--" {
                        self.state = State::Comment;
                        self.marks.clear();
                    } else if c == '>' {
                        self.state = State::Text;
                    }
                }
                State::Comment => {
                    self.marks.push(c);
                    if self.marks.len() > 3 {
                        self.marks.remove(0);
                    }
                    if self.marks.ends_with("-->") {
                        self.state = State::Text;
                        self.marks.clear();
                    }
                }
                State::EndTag => {
                    if c == '>' {
                        self.state = State::Text;
                    }
                }
                State::TagName => match c {
                    c if c.is_whitespace() => self.state = State::InTag,
                    '/' => self.state = State::InTag,
                    '>' => self.close_tag(),
                    c => self.tag.push(c),
                },
                State::InTag => match c {
                    '>' => self.close_tag(),
                    c if c.is_whitespace() || c == '/' => {}
                    c => {
                        self.state = State::AttrName;
                        self.attr.clear();
                        self.attr.push(c);
                    }
                },
                State::AttrName => match c {
                    '=' => self.state = State::BeforeValue,
                    '>' => self.close_tag(),
                    c if c.is_whitespace() => self.state = State::AfterAttrName,
                    '/' => self.state = State::InTag,
                    c => self.attr.push(c),
                },
                State::AfterAttrName => match c {
                    '=' => self.state = State::BeforeValue,
                    '>' => self.close_tag(),
                    c if c.is_whitespace() => {}
                    c => {
                        self.state = State::AttrName;
                        self.attr.clear();
                        self.attr.push(c);
                    }
                },
                State::BeforeValue => match c {
                    '"' | '\'' => {
                        self.state = State::Value;
                        self.quote = Some(c);
                        self.value_len = 0;
                        self.js = Some(Js::Code);
                        self.js_recent.clear();
                    }
                    '>' => self.close_tag(),
                    c if c.is_whitespace() => {}
                    c => {
                        self.state = State::Value;
                        self.quote = None;
                        self.value_len = 1;
                        self.js = Some(Js::Code);
                        self.js_recent.clear();
                        self.js_step(c);
                    }
                },
                State::Value => {
                    let ends = match self.quote {
                        Some(q) => c == q,
                        None => c.is_whitespace() || c == '>',
                    };
                    if ends {
                        self.js = None;
                        if c == '>' {
                            self.close_tag();
                        } else {
                            self.state = State::InTag;
                        }
                    } else {
                        self.value_len += 1;
                        self.js_step(c);
                    }
                }
                State::Script | State::Style => {
                    // `</script` and `</style` end raw text wherever they are.
                    if c == '<' {
                        self.raw_close = "<".into();
                    } else if !self.raw_close.is_empty() {
                        self.raw_close.push(c.to_ascii_lowercase());
                        let want = format!("</{}", self.raw_tag);
                        if self.raw_close == want {
                            self.state = State::EndTag;
                            self.raw_close.clear();
                            self.js = None;
                            continue;
                        }
                        if !want.starts_with(self.raw_close.as_str()) {
                            self.raw_close.clear();
                        }
                    }
                    if self.state == State::Script {
                        self.js_step(c);
                    }
                }
            }
        }
    }
}
