//! Java: the Servlet API, Spring MVC and JAX-RS as sources; JDBC, JPA,
//! JNDI/LDAP, XPath, XML parsers, files, processes, scripting and
//! deserialization as sinks; the escaping libraries (ESAPI, OWASP Encoder,
//! Commons Text, Spring HtmlUtils) as sanitizers; `java.util` collections,
//! `String` and `StringBuilder` as values the analysis follows.
//!
//! Library objects are [`Obj`] values named by their canonical class
//! (`java.sql.Statement`); static members are [`Value::Ref`] paths.

use super::common::*;
use super::python::{check_argv, regex_sub, str_method};
use crate::interp::*;
use crate::ir::{BinOp, Function, Param, Span};
use crate::rules::*;
use crate::value::*;
use std::rc::Rc;

pub struct Java;

const REQUEST: &str = "javax.servlet.http.HttpServletRequest";
const RESPONSE: &str = "javax.servlet.http.HttpServletResponse";
const WRITER: &str = "javax.servlet.ResponseWriter";
const SESSION: &str = "javax.servlet.http.HttpSession";
const SERVLET_CONTEXT: &str = "javax.servlet.ServletContext";
const COOKIE: &str = "javax.servlet.http.Cookie";

/// Output of Base64 and hex encoders: no quotes, markup, spaces or dots.
const ENCODED_SAFE: u32 = ctx::HTML
    | ctx::SQL
    | ctx::SHELL
    | ctx::PATH
    | ctx::LDAP
    | ctx::XPATH
    | ctx::CODE
    | ctx::HEADER
    | ctx::TEMPLATE
    | ctx::LOG
    | ctx::NO_SQUOTE
    | ctx::NO_DQUOTE;

/// `URLEncoder.encode` escapes everything but `[A-Za-z0-9.*_-]`.
const URL_ENCODED_SAFE: u32 = ENCODED_SAFE & !ctx::LDAP;

/// Simple names that need no import: `java.lang`, plus the classes code
/// most often reaches through wildcard imports.
const KNOWN_CLASSES: &[&str] = &[
    "java.lang.String",
    "java.lang.StringBuilder",
    "java.lang.StringBuffer",
    "java.lang.Integer",
    "java.lang.Long",
    "java.lang.Short",
    "java.lang.Byte",
    "java.lang.Double",
    "java.lang.Float",
    "java.lang.Boolean",
    "java.lang.Character",
    "java.lang.Math",
    "java.lang.System",
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "java.lang.Thread",
    "java.lang.Class",
    "java.lang.Object",
    "java.util.ArrayList",
    "java.util.LinkedList",
    "java.util.Vector",
    "java.util.Stack",
    "java.util.ArrayDeque",
    "java.util.HashSet",
    "java.util.LinkedHashSet",
    "java.util.TreeSet",
    "java.util.HashMap",
    "java.util.LinkedHashMap",
    "java.util.TreeMap",
    "java.util.Hashtable",
    "java.util.List",
    "java.util.Map",
    "java.util.Set",
    "java.util.Arrays",
    "java.util.Collections",
    "java.util.Random",
    "java.util.Properties",
    "java.util.Scanner",
    "java.util.Base64",
    "java.util.UUID",
    "java.util.Locale",
    "java.io.File",
    "java.io.FileInputStream",
    "java.io.FileOutputStream",
    "java.io.FileReader",
    "java.io.FileWriter",
    "java.io.RandomAccessFile",
    "java.io.PrintWriter",
    "java.io.BufferedReader",
    "java.io.InputStreamReader",
    "java.io.ObjectInputStream",
    "java.io.StringReader",
    "java.io.ByteArrayInputStream",
    "java.net.URL",
    "java.net.URI",
    "java.net.URLEncoder",
    "java.net.URLDecoder",
    "java.nio.file.Paths",
    "java.nio.file.Path",
    "java.nio.file.Files",
    "java.security.MessageDigest",
    "java.security.SecureRandom",
    "javax.crypto.Cipher",
    "javax.crypto.KeyGenerator",
    "javax.crypto.SecretKeyFactory",
    "java.sql.DriverManager",
    "java.sql.Connection",
    "java.sql.Statement",
    "java.sql.PreparedStatement",
    "java.sql.CallableStatement",
    "java.sql.ResultSet",
    "javax.servlet.http.HttpServletRequest",
    "javax.servlet.http.HttpServletResponse",
    "javax.servlet.http.HttpSession",
    "javax.servlet.http.Cookie",
    "javax.servlet.ServletRequest",
    "javax.servlet.ServletResponse",
    "javax.servlet.ServletContext",
    "javax.naming.directory.InitialDirContext",
    "javax.naming.directory.DirContext",
    "javax.naming.ldap.InitialLdapContext",
    "javax.xml.xpath.XPathFactory",
    "javax.xml.xpath.XPath",
    "javax.xml.parsers.DocumentBuilderFactory",
    "javax.xml.parsers.SAXParserFactory",
    "javax.xml.stream.XMLInputFactory",
    "javax.script.ScriptEngineManager",
    "java.beans.XMLDecoder",
];

/// Full name of a class written as `Foo`, `java.util.Foo` or with the
/// Jakarta EE package.
fn canonical(name: &str) -> String {
    let name = name.trim_end_matches("[]");
    if let Some(rest) = name.strip_prefix("jakarta.") {
        return format!("javax.{rest}");
    }
    if !name.contains('.') {
        if let Some(full) = KNOWN_CLASSES
            .iter()
            .find(|c| c.rsplit('.').next() == Some(name))
        {
            return full.to_string();
        }
    }
    name.to_string()
}

/// Canonical name of a member path: the class part is canonicalized.
fn canonical_path(path: &str) -> String {
    match path.rsplit_once('.') {
        Some((class, member)) if !class.contains('.') => format!("{}.{member}", canonical(class)),
        Some((class, member)) if class.starts_with("jakarta.") => {
            format!("{}.{member}", canonical(class))
        }
        _ => canonical(path),
    }
}

fn last(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

fn obj(class: &str) -> Value {
    Value::Obj(Rc::new(Obj::new(class)))
}

fn obj_tainted(class: &str, taint: Taint) -> Value {
    let mut o = Obj::new(class);
    o.taint = taint;
    Value::Obj(Rc::new(o))
}

fn a(args: &[ArgVal], i: usize) -> Value {
    arg(args, i, "").cloned().unwrap_or_else(Value::clean)
}

/// A Java value used as a string: `String.valueOf`, concatenation.
fn as_string(v: &Value) -> Value {
    match v {
        Value::Str(_) => v.clone(),
        Value::Int(_) | Value::Float(_) => Value::segs(v.to_segs()),
        Value::Bool(b) => Value::str(if *b { "true" } else { "false" }),
        Value::None => Value::str("null"),
        Value::OneOf(_) => Value::segs(v.to_segs()),
        other if other.is_tainted() => Value::tainted_str(other.taint()),
        other => Value::Unknown(other.taint()),
    }
}

fn numeric(v: &Value) -> Value {
    match v {
        Value::Int(_) | Value::Float(_) => v.clone(),
        Value::Str(_) => match v.as_str().and_then(|s| s.trim().parse::<i64>().ok()) {
            Some(i) => Value::Int(i),
            None => Value::Unknown(v.taint().with_safe(ctx::ALL)),
        },
        other => Value::Unknown(other.taint().with_safe(ctx::ALL)),
    }
}

fn is_numeric_type(t: &str) -> bool {
    crate::lower::java::is_numeric_type(t)
        || matches!(t, "boolean" | "Boolean" | "java.lang.Boolean")
}

/// Every string the value may be when it is known.
fn literals(v: &Value) -> Vec<String> {
    v.alternatives().iter().filter_map(|a| a.as_str()).collect()
}

/// A broken cipher, or for `Cipher.getInstance` (`transformation`) a mode
/// that leaks patterns: `AES` alone means AES/ECB.
fn weak_cipher(alg: &str, transformation: bool) -> bool {
    let a = alg.to_ascii_uppercase();
    let base = a.split('/').next().unwrap_or("");
    matches!(
        base,
        "DES" | "DESEDE" | "TRIPLEDES" | "3DES" | "RC2" | "RC4" | "ARCFOUR" | "BLOWFISH" | "IDEA"
    ) || (transformation
        && ((base == "AES" && (a == "AES" || a.contains("/ECB")))
            || (base == "RSA" && a.contains("NOPADDING"))))
}

fn weak_hash(alg: &str) -> bool {
    matches!(
        alg.to_ascii_uppercase().as_str(),
        "MD2" | "MD4" | "MD5" | "SHA" | "SHA1" | "SHA-1"
    )
}

/// Sanitizing library calls known by name, whatever their class: the
/// ESAPI encoder, OWASP Java Encoder, Commons Text, Spring `HtmlUtils`.
fn sanitizer(name: &str) -> u32 {
    let html = ctx::HTML | ctx::NO_SQUOTE | ctx::NO_DQUOTE;
    match name {
        "encodeForHTML"
        | "encodeForHTMLAttribute"
        | "encodeForXML"
        | "encodeForXMLAttribute"
        | "forHtml"
        | "forHtmlContent"
        | "forHtmlAttribute"
        | "forHtmlUnquotedAttribute"
        | "forXml"
        | "forXmlContent"
        | "forXmlAttribute"
        | "escapeHtml"
        | "escapeHtml3"
        | "escapeHtml4"
        | "escapeXml"
        | "escapeXml10"
        | "escapeXml11"
        | "htmlEscape"
        | "htmlEscapeDecimal"
        | "htmlEscapeHex" => html,
        "encodeForJavaScript" | "forJavaScript" | "escapeEcmaScript" | "escapeJavaScript" => {
            html | ctx::CODE
        }
        "encodeForCSS" | "forCssString" => html,
        "encodeForURL" | "forUriComponent" => URL_ENCODED_SAFE,
        "encodeForSQL" => ctx::SQL | ctx::NO_SQUOTE,
        "escapeSql" => ctx::NO_SQUOTE,
        "encodeForOS" => ctx::SHELL,
        "encodeForLDAP" | "encodeForDN" => ctx::LDAP,
        "encodeForXPath" => ctx::XPATH | ctx::NO_SQUOTE | ctx::NO_DQUOTE,
        "encodeForBase64" => ENCODED_SAFE,
        _ => name_sanitizer(name),
    }
}

/// The argument an encoder works on: the last one that is not a codec or
/// an option (`encodeForSQL(codec, s)`, `encodeForBase64(bytes, wrap)`).
fn encoded_arg(args: &[ArgVal]) -> Value {
    args.iter()
        .rev()
        .find(|a| match &a.value {
            Value::Bool(_) | Value::Int(_) => false,
            Value::Obj(o) => !o.class.contains("Codec"),
            _ => true,
        })
        .or(args.first())
        .map(|a| a.value.clone())
        .unwrap_or_else(Value::clean)
}

impl Model for Java {
    fn ref_attr(&self, _it: &mut Interp, path: &str, taint: &Taint, name: &str) -> Value {
        Value::Ref(format!("{path}.{name}").into(), taint.clone())
    }

    fn builtin(&self, _it: &mut Interp, name: &str) -> Value {
        Value::Ref(canonical(name).into(), Taint::clean())
    }

    fn call_ref(
        &self,
        it: &mut Interp,
        path: &str,
        taint: &Taint,
        args: &[ArgVal],
        span: Span,
    ) -> Value {
        let full = canonical_path(path);
        let p = full.as_str();
        let short = last(p);
        let propagate = || Value::Unknown(taint.union(&args_taint(args)));
        match p {
            // ---- strings ----
            "java.lang.String" => match args.first() {
                Some(x) => as_string(&x.value),
                None => Value::str(""),
            },
            "java.lang.StringBuilder" | "java.lang.StringBuffer" => match args.first() {
                Some(x) if !matches!(x.value, Value::Int(_)) => as_string(&x.value),
                _ => Value::str(""),
            },
            "java.lang.String.valueOf" | "java.lang.String.copyValueOf" => as_string(&a(args, 0)),
            "java.lang.String.format" => {
                let start = usize::from(!matches!(a(args, 0), Value::Str(_)));
                let fmt = a(args, start);
                let rest: Vec<Value> = args
                    .iter()
                    .skip(start + 1)
                    .map(|x| x.value.clone())
                    .collect();
                match &fmt {
                    Value::Str(segs) => percent_format(segs, &Value::list(rest)),
                    other => Value::tainted_str(other.taint().union(&args_taint(args))),
                }
            }
            "java.lang.String.join" => {
                let sep = a(args, 0);
                let items: Vec<Value> = match args.get(1).map(|x| &x.value) {
                    Some(Value::List(items)) if args.len() == 2 => items.as_ref().clone(),
                    _ => args.iter().skip(1).map(|x| x.value.clone()).collect(),
                };
                let mut parts = Vec::new();
                for (i, v) in items.into_iter().enumerate() {
                    if i > 0 {
                        parts.push(sep.clone());
                    }
                    parts.push(v);
                }
                concat(&parts)
            }
            "len" => match args.first().map(|x| &x.value) {
                Some(Value::List(items)) => Value::Int(items.len() as i64),
                _ => Value::Unknown(Taint::clean()),
            },
            _ if (p.starts_with("java.lang.Integer.")
                || p.starts_with("java.lang.Long.")
                || p.starts_with("java.lang.Short.")
                || p.starts_with("java.lang.Byte.")
                || p.starts_with("java.lang.Double.")
                || p.starts_with("java.lang.Float.")
                || p.starts_with("java.lang.Boolean.")
                || p.starts_with("java.lang.Math."))
                && short != "random" =>
            {
                match short {
                    "toString" | "toHexString" | "toBinaryString" | "toOctalString" => {
                        Value::tainted_str(args_taint(args).with_safe(ctx::ALL))
                    }
                    _ => numeric(&a(args, 0)),
                }
            }
            "java.lang.Character.toString" => as_string(&a(args, 0)),
            "java.lang.Integer" | "java.lang.Long" | "java.lang.Double" => numeric(&a(args, 0)),

            // ---- encoding ----
            "java.net.URLDecoder.decode" => a(args, 0).unsanitized(ctx::ALL),
            "java.net.URLEncoder.encode" => a(args, 0).sanitized(URL_ENCODED_SAFE),
            "java.util.Base64.getEncoder"
            | "java.util.Base64.getUrlEncoder"
            | "java.util.Base64.getMimeEncoder" => obj("java.util.Base64.Encoder"),
            "java.util.Base64.getDecoder"
            | "java.util.Base64.getUrlDecoder"
            | "java.util.Base64.getMimeDecoder" => obj("java.util.Base64.Decoder"),
            _ if p.starts_with("org.apache.commons.codec.binary.Base64.") => {
                if short.starts_with("decode") {
                    a(args, 0).unsanitized(ctx::ALL)
                } else {
                    a(args, 0).sanitized(ENCODED_SAFE)
                }
            }
            _ if p.starts_with("org.apache.commons.codec.binary.Hex.") => {
                if short.starts_with("decode") {
                    a(args, 0).unsanitized(ctx::ALL)
                } else {
                    a(args, 0).sanitized(ENCODED_SAFE)
                }
            }
            "org.owasp.esapi.ESAPI.encoder" => obj("org.owasp.esapi.Encoder"),
            "org.owasp.esapi.ESAPI.validator" => obj("org.owasp.esapi.Validator"),
            "org.apache.commons.io.FilenameUtils.getName"
            | "org.apache.commons.io.FilenameUtils.getBaseName"
            | "org.apache.commons.io.FilenameUtils.getExtension" => a(args, 0).sanitized(ctx::PATH),
            _ if sanitizer(short) != 0 => encoded_arg(args).sanitized(sanitizer(short)),

            // ---- collections ----
            "java.util.ArrayList"
            | "java.util.LinkedList"
            | "java.util.Vector"
            | "java.util.Stack"
            | "java.util.ArrayDeque"
            | "java.util.HashSet"
            | "java.util.LinkedHashSet"
            | "java.util.TreeSet"
            | "java.util.concurrent.CopyOnWriteArrayList" => match args.first().map(|x| &x.value) {
                None | Some(Value::Int(_)) => Value::list(Vec::new()),
                Some(Value::List(items)) => Value::List(items.clone()),
                Some(other) => Value::Unknown(other.taint()),
            },
            "java.util.HashMap"
            | "java.util.LinkedHashMap"
            | "java.util.TreeMap"
            | "java.util.Hashtable"
            | "java.util.concurrent.ConcurrentHashMap" => match args.first().map(|x| &x.value) {
                None | Some(Value::Int(_)) => Value::Dict(Rc::new(Vec::new())),
                Some(Value::Dict(pairs)) => Value::Dict(pairs.clone()),
                Some(other) => Value::Unknown(other.taint()),
            },
            "java.util.Arrays.asList"
            | "java.util.List.of"
            | "java.util.Set.of"
            | "java.util.Collections.singletonList"
            | "java.util.Collections.singleton"
            | "java.util.stream.Stream.of" => match args {
                [one] if matches!(one.value, Value::List(_)) => one.value.clone(),
                _ => Value::list(args.iter().map(|x| x.value.clone()).collect()),
            },
            "java.util.Map.of" => Value::Dict(Rc::new(
                args.chunks(2)
                    .filter(|c| c.len() == 2)
                    .map(|c| (c[0].value.clone(), c[1].value.clone()))
                    .collect(),
            )),
            _ if p.starts_with("java.util.Collections.unmodifiable")
                || p.starts_with("java.util.Collections.synchronized") =>
            {
                a(args, 0)
            }

            // ---- randomness and crypto ----
            "java.lang.Math.random" => it.weak_random("Math.random()", span, args),
            "java.util.Random" => obj("java.util.Random"),
            "java.util.concurrent.ThreadLocalRandom.current" => obj("java.util.Random"),
            "java.security.SecureRandom"
            | "java.security.SecureRandom.getInstance"
            | "java.security.SecureRandom.getInstanceStrong" => obj("java.security.SecureRandom"),
            _ if p.starts_with("org.apache.commons.lang.RandomStringUtils.")
                || p.starts_with("org.apache.commons.lang3.RandomStringUtils.") =>
            {
                it.weak_random(&format!("RandomStringUtils.{short}()"), span, args)
            }
            "java.security.MessageDigest.getInstance" => {
                let alg = a(args, 0);
                if let Some(weak) = literals(&alg).into_iter().find(|s| weak_hash(s)) {
                    it.flag(
                        &WEAK_HASH,
                        span,
                        &format!("MessageDigest.getInstance(\"{weak}\")"),
                    );
                }
                obj("java.security.MessageDigest")
            }
            _ if p.starts_with("org.apache.commons.codec.digest.DigestUtils.") => {
                let lower = short.to_ascii_lowercase();
                let weak = lower.starts_with("md5")
                    || lower.starts_with("md2")
                    || lower.starts_with("sha1")
                    || lower == "sha"
                    || lower == "shahex"
                    || lower == "getmd5digest"
                    || lower == "getsha1digest";
                if weak {
                    it.flag(&WEAK_HASH, span, &format!("DigestUtils.{short}"));
                }
                a(args, 0).sanitized(ENCODED_SAFE)
            }
            "javax.crypto.Cipher.getInstance"
            | "javax.crypto.KeyGenerator.getInstance"
            | "javax.crypto.SecretKeyFactory.getInstance" => {
                let alg = a(args, 0);
                let transformation = p == "javax.crypto.Cipher.getInstance";
                if let Some(weak) = literals(&alg)
                    .into_iter()
                    .find(|s| weak_cipher(s, transformation))
                {
                    let class = p.rsplit_once('.').map(|(c, _)| last(c)).unwrap_or("");
                    it.flag(
                        &WEAK_CIPHER,
                        span,
                        &format!("{class}.getInstance(\"{weak}\")"),
                    );
                }
                obj(p.rsplit_once('.').map(|(c, _)| c).unwrap_or(p))
            }

            // ---- processes ----
            "java.lang.Runtime.getRuntime" => obj("java.lang.Runtime"),
            "java.lang.ProcessBuilder" => {
                let cmd = match args {
                    [one] if matches!(one.value, Value::List(_) | Value::Unknown(_)) => {
                        one.value.clone()
                    }
                    _ => Value::list(args.iter().map(|x| x.value.clone()).collect()),
                };
                check_argv(it, &cmd, span, "new ProcessBuilder");
                obj("java.lang.ProcessBuilder")
            }

            // ---- files ----
            // A File or Path names a file; the file is reached when the
            // object is used, so a check of the normalized path in between
            // (`f.getCanonicalPath().startsWith(base)`) keeps it inside.
            "java.io.File"
            | "java.nio.file.Paths.get"
            | "java.nio.file.Path.of"
            | "java.nio.file.FileSystem.getPath" => {
                let n = if p == "java.io.File" { 2 } else { args.len() };
                let parts: Vec<Value> = args.iter().take(n).map(|x| path_text(&x.value)).collect();
                let path = concat(&parts);
                let class = if p == "java.io.File" {
                    p
                } else {
                    "java.nio.file.Path"
                };
                file_obj(it, class, path, span)
            }
            "java.io.FileInputStream"
            | "java.io.FileOutputStream"
            | "java.io.FileReader"
            | "java.io.FileWriter"
            | "java.io.RandomAccessFile"
            | "java.io.PrintWriter"
            | "java.io.PrintStream"
            | "java.util.logging.FileHandler" => {
                // The first argument names the file, unless it is a stream
                // being wrapped.
                let target = a(args, 0);
                let names_file = match &target {
                    Value::Obj(o) => is_file_obj(o) || o.field("url").is_some(),
                    _ => true,
                };
                let path = path_text(&target);
                if names_file {
                    file_sink(it, &target, span, &format!("new {}", last(p)));
                }
                let mut o = Obj::new("java.io.Stream");
                o.taint = path.taint();
                Value::Obj(Rc::new(o.with_field("path", path)))
            }
            _ if p.starts_with("java.nio.file.Files.") => {
                let what = format!("Files.{short}");
                for x in args.iter().take(2) {
                    if matches!(&x.value, Value::Obj(o) if is_file_obj(o)) {
                        file_sink(it, &x.value, span, &what);
                    }
                }
                match short {
                    "newInputStream" | "newBufferedReader" | "lines" | "readAllLines"
                    | "readAllBytes" | "readString" | "list" | "walk" => Value::clean(),
                    _ => Value::None,
                }
            }

            // ---- network ----
            "java.net.URL" | "java.net.URI" | "java.net.URI.create" => {
                let u = concat(&args.iter().map(|x| x.value.clone()).collect::<Vec<_>>());
                let class = if short == "URL" {
                    "java.net.URL"
                } else {
                    "java.net.URI"
                };
                let mut o = Obj::new(class);
                o.taint = u.taint();
                Value::Obj(Rc::new(o.with_field("url", u)))
            }
            "org.apache.http.client.methods.HttpGet"
            | "org.apache.http.client.methods.HttpPost"
            | "org.apache.http.client.methods.HttpPut"
            | "org.apache.http.client.methods.HttpDelete"
            | "org.apache.hc.client5.http.classic.methods.HttpGet"
            | "org.apache.hc.client5.http.classic.methods.HttpPost"
            | "java.net.http.HttpRequest.newBuilder" => {
                if let Some(u) = args.first() {
                    it.sink(&SSRF, &u.value, span, short);
                }
                obj(p)
            }

            // ---- servlet ----
            "javax.servlet.http.Cookie" => {
                let mut o = Obj::new(COOKIE);
                o.taint = args_taint(args);
                Value::Obj(Rc::new(
                    o.with_field("name", a(args, 0))
                        .with_field("value", a(args, 1)),
                ))
            }

            // ---- databases ----
            "java.sql.DriverManager.getConnection" => obj("java.sql.Connection"),
            "org.springframework.jdbc.core.JdbcTemplate"
            | "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate" => obj(p),

            // ---- XML, XPath, LDAP, scripting, deserialization ----
            "javax.xml.xpath.XPathFactory.newInstance" => obj("javax.xml.xpath.XPathFactory"),
            "javax.xml.parsers.DocumentBuilderFactory.newInstance"
            | "javax.xml.parsers.DocumentBuilderFactory.newDefaultInstance"
            | "javax.xml.parsers.SAXParserFactory.newInstance"
            | "javax.xml.stream.XMLInputFactory.newInstance"
            | "javax.xml.stream.XMLInputFactory.newFactory"
            | "javax.xml.transform.TransformerFactory.newInstance"
            | "org.xml.sax.helpers.XMLReaderFactory.createXMLReader"
            | "org.dom4j.io.SAXReader"
            | "org.jdom2.input.SAXBuilder" => {
                let class = match short {
                    "newInstance" | "newFactory" | "newDefaultInstance" => {
                        p.rsplit_once('.').map(|(c, _)| c).unwrap_or(p)
                    }
                    "createXMLReader" => "org.xml.sax.XMLReader",
                    _ => p,
                };
                obj(class)
            }
            "javax.naming.directory.InitialDirContext" | "javax.naming.ldap.InitialLdapContext" => {
                obj("javax.naming.directory.DirContext")
            }
            "javax.script.ScriptEngineManager" => obj("javax.script.ScriptEngineManager"),
            "org.springframework.expression.spel.standard.SpelExpressionParser" => {
                obj("org.springframework.expression.ExpressionParser")
            }
            "java.io.ObjectInputStream" | "java.beans.XMLDecoder" => {
                obj_tainted(p, args_taint(args))
            }
            "com.thoughtworks.xstream.XStream" => obj(p),
            "org.yaml.snakeyaml.Yaml" => {
                let safe = args.iter().any(
                    |x| matches!(&x.value, Value::Obj(o) if o.class.ends_with("SafeConstructor")),
                );
                let o = Obj::new(p).with_field("safe", Value::Bool(safe));
                Value::Obj(Rc::new(o))
            }
            "org.yaml.snakeyaml.constructor.SafeConstructor" => obj(p),
            "org.slf4j.LoggerFactory.getLogger"
            | "org.apache.logging.log4j.LogManager.getLogger"
            | "org.apache.log4j.Logger.getLogger"
            | "java.util.logging.Logger.getLogger"
            | "org.apache.commons.logging.LogFactory.getLog" => obj("logger"),
            "java.lang.System.getenv" | "java.lang.System.getProperty" => Value::clean(),
            "java.util.Properties" => obj("java.util.Properties"),

            // Readers and streams keep the data they wrap.
            "java.io.InputStreamReader"
            | "java.io.BufferedReader"
            | "java.io.StringReader"
            | "java.io.ByteArrayInputStream"
            | "java.io.BufferedInputStream"
            | "java.io.DataInputStream"
            | "java.util.Scanner"
            | "org.xml.sax.InputSource"
            | "javax.xml.transform.stream.StreamSource" => {
                file_args_reached(it, args, span, short);
                obj_tainted("java.io.Reader", args_taint(args))
            }

            _ => {
                // Constructors of other library classes keep their arguments'
                // data; static methods pass it through.
                let is_class = short.chars().next().is_some_and(|c| c.is_ascii_uppercase());
                file_args_accessed(it, args, span, short);
                if is_class {
                    obj_tainted(p, taint.union(&args_taint(args)))
                } else {
                    propagate()
                }
            }
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
            Value::Str(segs) => string_method(it, recv, segs, name, args),
            Value::Unknown(t) if t.is_tainted() && is_string_method(name) => {
                let segs = [Seg::Dyn(t.clone())];
                let as_str = Value::tainted_str(t.clone());
                string_method(it, &as_str, &segs, name, args)
            }
            Value::List(items) => list_method(it, recv, items, name, args),
            Value::Dict(pairs) => map_method(recv, pairs, name, args),
            Value::Obj(o) => obj_method(it, recv, o, name, args, span),
            _ => (generic_method(it, recv, name, args, span), None),
        }
    }

    fn binop(&self, _it: &mut Interp, op: BinOp, l: &Value, r: &Value) -> Option<Value> {
        // `+` with a string operand concatenates.
        if op == BinOp::Add && (matches!(l, Value::Str(_)) || matches!(r, Value::Str(_))) {
            return Some(concat(&[as_string(l), as_string(r)]));
        }
        None
    }

    fn route(&self, _it: &mut Interp, _module: usize, func: &Function) -> Option<Route> {
        let mapping = func.decorators.iter().find_map(|d| {
            let (name, args) = match d {
                crate::ir::Expr::Name(n) => (n.as_str(), None),
                crate::ir::Expr::Call { func, args, .. } => match &**func {
                    crate::ir::Expr::Name(n) => (n.as_str(), Some(args)),
                    _ => return None,
                },
                _ => return None,
            };
            let short = last(name);
            let is_mapping = matches!(
                short,
                "RequestMapping"
                    | "GetMapping"
                    | "PostMapping"
                    | "PutMapping"
                    | "DeleteMapping"
                    | "PatchMapping"
                    | "GET"
                    | "POST"
                    | "PUT"
                    | "DELETE"
                    | "Path"
            );
            is_mapping.then(|| {
                let path = args
                    .and_then(|a| {
                        a.iter()
                            .find(|x| matches!(x.name.as_deref(), None | Some("value" | "path")))
                    })
                    .and_then(|x| match &x.value {
                        crate::ir::Expr::Lit(crate::ir::Const::Str(s)) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let framework = if matches!(short, "GET" | "POST" | "PUT" | "DELETE" | "Path") {
                    "jaxrs"
                } else {
                    "spring"
                };
                (path, framework)
            })
        });
        if let Some((path, framework)) = mapping {
            return Some(Route {
                path,
                params: Vec::new(),
                typed_params: Vec::new(),
                fixed_path: false,
                framework,
            });
        }
        let servlet = matches!(
            func.name.as_str(),
            "doGet" | "doPost" | "doPut" | "doDelete" | "doPatch" | "service" | "doFilter"
        ) && func
            .params
            .iter()
            .any(|p| is_request_type(p.ty.as_deref().unwrap_or("")));
        servlet.then(|| Route {
            path: String::new(),
            params: Vec::new(),
            typed_params: Vec::new(),
            fixed_path: false,
            framework: "servlet",
        })
    }

    fn entry_param(
        &self,
        it: &mut Interp,
        _module: usize,
        _func: &Function,
        route: Option<&Route>,
        _index: usize,
        param: &Param,
    ) -> Value {
        let full = param.ty.as_deref().unwrap_or("");
        let (notes, ty) = match full.rfind('@') {
            Some(_) => {
                let ty = full.rsplit(' ').next().unwrap_or("");
                (full, ty)
            }
            None => ("", full),
        };
        if is_request_type(ty) {
            return obj(REQUEST);
        }
        match canonical(ty).as_str() {
            "javax.servlet.http.HttpServletResponse" | "javax.servlet.ServletResponse" => {
                return obj(RESPONSE)
            }
            "javax.servlet.http.HttpSession" => return obj(SESSION),
            _ => {}
        }
        let bound = [
            "@RequestParam",
            "@PathVariable",
            "@RequestHeader",
            "@CookieValue",
            "@RequestBody",
            "@ModelAttribute",
            "@MatrixVariable",
            "@RequestPart",
            "@QueryParam",
            "@PathParam",
            "@FormParam",
            "@HeaderParam",
            "@CookieParam",
            "@MatrixParam",
            "@BeanParam",
        ]
        .iter()
        .any(|n| notes.contains(n));
        // Spring binds plain parameters of a handler from the request too.
        let plain_spring = route.is_some_and(|r| r.framework == "spring")
            && notes.is_empty()
            && matches!(
                ty,
                "String" | "java.lang.String" | "String[]" | "List" | "Map"
            );
        if bound || plain_spring {
            let t = it.source(&format!("параметр запроса {}", param.name));
            if is_numeric_type(ty) {
                return Value::Unknown(t.with_safe(ctx::ALL & !ctx::SESSION));
            }
            return Value::tainted_str(t);
        }
        Value::clean()
    }

    fn sanitizer_of(&self, qualname: &str) -> u32 {
        let mut parts = qualname.rsplit('.');
        let method = parts.next().unwrap_or(qualname);
        let bits = sanitizer(method);
        if bits != 0 {
            return bits;
        }
        // An escaping class: `Escape.htmlElementContent`, `XssEncoder.forJs`.
        let class = parts.next().unwrap_or("");
        let lower = class.to_ascii_lowercase();
        if ["escape", "encode", "sanitiz"]
            .iter()
            .any(|w| lower.contains(w))
        {
            return name_sanitizer(&format!("{class}{method}"));
        }
        0
    }

    fn refine_method(
        &self,
        recv: &Value,
        name: &str,
        args: &[Value],
        truth: bool,
    ) -> Vec<(FactOn, Fact)> {
        match (name, truth) {
            ("equals" | "equalsIgnoreCase" | "contentEquals", true) => {
                // `x.equals("a")` or `"a".equals(x)`.
                let arg = args.first();
                match (recv.as_str(), arg.and_then(|v| v.as_str())) {
                    (Some(lit), None) => vec![(FactOn::Arg(0), Fact::OneOf(vec![Value::str(lit)]))],
                    (None, Some(lit)) => vec![(FactOn::Recv, Fact::OneOf(vec![Value::str(lit)]))],
                    _ => Vec::new(),
                }
            }
            ("contains", false) => match args.first().and_then(|v| v.as_str()) {
                Some(s) => vec![(FactOn::Recv, Fact::NotContains(s))],
                None => Vec::new(),
            },
            ("matches", true) => {
                // `s.matches(re)` or `Pattern.matches(re, s)`: whole-string match.
                let (pattern, on) = match recv {
                    Value::Ref(p, _) if p.ends_with("Pattern") => {
                        (args.first().and_then(|v| v.as_str()), FactOn::Arg(1))
                    }
                    _ => (args.first().and_then(|v| v.as_str()), FactOn::Recv),
                };
                match pattern.as_deref().and_then(regex_chars) {
                    Some(set) => vec![(on, Fact::Safe(set.safety()))],
                    None => Vec::new(),
                }
            }
            _ => refine_str_method(name, args, truth),
        }
    }

    fn facts_safety(&self, facts: &[Fact], _value: &Value) -> u32 {
        literal_check_safety(facts)
    }

    fn quiet_entries(&self) -> bool {
        true
    }

    fn coerce(&self, it: &mut Interp, ty: &str, value: Value) -> Value {
        if is_numeric_type(ty) {
            return match value {
                Value::Int(_) | Value::Float(_) | Value::Bool(_) => value,
                Value::Str(_) => numeric(&value),
                other => Value::Unknown(other.taint().with_safe(ctx::ALL)),
            };
        }
        // A declared library type gives an otherwise unknown value methods;
        // an array of them stays a container.
        if ty.ends_with("[]") {
            return value;
        }
        let class = canonical(ty);
        let typed = class.contains('.')
            && KNOWN_CLASSES.contains(&class.as_str())
            && !matches!(
                class.as_str(),
                // The object may be a SecureRandom made by reflection.
                "java.util.Random"
                    | "java.lang.String"
                    | "java.lang.StringBuilder"
                    | "java.lang.StringBuffer"
                    | "java.lang.Object"
                    | "java.util.List"
                    | "java.util.Map"
                    | "java.util.Set"
            );
        match value {
            Value::Unknown(t) if typed => obj_tainted(&class, t),
            // A project's own implementation of a modeled API (a container
            // implementing ServletContext): the API's contract is what the
            // calling code relies on.
            Value::Obj(o) if typed && o.def.is_some() => obj_tainted(&class, o.taint.clone()),
            Value::OneOf(ref alts)
                if typed
                    && alts.iter().any(|a| {
                        matches!(a, Value::Unknown(_))
                            || matches!(a, Value::Obj(o) if o.def.is_some())
                    }) =>
            {
                obj_tainted(&class, value.taint())
            }
            // A field or variable of a project type that the code does not
            // assign, typically one a framework injects: its methods are
            // the project's.
            Value::Unknown(t) => match it.java_type_class(ty) {
                Some(cv) => Value::Obj(Rc::new(Obj {
                    class: cv.qualname.clone(),
                    def: Some(cv),
                    fields: Vec::new(),
                    taint: t,
                })),
                None => Value::Unknown(t),
            },
            other => other,
        }
    }
}

/// A File or Path object.
fn is_file_obj(o: &Obj) -> bool {
    matches!(o.class.as_ref(), "java.io.File" | "java.nio.file.Path")
}

/// The path a value names: the text of a File, Path or URI, or the value.
fn path_text(v: &Value) -> Value {
    match v {
        Value::Obj(o) => o
            .field("path")
            .or_else(|| o.field("url"))
            .cloned()
            .unwrap_or_else(|| Value::Unknown(o.taint.clone())),
        other => other.clone(),
    }
}

/// File and Path methods that reach the file system.
fn file_access(name: &str) -> bool {
    matches!(
        name,
        "exists"
            | "delete"
            | "deleteOnExit"
            | "createNewFile"
            | "mkdir"
            | "mkdirs"
            | "renameTo"
            | "list"
            | "listFiles"
            | "length"
            | "lastModified"
            | "isFile"
            | "isDirectory"
            | "isHidden"
            | "canRead"
            | "canWrite"
            | "canExecute"
            | "setReadable"
            | "setWritable"
            | "setExecutable"
            | "setLastModified"
            | "setReadOnly"
    )
}

/// A library call given a File or Path reads or writes that file
/// (`FileUtils.readFileToString(f)`, `new Scanner(f)`, `part.transferTo(f)`).
fn file_args_accessed(it: &mut Interp, args: &[ArgVal], span: Span, what: &str) {
    if file_io_name(what) {
        file_args_reached(it, args, span, what);
    }
}

/// Every File or Path among the arguments is read or written.
fn file_args_reached(it: &mut Interp, args: &[ArgVal], span: Span, what: &str) {
    for x in args {
        if matches!(&x.value, Value::Obj(o) if is_file_obj(o)) {
            file_sink(it, &x.value, span, what);
        }
    }
}

/// A File or Path naming `path`, made at `span`.
fn file_obj(it: &Interp, class: &str, path: Value, span: Span) -> Value {
    // Kept as text so that joining two files keeps both places.
    let made = Value::str(format!(
        "{}:{}:{}:{}",
        it.module(),
        span.line,
        span.column,
        span.end_line
    ));
    let mut o = Obj::new(class);
    o.taint = path.taint();
    Value::Obj(Rc::new(o.with_field("path", path).with_field("made", made)))
}

/// A file reached through a File or Path: reported where the object was
/// made from user data, once however often it is used.
fn file_sink(it: &mut Interp, file: &Value, span: Span, what: &str) {
    let made: Vec<(usize, Span)> = match file {
        Value::Obj(o) => o
            .field("made")
            .map(|m| m.alternatives())
            .unwrap_or_default()
            .iter()
            .filter_map(|m| {
                let text = m.as_str()?;
                let mut n = text.split(':').map(|x| x.parse::<u32>().ok());
                let (module, line, column, end_line) =
                    (n.next()??, n.next()??, n.next()??, n.next()??);
                Some((
                    module as usize,
                    Span {
                        line,
                        column,
                        end_line,
                    },
                ))
            })
            .collect(),
        _ => Vec::new(),
    };
    if made.is_empty() {
        it.sink(&PATH, &path_text(file), span, what);
        return;
    }
    let path = path_text(file);
    for (module, at) in made {
        it.sink_at(&PATH, &path, module, at, what);
    }
}

/// Names of library calls that read, write or list the files they are given.
fn file_io_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "read", "write", "copy", "move", "delete", "transfer", "open", "load", "save", "store",
        "extract", "unzip", "zip", "upload", "download", "mkdir", "exists", "list", "touch",
        "lines", "append", "scanner", "image", "jarfile", "resource", "channel",
    ]
    .iter()
    .any(|w| n.contains(w))
}

fn is_request_type(ty: &str) -> bool {
    let t = ty.rsplit(' ').next().unwrap_or(ty);
    matches!(
        last(t),
        "HttpServletRequest"
            | "ServletRequest"
            | "HttpServletRequestWrapper"
            | "MultipartHttpServletRequest"
            | "WebRequest"
            | "NativeWebRequest"
    )
}

fn is_string_method(name: &str) -> bool {
    matches!(
        name,
        "trim"
            | "strip"
            | "toUpperCase"
            | "toLowerCase"
            | "substring"
            | "subSequence"
            | "replace"
            | "replaceAll"
            | "replaceFirst"
            | "concat"
            | "split"
            | "toCharArray"
            | "getBytes"
            | "toString"
            | "intern"
            | "charAt"
            | "append"
            | "insert"
            | "reverse"
            | "formatted"
            | "repeat"
            | "stripLeading"
            | "stripTrailing"
    )
}

/// `String`, `StringBuilder` and `StringBuffer` methods. Builders are
/// strings too: `append` returns the new value and replaces the receiver.
fn string_method(
    it: &mut Interp,
    recv: &Value,
    segs: &[Seg],
    name: &str,
    args: &[ArgVal],
) -> (Value, Option<Value>) {
    let int = |i: usize| match arg(args, i, "") {
        Some(Value::Int(n)) => Some(*n),
        _ => None,
    };
    let lit = literal(segs);
    let v = match name {
        "append" => {
            let added = match args {
                // append(char[] s, int offset, int len)
                [s, _, _] => as_string(&s.value),
                _ => as_string(&a(args, 0)),
            };
            let new = concat(&[recv.clone(), added]);
            return (new.clone(), Some(new));
        }
        "insert" => {
            let new = Value::tainted_str(recv.taint().union(&a(args, 1).taint()));
            return (new.clone(), Some(new));
        }
        "reverse" | "setLength" | "setCharAt" | "deleteCharAt" | "delete" => {
            let new = match lit {
                Some(s) if name == "reverse" => Value::str(s.chars().rev().collect::<String>()),
                _ => Value::tainted_str(recv.taint()),
            };
            return (new.clone(), Some(new));
        }
        "replace" if matches!(a(args, 0), Value::Int(_)) => {
            // StringBuilder.replace(start, end, str)
            let new = Value::tainted_str(recv.taint().union(&a(args, 2).taint()));
            return (new.clone(), Some(new));
        }
        "toString" | "intern" | "toCharArray" | "getBytes" | "chars" | "describeConstable" => {
            recv.clone()
        }
        "length" => match lit {
            Some(s) => Value::Int(s.chars().count() as i64),
            None => Value::Unknown(Taint::clean()),
        },
        "isEmpty" | "isBlank" => match lit {
            Some(s) => Value::Bool(if name == "isEmpty" {
                s.is_empty()
            } else {
                s.trim().is_empty()
            }),
            None => Value::clean(),
        },
        "charAt" | "codePointAt" => match int(0) {
            Some(i) => {
                let c = slice_value(recv, Some(i), Some(i + 1), true, true);
                if name == "codePointAt" {
                    numeric(&c)
                } else {
                    c
                }
            }
            None => Value::tainted_str(recv.taint()),
        },
        "substring" | "subSequence" => {
            let lo = int(0);
            let hi = int(1);
            let hi_known = args.len() < 2 || hi.is_some();
            slice_value(recv, lo, hi, lo.is_some(), hi_known)
        }
        "toUpperCase" => str_method(segs, "upper", &[]),
        "toLowerCase" => str_method(segs, "lower", &[]),
        "trim" | "strip" => str_method(segs, "strip", &[]),
        "stripLeading" => str_method(segs, "lstrip", &[]),
        "stripTrailing" => str_method(segs, "rstrip", &[]),
        "replace" => {
            let (old, new) = (as_string(&a(args, 0)), as_string(&a(args, 1)));
            str_method(segs, "replace", &[ArgVal::plain(old), ArgVal::plain(new)])
        }
        "replaceAll" | "replaceFirst" => match a(args, 0).as_str() {
            Some(pattern) => {
                let repl = a(args, 1);
                regex_sub(&pattern, Some(&repl), recv)
            }
            None => Value::tainted_str(recv.taint().union(&args_taint(args))),
        },
        "concat" => concat(&[recv.clone(), as_string(&a(args, 0))]),
        "repeat" => Value::tainted_str(recv.taint()),
        "split" => match a(args, 0).as_str() {
            Some(sep) if !sep.chars().any(|c| "\\[](){}.*+?^$|".contains(c)) => {
                str_method(segs, "split", &[ArgVal::plain(Value::str(sep))])
            }
            _ => Value::Unknown(recv.taint()),
        },
        "equals" | "equalsIgnoreCase" | "contentEquals" => match (lit, a(args, 0).as_str()) {
            (Some(x), Some(y)) => Value::Bool(if name == "equals" {
                x == y
            } else {
                x.eq_ignore_ascii_case(&y)
            }),
            _ => Value::clean(),
        },
        "startsWith" => str_method(segs, "startswith", args),
        "endsWith" => str_method(segs, "endswith", args),
        "contains" => match (lit, a(args, 0).as_str()) {
            (Some(x), Some(y)) => Value::Bool(x.contains(&y)),
            (None, Some(y)) => match str_contains(segs, &y) {
                Some(b) => Value::Bool(b),
                None => Value::clean(),
            },
            _ => Value::clean(),
        },
        "indexOf" => str_method(segs, "find", args),
        "lastIndexOf" => str_method(segs, "rfind", args),
        "matches" | "compareTo" | "compareToIgnoreCase" | "hashCode" | "regionMatches" => {
            Value::clean()
        }
        "format" | "formatted" => {
            let rest: Vec<Value> = args.iter().map(|x| x.value.clone()).collect();
            percent_format(segs, &Value::list(rest))
        }
        _ => {
            let _ = it;
            Value::Unknown(recv.taint().union(&args_taint(args)))
        }
    };
    (v, None)
}

/// `java.util` lists, sets, deques and arrays.
fn list_method(
    it: &mut Interp,
    recv: &Value,
    items: &Rc<Vec<Value>>,
    name: &str,
    args: &[ArgVal],
) -> (Value, Option<Value>) {
    let mut v = items.as_ref().clone();
    let changed = |v: Vec<Value>| Some(Value::list(v));
    match name {
        "add" | "addLast" | "offer" | "offerLast" | "addElement" => match args {
            [i, x] if matches!(i.value, Value::Int(_)) => {
                let Value::Int(i) = i.value else {
                    unreachable!()
                };
                let i = (i.max(0) as usize).min(v.len());
                v.insert(i, x.value.clone());
                (Value::Bool(true), changed(v))
            }
            _ => {
                v.push(a(args, 0));
                (Value::Bool(true), changed(v))
            }
        },
        "push" | "addFirst" | "offerFirst" => {
            v.insert(0, a(args, 0));
            (Value::None, changed(v))
        }
        "addAll" => match a(args, 0) {
            Value::List(more) => {
                v.extend(more.iter().cloned());
                (Value::Bool(true), changed(v))
            }
            other => {
                let t = other.taint().union(&recv.taint());
                (Value::Bool(true), Some(Value::Unknown(t)))
            }
        },
        "get" | "elementAt" => (it.index(recv, &a(args, 0)), None),
        "getFirst" | "peek" | "peekFirst" | "element" | "firstElement" => {
            (v.first().cloned().unwrap_or_else(Value::clean), None)
        }
        "getLast" | "peekLast" | "lastElement" => {
            (v.last().cloned().unwrap_or_else(Value::clean), None)
        }
        "pop" | "poll" | "pollFirst" | "removeFirst" => {
            if v.is_empty() {
                return (Value::clean(), None);
            }
            let x = v.remove(0);
            (x, changed(v))
        }
        "pollLast" | "removeLast" => match v.pop() {
            Some(x) => (x, changed(v)),
            None => (Value::clean(), None),
        },
        "remove" => match a(args, 0) {
            Value::Int(i) => {
                let n = v.len() as i64;
                if i >= 0 && i < n {
                    let x = v.remove(i as usize);
                    (x, changed(v))
                } else {
                    (Value::clean(), None)
                }
            }
            x if is_const(&x) => match v.iter().position(|e| values_eq(e, &x) == Some(true)) {
                Some(pos) => {
                    v.remove(pos);
                    (Value::Bool(true), changed(v))
                }
                None => (Value::Bool(false), None),
            },
            _ => (recv.element(), None),
        },
        "set" => match a(args, 0) {
            Value::Int(i) if i >= 0 && (i as usize) < v.len() => {
                let old = std::mem::replace(&mut v[i as usize], a(args, 1));
                (old, changed(v))
            }
            _ => {
                let t = recv.taint().union(&a(args, 1).taint());
                (Value::clean(), Some(Value::Unknown(t)))
            }
        },
        "size" => (Value::Int(v.len() as i64), None),
        "isEmpty" => (Value::Bool(v.is_empty()), None),
        "clear" => (Value::None, changed(Vec::new())),
        "contains" | "indexOf" | "lastIndexOf" | "hashCode" | "equals" | "hasNext"
        | "hasMoreElements" => (Value::clean(), None),
        "iterator" | "listIterator" | "toArray" | "stream" | "elements" | "descendingIterator"
        | "clone" | "copyOf" => (recv.clone(), None),
        "subList" => match (a(args, 0), a(args, 1)) {
            (Value::Int(lo), Value::Int(hi)) => {
                (slice_value(recv, Some(lo), Some(hi), true, true), None)
            }
            _ => (Value::Unknown(recv.taint()), None),
        },
        "next" | "nextElement" | "previous" | "findFirst" | "findAny" | "orElse" | "get_" => {
            (recv.element(), None)
        }
        // `Map.Entry` from `entrySet()`: a [key, value] pair.
        "getKey" if v.len() == 2 => (v[0].clone(), None),
        "getValue" if v.len() == 2 => (v[1].clone(), None),
        "forEach" => {
            let f = a(args, 0);
            for x in items.iter().take(8) {
                it.call_value(&f, &[ArgVal::plain(x.clone())], Span::default());
            }
            (Value::None, None)
        }
        _ => (Value::Unknown(recv.taint().union(&args_taint(args))), None),
    }
}

/// `java.util` maps with constant keys.
fn map_method(
    recv: &Value,
    pairs: &Rc<Vec<(Value, Value)>>,
    name: &str,
    args: &[ArgVal],
) -> (Value, Option<Value>) {
    let key = a(args, 0);
    let lookup = |k: &Value| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone());
    let all_values = || join_all(pairs.iter().map(|(_, v)| v.clone()));
    match name {
        "put" | "putIfAbsent" | "replace" => {
            let value = a(args, 1);
            if !is_const(&key) {
                let t = recv.taint().union(&value.taint());
                return (Value::clean(), Some(Value::Unknown(t)));
            }
            let mut out = pairs.as_ref().clone();
            let old = lookup(&key);
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) if name != "putIfAbsent" => slot.1 = value,
                Some(_) => {}
                None if name != "replace" => out.push((key, value)),
                None => {}
            }
            (old.unwrap_or(Value::None), Some(Value::Dict(Rc::new(out))))
        }
        "get" | "getOrDefault" => {
            let default = if name == "getOrDefault" {
                a(args, 1)
            } else {
                Value::None
            };
            if is_const(&key) {
                (lookup(&key).unwrap_or(default), None)
            } else {
                (
                    all_values().map(|v| join(&v, &default)).unwrap_or(default),
                    None,
                )
            }
        }
        "remove" => {
            if !is_const(&key) {
                return (all_values().unwrap_or_else(Value::clean), None);
            }
            let v = lookup(&key).unwrap_or(Value::None);
            let out: Vec<(Value, Value)> =
                pairs.iter().filter(|(pk, _)| *pk != key).cloned().collect();
            (v, Some(Value::Dict(Rc::new(out))))
        }
        "keySet" => (
            Value::list(pairs.iter().map(|(k, _)| k.clone()).collect()),
            None,
        ),
        "values" => (
            Value::list(pairs.iter().map(|(_, v)| v.clone()).collect()),
            None,
        ),
        "entrySet" => (
            Value::list(
                pairs
                    .iter()
                    .map(|(k, v)| Value::list(vec![k.clone(), v.clone()]))
                    .collect(),
            ),
            None,
        ),
        "putAll" => {
            let mut out = pairs.as_ref().clone();
            match a(args, 0) {
                Value::Dict(more) => {
                    for (k, v) in more.iter() {
                        match out.iter_mut().find(|(ok, _)| ok == k) {
                            Some(slot) => slot.1 = v.clone(),
                            None => out.push((k.clone(), v.clone())),
                        }
                    }
                    (Value::None, Some(Value::Dict(Rc::new(out))))
                }
                other => {
                    let t = recv.taint().union(&other.taint());
                    (Value::None, Some(Value::Unknown(t)))
                }
            }
        }
        "size" => (Value::Int(pairs.len() as i64), None),
        "isEmpty" => (Value::Bool(pairs.is_empty()), None),
        "containsKey" | "containsValue" => (Value::clean(), None),
        "clear" => (Value::None, Some(Value::Dict(Rc::new(Vec::new())))),
        _ => (Value::Unknown(recv.taint()), None),
    }
}

fn obj_method(
    it: &mut Interp,
    recv: &Value,
    o: &Obj,
    name: &str,
    args: &[ArgVal],
    span: Span,
) -> (Value, Option<Value>) {
    let class = o.class.as_ref();
    let a0 = || a(args, 0);
    let with = |f: &str, v: Value| Some(Value::Obj(Rc::new(o.clone().with_field(f, v))));
    match class {
        REQUEST => {
            let src = |it: &mut Interp| it.source(&format!("request.{name}()"));
            let v = match name {
                "getParameter"
                | "getHeader"
                | "getQueryString"
                | "getRequestURI"
                | "getPathInfo"
                | "getPathTranslated"
                | "getServerName"
                | "getContentType"
                | "getRemoteUser"
                | "getRequestedSessionId" => Value::tainted_str(src(it)),
                "getRequestURL" => Value::tainted_str(src(it)),
                "getParameterValues" | "getParameterMap" | "getParameterNames" | "getHeaders"
                | "getHeaderNames" | "getCookies" | "getInputStream" | "getReader" | "getPart"
                | "getParts" | "getHeaderValues" | "getNativeRequest" => Value::Unknown(src(it)),
                "getIntHeader" | "getContentLength" | "getDateHeader" => Value::clean(),
                "getSession" => obj(SESSION),
                "getServletContext" => obj(SERVLET_CONTEXT),
                _ => Value::clean(),
            };
            (v, None)
        }
        // Resources of the web application: the container confines the
        // path to it.
        SERVLET_CONTEXT => match name {
            "getResource" => (obj("java.net.URL"), None),
            "getResourceAsStream" => (obj("java.io.InputStream"), None),
            "getRealPath" | "getMimeType" | "getInitParameter" | "getContextPath"
            | "getServerInfo" | "getAttribute" => (Value::clean(), None),
            _ => (generic_method(it, recv, name, args, span), None),
        },
        RESPONSE => match name {
            "getWriter" | "getOutputStream" => {
                let mut w = Obj::new(WRITER);
                if let Some(ct) = o.field("content_type") {
                    w = w.with_field("content_type", ct.clone());
                }
                (Value::Obj(Rc::new(w)), None)
            }
            "setContentType" => {
                // Also applies to a writer obtained before the call.
                it.notes.insert("content_type", a0());
                (Value::None, with("content_type", a0()))
            }
            "setHeader" | "addHeader" => {
                let header = a0().as_str().unwrap_or_default().to_ascii_lowercase();
                let value = a(args, 1);
                match header.as_str() {
                    "content-type" => {
                        it.notes.insert("content_type", value.clone());
                        return (Value::None, with("content_type", value));
                    }
                    "location" => {
                        it.sink(&REDIRECT, &value, span, name);
                    }
                    "set-cookie" => {
                        it.sink(&HEADER, &value, span, name);
                        it.sink(&WEAK_RANDOM, &value, span, "значение cookie");
                    }
                    "access-control-allow-origin" => {
                        it.sink(&CORS, &value, span, name);
                    }
                    // Servlet containers drop CR and LF from header values,
                    // so other headers cannot be split.
                    _ => {}
                }
                (Value::None, None)
            }
            "sendRedirect" | "encodeRedirectURL" | "encodeRedirectUrl" => {
                if name == "sendRedirect" {
                    it.sink(&REDIRECT, &a0(), span, name);
                }
                (Value::None, None)
            }
            "addCookie" => {
                check_cookie_obj(it, &a0(), span);
                (Value::None, None)
            }
            _ => (Value::None, None),
        },
        WRITER => {
            if matches!(
                name,
                "print" | "println" | "write" | "format" | "printf" | "append"
            ) {
                let declared = o
                    .field("content_type")
                    .or_else(|| it.notes.get("content_type"))
                    .map(literals);
                let html = match declared {
                    Some(types) if !types.is_empty() => types
                        .iter()
                        .any(|t| t.to_ascii_lowercase().contains("html")),
                    _ => true,
                };
                if html {
                    for x in args {
                        if matches!(x.value, Value::Obj(ref ob) if ob.class.contains("Locale")) {
                            continue;
                        }
                        if it.sink(&XSS, &x.value, span, &format!("response.{name}")) {
                            break;
                        }
                    }
                }
                return (recv.clone(), None);
            }
            (Value::None, None)
        }
        SESSION => match name {
            "setAttribute" | "putValue" => {
                let (key, value) = (a0(), a(args, 1));
                if !it.sink(&TRUST, &key, span, "session.setAttribute") {
                    it.sink(&TRUST, &value, span, "session.setAttribute");
                }
                it.sink(&WEAK_RANDOM, &value, span, "session.setAttribute");
                (Value::None, None)
            }
            _ => (Value::clean(), None),
        },
        COOKIE => match name {
            "setSecure" => (Value::None, with("secure", a0())),
            "setValue" => (Value::None, with("value", a0())),
            "getValue" | "getName" => (
                o.field(&name[3..].to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_else(|| Value::Unknown(o.taint.clone())),
                None,
            ),
            _ => (Value::None, None),
        },
        "java.sql.Connection" => match name {
            "createStatement" => (obj("java.sql.Statement"), None),
            "prepareStatement" | "prepareCall" | "nativeSQL" => {
                it.sink(&SQLI, &a0(), span, &format!("Connection.{name}"));
                (obj("java.sql.PreparedStatement"), None)
            }
            _ => (Value::clean(), None),
        },
        "java.sql.Statement" | "java.sql.PreparedStatement" | "java.sql.CallableStatement" => {
            if matches!(
                name,
                "execute" | "executeQuery" | "executeUpdate" | "executeLargeUpdate" | "addBatch"
            ) && !args.is_empty()
            {
                it.sink(&SQLI, &a0(), span, &format!("Statement.{name}"));
            }
            match name {
                "executeQuery" | "getResultSet" => (obj("java.sql.ResultSet"), None),
                _ => (Value::clean(), None),
            }
        }
        "org.springframework.jdbc.core.JdbcTemplate"
        | "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate" => {
            if name.starts_with("query") || matches!(name, "update" | "execute" | "batchUpdate") {
                let sqls: Vec<Value> = if name == "batchUpdate" {
                    args.iter().map(|x| x.value.clone()).collect()
                } else {
                    vec![a0()]
                };
                for s in sqls {
                    if matches!(s, Value::Str(_) | Value::Unknown(_) | Value::OneOf(_))
                        && it.sink(&SQLI, &s, span, &format!("JdbcTemplate.{name}"))
                    {
                        break;
                    }
                }
            }
            (Value::clean(), None)
        }
        "java.lang.Runtime" => {
            if name == "exec" {
                check_argv(it, &a0(), span, "Runtime.exec");
                // Environment of the command: `exec(cmd, envp)`.
                if let Value::List(env) = a(args, 1) {
                    for e in env.iter() {
                        if it.sink(&CMDI, e, span, "Runtime.exec envp") {
                            break;
                        }
                    }
                }
                return (obj("java.lang.Process"), None);
            }
            (Value::clean(), None)
        }
        "java.lang.ProcessBuilder" => match name {
            "command" if !args.is_empty() => {
                let cmd = match args {
                    [one] if matches!(one.value, Value::List(_) | Value::Unknown(_)) => {
                        one.value.clone()
                    }
                    _ => Value::list(args.iter().map(|x| x.value.clone()).collect()),
                };
                check_argv(it, &cmd, span, "ProcessBuilder.command");
                (recv.clone(), None)
            }
            "start" => (obj("java.lang.Process"), None),
            _ => (recv.clone(), None),
        },
        "java.util.Random" => match name {
            "nextBytes" => {
                if let Some(var) = args.first().and_then(|x| x.var.clone()) {
                    let v = it.weak_random("Random.nextBytes()", span, &[]);
                    it.set_var(&var, v);
                }
                (Value::None, None)
            }
            "setSeed" => (Value::None, None),
            _ => (
                it.weak_random(&format!("Random.{name}()"), span, args),
                None,
            ),
        },
        "java.security.SecureRandom" => {
            if name == "nextBytes" {
                if let Some(var) = args.first().and_then(|x| x.var.clone()) {
                    it.set_var(&var, Value::clean());
                }
            }
            (Value::clean(), None)
        }
        "java.util.Base64.Encoder" => (a0().sanitized(ENCODED_SAFE), None),
        "java.util.Base64.Decoder" => (a0().unsanitized(ctx::ALL), None),
        "org.owasp.esapi.Encoder" => {
            let bits = sanitizer(name);
            let x = encoded_arg(args);
            if bits != 0 {
                return (x.sanitized(bits), None);
            }
            if name.starts_with("decode") || name == "canonicalize" {
                return (x.unsanitized(ctx::ALL), None);
            }
            (Value::Unknown(x.taint()), None)
        }
        "org.owasp.esapi.Validator" => {
            // getValidInput(context, input, type, maxLength, allowNull):
            // the input matched the named pattern.
            let x = a(args, 1);
            if name.starts_with("getValid") {
                return (x.sanitized(ctx::ALL & !ctx::SESSION), None);
            }
            (Value::clean(), None)
        }
        "java.security.MessageDigest" => match name {
            "digest" => (
                Value::Unknown(args_taint(args).with_safe(ENCODED_SAFE)),
                None,
            ),
            _ => (Value::None, None),
        },
        "javax.xml.xpath.XPathFactory" => (obj("javax.xml.xpath.XPath"), None),
        "javax.xml.xpath.XPath" => {
            if matches!(name, "compile" | "evaluate" | "evaluateExpression") {
                it.sink(&XPATHI, &a0(), span, &format!("XPath.{name}"));
            }
            (Value::clean(), None)
        }
        "javax.naming.directory.DirContext" | "org.springframework.ldap.core.LdapTemplate" => {
            if name == "search" {
                // search(name, filterExpr, filterArgs, controls) keeps the
                // arguments out of the filter.
                let filter = a(args, 1);
                it.sink(&LDAPI, &filter, span, "DirContext.search");
            }
            (Value::Unknown(Taint::clean()), None)
        }
        "javax.script.ScriptEngineManager" => (obj("javax.script.ScriptEngine"), None),
        "javax.script.ScriptEngine" => {
            if name == "eval" {
                it.sink(&CODEI, &a0(), span, "ScriptEngine.eval");
            }
            (Value::clean(), None)
        }
        "org.springframework.expression.ExpressionParser" => {
            if name == "parseExpression" || name == "parseRaw" {
                it.sink(&CODEI, &a0(), span, "SpEL parseExpression");
            }
            (obj("org.springframework.expression.Expression"), None)
        }
        "java.io.ObjectInputStream" | "java.beans.XMLDecoder" => {
            if matches!(name, "readObject" | "readUnshared") {
                it.sink(&DESER, &Value::Unknown(o.taint.clone()), span, name);
            }
            (Value::clean(), None)
        }
        "com.thoughtworks.xstream.XStream" => {
            if name == "fromXML" {
                it.sink(&DESER, &a0(), span, "XStream.fromXML");
            }
            (Value::clean(), None)
        }
        "org.yaml.snakeyaml.Yaml" => {
            let safe = o.field("safe").and_then(|v| v.truthy()) == Some(true);
            if !safe && matches!(name, "load" | "loadAll" | "loadAs") {
                it.sink(&DESER, &a0(), span, &format!("Yaml.{name}"));
            }
            (Value::clean(), None)
        }
        "javax.xml.parsers.DocumentBuilderFactory"
        | "javax.xml.parsers.SAXParserFactory"
        | "javax.xml.stream.XMLInputFactory"
        | "javax.xml.transform.TransformerFactory"
        | "org.xml.sax.XMLReader"
        | "org.dom4j.io.SAXReader"
        | "org.jdom2.input.SAXBuilder"
        | "javax.xml.parsers.DocumentBuilder"
        | "javax.xml.parsers.SAXParser" => xml_method(it, recv, o, name, args, span),
        "java.net.URL" | "java.net.URI" => match name {
            "openConnection" | "openStream" | "getContent" => {
                let u = o
                    .field("url")
                    .cloned()
                    .unwrap_or_else(|| Value::Unknown(o.taint.clone()));
                it.sink(&SSRF, &u, span, &format!("URL.{name}"));
                (obj_tainted("java.io.Reader", Taint::clean()), None)
            }
            "toURL" => {
                let mut u = o.clone();
                u.class = "java.net.URL".into();
                (Value::Obj(Rc::new(u)), None)
            }
            _ => (Value::Unknown(o.taint.clone()), None),
        },
        "org.springframework.web.client.RestTemplate" => {
            if matches!(
                name,
                "getForObject"
                    | "getForEntity"
                    | "postForObject"
                    | "postForEntity"
                    | "postForLocation"
                    | "exchange"
                    | "execute"
                    | "put"
                    | "delete"
                    | "patchForObject"
                    | "headForHeaders"
                    | "optionsForAllow"
            ) {
                it.sink(&SSRF, &a0(), span, &format!("RestTemplate.{name}"));
            }
            (Value::clean(), None)
        }
        "logger" => {
            if matches!(
                name,
                "trace"
                    | "debug"
                    | "info"
                    | "warn"
                    | "error"
                    | "fatal"
                    | "log"
                    | "severe"
                    | "warning"
                    | "fine"
                    | "finer"
                    | "finest"
                    | "config"
            ) {
                for x in args {
                    if it.sink(&LOGI, &x.value, span, &format!("log.{name}")) {
                        break;
                    }
                }
            }
            (Value::None, None)
        }
        "java.util.Properties" => match name {
            "getProperty" => (config_value(it, &a0(), args.get(1).map(|x| &x.value)), None),
            _ => (Value::None, None),
        },
        "java.io.File" | "java.nio.file.Path" if file_access(name) => {
            file_sink(it, recv, span, &format!("{}.{name}", last(&o.class)));
            let v = match name {
                "list" | "listFiles" => Value::Unknown(Taint::clean()),
                _ => Value::clean(),
            };
            (v, None)
        }
        "java.io.File" | "java.nio.file.Path" => match name {
            "getName" | "getFileName" => (
                Value::tainted_str(o.taint.clone().with_safe(ctx::PATH)),
                None,
            ),
            "getPath" | "getAbsolutePath" | "getCanonicalPath" | "toString" | "toAbsolutePath"
            | "normalize" | "toRealPath" | "getCanonicalFile" | "getAbsoluteFile" | "toFile"
            | "toPath" | "getParent" | "getParentFile" => {
                if name.ends_with("Path") || name == "toString" || name == "getParent" {
                    (
                        o.field("path")
                            .cloned()
                            .unwrap_or_else(|| Value::tainted_str(o.taint.clone())),
                        None,
                    )
                } else {
                    (recv.clone(), None)
                }
            }
            "resolve" | "resolveSibling" => {
                let other = path_text(&a0());
                let path = concat(&[path_text(recv), Value::str("/"), other]);
                (file_obj(it, "java.nio.file.Path", path, span), None)
            }
            _ => (Value::clean(), None),
        },
        "java.io.Reader" | "java.io.Stream" => match name {
            "close" | "mark" | "reset" | "ready" | "markSupported" => (Value::None, None),
            "nextInt" | "nextLong" | "nextDouble" => {
                (Value::Unknown(o.taint.clone().with_safe(ctx::ALL)), None)
            }
            _ => (Value::Unknown(o.taint.clone()), None),
        },
        _ => {
            let bits = sanitizer(name);
            if bits != 0 {
                return (encoded_arg(args).sanitized(bits), None);
            }
            (generic_method(it, recv, name, args, span), None)
        }
    }
}

/// XML parser factories and parsers: external entities stay enabled
/// unless DOCTYPEs or external entities are turned off.
fn xml_method(
    it: &mut Interp,
    recv: &Value,
    o: &Obj,
    name: &str,
    args: &[ArgVal],
    span: Span,
) -> (Value, Option<Value>) {
    let secure = o.field("secure").and_then(|v| v.truthy()) == Some(true);
    let mark_secure = || {
        Some(Value::Obj(Rc::new(
            o.clone().with_field("secure", Value::Bool(true)),
        )))
    };
    match name {
        "setFeature" => {
            let feature = a(args, 0).as_str().unwrap_or_default();
            let on = a(args, 1).truthy();
            let hardening = (feature.ends_with("disallow-doctype-decl") && on == Some(true))
                || (feature.ends_with("external-general-entities") && on == Some(false))
                || (feature.ends_with("FEATURE_SECURE_PROCESSING") && on == Some(true));
            (Value::None, if hardening { mark_secure() } else { None })
        }
        "setProperty" | "setAttribute" => {
            let key = match a(args, 0) {
                Value::Ref(p, _) => p.to_string(),
                v => v.as_str().unwrap_or_default(),
            };
            let off = a(args, 1).truthy() == Some(false)
                || a(args, 1).as_str().is_some_and(|s| s.is_empty());
            let hardening = off
                && (key.ends_with("SUPPORT_DTD")
                    || key.ends_with("IS_SUPPORTING_EXTERNAL_ENTITIES")
                    || key.ends_with("supportDTD")
                    || key.ends_with("ACCESS_EXTERNAL_DTD")
                    || key.ends_with("ACCESS_EXTERNAL_STYLESHEET")
                    || key.ends_with("isSupportingExternalEntities"));
            (Value::None, if hardening { mark_secure() } else { None })
        }
        "newDocumentBuilder" | "newSAXParser" | "getXMLReader" => {
            let class = match name {
                "newDocumentBuilder" => "javax.xml.parsers.DocumentBuilder",
                "newSAXParser" => "javax.xml.parsers.SAXParser",
                _ => "org.xml.sax.XMLReader",
            };
            let mut p = Obj::new(class);
            if secure {
                p = p.with_field("secure", Value::Bool(true));
            }
            (Value::Obj(Rc::new(p)), None)
        }
        "parse"
        | "read"
        | "build"
        | "createXMLStreamReader"
        | "createXMLEventReader"
        | "newTransformer"
        | "transform" => {
            if !secure {
                for x in args.iter().take(1) {
                    it.sink(&XXE, &x.value, span, &format!("{}.{name}", last(&o.class)));
                }
            }
            let _ = recv;
            (Value::clean(), None)
        }
        _ => (Value::None, None),
    }
}

/// `props.getProperty(key, default)`: the value the project's `.properties`
/// files give the key, or the default when none does. Several different
/// values in the project are all possible.
fn config_value(it: &Interp, key: &Value, default: Option<&Value>) -> Value {
    let found = key
        .as_str()
        .and_then(|k| it.project.config.get(&k))
        .filter(|v| !v.is_empty());
    match found {
        Some(values) => {
            join_all(values.iter().map(|v| Value::str(v.clone()))).unwrap_or_else(Value::clean)
        }
        None => default.cloned().unwrap_or_else(Value::clean),
    }
}

/// `response.addCookie(cookie)`: the cookie should be Secure and its value
/// must not be predictable when it identifies the user.
fn check_cookie_obj(it: &mut Interp, cookie: &Value, span: Span) {
    let Value::Obj(c) = cookie else { return };
    if c.class.as_ref() != COOKIE {
        return;
    }
    if c.field("secure").and_then(|v| v.truthy()) != Some(true) {
        it.flag(&INSECURE_COOKIE, span, "Cookie без setSecure(true)");
    }
    if let Some(v) = c.field("value") {
        it.sink(&WEAK_RANDOM, v, span, "значение cookie");
    }
}

/// Methods on values the analysis knows nothing about: well-known names
/// still identify common sinks.
fn generic_method(it: &mut Interp, recv: &Value, name: &str, args: &[ArgVal], span: Span) -> Value {
    let a0 = a(args, 0);
    if name == "getServletContext" {
        return obj(SERVLET_CONTEXT);
    }
    file_args_accessed(it, args, span, name);
    let looks_like_sql = |v: &Value| {
        let text: String = v
            .to_segs()
            .iter()
            .filter_map(|s| match s {
                Seg::Lit(t) => Some(t.to_ascii_uppercase()),
                Seg::Dyn(_) => None,
            })
            .collect();
        [
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ", " FROM ", " WHERE ", "CALL ",
        ]
        .iter()
        .any(|k| text.contains(k))
    };
    match name {
        "executeQuery" | "executeUpdate" | "executeLargeUpdate" | "addBatch"
        | "prepareStatement" | "prepareCall" | "nativeSQL" | "createNativeQuery"
        | "createSQLQuery" | "queryForObject" | "queryForList" | "queryForMap"
        | "queryForRowSet" | "queryForLong" | "queryForInt" | "batchUpdate"
            if matches!(a0, Value::Str(_)) =>
        {
            it.sink(&SQLI, &a0, span, name);
        }
        "execute" | "query" | "update" | "createQuery" if looks_like_sql(&a0) => {
            it.sink(&SQLI, &a0, span, name);
        }
        "sendRedirect" => {
            it.sink(&REDIRECT, &a0, span, name);
        }
        "addCookie" => check_cookie_obj(it, &a0, span),
        _ => {}
    }
    let bits = sanitizer(name);
    if bits != 0 {
        return encoded_arg(args).sanitized(bits);
    }
    Value::Unknown(recv.taint().union(&args_taint(args)))
}
