//! A model of a web application read from its code: the endpoints, the
//! HTTP methods each answers, whether it changes data, checks a login,
//! reads a password, sets or clears the login cookie; and the protections
//! the project has as a whole (CSRF tokens, limits on attempts, security
//! headers). Rules about the application come from it: CSRF, changes on
//! GET, logout on GET, logins without a limit on attempts, pages any site
//! can frame, session tokens that never change; and, in any function,
//! keys compared with `==`, passwords under a fast hash and request forms
//! written field by field.
//!
//! The model reads syntax, not data flow: what an endpoint does is what
//! its body and the helpers of its module it calls do.

use crate::ir::*;
use crate::project::{ModuleInfo, Project};
use crate::rules::{
    name_words, Rule, CSRF, LOGIN_NO_LIMIT, LOGOUT_GET, MASS_ASSIGNMENT, NO_FRAME_PROTECTION,
    STATE_CHANGE_GET, STATIC_SESSION, TIMING_COMPARE, WEAK_PASSWORD_HASH,
};
use crate::Language;
use std::collections::{HashMap, HashSet};

/// A finding of the model, in a module of the project.
pub struct Hit {
    pub rule: &'static Rule,
    pub module: usize,
    pub line: u32,
    pub what: String,
}

const GET: u8 = 1;
const POST: u8 = 2;
/// PUT, PATCH, DELETE.
const OTHER: u8 = 4;
const ANY: u8 = GET | POST | OTHER;

/// Code that answers requests.
struct Endpoint<'a> {
    module: usize,
    /// The route's decorator, or the function; 0 for a PHP page, whose
    /// findings point at the code that does the thing.
    line: u32,
    /// The function, or `None` for a PHP page's own code.
    func: Option<&'a Function>,
    body: &'a [Stmt],
    methods: u8,
    /// The framework refuses requests without its CSRF token unless told
    /// otherwise (Django, Spring Security).
    csrf_by_framework: bool,
}

/// What an endpoint's code does, its helpers included.
#[derive(Default, Debug)]
struct Facts {
    /// Reads the cookie or session that says who is logged in.
    cookie_auth: bool,
    /// Calls a guard named for a login whose code is elsewhere
    /// (`Depends(get_current_user)`, a `Principal` parameter).
    guessed_auth: bool,
    /// Puts someone in the session or sets the login cookie.
    sets_session: bool,
    /// Clears the session or the login cookie.
    clears_session: bool,
    /// Writes to a database or files (uploads apart).
    writes: u32,
    /// Saves an uploaded file, which only a POST can carry.
    uploads: bool,
    /// Some write runs whatever the method is.
    writes_any_method: bool,
    /// Reads form fields or uploads.
    form: bool,
    /// Reads a JSON body, which a form on another site cannot send.
    json: bool,
    /// Reads a field or parameter named as a password.
    password: bool,
    /// Checks a password: compares it or calls a check.
    verifies: bool,
    /// Checks a CSRF token or nonce.
    csrf: bool,
    /// Limits attempts: a limiter, a counter, a captcha.
    limit: bool,
    lines: Lines,
}

/// The first statement of the endpoint's own code that does a thing.
#[derive(Default, Debug)]
struct Lines {
    write: u32,
    login: u32,
    clear: u32,
}

pub fn check(project: &Project, include_tests: bool) -> Vec<Hit> {
    let mut hits = Vec::new();
    let text = ProjectText::new(project);
    let mut endpoints = Vec::new();
    let mut scopes = Vec::with_capacity(project.modules.len());
    for (i, m) in project.modules.iter().enumerate() {
        scopes.push(Scope::of(m));
        if (m.is_test && !include_tests) || matches!(m.lang, Language::C | Language::Cpp) {
            continue;
        }
        endpoints.extend(find_endpoints(i, m, &text));
        function_checks(i, m, &scopes[i], &mut hits);
    }
    if endpoints.is_empty() {
        return hits;
    }
    let cookies_read = cookie_reads(project);
    let mut lax = false;
    let mut facts = Vec::new();
    for e in &endpoints {
        let scope = &scopes[e.module];
        let mut w = Walk {
            scope,
            f: Facts::default(),
        };
        if let Some(func) = e.func {
            w.params(&func.params);
            for d in &func.decorators {
                w.decorator(d);
            }
        }
        w.body(e.body, 0, false);
        lax |= sets_samesite(e.body);
        if let Some(func) = e.func {
            static_session(e.module, func, scope, &cookies_read, &mut hits);
        }
        facts.push(w.f);
    }
    // Whether a login guard whose code is elsewhere rides on a cookie:
    // the application logs people in by setting one, or its framework
    // keeps logins in the session.
    let cookie_login = facts.iter().any(|f| f.sets_session) || text.session_framework;
    for (e, f) in endpoints.iter().zip(&facts) {
        let at = |own: u32| if e.line > 0 { e.line } else { own.max(1) };
        let unsafe_method = e.methods & (POST | OTHER) != 0;
        let get = e.methods & GET != 0 && e.methods != ANY;
        let auth = f.cookie_auth || (f.guessed_auth && cookie_login);
        let writes = f.writes > 0 || f.uploads;
        if unsafe_method
            && auth
            && writes
            && !f.csrf
            && !(f.json && !f.form)
            && !e.csrf_by_framework
            && !text.csrf
        {
            let what = if lax {
                "запрос меняет данные, а токен CSRF не проверяется; cookie с SameSite=Lax спасает только в новых браузерах и не от соседних поддоменов"
            } else {
                "запрос меняет данные, а токен CSRF не проверяется: чужой сайт может отправить этот запрос от имени вошедшего пользователя"
            };
            hits.push(Hit {
                rule: &CSRF,
                module: e.module,
                line: at(f.lines.write),
                what: what.into(),
            });
        }
        if get && auth && f.writes > 0 && f.writes_any_method && !f.csrf {
            hits.push(Hit {
                rule: &STATE_CHANGE_GET,
                module: e.module,
                line: at(f.lines.write),
                what: "GET-запрос меняет данные: его выполнит даже ссылка или картинка на чужой странице, открытая вошедшим пользователем".into(),
            });
        } else if get && f.clears_session && !f.sets_session && !f.password && !f.form && !writes {
            hits.push(Hit {
                rule: &LOGOUT_GET,
                module: e.module,
                line: at(f.lines.clear),
                what: "выход выполняется GET-запросом: любая страница может разлогинить пользователя картинкой или ссылкой".into(),
            });
        }
        if f.password && f.verifies && f.sets_session && !f.limit && !text.limit {
            hits.push(Hit {
                rule: &LOGIN_NO_LIMIT,
                module: e.module,
                line: at(f.lines.login),
                what: "вход проверяет пароль без ограничения числа попыток, задержки или капчи: пароль можно подбирать".into(),
            });
        }
    }
    let pages: Vec<usize> = endpoints
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            let m = &project.modules[e.module];
            if m.lang == Language::Php {
                prints_html(m.source())
            } else {
                renders_html(e.body)
            }
        })
        .map(|(i, _)| i)
        .collect();
    if !pages.is_empty() && !text.frame_protection {
        // Point at the application object, or at the login page, which
        // framing harms most.
        let i = pages
            .iter()
            .copied()
            .find(|&i| facts[i].sets_session && facts[i].password)
            .unwrap_or(pages[0]);
        let e = &endpoints[i];
        // A PHP page: where its HTML starts.
        let page_line = || html_line(project.modules[e.module].source()).unwrap_or(1);
        let (module, line) = text
            .app
            .unwrap_or_else(|| (e.module, if e.line > 0 { e.line } else { page_line() }));
        hits.push(Hit {
            rule: &NO_FRAME_PROTECTION,
            module,
            line,
            what: "приложение не задаёт ни X-Frame-Options, ни Content-Security-Policy с frame-ancestors: его страницы можно встроить в чужой сайт и подставить под клик (кликджекинг)".into(),
        });
    }
    hits
}

/// Protections and frameworks the project's files mention anywhere.
struct ProjectText {
    csrf: bool,
    limit: bool,
    frame_protection: bool,
    spring_security: bool,
    /// Logins live in the session whatever the endpoints do: Django,
    /// Spring Security with its default session.
    session_framework: bool,
    /// Where the application object is made (`app = FastAPI()`).
    app: Option<(usize, u32)>,
}

impl ProjectText {
    fn new(project: &Project) -> ProjectText {
        let mut t = ProjectText {
            csrf: false,
            limit: false,
            frame_protection: false,
            spring_security: false,
            session_framework: false,
            app: None,
        };
        let mut csrf_disabled = false;
        let mut stateless = false;
        let mut django = false;
        let sources = project.modules.iter().map(|m| m.source()).chain(
            project
                .texts
                .iter()
                .filter(|f| f.kind != crate::files::TextKind::Doc)
                .map(|f| f.text.as_str()),
        );
        for s in sources {
            let lower = s.to_ascii_lowercase();
            t.csrf |= [
                "csrfprotect",
                "csrf.init_app",
                "fastapi_csrf_protect",
                "starlette_csrf",
                "csrfmiddleware",
                "csrfpreventionfilter",
                "csrfguard",
                "verifycsrftoken",
                "wp_verify_nonce",
                "check_admin_referer",
            ]
            .iter()
            .any(|k| lower.contains(k));
            t.limit |= [
                "flask_limiter",
                "slowapi",
                "django_ratelimit",
                "ratelimit",
                "rate_limit",
                "ratelimiter",
                "django-axes",
                "axes.backends",
                "bucket4j",
                "throttle",
                "login_attempts",
                "failed_attempts",
                "failed_logins",
                "lockout",
            ]
            .iter()
            .any(|k| lower.contains(k));
            t.frame_protection |= [
                "x-frame-options",
                "frame-ancestors",
                "talisman",
                "secure_headers",
                "helmet(",
                "xframeoptionsmiddleware",
                "x_frame_options",
            ]
            .iter()
            .any(|k| lower.contains(k));
            t.spring_security |= s.contains("org.springframework.security");
            csrf_disabled |= lower.contains("csrf().disable()")
                || lower.contains("csrf(abstracthttpconfigurer::disable)")
                || lower.contains(".csrf(csrf -> csrf.disable())")
                || lower.contains(".csrf(c -> c.disable())");
            stateless |= s.contains("SessionCreationPolicy.STATELESS");
            django |= s.contains("django.contrib.sessions") || s.contains("from django.");
        }
        // Spring Security checks a CSRF token and sends X-Frame-Options
        // unless the application turns them off.
        if t.spring_security {
            t.frame_protection = true;
            t.csrf |= !csrf_disabled;
        }
        t.session_framework = django || (t.spring_security && !stateless);
        for (i, m) in project.modules.iter().enumerate() {
            for s in &m.ir.body {
                if let Stmt::Assign {
                    value: Expr::Call { func, .. },
                    span,
                    ..
                } = s
                {
                    if matches!(
                        callee_name(func),
                        "FastAPI" | "Flask" | "Starlette" | "Quart" | "Sanic"
                    ) {
                        t.app.get_or_insert((i, span.line));
                    }
                }
            }
        }
        t
    }
}

fn find_endpoints<'a>(module: usize, m: &'a ModuleInfo, text: &ProjectText) -> Vec<Endpoint<'a>> {
    let mut out = Vec::new();
    match m.lang {
        Language::Python => {
            let views = m.path.ends_with("views.py") || m.path.contains("/views/");
            for s in &m.ir.body {
                if let Stmt::FuncDef(f) = s {
                    if let Some(methods) = python_methods(f, views) {
                        let exempt = f.decorators.iter().any(|d| callee_name(d) == "csrf_exempt");
                        out.push(Endpoint {
                            module,
                            line: route_line(
                                f,
                                &[
                                    "route",
                                    "api_route",
                                    "get",
                                    "post",
                                    "put",
                                    "patch",
                                    "delete",
                                ],
                            ),
                            func: Some(f),
                            body: &f.body,
                            methods,
                            // Django checks CSRF tokens unless a view is exempt.
                            csrf_by_framework: views && !exempt && is_django_view(f),
                        });
                    }
                }
            }
        }
        Language::Java => {
            for s in &m.ir.body {
                let Stmt::ClassDef(c) = s else { continue };
                let servlet = c.bases.iter().any(|b| b.ends_with("HttpServlet"));
                for f in &c.methods {
                    let methods = if servlet {
                        match f.name.as_str() {
                            "doGet" => Some(GET),
                            "doPost" => Some(POST),
                            "doPut" | "doDelete" => Some(OTHER),
                            _ => None,
                        }
                    } else {
                        spring_methods(f)
                    };
                    if let Some(methods) = methods {
                        out.push(Endpoint {
                            module,
                            line: if servlet {
                                0
                            } else {
                                route_line(
                                    f,
                                    &[
                                        "GetMapping",
                                        "PostMapping",
                                        "PutMapping",
                                        "PatchMapping",
                                        "DeleteMapping",
                                        "RequestMapping",
                                    ],
                                )
                            },
                            func: Some(f),
                            body: &f.body,
                            methods,
                            csrf_by_framework: !servlet && text.spring_security && text.csrf,
                        });
                    }
                }
            }
        }
        Language::Php => {
            // A page is its own code; it answers the methods whose input
            // it reads.
            let src = m.source();
            let get = src.contains("$_GET") || src.contains("$_REQUEST");
            let post =
                src.contains("$_POST") || src.contains("$_REQUEST") || src.contains("$_FILES");
            let code = m.ir.body.iter().any(|s| {
                !matches!(
                    s,
                    Stmt::FuncDef(_) | Stmt::ClassDef(_) | Stmt::Import { .. }
                )
            });
            if (get || post) && code {
                out.push(Endpoint {
                    module,
                    line: 0,
                    func: None,
                    body: &m.ir.body,
                    methods: if get { GET } else { 0 } | if post { POST } else { 0 },
                    csrf_by_framework: false,
                });
            }
        }
        Language::C | Language::Cpp => {}
    }
    out
}

/// The line of a function's route decorator, which names its path and
/// method, or of the function itself.
fn route_line(f: &Function, names: &[&str]) -> u32 {
    f.decorators
        .iter()
        .find_map(|d| match d {
            Expr::Call { span, .. } if names.contains(&callee_name(d)) && span.line > 0 => {
                Some(span.line)
            }
            _ => None,
        })
        .unwrap_or(f.span.line)
}

/// The methods a Flask, FastAPI or Django view answers.
fn python_methods(f: &Function, views: bool) -> Option<u8> {
    for d in &f.decorators {
        let Expr::Call { func, args, .. } = d else {
            continue;
        };
        let Expr::Attr(_, name) = &**func else {
            continue;
        };
        let m = match name.as_str() {
            "get" => GET,
            "post" => POST,
            "put" | "patch" | "delete" => OTHER,
            "route" | "api_route" => {
                match args.iter().find(|a| a.name.as_deref() == Some("methods")) {
                    Some(a) => method_list(&a.value),
                    // Flask answers GET unless told otherwise.
                    None => GET,
                }
            }
            _ => continue,
        };
        // `@app.get(...)` of a dict or a cache is not a route.
        if !matches!(args.first(), Some(Arg { value: Expr::Lit(Const::Str(p)), .. }) if p.starts_with('/'))
        {
            continue;
        }
        return Some(m);
    }
    if views && is_django_view(f) {
        for d in &f.decorators {
            match callee_name(d) {
                "require_POST" => return Some(POST),
                "require_GET" | "require_safe" => return Some(GET),
                "require_http_methods" => {
                    if let Expr::Call { args, .. } = d {
                        if let Some(a) = args.first() {
                            return Some(method_list(&a.value));
                        }
                    }
                }
                _ => {}
            }
        }
        return Some(ANY);
    }
    None
}

fn is_django_view(f: &Function) -> bool {
    f.params.first().is_some_and(|p| p.name == "request")
}

fn method_list(e: &Expr) -> u8 {
    let mut m = 0;
    if let Expr::List(items) = e {
        for i in items {
            if let Expr::Lit(Const::Str(s)) = i {
                m |= match s.to_ascii_uppercase().as_str() {
                    "GET" | "HEAD" => GET,
                    "POST" => POST,
                    "PUT" | "PATCH" | "DELETE" => OTHER,
                    _ => 0,
                };
            }
        }
    }
    if m == 0 {
        GET
    } else {
        m
    }
}

/// The methods of a Spring controller method, from its mapping.
fn spring_methods(f: &Function) -> Option<u8> {
    for d in &f.decorators {
        let m = match callee_name(d) {
            "GetMapping" => GET,
            "PostMapping" => POST,
            "PutMapping" | "PatchMapping" | "DeleteMapping" => OTHER,
            "RequestMapping" => {
                let Expr::Call { args, .. } = d else {
                    return Some(ANY);
                };
                match args.iter().find(|a| a.name.as_deref() == Some("method")) {
                    Some(a) => {
                        let mut m = 0;
                        each_expr(&a.value, &mut |x| {
                            if let Expr::Name(n) | Expr::Attr(_, n) = x {
                                m |= match n.rsplit('.').next().unwrap_or(n) {
                                    "GET" | "HEAD" => GET,
                                    "POST" => POST,
                                    "PUT" | "PATCH" | "DELETE" => OTHER,
                                    _ => 0,
                                };
                            }
                        });
                        if m == 0 {
                            ANY
                        } else {
                            m
                        }
                    }
                    None => ANY,
                }
            }
            _ => continue,
        };
        return Some(m);
    }
    None
}

/// A module's functions by name, to follow calls to them, and its
/// imports.
struct Scope<'a> {
    funcs: HashMap<&'a str, &'a Function>,
    imports: HashMap<&'a str, &'a str>,
    lang: Language,
    /// Java: the module uses `MessageDigest`, whose `digest` and `update`
    /// hash.
    message_digest: bool,
}

impl<'a> Scope<'a> {
    fn of(m: &'a ModuleInfo) -> Scope<'a> {
        let mut funcs = HashMap::new();
        let mut imports = HashMap::new();
        for s in &m.ir.body {
            match s {
                Stmt::FuncDef(f) => {
                    funcs.insert(f.name.as_str(), &**f);
                }
                Stmt::ClassDef(c) => {
                    for f in &c.methods {
                        funcs.entry(f.name.as_str()).or_insert(&**f);
                    }
                }
                Stmt::Import { alias, path } => {
                    imports.insert(alias.as_str(), path.as_str());
                }
                _ => {}
            }
        }
        Scope {
            funcs,
            imports,
            lang: m.lang,
            message_digest: m.lang == Language::Java && m.source().contains("MessageDigest"),
        }
    }

    fn helper(&self, callee: &Expr) -> Option<&'a Function> {
        match callee {
            Expr::Name(n) => self.funcs.get(n.as_str()).copied(),
            Expr::Attr(o, n) if matches!(&**o, Expr::Name(s) if s == "self" || s == "this" || s == "$this") => {
                self.funcs.get(n.as_str()).copied()
            }
            _ => None,
        }
    }

    /// Whether `name` is imported from a module whose path starts with
    /// one of `from`.
    fn imported_from(&self, name: &str, from: &[&str]) -> bool {
        self.imports
            .get(name)
            .is_some_and(|p| from.iter().any(|f| p.starts_with(f)))
    }

    fn is_module(&self, name: &str) -> bool {
        self.imports.contains_key(name)
    }
}

/// The last name of a callee or decorator: `app.post(...)` gives `post`.
fn callee_name(e: &Expr) -> &str {
    match e {
        Expr::Name(n) => n.rsplit(['.', '\\']).next().unwrap_or(n),
        Expr::Attr(_, n) => n,
        Expr::Call { func, .. } => callee_name(func),
        _ => "",
    }
}

fn receiver_name(e: &Expr) -> &str {
    match e {
        Expr::Name(n) => n.rsplit('.').next().unwrap_or(n),
        Expr::Attr(_, n) => n,
        Expr::Call { func, .. } => callee_name(func),
        _ => "",
    }
}

/// `request`, `req`, Flask's `g`, `self.request`.
fn is_request(e: &Expr) -> bool {
    match e {
        Expr::Name(n) => matches!(n.as_str(), "request" | "req" | "g" | "self.request"),
        Expr::Attr(o, n) => n == "request" && matches!(&**o, Expr::Name(s) if s == "self"),
        _ => false,
    }
}

/// Names of cookies that carry a login.
fn auth_cookie(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "session", "sess", "auth", "token", "sid", "login", "admin", "user", "remember", "jwt",
    ]
    .iter()
    .any(|w| l.contains(w))
}

fn auth_word(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "auth", "admin", "login", "user", "session", "current", "token", "require", "staff",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

/// `password`, `passwd`, `pwd`, `pass`, `admin_password`, `user_pass`.
fn password_word(name: &str) -> bool {
    let words: Vec<String> = name_words(name).collect();
    words.last().is_some_and(|w| {
        matches!(
            w.as_str(),
            "password" | "passwd" | "pwd" | "pass" | "passphrase"
        ) || (w.len() > 8 && w.ends_with("password"))
    })
}

/// A field name, not text: `password`, `user-pass`.
fn identifier_like(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 40
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

enum Write {
    Data,
    /// Saving an uploaded file: only a POST carries one.
    Upload,
}

/// Calls that write to a database or the file system.
fn writes(func: &Expr, args: &[Arg]) -> Option<Write> {
    let name = callee_name(func);
    let recv = match func {
        Expr::Attr(o, _) => receiver_name(o).to_ascii_lowercase(),
        _ => String::new(),
    };
    let store = || {
        [
            "db",
            "session",
            "repo",
            "repository",
            "dao",
            "em",
            "entitymanager",
            "manager",
            "objects",
            "cursor",
            "conn",
            "connection",
            "collection",
            "wpdb",
            "store",
            "mongo",
            "template",
            "jdbctemplate",
        ]
        .iter()
        .any(|r| recv == *r || recv.ends_with(r))
    };
    let sql_write = || {
        args.iter().any(|a| {
            first_literal(&a.value).is_some_and(|s| {
                let s = s.trim_start().to_ascii_uppercase();
                [
                    "INSERT", "UPDATE", "DELETE", "REPLACE", "DROP", "ALTER", "TRUNCATE",
                ]
                .iter()
                .any(|k| s.starts_with(k))
            })
        })
    };
    let yes = match name {
        "move_uploaded_file" => return Some(Write::Upload),
        "commit" => args.is_empty() || store(),
        "persist" | "saveAll" | "saveAndFlush" | "executeUpdate" | "bulk_create" | "insert_one"
        | "insert_many" | "update_one" | "update_many" | "delete_one" | "delete_many"
        | "deleteById" | "deleteAll" | "deleteAllById" | "file_put_contents" | "unlink"
        | "rmtree" => true,
        // `obj.save()` of an ORM; `repo.save(entity)`.
        "save" => args.is_empty() || store(),
        // `obj.delete()`, `qs.filter(...).delete()`, `session.delete(obj)`.
        "delete" | "remove" => {
            (name == "delete" && args.is_empty())
                || store()
                || matches!(
                    recv.as_str(),
                    "filter" | "get" | "get_object_or_404" | "query" | "where" | "exclude" | "all"
                )
        }
        "add" | "add_all" | "merge" | "insert" | "update" => store(),
        "create" | "get_or_create" | "update_or_create" => recv == "objects",
        "execute" | "executemany" | "query" | "exec" | "mysqli_query" | "mysql_query"
        | "pg_query" | "prepare" | "mysqli_prepare" | "executescript" => sql_write(),
        _ => false,
    };
    yes.then_some(Write::Data)
}

/// The first literal text of an expression: a string, or the start of
/// one being built.
fn first_literal(e: &Expr) -> Option<&str> {
    match e {
        Expr::Lit(Const::Str(s)) => Some(s),
        Expr::Concat(parts) => parts.first().and_then(first_literal),
        Expr::Bin(BinOp::Add, l, _) => first_literal(l),
        _ => None,
    }
}

/// Walks an endpoint's code and collects its facts.
struct Walk<'s, 'a> {
    scope: &'s Scope<'a>,
    f: Facts,
}

impl<'a> Walk<'_, 'a> {
    fn params(&mut self, params: &'a [Param]) {
        for p in params {
            let ty = p.ty.as_deref().unwrap_or("");
            let default = p.default.as_ref().map(callee_name).unwrap_or("");
            match default {
                "Form" | "File" => self.f.form = true,
                "Cookie" if auth_cookie(&p.name) => self.f.cookie_auth = true,
                "Depends" | "Security" => {
                    if let Some(Expr::Call { args, .. }) = &p.default {
                        if let Some(dep) = args.first() {
                            match self.scope.helper(&dep.value) {
                                Some(h) => self.body(&h.body, 1, false),
                                None if auth_word(callee_name(&dep.value)) => {
                                    self.f.guessed_auth = true
                                }
                                None => {}
                            }
                        }
                    }
                }
                _ => {}
            }
            if ty.contains("UploadFile") || ty.contains("MultipartFile") {
                self.f.form = true;
            }
            if ty.contains("RequestParam") || ty.contains("ModelAttribute") {
                self.f.form = true;
            }
            if ty.contains("RequestBody") {
                self.f.json = true;
            }
            if ty.contains("HttpSession") || (ty.contains("CookieValue") && auth_cookie(&p.name)) {
                self.f.cookie_auth = true;
            }
            if ty.contains("Principal") || ty.contains("Authentication") {
                self.f.guessed_auth = true;
            }
            if password_word(&p.name)
                && (default == "Form"
                    || ty.contains("RequestParam")
                    || ty.contains("ModelAttribute"))
            {
                self.f.password = true;
            }
        }
    }

    fn decorator(&mut self, d: &Expr) {
        let name = callee_name(d).to_ascii_lowercase();
        if [
            "login_required",
            "permission_required",
            "user_passes_test",
            "staff_member_required",
            "admin_required",
            "fresh_login_required",
        ]
        .iter()
        .any(|w| name.contains(w))
        {
            self.f.cookie_auth = true;
        }
        if [
            "preauthorize",
            "secured",
            "rolesallowed",
            "jwt_required",
            "auth_required",
        ]
        .iter()
        .any(|w| name.contains(w))
        {
            self.f.guessed_auth = true;
        }
        if name.contains("csrf") && !name.contains("exempt") {
            self.f.csrf = true;
        }
        if name.contains("limit") || name.contains("throttle") {
            self.f.limit = true;
        }
    }

    /// Facts of statements; `depth` counts the helpers followed, and
    /// `post_only` is set where only a POST gets.
    fn body(&mut self, body: &'a [Stmt], depth: u8, mut post_only: bool) {
        for s in body {
            match s {
                Stmt::If {
                    test, then, other, ..
                } => {
                    self.expr(test, depth, post_only);
                    self.mark(s, depth);
                    let (then_post, else_post) = method_test(test);
                    self.body(then, depth, post_only || then_post);
                    self.body(other, depth, post_only || else_post);
                    // `if request.method != "POST": return ...`
                    if else_post && other.is_empty() && ends_flow(then) {
                        post_only = true;
                    }
                }
                Stmt::Loop {
                    body: inner,
                    iter,
                    test,
                    ..
                } => {
                    for e in iter.iter().chain(test.iter()) {
                        self.leaf(e, depth, post_only);
                    }
                    self.mark(s, depth);
                    self.body(inner, depth, post_only);
                }
                Stmt::Try {
                    body: inner,
                    handlers,
                    finally,
                } => {
                    self.body(inner, depth, post_only);
                    for h in handlers {
                        self.body(h, depth, post_only);
                    }
                    self.body(finally, depth, post_only);
                }
                Stmt::Switch { subject, cases, .. } => {
                    self.leaf(subject, depth, post_only);
                    for c in cases {
                        self.body(&c.body, depth, post_only);
                    }
                }
                Stmt::FuncDef(_) | Stmt::ClassDef(_) | Stmt::Import { .. } => {}
                _ => {
                    for e in own_exprs(s) {
                        self.leaf(e, depth, post_only);
                    }
                    if let Stmt::Assign { target, .. } = s {
                        self.store(target);
                    }
                    self.mark(s, depth);
                }
            }
        }
    }

    /// Notes `s` as where the endpoint's own code first writes, logs in
    /// or logs out, once its own expressions are walked.
    fn mark(&mut self, s: &Stmt, depth: u8) {
        let Some(span) = stmt_span(s) else { return };
        if depth > 0 {
            return;
        }
        let l = &mut self.f.lines;
        if (self.f.writes > 0 || self.f.uploads) && l.write == 0 {
            l.write = span.line;
        }
        if self.f.sets_session && self.f.password && l.login == 0 {
            l.login = span.line;
        }
        if self.f.clears_session && l.clear == 0 {
            l.clear = span.line;
        }
    }

    /// An expression of a simple statement: its writes count as running
    /// on any method unless `post_only`.
    fn leaf(&mut self, e: &'a Expr, depth: u8, post_only: bool) {
        let before = self.f.writes;
        self.expr(e, depth, post_only);
        if self.f.writes > before && !post_only && depth == 0 {
            self.f.writes_any_method = true;
        }
    }

    fn store(&mut self, target: &Target) {
        // `session["user"] = ...`, `$_SESSION['user'] = ...`,
        // `request.session["user"] = ...`
        if let Target::Index(base, _) = target {
            if self.is_session(base) {
                self.f.sets_session = true;
            }
        }
    }

    fn is_session(&self, e: &Expr) -> bool {
        match e {
            Expr::Name(n) if n == "$_SESSION" => true,
            Expr::Name(n) if n == "session" => {
                self.scope.imported_from("session", &["flask", "quart"])
            }
            Expr::Attr(o, n) => n == "session" && is_request(o),
            _ => false,
        }
    }

    fn expr(&mut self, e: &'a Expr, depth: u8, post_only: bool) {
        let mut follow: Vec<&'a Function> = Vec::new();
        let scope = self.scope;
        let f = &mut self.f;
        each_expr(e, &mut |x| match x {
            Expr::Attr(base, name) => {
                match name.as_str() {
                    "session" | "user" if is_request(base) => f.cookie_auth = true,
                    "current_user" => f.cookie_auth = true,
                    "form" | "POST" | "FILES" | "files" if is_request(base) => f.form = true,
                    "json" if is_request(base) => f.json = true,
                    _ => {}
                }
                if name.to_ascii_lowercase().contains("csrf") {
                    f.csrf = true;
                }
            }
            Expr::Index(base, key) => {
                let cookies = matches!(&**base, Expr::Attr(b, n) if (n == "cookies" || n == "COOKIES") && is_request(b))
                    || matches!(&**base, Expr::Name(n) if n == "$_COOKIE");
                if cookies && first_literal(key).is_some_and(auth_cookie) {
                    f.cookie_auth = true;
                }
            }
            Expr::Name(n) => {
                match n.as_str() {
                    "$_SESSION" => f.cookie_auth = true,
                    "$_POST" | "$_FILES" => f.form = true,
                    "current_user" if scope.imported_from("current_user", &["flask_login"]) => {
                        f.cookie_auth = true
                    }
                    "session" if scope.imported_from("session", &["flask", "quart"]) => {
                        f.cookie_auth = true
                    }
                    _ => {}
                }
                let lower = n.to_ascii_lowercase();
                if lower.contains("csrf") || lower.contains("xsrf") {
                    f.csrf = true;
                }
                if lower.contains("attempt")
                    || lower.contains("lockout")
                    || lower.contains("captcha")
                {
                    f.limit = true;
                }
            }
            Expr::Lit(Const::Str(s)) => {
                let lower = s.to_ascii_lowercase();
                // A field or header name, not page text about CSRF.
                if identifier_like(s) && (lower.contains("csrf") || lower.contains("xsrf"))
                    || matches!(
                        lower.as_str(),
                        "_token" | "user_token" | "authenticity_token" | "_wpnonce"
                    )
                {
                    f.csrf = true;
                }
                if identifier_like(s) && password_word(s) {
                    f.password = true;
                }
                if lower.trim_start().starts_with("select") && lower.contains("pass") {
                    f.verifies = true;
                }
                if lower == "php://input" {
                    f.json = true;
                }
            }
            Expr::Bin(BinOp::Eq | BinOp::NotEq | BinOp::Is | BinOp::IsNot, l, r) => {
                if mentions_password(l) || mentions_password(r) {
                    f.verifies = true;
                }
            }
            Expr::Call { func, args, .. } => {
                let name = callee_name(func);
                let lower = name.to_ascii_lowercase();
                match writes(func, args) {
                    Some(Write::Data) => f.writes += 1,
                    Some(Write::Upload) => f.uploads = true,
                    None => {}
                }
                let on_session = matches!(&**func, Expr::Attr(o, _) if receiver_name(o).to_ascii_lowercase().contains("session"));
                match name {
                    "set_cookie" | "setcookie" | "set_signed_cookie" => {
                        let cookie = args.first().and_then(|a| first_literal(&a.value));
                        if cookie.is_some_and(auth_cookie) {
                            if cookie_cleared(args) {
                                f.clears_session = true;
                            } else {
                                f.sets_session = true;
                            }
                        }
                    }
                    // `cookie.setMaxAge(0)`: the cookie is being removed.
                    "setMaxAge"
                        if matches!(
                            args.first(),
                            Some(Arg {
                                value: Expr::Lit(Const::Int(0)),
                                ..
                            })
                        ) =>
                    {
                        f.clears_session = true
                    }
                    "login_user" | "login" | "session_regenerate_id" | "remember" => {
                        f.sets_session = true
                    }
                    "setAttribute" if on_session => f.sets_session = true,
                    "delete_cookie" => {
                        if args
                            .first()
                            .and_then(|a| first_literal(&a.value))
                            .is_none_or(auth_cookie)
                        {
                            f.clears_session = true
                        }
                    }
                    "logout_user" | "logout" | "session_destroy" | "session_unset" => {
                        f.clears_session = true
                    }
                    "invalidate" | "clear" | "flush" | "pop" if on_session => {
                        f.clears_session = true
                    }
                    "getSession" | "getCookies" | "get_current_user" | "is_user_logged_in"
                    | "current_user_can" | "getUserPrincipal" | "isUserInRole" => {
                        f.cookie_auth = true
                    }
                    "get" => {
                        // `request.cookies.get("session")`
                        if let Expr::Attr(o, _) = &**func {
                            if matches!(&**o, Expr::Attr(b, n) if (n == "cookies" || n == "COOKIES") && is_request(b))
                                && args
                                    .first()
                                    .and_then(|a| first_literal(&a.value))
                                    .is_some_and(auth_cookie)
                            {
                                f.cookie_auth = true;
                            }
                        }
                    }
                    "get_json" => f.json = true,
                    "getParameter" => {
                        f.password |= args
                            .first()
                            .and_then(|a| first_literal(&a.value))
                            .is_some_and(password_word)
                    }
                    _ => {}
                }
                if [
                    "check_password",
                    "checkpw",
                    "password_verify",
                    "verify_password",
                    "authenticate",
                    "check_credentials",
                    "check_login",
                    "validate_login",
                ]
                .iter()
                .any(|w| lower.contains(w))
                    || ([
                        "check", "verify", "valid", "auth", "login", "match", "compare",
                    ]
                    .iter()
                    .any(|w| lower.contains(w))
                        && args.iter().any(|a| mentions_password(&a.value)))
                {
                    f.verifies = true;
                }
                // A token checked in constant time guards the endpoint
                // as a CSRF token does: `hash_equals($row['hash'], $_GET['key'])`.
                if lower.contains("csrf")
                    || lower.contains("nonce")
                    || matches!(
                        lower.as_str(),
                        "validate_on_submit" | "hash_equals" | "compare_digest" | "isequal"
                    )
                    || (lower.contains("token")
                        && ["check", "verify", "valid"]
                            .iter()
                            .any(|w| lower.starts_with(w)))
                {
                    f.csrf = true;
                }
                if ["limit", "throttle", "captcha", "lockout", "attempt"]
                    .iter()
                    .any(|w| lower.contains(w))
                {
                    f.limit = true;
                }
                // Helpers of the module run as part of the endpoint.
                if depth < 2 {
                    if let Some(h) = scope.helper(func) {
                        follow.push(h);
                    }
                }
            }
            _ => {}
        });
        for h in follow {
            self.body(&h.body, depth + 1, post_only);
        }
    }
}

/// What a test says about the method: whether its true branch runs only
/// for a POST, and whether its false branch does. `request.method ==
/// "POST"`, `isset($_POST['x'])` and `form.validate_on_submit()` hold
/// only for a POST; `request.method == "GET"` only for a GET.
fn method_test(test: &Expr) -> (bool, bool) {
    match test {
        Expr::Un(UnOp::Not, x) => {
            let (t, e) = method_test(x);
            (e, t)
        }
        Expr::Bin(BinOp::And, l, r) => {
            let (lt, le) = method_test(l);
            let (rt, re) = method_test(r);
            (lt || rt, le && re)
        }
        Expr::Bin(BinOp::Or, l, r) => {
            let (lt, le) = method_test(l);
            let (rt, re) = method_test(r);
            (lt && rt, le || re)
        }
        Expr::Bin(op @ (BinOp::Eq | BinOp::NotEq | BinOp::Is | BinOp::IsNot), l, r) => {
            let method = |e: &Expr| {
                matches!(e, Expr::Attr(_, n) if n == "method")
                    || matches!(e, Expr::Call { func, .. } if callee_name(func) == "getMethod")
                    || matches!(e, Expr::Index(b, k) if matches!(&**b, Expr::Name(n) if n == "$_SERVER")
                        && matches!(&**k, Expr::Lit(Const::Str(s)) if s == "REQUEST_METHOD"))
            };
            let lit = |e: &Expr| match e {
                Expr::Lit(Const::Str(s)) => Some(s.to_ascii_uppercase()),
                _ => None,
            };
            let verb = if method(l) {
                lit(r)
            } else if method(r) {
                lit(l)
            } else {
                None
            };
            let eq = matches!(op, BinOp::Eq | BinOp::Is);
            match verb.as_deref() {
                Some("POST") => (eq, !eq),
                Some("GET") => (!eq, eq),
                _ => (false, false),
            }
        }
        Expr::Call { func, args, .. } => {
            let name = callee_name(func);
            let post_arg = args.iter().any(|a| reads_post(&a.value));
            match name {
                "isset" | "array_key_exists" | "key_exists" if post_arg => (true, false),
                "empty" if post_arg => (false, true),
                "validate_on_submit" | "is_valid" => (true, false),
                _ => (false, false),
            }
        }
        e if reads_post(e) => (true, false),
        _ => (false, false),
    }
}

/// `$_POST`, `request.form`, `request.POST`: data only a POST carries.
fn reads_post(e: &Expr) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| match x {
        Expr::Name(n) if n == "$_POST" || n == "$_FILES" => found = true,
        Expr::Attr(b, n) if matches!(n.as_str(), "form" | "POST" | "FILES") && is_request(b) => {
            found = true
        }
        _ => {}
    });
    found
}

/// Whether a block ends the request: returns, raises, exits.
fn ends_flow(body: &[Stmt]) -> bool {
    match body.last() {
        Some(Stmt::Return(..)) => true,
        Some(Stmt::Expr(Expr::Call { func, .. }, _) | Stmt::Raw(Expr::Call { func, .. }, _)) => {
            matches!(
                callee_name(func),
                "die" | "exit" | "abort" | "redirect" | "header" | "sendRedirect" | "sendError"
            )
        }
        _ => false,
    }
}

/// `set_cookie(name, "", max_age=0)`, `setcookie(name, "", time() - 3600)`.
fn cookie_cleared(args: &[Arg]) -> bool {
    args.iter().any(|a| {
        matches!(a.name.as_deref(), Some("max_age" | "expires"))
            && matches!(a.value, Expr::Lit(Const::Int(0)))
    }) || matches!(args.get(1), Some(Arg { value: Expr::Lit(Const::Str(s)), .. }) if s.is_empty())
}

/// Whether the endpoint sets a cookie with `SameSite=Lax` or `Strict`.
fn sets_samesite(body: &[Stmt]) -> bool {
    let mut found = false;
    visit_stmts(body, &mut |s| {
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                if let Expr::Call { func, args, .. } = x {
                    if callee_name(func) == "set_cookie"
                        && args.iter().any(|a| {
                            a.name.as_deref() == Some("samesite")
                                && matches!(&a.value, Expr::Lit(Const::Str(v)) if !v.eq_ignore_ascii_case("none"))
                        })
                    {
                        found = true;
                    }
                }
            });
        }
    });
    found
}

/// Whether a PHP page prints HTML, which a frame could show.
fn prints_html(src: &str) -> bool {
    html_line(src).is_some()
}

/// The first line of a page that holds an HTML tag.
fn html_line(src: &str) -> Option<u32> {
    const TAGS: &[&str] = &[
        "<html",
        "<!doctype",
        "<body",
        "<form",
        "<div",
        "<table",
        "<h1",
        "<h2",
        "<h3",
        "<p>",
    ];
    src.lines()
        .position(|l| {
            let l = l.to_ascii_lowercase();
            TAGS.iter().any(|t| l.contains(t))
        })
        .map(|i| i as u32 + 1)
}

/// Whether the endpoint renders a page: a template or HTML.
fn renders_html(body: &[Stmt]) -> bool {
    let mut found = false;
    visit_stmts(body, &mut |s| {
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                if let Expr::Call { func, .. } = x {
                    found |= matches!(
                        callee_name(func),
                        "render_template"
                            | "render"
                            | "TemplateResponse"
                            | "HTMLResponse"
                            | "render_to_response"
                    );
                }
            });
        }
    });
    found
}

/// Names of the cookies the project's code reads.
fn cookie_reads(project: &Project) -> HashSet<String> {
    let mut names = HashSet::new();
    for m in &project.modules {
        if matches!(m.lang, Language::C | Language::Cpp) {
            continue;
        }
        for (_, _, body) in scopes(m) {
            visit_stmts(body, &mut |s| {
                for e in own_exprs(s) {
                    each_expr(e, &mut |x| {
                        let key = match x {
                            Expr::Index(b, k)
                                if matches!(&**b, Expr::Attr(_, n) if n == "cookies" || n == "COOKIES")
                                    || matches!(&**b, Expr::Name(n) if n == "$_COOKIE") =>
                            {
                                first_literal(k)
                            }
                            Expr::Call { func, args, .. } => match &**func {
                                Expr::Attr(o, n)
                                    if n == "get"
                                        && matches!(&**o, Expr::Attr(_, c) if c == "cookies" || c == "COOKIES") =>
                                {
                                    args.first().and_then(|a| first_literal(&a.value))
                                }
                                _ => None,
                            },
                            _ => None,
                        };
                        if let Some(k) = key {
                            names.insert(k.to_string());
                        }
                    });
                }
            });
        }
    }
    names
}

/// `resp.set_cookie("session", make_token())` where the value is the same
/// for every login: built from literals and constants only, here or in a
/// helper without parameters, and read back as a cookie elsewhere. A
/// token once seen then works for everyone and forever.
fn static_session(
    module: usize,
    func: &Function,
    scope: &Scope,
    cookies_read: &HashSet<String>,
    hits: &mut Vec<Hit>,
) {
    let locals = single_assignments(&func.body);
    visit_stmts(&func.body, &mut |s| {
        let Some(span) = stmt_span(s) else { return };
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                let Expr::Call {
                    func: callee, args, ..
                } = x
                else {
                    return;
                };
                if !matches!(
                    callee_name(callee),
                    "set_cookie" | "setcookie" | "set_signed_cookie"
                ) {
                    return;
                }
                let Some(name) = args.first().and_then(|a| first_literal(&a.value)) else {
                    return;
                };
                let Some(value) = args.get(1).map(|a| &a.value) else {
                    return;
                };
                if !cookies_read.contains(name) || cookie_cleared(args) {
                    return;
                }
                let value = match value {
                    Expr::Name(n) => locals.get(n.as_str()).copied().unwrap_or(value),
                    v => v,
                };
                let fixed = match value {
                    Expr::Lit(Const::Str(s)) => s.len() >= 8,
                    Expr::Lit(_) => false,
                    v => constant(v, scope, 0),
                };
                if fixed
                    && !hits
                        .iter()
                        .any(|h| h.module == module && h.line == span.line)
                {
                    hits.push(Hit {
                        rule: &STATIC_SESSION,
                        module,
                        line: span.line,
                        what: format!(
                            "значение cookie «{name}» собрано только из констант: у всех входов один и тот же токен, он не меняется и продолжает действовать после выхода"
                        ),
                    });
                }
            });
        }
    });
}

/// Variables of a body assigned exactly once.
fn single_assignments(body: &[Stmt]) -> HashMap<&str, &Expr> {
    let mut seen: HashMap<&str, Option<&Expr>> = HashMap::new();
    visit_stmts(body, &mut |s| {
        if let Stmt::Assign {
            target: Target::Name(n),
            value,
            ..
        } = s
        {
            seen.entry(n.as_str())
                .and_modify(|v| *v = None)
                .or_insert(Some(value));
        }
    });
    seen.into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect()
}

/// Whether an expression gives the same value on every run: literals,
/// constants (`SECRET`), imported modules and calls on them without
/// randomness or time, and helpers without parameters made of these.
fn constant(e: &Expr, scope: &Scope, depth: u8) -> bool {
    match e {
        Expr::Lit(_) => true,
        Expr::Name(n) => {
            let bare = n.trim_start_matches('$');
            (bare.len() > 1
                && bare
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                || scope.is_module(n)
                || n.contains('.') && scope.is_module(n.split('.').next().unwrap_or(""))
        }
        Expr::Attr(b, _) => constant(b, scope, depth),
        Expr::Bin(_, l, r) => constant(l, scope, depth) && constant(r, scope, depth),
        Expr::Concat(parts) | Expr::List(parts) => parts.iter().all(|p| constant(p, scope, depth)),
        Expr::Call { func, args, .. } => {
            let name = callee_name(func).to_ascii_lowercase();
            if [
                "rand", "uuid", "token", "urandom", "random", "nonce", "time", "now", "date",
                "uniqid", "secrets", "counter", "id",
            ]
            .iter()
            .any(|w| name.contains(w))
            {
                return false;
            }
            if let Some(h) = scope.helper(func) {
                if depth >= 2 || !h.params.is_empty() || !args.is_empty() {
                    return false;
                }
                let locals = single_assignments(&h.body);
                let mut returns = Vec::new();
                visit_stmts(&h.body, &mut |s| {
                    if let Stmt::Return(Some(v), _) = s {
                        returns.push(v);
                    }
                });
                return !returns.is_empty()
                    && returns.iter().all(|v| {
                        let v = match v {
                            Expr::Name(n) => locals.get(n.as_str()).copied().unwrap_or(v),
                            v => v,
                        };
                        constant(v, scope, depth + 1)
                    });
            }
            let recv = match &**func {
                Expr::Attr(o, _) => constant(o, scope, depth),
                Expr::Name(n) => {
                    !n.contains('.') || scope.is_module(n.split('.').next().unwrap_or(""))
                }
                _ => false,
            };
            recv && args.iter().all(|a| constant(&a.value, scope, depth))
        }
        _ => false,
    }
}

/// The functions of a module and its own top-level code: name,
/// parameters, body.
fn scopes(m: &ModuleInfo) -> Vec<(&str, &[Param], &[Stmt])> {
    let mut out: Vec<(&str, &[Param], &[Stmt])> = vec![("", &[], &m.ir.body)];
    for s in &m.ir.body {
        match s {
            Stmt::FuncDef(f) => out.push((&f.name, &f.params, &f.body)),
            Stmt::ClassDef(c) => {
                out.extend(
                    c.methods
                        .iter()
                        .map(|f| (f.name.as_str(), f.params.as_slice(), f.body.as_slice())),
                );
            }
            _ => {}
        }
    }
    out
}

/// Checks in any function: keys compared with `==`, passwords under a
/// fast hash, request forms written field by field.
fn function_checks(module: usize, m: &ModuleInfo, scope: &Scope, hits: &mut Vec<Hit>) {
    for (name, params, body) in scopes(m) {
        let request = request_vars(params, body);
        let password_fn = name_words(name).any(|w| w == "password" || w == "passwd");
        // Hashing again in a loop stretches the hash (phpass, PBKDF2 by
        // hand): not a fast hash.
        let mut stretched = false;
        visit_stmts(body, &mut |s| {
            if let Stmt::Loop { body: inner, .. } = s {
                visit_stmts(inner, &mut |t| {
                    for e in own_exprs(t) {
                        each_expr(e, &mut |x| {
                            if let Expr::Call { func, args, .. } = x {
                                stretched |= fast_hash(func, args, scope).is_some();
                            }
                        });
                    }
                });
            }
        });
        let locals = single_assignments(body);
        let cx = Checked {
            params,
            request: &request,
            locals: &locals,
            password_fn,
            stretched,
        };
        visit_stmts(body, &mut |s| {
            if let Some(span) = stmt_span(s) {
                stmt_checks(module, s, span.line, &cx, scope, hits);
            }
        });
    }
}

/// A function under `function_checks`.
struct Checked<'a> {
    params: &'a [Param],
    /// Its variables that hold request data.
    request: &'a [String],
    /// Its variables assigned once, by name.
    locals: &'a HashMap<&'a str, &'a Expr>,
    /// Named for passwords: `hash_password(p)`.
    password_fn: bool,
    /// Hashes in a loop, which stretches the hash.
    stretched: bool,
}

fn stmt_checks(
    module: usize,
    s: &Stmt,
    line: u32,
    cx: &Checked,
    scope: &Scope,
    hits: &mut Vec<Hit>,
) {
    let request = cx.request;
    let mut push = |rule: &'static Rule, what: String| {
        if !hits
            .iter()
            .any(|h| h.module == module && h.line == line && h.rule.id == rule.id)
        {
            hits.push(Hit {
                rule,
                module,
                line,
                what,
            });
        }
    };
    // `for k, v in form.items(): setattr(obj, k, v)`
    if let Stmt::Loop {
        target: Some(Target::Tuple(t)),
        iter: Some(Expr::Call { func: it, .. }),
        body,
        ..
    } = s
    {
        if let (Expr::Attr(src, items), Some(Target::Name(key))) = (&**it, t.first()) {
            if items == "items" && from_request(src, request) && key_written(body, key) {
                push(
                    &MASS_ASSIGNMENT,
                    "в цикле записываются все поля пришедшей формы: какие ключи менять, выбирает отправитель, списка разрешённых полей нет".into(),
                );
            }
        }
    }
    let lang = scope.lang;
    for e in own_exprs(s) {
        each_expr(e, &mut |x| match x {
            Expr::Bin(BinOp::Eq | BinOp::NotEq | BinOp::Is | BinOp::IsNot, l, r) => {
                let other = if from_request(l, request) {
                    r
                } else if from_request(r, request) {
                    l
                } else {
                    return;
                };
                if !from_request(other, request) && key_secret(other, cx.locals, scope, 0) {
                    push(
                        &TIMING_COMPARE,
                        format!(
                            "значение из запроса сравнивается с ключом или подписью обычным сравнением: по времени ответа можно подбирать значение по символу; используйте {}",
                            constant_time(lang)
                        ),
                    );
                }
            }
            Expr::Call {
                func: callee, args, ..
            } => {
                if lang == Language::Java && callee_name(callee) == "equals" {
                    if let (Expr::Attr(recv, _), Some(a)) = (&**callee, args.first()) {
                        let pair = [(&**recv, &a.value), (&a.value, &**recv)];
                        if pair.iter().any(|(u, o)| {
                            from_request(u, request)
                                && !from_request(o, request)
                                && key_secret(o, cx.locals, scope, 0)
                        }) {
                            push(
                                &TIMING_COMPARE,
                                "значение из запроса сравнивается с ключом или подписью через equals(): по времени ответа можно подбирать значение по символу; используйте MessageDigest.isEqual()".into(),
                            );
                        }
                    }
                }
                // `Model(**request.form)`, `Model.objects.create(**request.POST)`
                if args
                    .iter()
                    .any(|a| a.spread && a.name.is_none() && from_request(&a.value, request))
                    && (callee_name(callee)
                        .chars()
                        .next()
                        .is_some_and(char::is_uppercase)
                        || matches!(callee_name(callee), "create" | "update" | "insert"))
                    && lang == Language::Python
                {
                    push(
                        &MASS_ASSIGNMENT,
                        "в модель передаются все поля запроса: отправитель может задать и те поля, которые менять не должен (роль, владелец, цена)".into(),
                    );
                }
                if let Some((hashed, func)) =
                    fast_hash(callee, args, scope).filter(|_| !cx.stretched)
                {
                    let password = mentions_password(hashed)
                        || (cx.password_fn && mentions_param(hashed, cx.params));
                    if password {
                        push(
                            &WEAK_PASSWORD_HASH,
                            match constant_salt(hashed) {
                                Some(s) => format!(
                                    "пароль хешируется быстрой функцией {func} с постоянной солью «{s}»: соль одна на всех, а перебор идёт миллиардами вариантов в секунду; используйте bcrypt, scrypt, Argon2 или PBKDF2"
                                ),
                                None => format!(
                                    "пароль хешируется быстрой функцией {func}: перебор идёт миллиардами вариантов в секунду; используйте bcrypt, scrypt, Argon2 или PBKDF2"
                                ),
                            },
                        );
                    }
                }
            }
            _ => {}
        });
    }
}

fn constant_time(lang: Language) -> &'static str {
    match lang {
        Language::Python => "hmac.compare_digest()",
        Language::Php => "hash_equals()",
        Language::Java => "MessageDigest.isEqual()",
        _ => "сравнение за постоянное время",
    }
}

/// Names that hold request data in a function: its request parameters
/// (FastAPI `Form`, `Cookie`, Spring `@RequestParam`), and variables
/// assigned from `request.*`, `$_GET` and the like.
fn request_vars(params: &[Param], body: &[Stmt]) -> Vec<String> {
    let mut vars = Vec::new();
    for p in params {
        let ty = p.ty.as_deref().unwrap_or("");
        let default = p.default.as_ref().map(callee_name).unwrap_or("");
        if matches!(default, "Form" | "Cookie" | "Header" | "Query" | "Body")
            || ty.contains("RequestParam")
            || ty.contains("RequestHeader")
            || ty.contains("CookieValue")
            || ty.contains("PathVariable")
        {
            vars.push(p.name.clone());
        }
    }
    let mut assigns: Vec<(&str, &Expr)> = Vec::new();
    visit_stmts(body, &mut |s| match s {
        Stmt::Assign {
            target: Target::Name(n),
            value,
            ..
        } => assigns.push((n, value)),
        Stmt::Declare {
            name,
            value: Some(value),
            ..
        } => assigns.push((name, value)),
        _ => {}
    });
    loop {
        let before = vars.len();
        for (n, v) in &assigns {
            if !vars.iter().any(|x| x == n) && from_request(v, &vars) {
                vars.push(n.to_string());
            }
        }
        if vars.len() == before {
            break;
        }
    }
    vars
}

/// Whether an expression reads request data.
fn from_request(e: &Expr, vars: &[String]) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| match x {
        Expr::Name(n) => {
            if vars.contains(n)
                || matches!(
                    n.as_str(),
                    "$_GET" | "$_POST" | "$_REQUEST" | "$_COOKIE" | "$_SERVER"
                )
            {
                found = true;
            }
        }
        Expr::Attr(b, n) => {
            if is_request(b)
                && matches!(
                    n.as_str(),
                    "cookies"
                        | "COOKIES"
                        | "form"
                        | "args"
                        | "values"
                        | "headers"
                        | "POST"
                        | "GET"
                        | "json"
                        | "data"
                        | "query_params"
                        | "META"
                )
            {
                found = true;
            }
        }
        Expr::Call { func, .. } => {
            if matches!(
                callee_name(func),
                "getParameter" | "getHeader" | "getCookies" | "getQueryString" | "get_json"
            ) {
                found = true;
            }
        }
        _ => {}
    });
    found
}

/// A name for a value that grants access when matched: a token, an API
/// key, a signature or MAC; not a password (those are hashed and
/// compared as hashes) and not a CSRF token (the attacker cannot time
/// someone else's).
fn key_name(name: &str) -> bool {
    let words: Vec<String> = name_words(name.trim_start_matches('$')).collect();
    if words.iter().any(|w| {
        matches!(
            w.as_str(),
            "password"
                | "passwd"
                | "pwd"
                | "pass"
                | "passphrase"
                | "csrf"
                | "xsrf"
                | "hash"
                | "hashed"
                | "answer"
                | "solution"
                | "flag"
        )
    }) {
        return false;
    }
    let qualified_key = words.len() > 1
        && words.last().is_some_and(|w| w == "key")
        && words.iter().any(|w| {
            matches!(
                w.as_str(),
                "api"
                    | "secret"
                    | "signing"
                    | "access"
                    | "auth"
                    | "hmac"
                    | "private"
                    | "master"
                    | "app"
                    | "client"
                    | "admin"
            )
        });
    qualified_key
        || words.iter().any(|w| {
            matches!(
                w.as_str(),
                "token"
                    | "secret"
                    | "apikey"
                    | "signature"
                    | "sig"
                    | "hmac"
                    | "mac"
                    | "digest"
                    | "otp"
                    | "totp"
            )
        })
}

/// Whether a value is a key, token or MAC: named as one, computed by an
/// HMAC, digest or signature, or returned by a helper of the module that
/// gives one. Values kept in the user's own session are not: each user
/// has their own.
fn key_secret(e: &Expr, locals: &HashMap<&str, &Expr>, scope: &Scope, depth: u8) -> bool {
    let mut found = false;
    let mut session = false;
    each_expr(e, &mut |x| match x {
        Expr::Name(n) | Expr::Attr(_, n) => {
            if n == "$_SESSION" || n == "session" {
                session = true;
            }
            if key_name(n.rsplit('.').next().unwrap_or(n)) {
                found = true;
            }
            // `expected = hmac.new(...).hexdigest()`
            if let (Expr::Name(_), Some(v)) = (x, locals.get(n.as_str())) {
                if depth < 2 && key_secret(v, &HashMap::new(), scope, depth + 1) {
                    found = true;
                }
            }
        }
        Expr::Index(_, k) => {
            if first_literal(k).is_some_and(key_name) {
                found = true;
            }
        }
        Expr::Call { func, .. } => {
            let n = callee_name(func).to_ascii_lowercase();
            if n.contains("hmac") || n.contains("hexdigest") || n == "digest" || n == "sign" {
                found = true;
            }
            // Per user: the session's own values, CSRF tokens, nonces.
            if n.contains("getsession") || n.contains("nonce") || n.contains("csrf") {
                session = true;
            }
            if depth < 2 {
                if let Some(h) = scope.helper(func) {
                    let mut r = false;
                    let own = single_assignments(&h.body);
                    visit_stmts(&h.body, &mut |s| {
                        if let Stmt::Return(Some(v), _) = s {
                            r |= key_secret(v, &own, scope, depth + 1);
                        }
                    });
                    found |= r;
                }
            }
        }
        _ => {}
    });
    found && !session
}

/// The data a call hashes and the call's name, when it is a fast
/// general-purpose hash.
fn fast_hash<'e>(callee: &'e Expr, args: &'e [Arg], scope: &Scope) -> Option<(&'e Expr, String)> {
    let name = callee_name(callee);
    let lower = name.to_ascii_lowercase();
    let fast = |n: &str| {
        matches!(
            n,
            "md5"
                | "sha1"
                | "sha224"
                | "sha256"
                | "sha384"
                | "sha512"
                | "sha3_256"
                | "sha3_512"
                | "blake2b"
                | "blake2s"
        )
    };
    let first = || args.first().map(|a| &a.value);
    match scope.lang {
        Language::Python => {
            let hashlib = matches!(callee, Expr::Attr(o, _) if receiver_name(o) == "hashlib")
                || matches!(callee, Expr::Name(n) if n.starts_with("hashlib."));
            if hashlib && fast(&lower) {
                return first().map(|e| (e, format!("hashlib.{name}()")));
            }
            if hashlib && lower == "new" {
                let algo = first().and_then(first_literal).unwrap_or("");
                return args
                    .get(1)
                    .map(|a| (&a.value, format!("hashlib.new(\"{algo}\")")));
            }
            None
        }
        Language::Java => {
            let recv = match callee {
                Expr::Attr(o, _) => receiver_name(o),
                _ => return None,
            };
            if recv == "DigestUtils" && lower.starts_with("sha")
                || lower.starts_with("md5") && recv == "DigestUtils"
            {
                return first().map(|e| (e, format!("DigestUtils.{name}()")));
            }
            if scope.message_digest && matches!(name, "digest" | "update") {
                return first().map(|e| (e, "MessageDigest".to_string()));
            }
            None
        }
        Language::Php => {
            if matches!(lower.as_str(), "md5" | "sha1") {
                return first().map(|e| (e, format!("{lower}()")));
            }
            if lower == "hash" {
                let algo = first().and_then(first_literal).unwrap_or("");
                if fast(&algo.replace('-', "").to_ascii_lowercase()) {
                    return args.get(1).map(|a| (&a.value, format!("hash('{algo}')")));
                }
            }
            None
        }
        _ => None,
    }
}

fn mentions_password(e: &Expr) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| match x {
        Expr::Name(n) | Expr::Attr(_, n) => {
            if password_word(n.trim_start_matches('$')) {
                found = true;
            }
        }
        Expr::Index(_, k) => {
            if first_literal(k).is_some_and(|s| identifier_like(s) && password_word(s)) {
                found = true;
            }
        }
        Expr::Call { func, args, .. } => {
            found |= callee_name(func) == "getParameter"
                && args
                    .first()
                    .and_then(|a| first_literal(&a.value))
                    .is_some_and(password_word)
        }
        _ => {}
    });
    found
}

fn mentions_param(e: &Expr, params: &[Param]) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| {
        if let Expr::Name(n) = x {
            if params.iter().any(|p| &p.name == n) {
                found = true;
            }
        }
    });
    found
}

/// The literal text a hashed value is built with: `"shifo" + p`.
fn constant_salt(e: &Expr) -> Option<String> {
    let mut found = None;
    each_expr(e, &mut |x| {
        let parts: Vec<&Expr> = match x {
            Expr::Bin(BinOp::Add, l, r) => vec![l, r],
            Expr::Concat(p) => p.iter().collect(),
            _ => return,
        };
        for p in parts {
            if let Expr::Lit(Const::Str(s)) = p {
                if !s.is_empty() && found.is_none() {
                    found = Some(s.clone());
                }
            }
        }
    });
    found
}

/// Whether the loop body writes using `key` as the name it stores under:
/// `setattr(obj, key, v)`, `Model(key=key)`, `obj[key] = v`.
fn key_written(body: &[Stmt], key: &str) -> bool {
    let mut found = false;
    let is_key = |e: &Expr| matches!(e, Expr::Name(n) if n == key);
    visit_stmts(body, &mut |s| {
        if let Stmt::Assign {
            target: Target::Index(_, k),
            ..
        } = s
        {
            found |= is_key(k);
        }
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                if let Expr::Call { func, args, .. } = x {
                    let name = callee_name(func);
                    if name == "setattr" && args.get(1).is_some_and(|a| is_key(&a.value)) {
                        found = true;
                    }
                    // A model made with the key: `Setting(key=key, ...)`.
                    if name.chars().next().is_some_and(char::is_uppercase)
                        && args.iter().any(|a| a.name.is_some() && is_key(&a.value))
                    {
                        found = true;
                    }
                }
            });
        }
    });
    found
}

fn stmt_span(s: &Stmt) -> Option<Span> {
    match s {
        Stmt::Assign { span, .. }
        | Stmt::Declare { span, .. }
        | Stmt::Expr(_, span)
        | Stmt::If { span, .. }
        | Stmt::Loop { span, .. }
        | Stmt::Return(_, span)
        | Stmt::Raw(_, span) => Some(*span),
        _ => None,
    }
}

/// Expressions of a statement itself, not of the statements it holds.
fn own_exprs(s: &Stmt) -> Vec<&Expr> {
    match s {
        Stmt::Assign { value, target, .. } => {
            let mut v = vec![value];
            match target {
                Target::Index(b, k) => {
                    v.push(b);
                    v.push(k);
                }
                Target::Attr(b, _) => v.push(b),
                _ => {}
            }
            v
        }
        Stmt::Declare { value: Some(v), .. } => vec![v],
        Stmt::Expr(e, _) | Stmt::Raw(e, _) | Stmt::Return(Some(e), _) => vec![e],
        Stmt::If { test, .. } => vec![test],
        Stmt::Loop { iter, test, .. } => iter.iter().chain(test.iter()).collect(),
        Stmt::Switch { subject, .. } => vec![subject],
        _ => Vec::new(),
    }
}

/// Calls `f` on every statement of a body, nested blocks included,
/// functions defined inside excluded.
fn visit_stmts<'a>(body: &'a [Stmt], f: &mut dyn FnMut(&'a Stmt)) {
    for s in body {
        f(s);
        match s {
            Stmt::If { then, other, .. } => {
                visit_stmts(then, f);
                visit_stmts(other, f);
            }
            Stmt::Loop { body, .. } => visit_stmts(body, f),
            Stmt::Try {
                body,
                handlers,
                finally,
            } => {
                visit_stmts(body, f);
                for h in handlers {
                    visit_stmts(h, f);
                }
                visit_stmts(finally, f);
            }
            Stmt::Switch { cases, .. } => {
                for c in cases {
                    visit_stmts(&c.body, f);
                }
            }
            _ => {}
        }
    }
}

/// Calls `f` on `e` and every expression inside it, lambdas excluded.
fn each_expr<'a>(e: &'a Expr, f: &mut dyn FnMut(&'a Expr)) {
    f(e);
    match e {
        Expr::Attr(b, _) => each_expr(b, f),
        Expr::Index(b, k) => {
            each_expr(b, f);
            each_expr(k, f);
        }
        Expr::Slice {
            value,
            lower,
            upper,
        } => {
            each_expr(value, f);
            if let Some(l) = lower {
                each_expr(l, f);
            }
            if let Some(u) = upper {
                each_expr(u, f);
            }
        }
        Expr::Call { func, args, .. } => {
            each_expr(func, f);
            for a in args {
                each_expr(&a.value, f);
            }
        }
        Expr::New { args, .. } => {
            for a in args {
                each_expr(&a.value, f);
            }
        }
        Expr::Bin(_, l, r) => {
            each_expr(l, f);
            each_expr(r, f);
        }
        Expr::Un(_, x) | Expr::Cast(_, x) => each_expr(x, f),
        Expr::Concat(parts) | Expr::List(parts) | Expr::Other(parts) => {
            for p in parts {
                each_expr(p, f);
            }
        }
        Expr::Cond { test, then, other } => {
            each_expr(test, f);
            each_expr(then, f);
            each_expr(other, f);
        }
        Expr::Dict(pairs) => {
            for (k, v) in pairs {
                each_expr(k, f);
                each_expr(v, f);
            }
        }
        Expr::Lit(_) | Expr::Name(_) | Expr::Lambda(_) => {}
    }
}
