//! A model of a web application read from its code: the endpoints, the
//! HTTP methods each answers, whether it changes data, checks a login,
//! reads a password, sets or clears the login cookie; and the protections
//! the project has as a whole (CSRF tokens, limits on attempts, security
//! headers). Rules about the application come from it: CSRF, changes on
//! GET, logout on GET, logins without a limit on attempts, public forms
//! without a limit on requests, messages taken from the address, pages
//! any site can frame, session tokens that never change; and, in any
//! function, keys compared with `==`, passwords under a fast hash or a
//! constant salt, request forms written field by field, numbers parsed
//! from a request with no handler, empty handlers around checks and
//! startup, database files relative to the working folder.
//!
//! The model reads syntax, not data flow: what an endpoint does is what
//! its body and the helpers of its module it calls do.

use crate::ir::*;
use crate::project::{ModuleInfo, Project};
use crate::rules::{
    name_words, Rule, CONTENT_SPOOFING, CSRF, DB_IN_WORKDIR, FAIL_OPEN, LOGIN_NO_LIMIT, LOGOUT_GET,
    MASS_ASSIGNMENT, NO_FRAME_PROTECTION, PREDICTABLE_SALT, PUBLIC_FORM_NO_LIMIT, STATE_CHANGE_GET,
    STATIC_SESSION, STORED_SSTI, SWALLOWED_ERROR, TIMING_COMPARE, UNHANDLED_PARSE,
    WEAK_PASSWORD_HASH,
};
use crate::Language;
use std::cell::RefCell;
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
    /// Renders a page: a template or HTML, which a frame could show.
    page: bool,
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
    let scopes: Vec<Scope> = project.modules.iter().map(Scope::of).collect();
    let checked = |m: &ModuleInfo| {
        (include_tests || !m.is_test) && !matches!(m.lang, Language::C | Language::Cpp)
    };
    let helpers = HashHelpers::of(project, &scopes, &checked);
    let mut uses = Vec::new();
    for (i, m) in project.modules.iter().enumerate() {
        if checked(m) {
            endpoints.extend(find_endpoints(i, m, &text));
        }
    }
    let shared = Shared {
        text: &text,
        handlers: endpoints.iter().map(|e| e.body.as_ptr()).collect(),
        db_paths: RefCell::new(HashSet::new()),
    };
    for (i, m) in project.modules.iter().enumerate() {
        if checked(m) {
            function_checks(i, m, &scopes[i], &shared, &helpers, &mut uses, &mut hits);
        }
    }
    helpers.report(project, &uses, &mut hits);
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
            guards: &text.php_guards,
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
        // A form anyone can post that saves what it gets: a script can
        // fill the database with it.
        if unsafe_method
            && f.form
            && f.writes > 0
            && !f.cookie_auth
            && !f.guessed_auth
            && !f.verifies
            && !f.limit
            && !text.rate_limit
            && !login_everywhere(e, &text, &scopes)
        {
            hits.push(Hit {
                rule: &PUBLIC_FORM_NO_LIMIT,
                module: e.module,
                line: at(f.lines.write),
                what: "форма без входа записывает данные, а частота запросов не ограничена и капчи нет: скрипт может заваливать её спамом и раздувать базу данных".into(),
            });
        }
        if let Some((line, name)) = spoofed(e, &scopes[e.module]) {
            hits.push(Hit {
                rule: &CONTENT_SPOOFING,
                module: e.module,
                line,
                what: format!("текст сообщения «{name}» берётся из адреса страницы и показывается как надпись сайта: ссылкой вида ?{name}=… можно показать пользователю любое сообщение от имени сайта (например, «позвоните по номеру…»); показывайте сообщения по коду из своего списка"),
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
        .filter(|(i, e)| {
            let m = &project.modules[e.module];
            if m.lang == Language::Php {
                prints_html(m.source())
            } else {
                facts[*i].page || e.func.is_some_and(html_route)
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
    /// Limits the rate of any request or asks for a captcha, not only
    /// on a login.
    rate_limit: bool,
    /// Every page asks for a login unless told otherwise: Django's
    /// `LoginRequiredMiddleware`.
    login_everywhere: bool,
    /// A handler for bad numbers or any error answers the request
    /// (`@app.errorhandler(ValueError)`, `@ExceptionHandler`).
    errors_handled: bool,
    /// PHP files that check a login, by file name: a page that
    /// includes one is behind the login.
    php_guards: HashSet<String>,
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
            rate_limit: false,
            login_everywhere: false,
            errors_handled: false,
            php_guards: HashSet::new(),
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
            t.rate_limit |= [
                "flask_limiter",
                "slowapi",
                "django_ratelimit",
                "ratelimit",
                "rate_limit",
                "ratelimiter",
                "bucket4j",
                "throttle",
                "captcha",
                "turnstile",
            ]
            .iter()
            .any(|k| lower.contains(k));
            t.login_everywhere |= s.contains("LoginRequiredMiddleware");
            t.errors_handled |= [
                "errorhandler(valueerror",
                "errorhandler(exception",
                "exception_handler(valueerror",
                "exception_handler(exception",
                "@exceptionhandler",
                "@controlleradvice",
                "@restcontrolleradvice",
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
        for m in &project.modules {
            if m.lang == Language::Php && php_guard(m.source()) {
                if let Some(name) = m.path.rsplit('/').next() {
                    t.php_guards.insert(name.to_string());
                }
            }
        }
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
    /// Text constants of the module: `SALT = "shifo"`.
    texts: HashMap<&'a str, &'a str>,
    lang: Language,
    /// Java: the module uses `MessageDigest`, whose `digest` and `update`
    /// hash.
    message_digest: bool,
}

impl<'a> Scope<'a> {
    fn of(m: &'a ModuleInfo) -> Scope<'a> {
        let mut funcs = HashMap::new();
        let mut imports = HashMap::new();
        let mut texts = HashMap::new();
        for s in &m.ir.body {
            match s {
                Stmt::Assign {
                    target: Target::Name(n),
                    value,
                    ..
                } => {
                    if let Some(v) = literal_of(value) {
                        texts.insert(n.as_str(), v);
                    }
                }
                Stmt::FuncDef(f) => {
                    funcs.insert(f.name.as_str(), &**f);
                }
                Stmt::ClassDef(c) => {
                    for f in &c.methods {
                        funcs.entry(f.name.as_str()).or_insert(&**f);
                    }
                    // `private static final byte[] SALT = "shifo".getBytes();`
                    for field in &c.fields {
                        if let Stmt::Declare {
                            name,
                            value: Some(value),
                            ..
                        } = field
                        {
                            if let Some(v) = literal_of(value) {
                                texts.entry(name.as_str()).or_insert(v);
                            }
                        }
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
            texts,
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

/// The text of a literal, encoded or not: `"shifo"`, `b"shifo"`,
/// `"shifo".encode()`, `"shifo".getBytes()`, `bytes("shifo", "utf-8")`.
fn literal_of(e: &Expr) -> Option<&str> {
    match e {
        Expr::Lit(Const::Str(s)) => Some(s),
        Expr::Call { func, args, .. } => match &**func {
            Expr::Attr(o, m) if matches!(m.as_str(), "encode" | "getBytes" | "toCharArray") => {
                literal_of(o)
            }
            Expr::Name(n) if n == "bytes" || n == "bytearray" => {
                args.first().and_then(|a| literal_of(&a.value))
            }
            _ => None,
        },
        _ => None,
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
        // WordPress options, meta and posts; a fixed flag the code resets
        // itself (`update_option('db_upgraded', false)`) is housekeeping.
        "update_option" | "add_option" | "delete_option" | "update_site_option"
        | "update_user_meta" | "update_post_meta" | "add_post_meta" | "delete_post_meta"
        | "wp_insert_post" | "wp_update_post" | "wp_delete_post" | "wp_insert_user"
        | "wp_update_user" | "wp_delete_user" => {
            !args.iter().all(|a| matches!(a.value, Expr::Lit(_)))
        }
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

/// A name for a message the page shows: `error`, `msg`, `notice`.
fn message_name(name: &str) -> bool {
    name_words(name.trim_start_matches('$')).any(|w| {
        matches!(
            w.as_str(),
            "error"
                | "err"
                | "errors"
                | "msg"
                | "message"
                | "messages"
                | "notice"
                | "alert"
                | "flash"
                | "info"
                | "success"
                | "warning"
                | "warn"
                | "notification"
        )
    })
}

/// A read of a message from the query string: `request.args.get("error")`,
/// `request.GET["msg"]`, `$_GET['msg']`, `request.getParameter("error")`.
fn query_message(e: &Expr) -> Option<&str> {
    let query = |b: &Expr| match b {
        Expr::Attr(r, n) => {
            is_request(r) && matches!(n.as_str(), "args" | "GET" | "query_params" | "values")
        }
        Expr::Name(n) => n == "$_GET" || n == "$_REQUEST",
        _ => false,
    };
    let key = match e {
        Expr::Index(b, k) if query(b) => first_literal(k),
        Expr::Call { func, args, .. } => match &**func {
            Expr::Attr(b, n) if n == "get" && query(b) => {
                args.first().and_then(|a| first_literal(&a.value))
            }
            _ if callee_name(func) == "getParameter" => {
                args.first().and_then(|a| first_literal(&a.value))
            }
            _ => None,
        },
        _ => None,
    }?;
    message_name(key).then_some(key)
}

/// Where an endpoint shows a message taken from its address as its own
/// text, and the message's name: a query parameter named `error` passed
/// to a template, or printed escaped (unescaped it is XSS).
fn spoofed(e: &Endpoint, scope: &Scope) -> Option<(u32, String)> {
    let mut sources: HashMap<String, String> = HashMap::new();
    let mut escaped: HashSet<String> = HashSet::new();
    if let Some(f) = e.func {
        let path: String = f
            .decorators
            .iter()
            .filter_map(|d| match d {
                Expr::Call { args, .. } => args.first().and_then(|a| first_literal(&a.value)),
                _ => None,
            })
            .filter(|p| p.starts_with('/'))
            .collect();
        // A Django view has no route of its own: its parameters come
        // from the URL pattern.
        let routed = !path.is_empty();
        for p in &f.params {
            if !message_name(&p.name) {
                continue;
            }
            let ty = p.ty.as_deref().unwrap_or("");
            let query = match scope.lang {
                // FastAPI: a plain parameter not in the path comes from the
                // query string.
                Language::Python => {
                    routed
                        && !path.contains(&format!("{{{}}}", p.name))
                        && !path.contains(&format!("{}>", p.name))
                        && (ty.is_empty() || ty.contains("str"))
                        && p.default
                            .as_ref()
                            .is_none_or(|d| matches!(d, Expr::Lit(_)) || callee_name(d) == "Query")
                }
                Language::Java => ty.contains("RequestParam"),
                _ => false,
            };
            if query {
                sources.insert(p.name.clone(), p.name.clone());
            }
        }
    }
    visit_stmts(e.body, &mut |s| {
        if let Stmt::Assign {
            target: Target::Name(n),
            value,
            ..
        }
        | Stmt::Declare {
            name: n,
            value: Some(value),
            ..
        } = s
        {
            // `$msg = htmlspecialchars($_GET['msg'])` keeps the source.
            let mut key = None;
            each_expr(value, &mut |x| key = key.or(query_message(x)));
            if let Some(k) = key {
                sources.insert(n.clone(), k.to_string());
                if escapes(value) {
                    escaped.insert(n.clone());
                }
            }
        }
    });
    let source = |x: &Expr| -> Option<String> {
        match x {
            Expr::Name(n) => sources.get(n).cloned(),
            x => query_message(x).map(str::to_string),
        }
    };
    let mut found = None;
    visit_stmts(e.body, &mut |s| {
        if found.is_some() {
            return;
        }
        let Some(span) = stmt_span(s) else { return };
        for x in own_exprs(s) {
            each_expr(x, &mut |c| {
                let Expr::Call { func, args, .. } = c else {
                    return;
                };
                let name = callee_name(func);
                let shown: Vec<&Expr> = match name {
                    n if renders(n) && n != "get_template" => args
                        .iter()
                        .flat_map(|a| match &a.value {
                            Expr::Dict(pairs) => pairs.iter().map(|(_, v)| v).collect(),
                            v if a.name.is_some() => vec![v],
                            _ => Vec::new(),
                        })
                        .collect(),
                    "addAttribute" | "addObject" => {
                        args.get(1).map(|a| &a.value).into_iter().collect()
                    }
                    // Escaped, or it is XSS.
                    "echo" | "print" => {
                        let mut v = Vec::new();
                        for a in args {
                            each_expr(&a.value, &mut |y| match y {
                                Expr::Call { args, .. } if escapes(y) => {
                                    v.extend(args.first().map(|a| &a.value));
                                }
                                Expr::Name(n) if escaped.contains(n) => v.push(y),
                                _ => {}
                            });
                        }
                        v
                    }
                    _ => return,
                };
                if found.is_none() {
                    if let Some(k) = shown.into_iter().find_map(&source) {
                        found = Some((span.line, k));
                    }
                }
            });
        }
    });
    found
}

/// Whether an expression is a call that escapes HTML.
fn escapes(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(
        callee_name(func),
        "htmlspecialchars" | "htmlentities" | "esc_html" | "esc_attr"
    ))
}

/// The last literal text of an expression: a string, or the end of one
/// being built (`__DIR__ . '/auth.php'`).
fn last_literal(e: &Expr) -> Option<&str> {
    match e {
        Expr::Lit(Const::Str(s)) => Some(s),
        Expr::Concat(parts) => parts.last().and_then(last_literal),
        Expr::Bin(BinOp::Add, _, r) => last_literal(r),
        _ => None,
    }
}

/// Whether a PHP file checks a login: reads the session or calls a
/// check of the logged-in user.
fn php_guard(src: &str) -> bool {
    src.contains("$_SESSION")
        || [
            "is_user_logged_in",
            "current_user_can",
            "auth_redirect",
            "check_admin_referer",
        ]
        .iter()
        .any(|k| src.contains(k))
}

/// Whether the application asks for a login before any endpoint runs:
/// Django's `LoginRequiredMiddleware`, Spring Security, a Flask
/// `before_request` hook that reads the session.
fn login_everywhere(e: &Endpoint, text: &ProjectText, scopes: &[Scope]) -> bool {
    if text.login_everywhere {
        return true;
    }
    let Some(func) = e.func else { return false };
    let scope = &scopes[e.module];
    if scope.lang == Language::Java {
        // Spring Security guards controllers, not plain servlets.
        return text.spring_security && !func.name.starts_with("do");
    }
    scope.funcs.values().any(|h| {
        h.decorators
            .iter()
            .any(|d| matches!(callee_name(d), "before_request" | "before_app_request"))
            && {
                let mut w = Walk {
                    scope,
                    guards: &text.php_guards,
                    f: Facts::default(),
                };
                w.body(&h.body, 1, false);
                w.f.cookie_auth || w.f.guessed_auth
            }
    })
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
    /// PHP files that check a login, by name.
    guards: &'s HashSet<String>,
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
                    ..
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
        let guards = self.guards;
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
                if template_file(s) || html_text(&lower) {
                    f.page = true;
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
                if renders(name) {
                    f.page = true;
                }
                match name {
                    // `require 'auth.php'`: the included file checks the login.
                    "include" => {
                        if args
                            .first()
                            .and_then(|a| last_literal(&a.value))
                            .and_then(|p| p.rsplit(['/', '\\']).next())
                            .is_some_and(|n| guards.contains(n))
                        {
                            f.cookie_auth = true;
                        }
                    }
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
                    // `check_admin_referer('save')`, `check_ajax_referer()`
                    || (lower.contains("referer")
                        && (lower.starts_with("check") || lower.starts_with("verify")))
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

/// A route declared to answer with HTML:
/// `@app.get("/", response_class=HTMLResponse)`.
fn html_route(f: &Function) -> bool {
    let mut found = false;
    for d in &f.decorators {
        each_expr(d, &mut |x| {
            found |= matches!(x, Expr::Name(n) | Expr::Attr(_, n) if n.rsplit('.').next() == Some("HTMLResponse"));
        });
    }
    found
}

/// Calls that render a page from a template or send HTML.
fn renders(name: &str) -> bool {
    matches!(
        name,
        "render_template"
            | "render_template_string"
            | "render"
            | "TemplateResponse"
            | "HTMLResponse"
            | "render_to_response"
            | "render_to_string"
            | "get_template"
            | "ModelAndView"
    )
}

/// A template's file name: `"index.html"`, `"admin/news.jinja2"`.
fn template_file(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    !l.contains(char::is_whitespace)
        && l.len() < 120
        && [
            ".html", ".htm", ".jinja", ".jinja2", ".j2", ".twig", ".jsp", ".ftl", ".mako", ".tpl",
        ]
        .iter()
        .any(|x| l.ends_with(x) && l.len() > x.len())
        && !l.starts_with("http:")
        && !l.starts_with("https:")
}

/// Text of an HTML page, lowercased.
fn html_text(lower: &str) -> bool {
    ["<html", "<!doctype html", "<body"]
        .iter()
        .any(|t| lower.contains(t))
}

/// Names of the cookies the project's code reads.
fn cookie_reads(project: &Project) -> HashSet<String> {
    let mut names = HashSet::new();
    for m in &project.modules {
        if matches!(m.lang, Language::C | Language::Cpp) {
            continue;
        }
        for code in scopes(m) {
            visit_stmts(code.body, &mut |s| {
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

/// A function of a module, or code that runs outside any function (the
/// module's top level, a class's field initializers), which has no name.
struct Code<'a> {
    name: &'a str,
    params: &'a [Param],
    body: &'a [Stmt],
    decorators: &'a [Expr],
}

/// The functions of a module and its code outside them.
fn scopes(m: &ModuleInfo) -> Vec<Code<'_>> {
    let mut out = vec![Code {
        name: "",
        params: &[],
        body: &m.ir.body,
        decorators: &[],
    }];
    fn function(f: &Function) -> Code<'_> {
        Code {
            name: &f.name,
            params: &f.params,
            body: &f.body,
            decorators: &f.decorators,
        }
    }
    for s in &m.ir.body {
        match s {
            Stmt::FuncDef(f) => out.push(function(f)),
            Stmt::ClassDef(c) => {
                out.push(Code {
                    name: "",
                    params: &[],
                    body: &c.fields,
                    decorators: &[],
                });
                out.extend(c.methods.iter().map(|f| function(f)));
            }
            _ => {}
        }
    }
    out
}

/// Checks in any function: keys compared with `==`, passwords under a
/// fast hash, request forms written field by field.
/// What the checks in functions share across the project.
struct Shared<'p> {
    text: &'p ProjectText,
    /// The bodies of the endpoints, which answer requests.
    handlers: HashSet<*const Stmt>,
    /// Database files already reported, once per project.
    db_paths: RefCell<HashSet<String>>,
}

fn function_checks(
    module: usize,
    m: &ModuleInfo,
    scope: &Scope,
    shared: &Shared,
    helpers: &HashHelpers,
    uses: &mut Vec<HelperUse>,
    hits: &mut Vec<Hit>,
) {
    for code in scopes(m) {
        let Code {
            name, params, body, ..
        } = code;
        let request = request_vars(params, body);
        let password_fn = name_words(name).any(|w| w == "password" || w == "passwd");
        // Hashing again in a loop stretches the hash (phpass, PBKDF2 by
        // hand): not a fast hash.
        let stretched = stretches(body, scope);
        let locals = single_assignments(body);
        let cx = Checked {
            params,
            request: &request,
            locals: &locals,
            password_fn,
            stretched,
            db_paths: &shared.db_paths,
        };
        visit_stmts(body, &mut |s| {
            if let Some(span) = stmt_span(s) {
                stmt_checks(module, s, span.line, &cx, scope, hits);
                helpers.uses_in(module, s, span.line, scope, uses);
            }
        });
        let startup = startup_code(&code);
        let mut flow = Flow {
            module,
            cx: &cx,
            scope,
            // A bad number ends a request in an error page only where the
            // code answers the request.
            parse_handled: shared.text.errors_handled || !shared.handlers.contains(&body.as_ptr()),
            startup,
            hits,
        };
        flow.body(body, false);
    }
}

/// Code that runs when the application starts: a startup hook or a
/// function named for setting up. A module's own code may be a script's
/// (it counts only where it connects to a database).
fn startup_code(code: &Code) -> bool {
    if code.name.is_empty() {
        return false;
    }
    code.decorators.iter().any(|d| match callee_name(d) {
        "on_event" => matches!(d, Expr::Call { args, .. }
            if args.first().and_then(|a| first_literal(&a.value)) == Some("startup")),
        "before_first_request" | "before_serving" | "PostConstruct" => true,
        _ => false,
    }) || matches!(
        code.name,
        "startup"
            | "on_startup"
            | "lifespan"
            | "init_db"
            | "initdb"
            | "init_database"
            | "create_tables"
            | "setup_db"
            | "setup_database"
            | "create_app"
            | "contextInitialized"
    )
}

/// Checks that depend on the statements around a call: numbers parsed
/// from a request that no handler catches; errors of a check or of
/// starting up that an empty handler swallows.
struct Flow<'c, 'a> {
    module: usize,
    cx: &'c Checked<'a>,
    scope: &'c Scope<'a>,
    /// The project answers bad numbers itself (`@app.errorhandler(ValueError)`).
    parse_handled: bool,
    /// The code runs at startup.
    startup: bool,
    hits: &'c mut Vec<Hit>,
}

impl Flow<'_, '_> {
    fn push(&mut self, rule: &'static Rule, line: u32, what: String) {
        let module = self.module;
        if !self
            .hits
            .iter()
            .any(|h| h.module == module && h.line == line && h.rule.id == rule.id)
        {
            self.hits.push(Hit {
                rule,
                module,
                line,
                what,
            });
        }
    }

    /// `safe`: a handler around catches a bad number, or a test checked
    /// the text is one.
    fn body(&mut self, body: &[Stmt], safe: bool) {
        for s in body {
            match s {
                Stmt::Try {
                    body: inner,
                    handlers,
                    catches,
                    finally,
                } => {
                    let lang = self.scope.lang;
                    self.swallowed(inner, catches);
                    let caught = catches.iter().any(|c| catches_bad_number(c, lang));
                    self.body(inner, safe || caught);
                    for h in handlers {
                        self.body(h, safe);
                    }
                    self.body(finally, safe);
                }
                Stmt::If {
                    test, then, other, ..
                } => {
                    self.parses(test, s, safe);
                    let checked = safe || checks_number(test);
                    self.body(then, checked);
                    self.body(other, checked);
                }
                Stmt::Loop { body: inner, .. } => {
                    for e in own_exprs(s) {
                        self.parses(e, s, safe);
                    }
                    self.body(inner, safe);
                }
                Stmt::Switch { subject, cases, .. } => {
                    self.parses(subject, s, safe);
                    for c in cases {
                        self.body(&c.body, safe);
                    }
                }
                Stmt::FuncDef(_) | Stmt::ClassDef(_) => {}
                _ => {
                    for e in own_exprs(s) {
                        self.parses(e, s, safe);
                    }
                }
            }
        }
    }

    /// `int(request.args["page"])`, `Integer.parseInt(request.getParameter("id"))`
    /// with nothing to catch a value that is not a number: the request
    /// ends in a 500 error.
    fn parses(&mut self, e: &Expr, s: &Stmt, safe: bool) {
        if safe || self.parse_handled {
            return;
        }
        let Some(span) = stmt_span(s) else { return };
        let mut found: Option<String> = None;
        let request = self.cx.request;
        let params = self.cx.params;
        let lang = self.scope.lang;
        each_expr(e, &mut |x| {
            if found.is_some() {
                return;
            }
            // `int(x) if x.isdigit() else 0`
            if let Expr::Cond { test, .. } = x {
                if checks_number(test) {
                    found = Some(String::new());
                }
                return;
            }
            let Expr::Call { func, args, .. } = x else {
                return;
            };
            let Some(arg) = args.first().map(|a| &a.value) else {
                return;
            };
            let parse = match (lang, &**func) {
                (Language::Python, Expr::Name(n)) if n == "int" || n == "float" => {
                    Some(format!("{n}()"))
                }
                (Language::Java, Expr::Attr(o, m)) => {
                    let class = receiver_name(o);
                    let number = matches!(
                        class,
                        "Integer" | "Long" | "Short" | "Byte" | "Double" | "Float"
                    );
                    (number && (m.starts_with("parse") || m == "valueOf"))
                        .then(|| format!("{class}.{m}()"))
                }
                _ => None,
            };
            let Some(parse) = parse else { return };
            // A parameter the framework already made a number.
            let typed = matches!(arg, Expr::Name(n) if params.iter().any(|p| &p.name == n
            && p.ty.as_deref().is_some_and(|t| {
                let t = t.to_ascii_lowercase();
                t.contains("int") || t.contains("float") || t.contains("long")
            })));
            if !typed && from_request(arg, request) && args.len() == 1 {
                found = Some(parse);
            }
        });
        if let Some(parse) = found.filter(|p| !p.is_empty()) {
            self.push(
                &UNHANDLED_PARSE,
                span.line,
                format!(
                    "{parse} разбирает число из запроса, а ошибку разбора ничто не перехватывает: строка вроде «abc» в этом поле обрывает запрос ошибкой 500 (а в режиме отладки показывает трассировку); проверьте значение или перехватите ошибку и ответьте 400"
                ),
            );
        }
    }

    /// An empty handler of every error around a check whose failure it
    /// hides, or around starting up.
    fn swallowed(&mut self, body: &[Stmt], catches: &[Catch]) {
        let lang = self.scope.lang;
        let Some(catch) = catches.iter().find(|c| c.empty && catches_all(c, lang)) else {
            return;
        };
        let mut check: Option<String> = None;
        let mut setup = false;
        let mut work = false;
        visit_stmts(body, &mut |s| {
            // A check whose result the code ignores signals by raising.
            if let Stmt::Expr(Expr::Call { func, .. }, _) = s {
                let name = callee_name(func);
                if check.is_none() && security_check(name) {
                    check = Some(name.to_string());
                }
            }
            for e in own_exprs(s) {
                each_expr(e, &mut |x| {
                    let name = match x {
                        Expr::Call { func, .. } => callee_name(func),
                        Expr::New { class, .. } => {
                            class.rsplit(['.', '\\']).next().unwrap_or(class)
                        }
                        _ => return,
                    };
                    setup |= db_setup(x);
                    work |= !cleanup(&name.to_ascii_lowercase());
                });
            }
        });
        if let Some(name) = check {
            self.push(
                &FAIL_OPEN,
                catch.span.line,
                format!(
                    "проверка {name}() сообщает об отказе исключением, а пустой обработчик его глушит: при подделанных данных или сбое проверка просто пропускается и код идёт дальше; при ошибке проверки отказывайте"
                ),
            );
        } else if work && (setup || self.startup) {
            self.push(
                &SWALLOWED_ERROR,
                catch.span.line,
                "ошибка при запуске или подключении к базе данных глушится пустым обработчиком: приложение продолжит работу без базы или настроек, и о сбое никто не узнает; запишите ошибку в журнал или остановите запуск".into(),
            );
        }
    }
}

/// Whether a handler catches a text that is not a number.
fn catches_bad_number(c: &Catch, lang: Language) -> bool {
    catches_all(c, lang)
        || c.types.iter().any(|t| {
            matches!(
                t.as_str(),
                "ValueError" | "NumberFormatException" | "IllegalArgumentException"
            )
        })
}

/// Whether a handler catches every error: a bare `except:`, `Exception`,
/// `Throwable`.
fn catches_all(c: &Catch, lang: Language) -> bool {
    match lang {
        Language::Python => {
            c.types.is_empty()
                || c.types
                    .iter()
                    .any(|t| t == "Exception" || t == "BaseException")
        }
        Language::Java => c
            .types
            .iter()
            .any(|t| matches!(t.as_str(), "Exception" | "Throwable" | "RuntimeException")),
        Language::Php => c
            .types
            .iter()
            .any(|t| matches!(t.as_str(), "Exception" | "Throwable" | "Error")),
        Language::C | Language::Cpp => false,
    }
}

/// Whether a test checks that a text is a number: `x.isdigit()`,
/// `re.fullmatch(r"\d+", x)`, `StringUtils.isNumeric(x)`.
fn checks_number(test: &Expr) -> bool {
    let mut found = false;
    each_expr(test, &mut |x| {
        if let Expr::Call { func, .. } = x {
            let lower = callee_name(func).to_ascii_lowercase();
            found |= matches!(
                lower.as_str(),
                "isdigit"
                    | "isnumeric"
                    | "isdecimal"
                    | "fullmatch"
                    | "match"
                    | "matches"
                    | "is_numeric"
                    | "ctype_digit"
                    | "isdigits"
                    | "iscreatable"
                    | "isparsable"
            ) || lower.starts_with("isnumber")
                || lower.starts_with("is_int")
                || lower.starts_with("isint");
        }
    });
    found
}

/// A check that answers by raising when it fails: `verify_signature`,
/// `validate_token`, `check_permission`.
fn security_check(name: &str) -> bool {
    let words: Vec<String> = name_words(name).collect();
    let has = |set: &[&str]| words.iter().any(|w| set.contains(&w.as_str()));
    has(&[
        "verify",
        "validate",
        "authenticate",
        "authorize",
        "authorise",
    ]) || (has(&["check", "ensure", "require"])
        && has(&[
            "password",
            "permission",
            "permissions",
            "perm",
            "perms",
            "token",
            "signature",
            "sig",
            "csrf",
            "auth",
            "access",
            "login",
            "owner",
            "role",
            "admin",
            "referer",
            "nonce",
            "hmac",
            "captcha",
        ]))
}

/// Calls that connect to a database or create its tables:
/// `sqlite3.connect`, `mysqli_connect`, `DriverManager.getConnection`,
/// `create_engine`, `new PDO`; not a socket's `connect`.
fn db_setup(call: &Expr) -> bool {
    let (name, recv) = match call {
        Expr::Call { func, .. } => (
            callee_name(func),
            match &**func {
                Expr::Attr(o, _) => receiver_name(o),
                _ => "",
            },
        ),
        Expr::New { class, .. } => (class.rsplit(['.', '\\']).next().unwrap_or(class), ""),
        _ => return false,
    };
    let words: Vec<String> = name_words(name).collect();
    let first = words.first().map(String::as_str);
    match name {
        "connect" => matches!(
            recv,
            "sqlite3"
                | "aiosqlite"
                | "psycopg2"
                | "psycopg"
                | "pymysql"
                | "MySQLdb"
                | "connector"
                | "cx_Oracle"
                | "oracledb"
                | "pyodbc"
                | "asyncpg"
                | "pymssql"
                | "mariadb"
        ),
        "mysqli_connect"
        | "mysqli_real_connect"
        | "mysql_connect"
        | "pg_connect"
        | "pg_pconnect"
        | "sqlsrv_connect"
        | "oci_connect"
        | "odbc_connect"
        | "create_engine"
        | "create_all"
        | "init_db"
        | "initdb"
        | "migrate"
        | "PDO"
        | "mysqli"
        | "MongoClient"
        | "SessionLocal"
        | "sessionmaker" => true,
        // `dataSource.getConnection()`; `url.openConnection()` is HTTP.
        _ => {
            words.last().map(String::as_str) == Some("connection")
                && matches!(first, Some("get" | "create" | "new" | "establish"))
        }
    }
}

/// Calls that only tidy up, whose errors may be ignored.
fn cleanup(lower: &str) -> bool {
    matches!(
        lower,
        "close"
            | "shutdown"
            | "unlink"
            | "remove"
            | "rmtree"
            | "delete"
            | "release"
            | "rollback"
            | "disconnect"
            | "quit"
            | "terminate"
            | "kill"
            | "cancel"
            | "stop"
            | "flush"
            | "dispose"
            | "destroy"
            | "cleanup"
            | "join"
            | "wait"
            | "closequietly"
    )
}

/// Whether a body hashes again in a loop, which stretches the hash
/// (phpass, PBKDF2 by hand): not a fast hash.
fn stretches(body: &[Stmt], scope: &Scope) -> bool {
    let mut found = false;
    visit_stmts(body, &mut |s| {
        if let Stmt::Loop { body: inner, .. } = s {
            visit_stmts(inner, &mut |t| {
                for e in own_exprs(t) {
                    each_expr(e, &mut |x| {
                        if let Expr::Call { func, args, .. } = x {
                            found |= fast_hash(func, args, scope).is_some();
                        }
                    });
                }
            });
        }
    });
    found
}

/// A function that puts its parameter under a fast hash:
/// `def _hash(p): return sha256(("salt" + p).encode()).hexdigest()`. It
/// hashes passwords when some code passes it one.
struct HashHelper {
    name: String,
    module: usize,
    /// The module's dotted name, to match imports of the helper.
    module_name: String,
    line: u32,
    /// The hash and the salt it adds, for the message.
    label: String,
    how: Hashing,
}

/// A call of a hash helper with a password.
struct HelperUse {
    helper: usize,
    module: usize,
    line: u32,
}

struct HashHelpers {
    list: Vec<HashHelper>,
    by_name: HashMap<String, Vec<usize>>,
}

impl HashHelpers {
    fn of(
        project: &Project,
        module_scopes: &[Scope],
        checked: &dyn Fn(&ModuleInfo) -> bool,
    ) -> HashHelpers {
        let mut list = Vec::new();
        for (i, m) in project.modules.iter().enumerate() {
            if !checked(m) {
                continue;
            }
            for Code {
                name, params, body, ..
            } in scopes(m)
            {
                // A MAC keyed with a password (CRAM-MD5) stores nothing.
                let mac = name_words(name).any(|w| matches!(w.as_str(), "hmac" | "mac" | "sign"));
                if name.is_empty() || params.is_empty() || mac {
                    continue;
                }
                let scope = &module_scopes[i];
                let stretched = stretches(body, scope);
                let locals = single_assignments(body);
                let mut found: Option<(u32, String, Hashing)> = None;
                visit_stmts(body, &mut |s| {
                    let Some(span) = stmt_span(s) else { return };
                    for e in own_exprs(s) {
                        each_expr(e, &mut |x| {
                            if found.is_some() {
                                return;
                            }
                            if let Some((hashed, label, how)) = hash_call(x, scope, &locals) {
                                if mentions_param(hashed, params)
                                    && !(stretched && how == Hashing::Fast)
                                {
                                    let label = match how {
                                        Hashing::Fast => hash_how(&label, hashed, scope),
                                        Hashing::FixedSalt => label,
                                    };
                                    found = Some((span.line, label, how));
                                }
                            }
                        });
                    }
                });
                if let Some((line, label, how)) = found {
                    list.push(HashHelper {
                        name: name.to_string(),
                        module: i,
                        module_name: m.name.clone(),
                        line,
                        label,
                        how,
                    });
                }
            }
        }
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, h) in list.iter().enumerate() {
            by_name.entry(h.name.clone()).or_default().push(i);
        }
        HashHelpers { list, by_name }
    }

    /// Calls in `s` of a helper with a password: an argument named as
    /// one, a result stored as a password, or a result compared with one
    /// (`admin.password_hash == _hash(p)`).
    fn uses_in(
        &self,
        module: usize,
        s: &Stmt,
        line: u32,
        scope: &Scope,
        uses: &mut Vec<HelperUse>,
    ) {
        if self.list.is_empty() {
            return;
        }
        let stored = match s {
            Stmt::Assign {
                target: Target::Name(n) | Target::Attr(_, n),
                ..
            } => password_ish(n),
            Stmt::Assign {
                target: Target::Index(_, k),
                ..
            } => first_literal(k).is_some_and(|k| identifier_like(k) && password_ish(k)),
            _ => false,
        };
        // Calls whose result is compared with a password or passed as one
        // (`Admin(password_hash=_hash(p))`).
        let mut compared = Vec::new();
        for e in own_exprs(s) {
            each_expr(e, &mut |x| match x {
                Expr::Bin(BinOp::Eq | BinOp::NotEq | BinOp::Is | BinOp::IsNot, l, r) => {
                    for (call, other) in [(l, r), (r, l)] {
                        if let Expr::Call { span, .. } = &**call {
                            if names_password(other) {
                                compared.push(*span);
                            }
                        }
                    }
                }
                Expr::Call { args, .. } | Expr::New { args, .. } => {
                    for a in args {
                        if a.name.as_deref().is_some_and(password_ish) {
                            if let Expr::Call { span, .. } = &a.value {
                                compared.push(*span);
                            }
                        }
                    }
                }
                _ => {}
            });
        }
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                let Expr::Call { func, args, span } = x else {
                    return;
                };
                let Some(candidates) = self.by_name.get(callee_name(func)) else {
                    return;
                };
                if !(stored
                    || compared.contains(span)
                    || args
                        .iter()
                        .any(|a| names_password(&a.value) || mentions_password(&a.value)))
                {
                    return;
                }
                // The helper of this module, else the one its import names.
                let path = match &**func {
                    Expr::Name(n) => scope.imports.get(n.as_str()).copied(),
                    Expr::Attr(o, _) => match &**o {
                        Expr::Name(r) => {
                            scope.imports.get(r.as_str()).copied().or(Some(r.as_str()))
                        }
                        _ => None,
                    },
                    _ => None,
                };
                let pick = candidates
                    .iter()
                    .copied()
                    .find(|&h| self.list[h].module == module)
                    .or_else(|| {
                        let path = path?;
                        candidates.iter().copied().find(|&h| {
                            let m = &self.list[h].module_name;
                            path == m
                                || path.starts_with(&format!("{m}."))
                                || path.ends_with(&format!(".{m}"))
                                || path.contains(&format!(".{m}."))
                        })
                    })
                    .or_else(|| (candidates.len() == 1).then(|| candidates[0]));
                if let Some(helper) = pick {
                    uses.push(HelperUse {
                        helper,
                        module,
                        line,
                    });
                }
            });
        }
    }

    /// One finding per helper that hashes passwords, at its hash.
    fn report(&self, project: &Project, uses: &[HelperUse], hits: &mut Vec<Hit>) {
        for (i, h) in self.list.iter().enumerate() {
            let Some(u) = uses.iter().find(|u| u.helper == i) else {
                continue;
            };
            let rule = match h.how {
                Hashing::Fast => &WEAK_PASSWORD_HASH,
                Hashing::FixedSalt => &PREDICTABLE_SALT,
            };
            if hits
                .iter()
                .any(|x| x.module == h.module && x.line == h.line && x.rule.id == rule.id)
            {
                continue;
            }
            let at = &project.modules[u.module].path;
            let what = match h.how {
                Hashing::Fast => format!(
                    "{}() хеширует пароль (вызов в {at}:{}) быстрой функцией {}: перебор идёт миллиардами вариантов в секунду; используйте bcrypt, scrypt, Argon2 или PBKDF2",
                    h.name, u.line, h.label
                ),
                Hashing::FixedSalt => format!(
                    "{}() (вызов в {at}:{}): {}",
                    h.name,
                    u.line,
                    salt_message(&h.label)
                ),
            };
            hits.push(Hit {
                rule,
                module: h.module,
                line: h.line,
                what,
            });
        }
    }
}

/// `hashlib.sha256()` or, with a salt, `hashlib.sha256() с постоянной
/// солью «shifo»`.
fn hash_how(label: &str, hashed: &Expr, scope: &Scope) -> String {
    match constant_salt(hashed, scope) {
        Some(s) => format!("{label} с постоянной солью «{s}»"),
        None => label.to_string(),
    }
}

/// Whether an expression names a password anywhere: `admin.password_hash`,
/// `ADMIN_PASS_HASH`, `stored_pw`.
fn names_password(e: &Expr) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| match x {
        Expr::Name(n) | Expr::Attr(_, n) => found |= password_ish(n.trim_start_matches('$')),
        Expr::Index(_, k) => {
            found |= first_literal(k).is_some_and(|s| identifier_like(s) && password_ish(s))
        }
        _ => {}
    });
    found
}

/// A name with a password word anywhere in it.
fn password_ish(name: &str) -> bool {
    name_words(name).any(|w| {
        matches!(
            w.as_str(),
            "password" | "passwd" | "pwd" | "pw" | "pass" | "passphrase"
        )
    })
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
    /// Database files already reported in the project.
    db_paths: &'a RefCell<HashSet<String>>,
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
    // `for k, v in form.items(): setattr(obj, k, v)`, `for k in form:
    // db.add(Setting(k, form[k]))`, `foreach ($_POST as $k => $v)
    // update_option($k, $v)`.
    if let Stmt::Loop {
        target: Some(target),
        iter: Some(iter),
        body,
        ..
    } = s
    {
        if let Some(key) = form_key_var(target, iter, request, cx.locals) {
            if key_written(body, key) && !key_checked(body, key, request) {
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
                // A template compiled from text kept in a database: whoever
                // can change that text runs code in the template engine.
                if let Some((source, how)) = template_source(callee, args, scope) {
                    if !from_request(source, request) && stored(source, cx.locals, 0) {
                        push(
                            &STORED_SSTI,
                            format!(
                                "{how} компилирует шаблон из сохранённых данных, а не из файла шаблона: кто может изменить эти данные (форма админки, запись в БД), тот выполняет код на сервере; выводите такие данные как переменную шаблона"
                            ),
                        );
                    }
                }
            }
            _ => {}
        });
    }
    // A database file wherever the server happens to start; Flask-SQLAlchemy
    // puts a relative path in the app's instance folder instead.
    let flask_sqlalchemy = match s {
        Stmt::Assign {
            target: Target::Index(_, k),
            ..
        } => first_literal(k) == Some("SQLALCHEMY_DATABASE_URI"),
        Stmt::Assign {
            target: Target::Name(n) | Target::Attr(_, n),
            ..
        } => n == "SQLALCHEMY_DATABASE_URI",
        _ => false,
    };
    if !flask_sqlalchemy {
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                let Some(path) = workdir_db(x, scope, cx.locals) else {
                    return;
                };
                if cx.db_paths.borrow_mut().insert(path.to_string()) {
                    let what = if lang == Language::Php {
                        format!("база SQLite «{path}» лежит в папке сайта: если веб-сервер отдаёт файлы .db и .sqlite, её можно скачать целиком по прямой ссылке; храните базу вне корня сайта")
                    } else {
                        format!("база данных «{path}» задана путём от текущей папки: файл появится там, откуда запущен сервер, обычно рядом с кодом; если эту папку раздаёт веб-сервер или её копируют в архив или git, базу можно скачать целиком; укажите абсолютный путь вне папки сайта")
                    };
                    push(&DB_IN_WORKDIR, what);
                }
            });
        }
    }
    for e in own_exprs(s) {
        each_expr(e, &mut |x| {
            let Some((hashed, label, how)) = hash_call(x, scope, cx.locals) else {
                return;
            };
            let password =
                mentions_password(hashed) || (cx.password_fn && mentions_param(hashed, cx.params));
            match how {
                _ if !password => {}
                Hashing::Fast if !cx.stretched => push(
                    &WEAK_PASSWORD_HASH,
                    format!(
                        "пароль хешируется быстрой функцией {}: перебор идёт миллиардами вариантов в секунду; используйте bcrypt, scrypt, Argon2 или PBKDF2",
                        hash_how(&label, hashed, scope)
                    ),
                ),
                Hashing::Fast => {}
                Hashing::FixedSalt => push(&PREDICTABLE_SALT, salt_message(&label)),
            }
        });
    }
}

/// The path of a database file relative to the working directory that an
/// expression names: `"sqlite:///./app.db"`, `sqlite3.connect("app.db")`,
/// `"jdbc:sqlite:app.db"`, PHP `new PDO("sqlite:app.db")`, a Django
/// database whose `NAME` is `"db.sqlite3"`.
fn workdir_db<'e>(
    e: &'e Expr,
    scope: &'e Scope,
    locals: &HashMap<&str, &'e Expr>,
) -> Option<&'e str> {
    let relative = |p: &str| {
        !p.is_empty()
            && !p.starts_with('/')
            && !p.starts_with('\\')
            && !p.starts_with('~')
            && !p.starts_with(":memory:")
            && !p.starts_with("file:")
            && !p.contains(['{', '%', '$', '?'])
            && p.as_bytes().get(1) != Some(&b':')
    };
    let php = scope.lang == Language::Php;
    match e {
        Expr::Lit(Const::Str(s)) => {
            let path = if let Some((scheme, rest)) = s.split_once(":///") {
                // `sqlite:///./app.db`, `sqlite+aiosqlite:///app.db`
                (scheme == "sqlite" || scheme.starts_with("sqlite+")).then_some(rest)?
            } else if let Some(rest) = s.strip_prefix("jdbc:sqlite:") {
                rest
            } else if let Some(rest) = s.strip_prefix("jdbc:h2:") {
                if ["mem:", "tcp:", "ssl:", "zip:"]
                    .iter()
                    .any(|p| rest.starts_with(p))
                {
                    return None;
                }
                rest.strip_prefix("file:").unwrap_or(rest)
            } else if php {
                let rest = s.strip_prefix("sqlite:")?;
                // A file above the page's folder is outside the site.
                if rest.starts_with("..") {
                    return None;
                }
                rest
            } else {
                return None;
            };
            relative(path).then_some(path)
        }
        // `sqlite3.connect("app.db")`, PHP `new SQLite3("app.db")`
        Expr::Call { func, args, .. } if scope.lang == Language::Python => {
            let sqlite = match &**func {
                Expr::Attr(o, n) => {
                    n == "connect"
                        && matches!(&**o, Expr::Name(r) if r == "sqlite3" || r == "aiosqlite")
                }
                Expr::Name(n) => {
                    callee_name(func) == "connect"
                        && scope.imported_from(n, &["sqlite3", "aiosqlite"])
                }
                _ => false,
            };
            if !sqlite {
                return None;
            }
            let path = constant_text(&args.first()?.value, scope, locals)?;
            relative(path).then_some(path)
        }
        Expr::New { class, args, .. } if php && class.trim_start_matches('\\') == "SQLite3" => {
            let path = constant_text(&args.first()?.value, scope, locals)?;
            (relative(path) && !path.starts_with("..")).then_some(path)
        }
        // Django: `{"ENGINE": "django.db.backends.sqlite3", "NAME": "db.sqlite3"}`
        Expr::Dict(pairs) if scope.lang == Language::Python => {
            let value = |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| first_literal(k) == Some(key))
                    .map(|(_, v)| v)
            };
            let engine = value("ENGINE").and_then(first_literal)?;
            if !engine.ends_with("sqlite3") {
                return None;
            }
            let path = constant_text(value("NAME")?, scope, locals)?;
            relative(path).then_some(path)
        }
        _ => None,
    }
}

/// The finding for a slow hash under a constant salt.
fn salt_message(label: &str) -> String {
    format!(
        "пароль хешируется {label}: у всех паролей одна соль, поэтому одинаковые пароли дают одинаковые хеши, а подбор идёт сразу по всей базе; генерируйте случайную соль для каждого пароля (os.urandom(16), bcrypt.gensalt(), SecureRandom)"
    )
}

/// The text a call compiles as a template, and how to name the call:
/// `jinja2.Template(src)`, `env.from_string(src)`,
/// `render_template_string(src)`, Twig `createTemplate($src)`, Velocity
/// `evaluate(ctx, out, tag, src)`.
fn template_source<'e>(
    callee: &'e Expr,
    args: &'e [Arg],
    scope: &Scope,
) -> Option<(&'e Expr, String)> {
    let name = callee_name(callee);
    let nth = |i: usize| args.get(i).filter(|a| a.name.is_none()).map(|a| &a.value);
    match scope.lang {
        Language::Python => {
            let template_class = name == "Template"
                && match callee {
                    Expr::Name(n) => {
                        n.starts_with("jinja2.")
                            || n.starts_with("mako.")
                            || scope.imported_from(n, &["jinja2", "mako"])
                    }
                    Expr::Attr(o, _) => matches!(&**o, Expr::Name(r)
                        if r == "jinja2" || scope.imported_from(r, &["jinja2", "mako"])),
                    _ => false,
                };
            if template_class || matches!(name, "from_string" | "render_template_string") {
                return nth(0).map(|e| (e, format!("{name}()")));
            }
        }
        Language::Php if name == "createTemplate" => {
            return nth(0).map(|e| (e, format!("{name}()")))
        }
        Language::Java if name == "evaluate" && args.len() == 4 => {
            return nth(3).map(|e| (e, "Velocity.evaluate()".to_string()));
        }
        _ => {}
    }
    None
}

/// Whether a value comes from stored data: what a query returns
/// (`.first()`, `fetchone()`) or a field of it (`setting.value`,
/// `row["footer"]`), directly or through variables.
fn stored(e: &Expr, locals: &HashMap<&str, &Expr>, depth: u8) -> bool {
    const FETCH: &[&str] = &[
        "first",
        "one",
        "one_or_none",
        "scalar",
        "scalar_one",
        "fetchone",
        "fetch",
        "fetch_assoc",
        "fetch_array",
        "fetch_object",
        "mysqli_fetch_assoc",
        "mysqli_fetch_array",
        "fetchColumn",
        "get_object_or_404",
        "find_one",
        "get_var",
        "get_row",
        "get_option",
    ];
    if depth > 4 {
        return false;
    }
    match e {
        Expr::Attr(o, _) | Expr::Index(o, _) => stored(o, locals, depth + 1),
        Expr::Name(n) => locals
            .get(n.as_str())
            .is_some_and(|v| stored(v, locals, depth + 1)),
        Expr::Call { func, .. } => {
            let name = callee_name(func);
            FETCH.contains(&name)
                // `Setting.objects.get(key="footer")`, `Page.query.get(id)`
                || (name == "get"
                    && matches!(&**func, Expr::Attr(o, _) if matches!(callee_name(o), "objects" | "query")))
        }
        _ => false,
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
/// How a call hashes what it is given.
#[derive(Clone, Copy, PartialEq)]
enum Hashing {
    /// A fast hash: billions of guesses a second.
    Fast,
    /// A slow function whose salt is the same for every password.
    FixedSalt,
}

/// A call that hashes `input`, how it names the hash, and how it hashes:
/// a fast hash (`hashlib.sha256(x)`, a hash object's `h.update(x)`, an
/// HMAC under a constant key), or a slow one whose salt never changes
/// (`pbkdf2_hmac("sha256", x, b"salt", n)`, `bcrypt.hashpw(x, b"$2b$...")`,
/// `new PBEKeySpec(x, SALT, n, len)`).
fn hash_call<'e>(
    call: &'e Expr,
    scope: &Scope,
    locals: &HashMap<&str, &'e Expr>,
) -> Option<(&'e Expr, String, Hashing)> {
    let (callee, args) = match call {
        Expr::Call { func, args, .. } => (&**func, args.as_slice()),
        Expr::New { class, args, .. } => {
            let class = class.rsplit(['.', '\\']).next().unwrap_or(class);
            if class == "PBEKeySpec" && scope.lang == Language::Java {
                let salt = constant_text(&args.get(1)?.value, scope, locals)?;
                return Some((
                    &args.first()?.value,
                    format!("PBEKeySpec с постоянной солью «{salt}»"),
                    Hashing::FixedSalt,
                ));
            }
            return None;
        }
        _ => return None,
    };
    if let Some((input, label)) = fast_hash(callee, args, scope) {
        return Some((input, label, Hashing::Fast));
    }
    let name = callee_name(callee);
    let recv = match callee {
        Expr::Attr(o, _) => match &**o {
            Expr::Name(r) => scope
                .imports
                .get(r.as_str())
                .map(|p| p.rsplit('.').next().unwrap_or(p))
                .unwrap_or(r),
            _ => "",
        },
        Expr::Name(n) => match scope.imports.get(n.as_str()) {
            // `from hashlib import pbkdf2_hmac`
            Some(p) => p.rsplit('.').nth(1).unwrap_or(""),
            None => "",
        },
        _ => "",
    };
    let nth = |i: usize| args.get(i).filter(|a| a.name.is_none()).map(|a| &a.value);
    let kw = |k: &str| {
        args.iter()
            .find(|a| a.name.as_deref() == Some(k))
            .map(|a| &a.value)
    };
    // A slow hash of `input` with a constant `salt`.
    let slow = |input: Option<&'e Expr>, salt: Option<&'e Expr>, label: String| {
        let salt = constant_text(salt?, scope, locals)?;
        Some((
            input?,
            format!("{label} с постоянной солью «{salt}»"),
            Hashing::FixedSalt,
        ))
    };
    let label = |n: &str| match recv {
        "" => format!("{n}()"),
        r => format!("{r}.{n}()"),
    };
    match scope.lang {
        Language::Python => {
            match (recv, name) {
                // `h = hashlib.sha256(); h.update(p)`
                (_, "update") => {
                    let Expr::Attr(o, _) = callee else {
                        return None;
                    };
                    let Expr::Name(v) = &**o else { return None };
                    let Expr::Call { func, args: a, .. } = locals.get(v.as_str())? else {
                        return None;
                    };
                    let label = hash_object(func, a, scope)?;
                    Some((nth(0)?, label, Hashing::Fast))
                }
                // An HMAC whose key is a constant is a salted fast hash.
                ("hmac", "new" | "digest") => {
                    let key = nth(0).or_else(|| kw("key"))?;
                    let k = constant_text(key, scope, locals)?;
                    let msg = nth(1).or_else(|| kw("msg"))?;
                    Some((
                        msg,
                        format!("HMAC с постоянным ключом «{k}»"),
                        Hashing::Fast,
                    ))
                }
                ("hashlib", "pbkdf2_hmac") => slow(
                    nth(1).or_else(|| kw("password")),
                    nth(2).or_else(|| kw("salt")),
                    label(name),
                ),
                ("hashlib", "scrypt") => {
                    slow(nth(0).or_else(|| kw("password")), kw("salt"), label(name))
                }
                ("bcrypt" | "crypt", "hashpw" | "crypt") => slow(nth(0), nth(1), label(name)),
                // `kdf = PBKDF2HMAC(..., salt=SALT, ...); kdf.derive(p)`
                (_, "derive") => {
                    let Expr::Attr(o, _) = callee else {
                        return None;
                    };
                    let Expr::Name(v) = &**o else { return None };
                    let Expr::Call { func, args: a, .. } = locals.get(v.as_str())? else {
                        return None;
                    };
                    let kdf = callee_name(func);
                    if !matches!(kdf, "PBKDF2HMAC" | "Scrypt") {
                        return None;
                    }
                    let salt = a.iter().find(|x| x.name.as_deref() == Some("salt"))?;
                    slow(nth(0), Some(&salt.value), format!("{kdf}()"))
                }
                _ => None,
            }
        }
        Language::Php => match name.to_ascii_lowercase().as_str() {
            "hash_hmac" => {
                let k = constant_text(nth(2)?, scope, locals)?;
                Some((
                    nth(1)?,
                    format!("hash_hmac() с постоянным ключом «{k}»"),
                    Hashing::Fast,
                ))
            }
            "hash_pbkdf2" => slow(nth(1), nth(2), "hash_pbkdf2()".into()),
            "crypt" => slow(nth(0), nth(1), "crypt()".into()),
            // `password_hash($p, PASSWORD_BCRYPT, ['salt' => '...'])`
            "password_hash" => {
                let Expr::Dict(pairs) = nth(2)? else {
                    return None;
                };
                let salt = pairs
                    .iter()
                    .find(|(k, _)| first_literal(k) == Some("salt"))
                    .map(|(_, v)| v);
                slow(nth(0), salt, "password_hash()".into())
            }
            _ => None,
        },
        Language::Java if recv == "BCrypt" && name == "hashpw" => {
            slow(nth(0), nth(1), "BCrypt.hashpw()".into())
        }
        _ => None,
    }
}

/// The fast hash whose object a call makes: `hashlib.sha256()`,
/// `hashlib.new("md5")`.
fn hash_object(func: &Expr, args: &[Arg], scope: &Scope) -> Option<String> {
    let mut probe = args.to_vec();
    probe.resize(
        2,
        Arg {
            name: None,
            value: Expr::Name(String::new()),
            spread: false,
        },
    );
    fast_hash(func, &probe, scope).map(|(_, label)| label)
}

/// The text of a value that never changes: a literal, encoded or not, a
/// constant of the module or class, a local assigned one once.
fn constant_text<'e>(
    e: &'e Expr,
    scope: &'e Scope,
    locals: &HashMap<&str, &'e Expr>,
) -> Option<&'e str> {
    if let Some(s) = literal_of(e) {
        return Some(s);
    }
    let name = match e {
        Expr::Name(n) => n.as_str(),
        // `SALT.encode()`, `self.SALT`
        Expr::Call { func, .. } => match &**func {
            Expr::Attr(o, m) if matches!(m.as_str(), "encode" | "getBytes" | "toCharArray") => {
                return constant_text(o, scope, locals)
            }
            _ => return None,
        },
        // `self.SALT`, `Pw.SALT` in Java
        Expr::Attr(o, n)
            if matches!(&**o, Expr::Name(s) if s == "self" || s == "this"
                || s.starts_with(|c: char| c.is_ascii_uppercase())) =>
        {
            n.as_str()
        }
        _ => return None,
    };
    let name = name.rsplit('.').next().unwrap_or(name);
    scope
        .texts
        .get(name)
        .copied()
        .or_else(|| locals.get(name).and_then(|v| literal_of(v)))
}

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
            // `hashlib.sha256`, `hl.sha256` after `import hashlib as hl`,
            // `sha256` after `from hashlib import sha256`.
            let hashlib = match callee {
                Expr::Attr(o, _) => matches!(&**o, Expr::Name(r)
                    if r == "hashlib" || scope.imports.get(r.as_str()) == Some(&"hashlib")),
                Expr::Name(n) => {
                    n.starts_with("hashlib.")
                        || scope
                            .imports
                            .get(n.as_str())
                            .is_some_and(|p| p.starts_with("hashlib."))
                }
                _ => false,
            };
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
fn constant_salt(e: &Expr, scope: &Scope) -> Option<String> {
    let mut found = None;
    each_expr(e, &mut |x| {
        let parts: Vec<&Expr> = match x {
            Expr::Bin(BinOp::Add, l, r) => vec![l, r],
            Expr::Concat(p) => p.iter().collect(),
            _ => return,
        };
        for p in parts {
            let text = match p {
                Expr::Lit(Const::Str(s)) => Some(s.as_str()),
                // `SALT + p` with `SALT = "shifo"` in the module.
                Expr::Name(n) => scope.texts.get(n.as_str()).copied(),
                _ => None,
            };
            if let Some(s) = text.filter(|s| !s.is_empty()) {
                if found.is_none() {
                    found = Some(s.to_string());
                }
            }
        }
    });
    found
}

/// The variable a loop binds to the field names of a whole request form:
/// `for k in form`, `for k in form.keys()`, `for k, v in form.items()`,
/// PHP `foreach ($_POST as $k => $v)`.
fn form_key_var<'s>(
    target: &'s Target,
    iter: &Expr,
    request: &[String],
    locals: &HashMap<&str, &Expr>,
) -> Option<&'s str> {
    let (key, single) = match target {
        Target::Name(n) => (n.as_str(), true),
        Target::Tuple(t) => match t.first() {
            Some(Target::Name(n)) => (n.as_str(), false),
            _ => return None,
        },
        _ => return None,
    };
    let form = |e: &Expr| form_object(e, request, locals, 0);
    let keyed = match iter {
        Expr::Call { func, args, .. } => match &**func {
            Expr::Attr(src, m) => match m.as_str() {
                "items" | "iteritems" | "multi_items" | "lists" => !single && form(src),
                "keys" | "iterkeys" => single && form(src),
                _ => false,
            },
            Expr::Name(n) => match n.as_str() {
                "__php_pairs" => !single && args.first().is_some_and(|a| form(&a.value)),
                "list" | "sorted" | "set" | "iter" => {
                    single && args.first().is_some_and(|a| form(&a.value))
                }
                _ => single && form(iter),
            },
            _ => single && form(iter),
        },
        e => single && form(e),
    };
    keyed.then_some(key)
}

/// A whole form or body the sender fills: `request.form`, `await
/// request.form()`, `request.POST`, `request.get_json()`, `$_POST`, or a
/// variable holding one.
fn form_object(e: &Expr, request: &[String], locals: &HashMap<&str, &Expr>, depth: u8) -> bool {
    const FORMS: &[&str] = &[
        "form",
        "POST",
        "GET",
        "args",
        "values",
        "json",
        "data",
        "query_params",
        "query",
        "body",
    ];
    match e {
        Expr::Name(n) => {
            matches!(n.as_str(), "$_POST" | "$_GET" | "$_REQUEST")
                || (depth < 3
                    && request.contains(n)
                    && locals
                        .get(n.as_str())
                        .is_some_and(|v| form_object(v, request, locals, depth + 1)))
        }
        Expr::Attr(b, n) => is_request(b) && FORMS.contains(&n.as_str()),
        Expr::Call { func, args, .. } => match &**func {
            // `request.form()`, `request.get_json()`, `request.POST.copy()`,
            // `request.form.to_dict()`.
            Expr::Attr(b, n) => {
                (is_request(b)
                    && (FORMS.contains(&n.as_str()) || matches!(n.as_str(), "get_json" | "json")))
                    || (matches!(n.as_str(), "copy" | "to_dict" | "dict")
                        && form_object(b, request, locals, depth))
            }
            // `dict(request.form)`
            Expr::Name(n) if n == "dict" => args
                .first()
                .is_some_and(|a| form_object(&a.value, request, locals, depth)),
            _ => false,
        },
        _ => false,
    }
}

/// Whether a loop body stores data under a key the sender chose: as an
/// attribute (`setattr(obj, k, v)`), an index (`obj[k] = v`), a model
/// field or row (`Setting(key=k, value=v)`, `db.add(Setting(k, v))`), a
/// setting (`update_option($k, $v)`), a record it looks up and changes
/// (`s = Setting.query.filter_by(key=k).first(); s.value = v`), or an SQL
/// write with the key.
fn key_written(body: &[Stmt], key: &str) -> bool {
    let mut found = false;
    let is_key = |e: &Expr| matches!(e, Expr::Name(n) if n == key);
    let has_key = |e: &Expr| {
        let mut f = false;
        each_expr(e, &mut |x| f |= is_key(x));
        f
    };
    let mut looked_up = false;
    let mut changes_attr = false;
    visit_stmts(body, &mut |s| {
        match s {
            // Not `$_POST[$key] = ...`, which edits the request.
            Stmt::Assign {
                target: Target::Index(c, k),
                ..
            } => found |= is_key(k) && !request_data(c),
            Stmt::Assign {
                target: Target::Attr(..),
                ..
            } => changes_attr = true,
            _ => {}
        }
        for e in own_exprs(s) {
            each_expr(e, &mut |x| {
                let Expr::Call { func, args, .. } = x else {
                    return;
                };
                let name = callee_name(func);
                let lower = name.to_ascii_lowercase();
                if name == "setattr" && args.get(1).is_some_and(|a| is_key(&a.value)) {
                    found = true;
                }
                // A model made with the key: `Setting(key=key, ...)`,
                // `Setting(k, v)`; not an error or a response.
                if name.chars().next().is_some_and(char::is_uppercase)
                    && !["Error", "Exception", "Response", "Warning", "Redirect"]
                        .iter()
                        .any(|w| name.ends_with(w))
                    && (args.iter().any(|a| a.name.is_some() && is_key(&a.value))
                        || (args.len() >= 2 && args.iter().any(|a| is_key(&a.value))))
                {
                    found = true;
                }
                // `update_option($k, $v)`, `cache.set(k, v)`.
                if args.len() >= 2
                    && args.first().is_some_and(|a| is_key(&a.value))
                    && [
                        "update", "set", "save", "store", "put", "insert", "add", "write",
                    ]
                    .iter()
                    .any(|w| lower.starts_with(w))
                    && !matches!(lower.as_str(), "setdefault" | "set_cookie" | "setcookie")
                {
                    found = true;
                }
                // `obj.update({k: v})`, `coll.update_one(q, {"$set": {k: v}})`
                if ["update", "insert", "create", "set", "replace", "patch"]
                    .iter()
                    .any(|w| lower.starts_with(w))
                {
                    for a in args {
                        each_expr(&a.value, &mut |d| {
                            if let Expr::Dict(pairs) = d {
                                found |= pairs.iter().any(|(k, _)| is_key(k));
                            }
                        });
                    }
                }
                // A record picked by the key: `filter_by(key=k)`,
                // `objects.get(name=k)`, `filter(Setting.key == k)`.
                let lookup = matches!(
                    name,
                    "filter_by" | "filter" | "where" | "find_one" | "find" | "get_or_create"
                ) || (name == "get"
                    && matches!(&**func, Expr::Attr(o, _) if matches!(callee_name(o), "objects" | "query")));
                if lookup && args.iter().any(|a| has_key(&a.value)) {
                    looked_up = true;
                }
                if name == "update_or_create" && args.iter().any(|a| has_key(&a.value)) {
                    found = true;
                }
                // `cur.execute("UPDATE settings SET value=? WHERE key=?", (v, k))`
                if matches!(name, "execute" | "executemany" | "query" | "exec") {
                    let sql = args.first().map(|a| sql_text(&a.value)).unwrap_or_default();
                    let sql = sql.trim_start().to_ascii_lowercase();
                    if ["update", "insert", "replace"]
                        .iter()
                        .any(|w| sql.starts_with(w))
                        && args.iter().any(|a| has_key(&a.value))
                    {
                        found = true;
                    }
                }
            });
        }
    });
    found || (looked_up && changes_attr)
}

/// The request's own data: `$_POST`, `request.form`.
fn request_data(e: &Expr) -> bool {
    match e {
        Expr::Name(n) => n.starts_with("$_"),
        Expr::Attr(b, _) => is_request(b),
        _ => false,
    }
}

/// The literal text of an SQL argument, string-building included.
fn sql_text(e: &Expr) -> String {
    match e {
        Expr::Lit(Const::Str(s)) => s.clone(),
        Expr::Concat(parts) => parts.iter().map(sql_text).collect(),
        Expr::Bin(BinOp::Add, l, r) => sql_text(l) + &sql_text(r),
        _ => String::new(),
    }
}

/// Whether a loop body checks the key against a list of allowed names
/// before using it: `if k in ALLOWED`, `if k not in FIELDS: continue`,
/// `k.startswith("site_")`, `in_array($k, $allowed)`. `hasattr(obj, k)`
/// is no such check: it lets every attribute through.
fn key_checked(body: &[Stmt], key: &str, request: &[String]) -> bool {
    let is_key = |e: &Expr| matches!(e, Expr::Name(n) if n == key);
    let mut found = false;
    visit_stmts(body, &mut |s| {
        let test = match s {
            Stmt::If { test, .. } => test,
            Stmt::Loop { test: Some(t), .. } => t,
            _ => return,
        };
        each_expr(test, &mut |x| match x {
            Expr::Bin(BinOp::In | BinOp::NotIn, l, r) if is_key(l) => {
                found |= !from_request(r, request) && !only_form_fields(r) && !every_field(r);
            }
            Expr::Call { func, args, .. } => {
                let name = callee_name(func);
                let on_key = matches!(&**func, Expr::Attr(o, _) if is_key(o));
                let key_arg = args.iter().any(|a| is_key(&a.value));
                found |= (on_key
                    && matches!(name, "startswith" | "endswith" | "isidentifier" | "match"))
                    || (key_arg
                        && matches!(
                            name,
                            "in_array" | "array_key_exists" | "match" | "fullmatch" | "preg_match"
                        )
                        && !args.iter().any(|a| from_request(&a.value, request)));
            }
            // `isset($allowed[$k])`
            Expr::Index(b, k) if is_key(k) => {
                found |= !from_request(b, request)
                    && matches!(&**b, Expr::Name(n) if !n.starts_with("$_"));
            }
            _ => {}
        });
    });
    found
}

/// All fields of an object or model, which a check against lets every
/// field through: `obj.__dict__`, `Model.__table__.columns`, `vars(obj)`.
fn every_field(e: &Expr) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| match x {
        Expr::Attr(_, n) => {
            found |= matches!(
                n.as_str(),
                "__dict__"
                    | "__table__"
                    | "__annotations__"
                    | "__fields__"
                    | "model_fields"
                    | "_meta"
            )
        }
        Expr::Call { func, .. } => found |= matches!(callee_name(func), "vars" | "dir"),
        _ => {}
    });
    found
}

/// A literal list of names a form carries besides its data
/// (`("csrf_token", "submit")`): skipping them allows every other field.
fn only_form_fields(e: &Expr) -> bool {
    let items = match e {
        Expr::List(items) => items,
        _ => return false,
    };
    !items.is_empty()
        && items.iter().all(|i| {
            first_literal(i).is_some_and(|s| {
                let l = s.to_ascii_lowercase();
                l.contains("csrf")
                    || l.contains("token")
                    || matches!(l.as_str(), "submit" | "action" | "_method" | "save")
            })
        })
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
                ..
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
