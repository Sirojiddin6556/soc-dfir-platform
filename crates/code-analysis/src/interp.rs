//! Abstract interpreter over the shared IR.
//!
//! It runs every function of a project with abstract values: constants are
//! folded, containers keep their slots, branches with a known condition are
//! followed alone and other branches are joined. User-controlled data is
//! tracked as taint; language models decide where it enters (sources), what
//! cleans it (sanitizers) and where it must not arrive (sinks).

use crate::ir::*;
use crate::project::Project;
use crate::rules::{makes_secret, name_words, secret_name, Finding, Location, Rule, WEAK_RANDOM};
use crate::value::*;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

const MAX_DEPTH: usize = 10;
const MAX_STEPS: usize = 400_000;
/// Call frames explored from an entry with no user data (see `quiet`).
const QUIET_DEPTH: usize = 3;

/// An evaluated call argument.
#[derive(Debug, Clone)]
pub struct ArgVal {
    pub name: Option<Rc<str>>,
    pub value: Value,
    pub spread: bool,
    /// The variable passed, when the argument is a plain name.
    pub var: Option<Rc<str>>,
}

impl ArgVal {
    pub fn plain(value: Value) -> ArgVal {
        ArgVal {
            name: None,
            value,
            spread: false,
            var: None,
        }
    }
}

/// Positional argument `i`, or the keyword argument `name`.
pub fn arg<'a>(args: &'a [ArgVal], i: usize, name: &str) -> Option<&'a Value> {
    if let Some(a) = args.iter().find(|a| a.name.as_deref() == Some(name)) {
        return Some(&a.value);
    }
    args.iter()
        .filter(|a| a.name.is_none() && !a.spread)
        .nth(i)
        .map(|a| &a.value)
}

pub fn kwarg<'a>(args: &'a [ArgVal], name: &str) -> Option<&'a Value> {
    args.iter()
        .find(|a| a.name.as_deref() == Some(name))
        .map(|a| &a.value)
}

pub fn args_taint(args: &[ArgVal]) -> Taint {
    args.iter()
        .fold(Taint::clean(), |t, a| t.union(&a.value.taint()))
}

/// An HTTP handler: its return value is the response body.
#[derive(Debug, Clone)]
pub struct Route {
    pub path: String,
    /// Path parameters (`<name>` in Flask, `{name}` in FastAPI).
    pub params: Vec<String>,
    /// Parameters with a numeric converter (`<int:id>`).
    pub typed_params: Vec<String>,
    /// The rule has no parameters, so the request path equals it.
    pub fixed_path: bool,
    pub framework: &'static str,
}

/// A fact a condition establishes about a variable.
#[derive(Debug, Clone)]
pub enum Fact {
    StartsWith(String),
    EndsWith(String),
    NotContains(String),
    /// `q not in x[1:-1]`: no `q` strictly inside.
    NotContainsInner(String),
    /// The variable equals one of these values.
    OneOf(Vec<Value>),
    /// Starts with another (non-literal) string: a containment check.
    StartsWithValue,
    Safe(u32),
}

/// What a fact from a call condition is about.
#[derive(Debug, Clone, Copy)]
pub enum FactOn {
    Recv,
    Arg(usize),
}

/// Language-specific knowledge: libraries, frameworks, sources and sinks.
pub trait Model {
    /// Attribute of an external reference (a module member, a framework object).
    fn ref_attr(&self, it: &mut Interp, path: &str, taint: &Taint, name: &str) -> Value;
    /// Call of an external function or class.
    fn call_ref(
        &self,
        it: &mut Interp,
        path: &str,
        taint: &Taint,
        args: &[ArgVal],
        span: Span,
    ) -> Value;
    /// Method call on a value that is not user code. Returns the result and
    /// the receiver's new value when the method changed it.
    fn call_method(
        &self,
        it: &mut Interp,
        recv: &Value,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>);
    /// Attribute of a non-module value such as a modeled object.
    fn attr(&self, _it: &mut Interp, _base: &Value, _name: &str) -> Option<Value> {
        None
    }
    /// Subscript the core cannot evaluate, e.g. `request.args['x']`.
    fn index(&self, _it: &mut Interp, _base: &Value, _key: &Value) -> Option<Value> {
        None
    }
    /// `base[key] = value` on a value the core does not model; returns the
    /// new base when it changed.
    fn store_index(
        &self,
        _it: &mut Interp,
        _base: &Value,
        _key: &Value,
        _value: &Value,
        _span: Span,
    ) -> Option<Value> {
        None
    }
    fn binop(&self, _it: &mut Interp, _op: BinOp, _l: &Value, _r: &Value) -> Option<Value> {
        None
    }
    /// Value of a name no scope defines.
    fn builtin(&self, _it: &mut Interp, name: &str) -> Value {
        Value::Ref(format!("builtins.{name}").into(), Taint::clean())
    }
    fn route(&self, _it: &mut Interp, _module: usize, _func: &Function) -> Option<Route> {
        None
    }
    /// Value of a parameter when the function is analyzed as an entry point.
    fn entry_param(
        &self,
        _it: &mut Interp,
        _module: usize,
        _func: &Function,
        _route: Option<&Route>,
        _index: usize,
        _param: &Param,
    ) -> Value {
        Value::clean()
    }
    fn on_return(&self, _it: &mut Interp, _route: &Route, _value: &Value, _span: Span) {}
    /// Safety the result of a user function gets from its qualified name
    /// alone (`escape_html`, `Escape.htmlElementContent`), for hand-written
    /// escapers the interpreter cannot see through.
    fn sanitizer_of(&self, _qualname: &str) -> u32 {
        0
    }
    /// Facts from a method call used as a condition: `x.startswith("'")`
    /// is about the receiver, `re.fullmatch(p, x)` about an argument.
    fn refine_method(
        &self,
        _recv: &Value,
        _name: &str,
        _args: &[Value],
        _truth: bool,
    ) -> Vec<(FactOn, Fact)> {
        Vec::new()
    }
    /// Facts from a call of a library function used as a condition:
    /// `preg_match('/^\d+$/', $x)` is about its second argument.
    fn refine_call(&self, _name: &str, _args: &[Value], _truth: bool) -> Vec<(FactOn, Fact)> {
        Vec::new()
    }
    /// Variables sanitized by a fact about an attribute of an object,
    /// e.g. a check of `urlparse(u).netloc` validates `u`.
    fn refine_attr(&self, _obj: &Obj, _field: &str, _fact: &Fact) -> Vec<(Rc<str>, u32)> {
        Vec::new()
    }
    /// Safety a set of facts about one variable establishes.
    fn facts_safety(&self, _facts: &[Fact], _value: &Value) -> u32 {
        0
    }
    /// Whether entries that receive no request data explore their calls
    /// only a few frames deep (see `Interp::quiet`).
    fn quiet_entries(&self) -> bool {
        false
    }
    /// A function the model knows better than the project's own definition
    /// of it (WordPress's escaping functions when WordPress is scanned).
    fn library_over_project(&self, _name: &str) -> bool {
        false
    }
    /// A typed declaration (`int n = ...`).
    fn coerce(&self, _it: &mut Interp, _ty: &str, value: Value) -> Value {
        value
    }
    fn raw(&self, _it: &mut Interp, _value: &Value, _span: Span) {}
    /// A value as it reads inside a string being built (`"a $x"`).
    fn stringify(&self, _it: &mut Interp, value: Value) -> Value {
        value
    }
}

struct LoopAcc {
    breaks: Option<Env>,
    continues: Option<Env>,
    is_switch: bool,
}

struct Frame {
    module: usize,
    func: Option<Rc<Function>>,
    env: Option<Env>,
    closure: Option<Rc<Env>>,
    scope: Option<Rc<Scope>>,
    ret: Option<Value>,
    self_name: Option<Rc<str>>,
    final_self: Option<Value>,
    loops: Vec<LoopAcc>,
    /// The environment holds checks on array elements (`$a[0]`, see
    /// [`path_key`]), which assignments to the array must drop.
    paths: bool,
    route: Option<Route>,
    span: Span,
    /// Variables of a module's top level where it returned or exited:
    /// a PHP script that ends with `exit` still defined them.
    exit_env: Option<Env>,
}

enum Globals {
    Pending,
    Running,
    Done(Rc<Env>),
}

pub struct Interp<'p> {
    pub project: &'p Project,
    globals: Vec<Globals>,
    frames: Vec<Frame>,
    /// Call sites from the entry function down to the current frame.
    calls: Vec<(usize, Span)>,
    pub findings: Vec<Finding>,
    /// Reported sinks and the index of their finding.
    seen: HashMap<(String, usize, u32, u32, usize, u32), usize>,
    steps: usize,
    /// The entry being analyzed is not a handler and receives no request
    /// data. Its callees are entries of their own, so clean calls are only
    /// followed a few frames deep: whole-program walks from every test or
    /// helper made large projects slow without finding more.
    quiet: bool,
    /// Nesting of expression evaluation, bounded to keep the stack safe.
    depth: usize,
    /// Modules whose top level is being run (imports inside imports).
    loading: usize,
    /// Times a limit cut the analysis short; a call whose analysis was cut
    /// is not reused.
    cutoffs: usize,
    /// Results of calls with clean arguments, by callee and arguments: the
    /// same helper called the same way behaves the same.
    memo: HashMap<String, (Value, Option<Value>)>,
    /// State a language model keeps for the entry being analyzed, such as
    /// the content type its response was given.
    pub notes: HashMap<&'static str, Value>,
    /// See `subclass_index`.
    subclasses: Option<SubclassIndex>,
    /// Also treat file contents, command output and session data as
    /// untrusted (see `Options::external_sources`).
    pub external_sources: bool,
    /// See `php_index`.
    php_defs: Option<PhpIndex>,
    php_consts: Option<Rc<HashMap<String, Value>>>,
    /// Values of the array elements a condition being refined checks.
    path_vals: Vec<(Rc<str>, Value)>,
    /// PHP script variables that the project sets to one class's object
    /// (`$db = new Database();` in index.php), by name.
    php_objects: Option<Rc<HashMap<String, Expr>>>,
    php_objects_building: Vec<String>,
    /// Top-level definitions of each PHP module, its functions' scope.
    php_scopes: HashMap<usize, Option<Rc<Scope>>>,
}

/// Top-level PHP functions and classes of the project by lowercase name,
/// with the module defining each.
type PhpIndex = Rc<HashMap<String, Vec<(usize, Def)>>>;

/// Project classes deriving directly from each class, by qualified name.
type SubclassIndex = Rc<HashMap<Rc<str>, Vec<Rc<ClassVal>>>>;

const MAX_MEMO: usize = 200_000;

const MAX_EVAL_DEPTH: usize = 300;
const MAX_IMPORT_DEPTH: usize = 12;

impl<'p> Interp<'p> {
    pub fn new(project: &'p Project) -> Self {
        Interp {
            project,
            globals: project.modules.iter().map(|_| Globals::Pending).collect(),
            frames: Vec::new(),
            calls: Vec::new(),
            findings: Vec::new(),
            seen: HashMap::new(),
            steps: 0,
            quiet: false,
            notes: HashMap::new(),
            subclasses: None,
            external_sources: false,
            php_defs: None,
            php_consts: None,
            path_vals: Vec::new(),
            php_objects: None,
            php_objects_building: Vec::new(),
            php_scopes: HashMap::new(),

            depth: 0,
            loading: 0,
            cutoffs: 0,
            memo: HashMap::new(),
        }
    }

    // ----- entry points -----

    /// Runs a module's top level and then every function in it.
    pub fn analyze_module(&mut self, module: usize) {
        // A script's own code (PHP pages, Python modules) is explored fully.
        self.quiet = false;
        self.module_globals(module);
        let ir = &self.project.modules[module].ir;
        let mut entries = Vec::new();
        let top = self.php_scope(module);
        collect_functions(&ir.body, top, None, &mut entries);
        for (func, scope, class) in entries {
            self.steps = 0;
            let class = class.map(|c| {
                Rc::new(ClassVal {
                    qualname: format!("{}.{}", self.project.modules[module].name, c.name).into(),
                    def: c,
                    module,
                    scope: scope.clone(),
                })
            });
            self.notes.clear();
            self.analyze_entry(module, func, scope, class);
        }
    }

    fn analyze_entry(
        &mut self,
        module: usize,
        func: Rc<Function>,
        scope: Option<Rc<Scope>>,
        class: Option<Rc<ClassVal>>,
    ) {
        let model = crate::models::for_language(self.project.modules[module].lang);
        let route = model.route(self, module, &func);
        let mut env = Env::new();
        let mut self_name = None;
        for (i, p) in func.params.iter().enumerate() {
            let v = if i == 0 && class.is_some() && !is_static(&func) {
                self_name = Some(Rc::from(p.name.as_str()));
                let cv = class.clone().unwrap();
                Value::Obj(Rc::new(Obj {
                    class: cv.qualname.clone(),
                    def: Some(cv),
                    fields: Vec::new(),
                    taint: Taint::clean(),
                }))
            } else {
                let mut f = Frame::new(module, None, Some(Env::new()));
                f.span = func.span;
                self.frames.push(f);
                let v = model.entry_param(self, module, &func, route.as_ref(), i, p);
                self.frames.pop();
                v
            };
            env.insert(p.name.as_str().into(), v);
        }
        self.quiet = model.quiet_entries()
            && route.is_none()
            && func.params.iter().enumerate().all(|(i, p)| {
                (i == 0 && self_name.is_some())
                    || match env.get(p.name.as_str()) {
                        Some(Value::Obj(_) | Value::Ref(..)) => false,
                        Some(v) => !v.taint().is_tainted(),
                        None => true,
                    }
            });
        let mut frame = Frame::new(module, Some(func.clone()), Some(env));
        frame.scope = Scope::of_body(&func.body, scope);
        frame.route = route;
        frame.self_name = self_name;
        self.frames.push(frame);
        self.exec_block(&func.body);
        self.frames.pop();
    }

    // ----- reporting -----

    pub fn module(&self) -> usize {
        self.frames.last().map(|f| f.module).unwrap_or(0)
    }

    /// Library knowledge for the language of the code being run.
    fn model(&self) -> &'static dyn Model {
        crate::models::for_language(self.project.modules[self.module()].lang)
    }

    pub fn span(&self) -> Span {
        self.frames.last().map(|f| f.span).unwrap_or_default()
    }

    /// The innermost HTTP handler being run.
    pub fn current_route(&self) -> Option<&Route> {
        self.frames.iter().rev().find_map(|f| f.route.as_ref())
    }

    pub fn source(&self, what: &str) -> Taint {
        Taint::from_source(Source {
            what: what.into(),
            module: self.module(),
            span: self.span(),
            weak_random: false,
        })
    }

    /// A value from a non-cryptographic generator, made at `span`: reported
    /// where it is used as a secret, harmless anywhere else.
    pub fn weak_random(&self, what: &str, span: Span, args: &[ArgVal]) -> Value {
        let t = Taint {
            sources: vec![Source {
                what: what.into(),
                module: self.module(),
                span,
                weak_random: true,
            }],
            safe: ctx::ALL,
        };
        Value::Unknown(t.union(&args_taint(args)))
    }

    /// Reports `rule` when user data reaches `value` unsanitized. String
    /// values are checked piece by piece, so data inside a quoted literal
    /// that cannot contain that quote is accepted.
    pub fn sink(&mut self, rule: &'static Rule, value: &Value, span: Span, what: &str) -> bool {
        let module = self.module();
        self.sink_at(rule, value, module, span, what)
    }

    /// Like `sink`, reported at a place in another module, such as where
    /// the object that reached the sink was made.
    pub fn sink_at(
        &mut self,
        rule: &'static Rule,
        value: &Value,
        module: usize,
        span: Span,
        what: &str,
    ) -> bool {
        let Some(t) = reaching(value, rule.context) else {
            return false;
        };
        let want_random = rule.context & ctx::SECRET != 0;
        let src = t
            .sources
            .iter()
            .find(|s| s.weak_random == want_random)
            .cloned();
        self.report(rule, module, span, what, src);
        true
    }

    /// Reports a finding that does not depend on data flow.
    pub fn flag(&mut self, rule: &'static Rule, span: Span, what: &str) {
        let module = self.module();
        self.report(rule, module, span, what, None);
    }

    fn report(
        &mut self,
        rule: &'static Rule,
        module: usize,
        span: Span,
        what: &str,
        src: Option<Source>,
    ) {
        // One finding per sink: the same sink reached from several handlers
        // or callers is reported once, with the first source found and the
        // others listed. A predictable random value is reported once where
        // it is made, however many secrets it fills.
        let key = match &src {
            Some(s) if s.weak_random => (
                rule.id.to_string(),
                s.module,
                s.span.line,
                s.span.column,
                usize::MAX,
                1,
            ),
            _ => (
                rule.id.to_string(),
                module,
                span.line,
                span.column,
                usize::MAX,
                0,
            ),
        };
        let loc = |m: usize, s: Span, note: String| Location {
            file: self.project.modules[m].path.clone(),
            line: s.line,
            column: s.column,
            note,
        };
        if let Some(&i) = self.seen.get(&key) {
            if let Some(s) = src.filter(|s| !s.weak_random) {
                let l = loc(s.module, s.span, s.what.to_string());
                let f = &mut self.findings[i];
                let same =
                    |o: &Location| o.file == l.file && o.line == l.line && o.column == l.column;
                if !f.source.as_ref().is_some_and(same)
                    && !f.other_sources.iter().any(same)
                    && f.other_sources.len() < 50
                {
                    f.other_sources.push(l);
                }
            }
            return;
        }
        self.seen.insert(key, self.findings.len());
        let mut trace = Vec::new();
        if let Some(s) = &src {
            trace.push(loc(s.module, s.span, format!("источник: {}", s.what)));
        }
        for (m, s) in &self.calls {
            trace.push(loc(*m, *s, "вызов".into()));
        }
        trace.push(loc(module, span, format!("сток: {what}")));
        let (at_module, at) = match &src {
            Some(s) if s.weak_random => (s.module, s.span),
            _ => (module, span),
        };
        let file = &self.project.modules[at_module];
        self.findings.push(Finding {
            rule: rule.id.to_string(),
            cwe: rule.cwe,
            severity: rule.severity,
            title: rule.title.to_string(),
            message: match &src {
                Some(s) if s.weak_random => {
                    format!(
                        "{}: значение {} используется как {what}",
                        rule.title, s.what
                    )
                }
                Some(s) => format!("{}: данные из {} попадают в {what}", rule.title, s.what),
                None => format!("{}: {what}", rule.title),
            },
            file: file.path.clone(),
            line: at.line,
            column: at.column,
            snippet: file.line_text(at.line),
            source: src.map(|s| loc(s.module, s.span, s.what.to_string())),
            trace,
            other_sources: Vec::new(),
        });
    }

    // ----- frames and variables -----

    fn frame(&mut self) -> &mut Frame {
        self.frames.last_mut().expect("frame")
    }

    fn frame_ref(&self) -> &Frame {
        self.frames.last().expect("frame")
    }

    fn live(&self) -> bool {
        self.frames.last().map(|f| f.env.is_some()).unwrap_or(false)
    }

    pub fn get_var(&mut self, name: &str) -> Option<Value> {
        let frame = self.frames.last()?;
        if let Some(v) = frame.env.as_ref().and_then(|e| e.get(name)) {
            return Some(v.clone());
        }
        if let Some(v) = frame.closure.as_ref().and_then(|e| e.get(name)) {
            return Some(v.clone());
        }
        let module = frame.module;
        let mut scope = frame.scope.clone();
        while let Some(s) = scope {
            if let Some(def) = s.defs.get(name) {
                return Some(self.def_value(module, def, &s));
            }
            scope = s.parent.clone();
        }
        if self.project.modules[module].lang == crate::Language::Php {
            // PHP functions see the script's variables only through
            // `global`; functions and classes are found by name.
            return None;
        }
        let globals = self.module_globals(module)?;
        globals.get(name).cloned()
    }

    fn def_value(&self, module: usize, def: &Def, scope: &Rc<Scope>) -> Value {
        let mname = &self.project.modules[module].name;
        match def {
            Def::Func(f) => Value::Func(Rc::new(FuncVal {
                qualname: format!("{mname}.{}", f.name).into(),
                def: f.clone(),
                module,
                bound: None,
                closure: None,
                scope: Some(scope.clone()),
            })),
            Def::Class(c) => Value::Class(Rc::new(ClassVal {
                qualname: format!("{mname}.{}", c.name).into(),
                def: c.clone(),
                module,
                scope: Some(scope.clone()),
            })),
        }
    }

    pub fn set_var(&mut self, name: &str, value: Value) {
        if let Some(env) = self.frame().env.as_mut() {
            env.insert(name.into(), value);
        }
    }

    fn module_globals(&mut self, module: usize) -> Option<Rc<Env>> {
        match &self.globals[module] {
            Globals::Done(env) => return Some(env.clone()),
            Globals::Running => {
                self.cutoffs += 1;
                return None;
            }
            Globals::Pending => {}
        }
        if self.loading >= MAX_IMPORT_DEPTH {
            self.cutoffs += 1;
            return None;
        }
        self.loading += 1;
        self.globals[module] = Globals::Running;
        let saved_calls = std::mem::take(&mut self.calls);
        let saved_steps = self.steps;
        let mut frame = Frame::new(module, None, Some(Env::new()));
        frame.scope = self.php_scope(module);
        self.frames.push(frame);
        let body = &self.project.modules[module].ir.body;
        self.exec_block(body);
        let frame = self.frames.pop().expect("frame");
        self.calls = saved_calls;
        self.steps = saved_steps;
        let env = Rc::new(join_env(frame.env, frame.exit_env).unwrap_or_default());
        self.globals[module] = Globals::Done(env.clone());
        self.loading -= 1;
        Some(env)
    }

    // ----- statements -----

    pub fn exec_block(&mut self, stmts: &[Stmt]) {
        for s in stmts {
            if !self.live() {
                return;
            }
            self.steps += 1;
            if self.steps > MAX_STEPS {
                self.cutoffs += 1;
                return;
            }
            self.exec(s);
        }
    }

    fn exec(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign {
                target,
                value,
                span,
            } => {
                self.frame().span = *span;
                let v = self.eval(value);
                self.assign(target, v, *span);
            }
            Stmt::Declare {
                name,
                ty,
                value,
                span,
            } => {
                self.frame().span = *span;
                let v = value
                    .as_ref()
                    .map(|e| self.eval(e))
                    .unwrap_or_else(Value::clean);
                let model = self.model();
                let v = model.coerce(self, ty, v);
                if secret_name(name) {
                    self.sink(&WEAK_RANDOM, &v, *span, name);
                }
                self.set_var(name, v);
            }
            Stmt::Expr(e, span) => {
                self.frame().span = *span;
                self.eval(e);
            }
            Stmt::Raw(e, span) => {
                self.frame().span = *span;
                let v = self.eval(e);
                let model = self.model();
                model.raw(self, &v, *span);
            }
            Stmt::If { test, then, other } => self.exec_if(test, then, other),
            Stmt::Loop {
                target,
                iter,
                test,
                body,
            } => self.exec_loop(target.as_ref(), iter.as_ref(), test.as_ref(), body),
            Stmt::Switch {
                subject,
                cases,
                fallthrough,
            } => self.exec_switch(subject, cases, *fallthrough),
            Stmt::Try {
                body,
                handlers,
                finally,
            } => {
                let entry = self.frame().env.clone();
                self.exec_block(body);
                let after_body = self.frame().env.take();
                let mut out = after_body.clone();
                let handler_entry = join_env(entry, after_body);
                for h in handlers {
                    self.frame().env = handler_entry.clone();
                    self.exec_block(h);
                    let end = self.frame().env.take();
                    out = join_env(out, end);
                }
                self.frame().env = out;
                if !finally.is_empty() {
                    if self.live() {
                        self.exec_block(finally);
                    } else {
                        // The finally block still runs on the way out.
                        self.frame().env = handler_entry;
                        self.exec_block(finally);
                        self.frame().env = None;
                    }
                }
            }
            Stmt::Return(e, span) => {
                self.frame().span = *span;
                let v = e.as_ref().map(|e| self.eval(e)).unwrap_or(Value::None);
                let func = self.frames.last().and_then(|f| f.func.clone());
                if let Some(func) = func.filter(|f| makes_secret(&f.name)) {
                    self.sink(&WEAK_RANDOM, &v, *span, &format!("{}()", func.name));
                }
                if let Some(route) = self.frames.last().and_then(|f| f.route.clone()) {
                    let model = self.model();
                    model.on_return(self, &route, &v, *span);
                }
                self.capture_self();
                let f = self.frame();
                f.ret = Some(match f.ret.take() {
                    None => v,
                    Some(prev) => join(&prev, &v),
                });
                if f.func.is_none() {
                    f.exit_env = join_env(f.exit_env.take(), f.env.take());
                }
                f.env = None;
            }
            Stmt::Break => {
                let f = self.frame();
                let env = f.env.take();
                if let Some(acc) = f.loops.last_mut() {
                    acc.breaks = join_env(acc.breaks.take(), env);
                }
            }
            Stmt::Continue => {
                let f = self.frame();
                let env = f.env.take();
                if let Some(acc) = f.loops.iter_mut().rev().find(|l| !l.is_switch) {
                    acc.continues = join_env(acc.continues.take(), env);
                }
            }
            Stmt::Import { alias, path } => {
                // Java wildcard imports are looked up on demand.
                if alias != "*" {
                    let v = self.import_value(path);
                    self.set_var(alias, v);
                }
            }
            Stmt::FuncDef(f) => {
                for d in &f.decorators {
                    self.eval(d);
                }
                let module = self.module();
                let closure = self.closure_snapshot();
                let scope = self.frames.last().and_then(|fr| fr.scope.clone());
                let v = Value::Func(Rc::new(FuncVal {
                    qualname: format!("{}.{}", self.project.modules[module].name, f.name).into(),
                    def: f.clone(),
                    module,
                    bound: None,
                    closure,
                    scope,
                }));
                self.set_var(&f.name, v);
            }
            Stmt::ClassDef(c) => {
                let module = self.module();
                let scope = self.frames.last().and_then(|fr| fr.scope.clone());
                let v = Value::Class(Rc::new(ClassVal {
                    qualname: format!("{}.{}", self.project.modules[module].name, c.name).into(),
                    def: c.clone(),
                    module,
                    scope,
                }));
                self.set_var(&c.name, v);
            }
        }
    }

    fn closure_snapshot(&self) -> Option<Rc<Env>> {
        let f = self.frames.last()?;
        f.func.as_ref()?;
        let mut env = f
            .closure
            .as_ref()
            .map(|c| (**c).clone())
            .unwrap_or_default();
        if let Some(e) = &f.env {
            env.extend(e.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        Some(Rc::new(env))
    }

    fn capture_self(&mut self) {
        let f = self.frame();
        if let (Some(name), Some(env)) = (&f.self_name, &f.env) {
            if let Some(v) = env.get(name).cloned() {
                f.final_self = Some(match f.final_self.take() {
                    None => v,
                    Some(prev) => join(&prev, &v),
                });
            }
        }
    }

    fn exec_if(&mut self, test: &Expr, then: &[Stmt], other: &[Stmt]) {
        let cond = self.eval(test);
        match cond.truthy() {
            Some(true) => {
                self.refine(test, true);
                self.exec_block(then);
            }
            Some(false) => {
                self.refine(test, false);
                self.exec_block(other);
            }
            None => {
                let saved = self.frame().env.clone();
                self.refine(test, true);
                self.exec_block(then);
                let after_then = self.frame().env.take();
                self.frame().env = saved;
                self.refine(test, false);
                self.exec_block(other);
                let after_other = self.frame().env.take();
                self.frame().env = join_env(after_then, after_other);
            }
        }
    }

    fn exec_loop(
        &mut self,
        target: Option<&Target>,
        iter: Option<&Expr>,
        test: Option<&Expr>,
        body: &[Stmt],
    ) {
        let element = iter.map(|e| {
            let it = self.eval(e);
            it.element()
        });
        let entry = self.frame().env.clone();
        let mut state = entry.clone();
        let mut exits = None;
        let mut settled = true;
        self.frame().loops.push(LoopAcc {
            breaks: None,
            continues: None,
            is_switch: false,
        });
        for pass in 0..2 {
            self.frame().env = state.clone();
            if let Some(t) = test {
                let c = self.eval(t);
                match c.truthy() {
                    Some(false) => {
                        exits = join_env(exits, self.frame().env.take());
                        break;
                    }
                    Some(true) => {}
                    None => exits = join_env(exits, self.frame().env.clone()),
                }
                self.refine(t, true);
            }
            if let (Some(t), Some(el)) = (target, &element) {
                self.assign(t, el.clone(), Span::default());
            }
            self.exec_block(body);
            let end = self.frame().env.take();
            let cont = self
                .frame()
                .loops
                .last_mut()
                .and_then(|l| l.continues.take());
            let end = join_env(end, cont);
            if end.is_none() {
                break;
            }
            let next = join_env(state.clone(), end);
            if pass == 1 || env_eq(&next, &state) {
                settled = env_eq(&next, &state);
                state = next;
                break;
            }
            state = next;
        }
        let acc = self.frame().loops.pop().expect("loop");
        let mut out = join_env(exits, acc.breaks);
        if test.is_none() {
            // A for loop may run zero times or to completion.
            out = join_env(out, join_env(entry, state));
        } else if let Some(t) = test {
            // `while cond:` exits when the condition fails.
            if self.eval_in(state.clone(), t).truthy() != Some(true) {
                out = join_env(out, state);
            } else if !settled && !matches!(t, Expr::Lit(_)) {
                // `for ($i = 0; $i < 50; $i++)`: two passes saw only the
                // first values of `$i`, the loop ends with later ones.
                out = join_env(out, state.map(|s| widen_changed(s, entry.as_ref())));
            }
        }
        self.frame().env = out;
    }

    fn eval_in(&mut self, env: Option<Env>, e: &Expr) -> Value {
        if env.is_none() {
            return Value::Bool(true);
        }
        let saved = std::mem::replace(&mut self.frame().env, env);
        let v = self.eval(e);
        self.frame().env = saved;
        v
    }

    fn exec_switch(&mut self, subject: &Expr, cases: &[Case], fallthrough: bool) {
        let s = self.eval(subject);
        let mut remaining = self.frame().env.take();
        let mut out: Option<Env> = None;
        let mut carried: Option<Env> = None;
        self.frame().loops.push(LoopAcc {
            breaks: None,
            continues: None,
            is_switch: true,
        });
        for case in cases {
            let matched = if case.patterns.is_empty() {
                Some(true)
            } else {
                let mut any_maybe = false;
                let mut hit = false;
                for p in &case.patterns {
                    let pv = self.eval_in(remaining.clone().or_else(|| carried.clone()), p);
                    match values_eq(&s, &pv) {
                        Some(true) => hit = true,
                        Some(false) => {}
                        None => any_maybe = true,
                    }
                }
                if hit {
                    Some(true)
                } else if any_maybe {
                    None
                } else {
                    Some(false)
                }
            };
            let entry = match matched {
                Some(false) => carried.take(),
                Some(true) => join_env(remaining.take(), carried.take()),
                None => join_env(remaining.clone(), carried.take()),
            };
            if entry.is_none() {
                continue;
            }
            self.frame().env = entry;
            self.exec_block(&case.body);
            let end = self.frame().env.take();
            if fallthrough {
                carried = end;
            } else {
                out = join_env(out, end);
            }
            if remaining.is_none() && carried.is_none() {
                break;
            }
        }
        let acc = self.frame().loops.pop().expect("switch");
        out = join_env(out, carried);
        out = join_env(out, acc.breaks);
        out = join_env(out, remaining);
        if let Some(cont) = acc.continues {
            // `continue` inside a switch belongs to the enclosing loop.
            if let Some(l) = self.frame().loops.iter_mut().rev().find(|l| !l.is_switch) {
                l.continues = join_env(l.continues.take(), Some(cont));
            }
        }
        self.frame().env = out;
    }

    pub fn assign(&mut self, target: &Target, value: Value, span: Span) {
        match target {
            Target::Name(n) => {
                if secret_name(n) {
                    self.sink(&WEAK_RANDOM, &value, span, n);
                }
                self.forget_paths(n);
                self.set_var(n, value)
            }
            Target::Attr(obj, field) => {
                if secret_name(field) {
                    self.sink(&WEAK_RANDOM, &value, span, field);
                }
                let base = self.eval(obj);
                if let Value::Obj(o) = &base {
                    let mut o = (**o).clone();
                    o.set_field(field, value);
                    self.assign_expr(obj, Value::Obj(Rc::new(o)), span);
                }
            }
            Target::Index(base_e, key_e) => {
                if let Expr::Name(n) = &**base_e {
                    self.forget_paths(n);
                }
                let base = self.eval(base_e);
                let key = self.eval(key_e);
                let key_name = key.as_str().unwrap_or_default();
                let store = match &**base_e {
                    Expr::Name(n) | Expr::Attr(_, n) => n.as_str(),
                    _ => "",
                };
                if secret_name(&key_name) || name_words(store).any(|w| w == "session") {
                    let what = format!("{store}[{key_name:?}]");
                    self.sink(&WEAK_RANDOM, &value, span, &what);
                }
                let model = self.model();
                if let Some(nb) = model.store_index(self, &base, &key, &value, span) {
                    self.assign_expr(base_e, nb, span);
                    return;
                }
                if let Some(nb) = store_index(&base, &key, value) {
                    self.assign_expr(base_e, nb, span);
                }
            }
            Target::Tuple(ts) => match &value {
                Value::List(items) if items.len() == ts.len() => {
                    for (t, v) in ts.iter().zip(items.iter()) {
                        self.assign(t, v.clone(), span);
                    }
                }
                other => {
                    let el = other.element();
                    for t in ts {
                        self.assign(t, el.clone(), span);
                    }
                }
            },
            Target::Other => {}
        }
    }

    /// Drops the checks on elements of `name` once it is assigned.
    fn forget_paths(&mut self, name: &str) {
        let frame = self.frame();
        if !frame.paths {
            return;
        }
        if let Some(env) = frame.env.as_mut() {
            let prefix = format!("{name}[");
            env.retain(|k, _| !k.starts_with(prefix.as_str()));
        }
    }

    /// Writes a changed receiver back to the place it was read from.
    pub fn assign_expr(&mut self, e: &Expr, value: Value, span: Span) {
        let target = match e {
            Expr::Name(n) => Target::Name(n.clone()),
            Expr::Attr(o, f) => Target::Attr(o.clone(), f.clone()),
            Expr::Index(b, k) => Target::Index(b.clone(), k.clone()),
            _ => return,
        };
        self.assign(&target, value, span);
    }

    // ----- conditions -----

    /// Narrows variables after a condition is known to be `truth`.
    fn refine(&mut self, test: &Expr, truth: bool) {
        let mut facts: Vec<(Rc<str>, Fact)> = Vec::new();
        self.collect_facts(test, truth, &mut facts);
        if facts.is_empty() {
            return;
        }
        let mut by_var: Vec<(Rc<str>, Vec<Fact>)> = Vec::new();
        for (v, f) in facts {
            match by_var.iter_mut().find(|(n, _)| *n == v) {
                Some(slot) => slot.1.push(f),
                None => by_var.push((v, vec![f])),
            }
        }
        let model = self.model();
        let paths = std::mem::take(&mut self.path_vals);
        for (var, facts) in by_var {
            let cur = match self.get_var(&var) {
                Some(v) => v,
                None => match paths.iter().find(|(k, _)| *k == var) {
                    Some((_, v)) => {
                        self.frame().paths = true;
                        v.clone()
                    }
                    None => continue,
                },
            };
            let mut bits = model.facts_safety(&facts, &cur);
            let mut narrowed = None;
            for f in &facts {
                match f {
                    Fact::Safe(b) => bits |= b,
                    Fact::OneOf(vals) if !vals.is_empty() => {
                        narrowed = join_all(vals.iter().cloned());
                    }
                    _ => {}
                }
            }
            if let Some(n) = narrowed {
                self.set_var(&var, n);
            } else if bits != 0 {
                self.set_var(&var, cur.sanitized(bits));
            }
        }
    }

    fn collect_facts(&mut self, e: &Expr, truth: bool, out: &mut Vec<(Rc<str>, Fact)>) {
        match e {
            Expr::Un(UnOp::Not, inner) => self.collect_facts(inner, !truth, out),
            Expr::Bin(BinOp::And, a, b) if truth => {
                self.collect_facts(a, true, out);
                self.collect_facts(b, true, out);
            }
            Expr::Bin(BinOp::Or, a, b) if !truth => {
                self.collect_facts(a, false, out);
                self.collect_facts(b, false, out);
            }
            Expr::Bin(op @ (BinOp::In | BinOp::NotIn), needle, hay) => {
                let present = (*op == BinOp::In) == truth;
                let needle_v = self.eval(needle);
                if let (Some(n), false) = (needle_v.as_str(), present) {
                    // `"x" not in var` / `"x" not in var[1:-1]`
                    match &**hay {
                        Expr::Slice {
                            value,
                            lower,
                            upper,
                        } if lower.is_some() && upper.is_some() => {
                            if let Some(var) = root_var(value) {
                                out.push((var, Fact::NotContainsInner(n)));
                            }
                        }
                        other => {
                            if let Some(var) = root_var(other) {
                                out.push((var, Fact::NotContains(n)));
                            }
                        }
                    }
                }
                if present {
                    // `var in ("a", "b")`: var is one of the constants.
                    let hay_v = self.eval(hay);
                    if let Value::List(items) = &hay_v {
                        if items.iter().all(is_const) {
                            self.fact_on(needle, Fact::OneOf(items.as_ref().clone()), out);
                        }
                    }
                }
            }
            // `preg_match(...) == 1`, `in_array(...) === false`
            Expr::Bin(op @ (BinOp::Eq | BinOp::NotEq | BinOp::Is | BinOp::IsNot), l, r)
                if matches!(&**l, Expr::Call { .. }) && const_truth(r).is_some() =>
            {
                let t = const_truth(r).unwrap_or(true);
                let eq = matches!(op, BinOp::Eq | BinOp::Is);
                self.collect_facts(l, eq == (t == truth), out);
            }
            Expr::Bin(op @ (BinOp::Eq | BinOp::NotEq | BinOp::Is | BinOp::IsNot), l, r) => {
                if matches!(op, BinOp::Eq | BinOp::Is) == truth {
                    let rv = self.eval(r);
                    if is_const(&rv) {
                        self.fact_on(l, Fact::OneOf(vec![rv]), out);
                    } else {
                        let lv = self.eval(l);
                        if is_const(&lv) {
                            self.fact_on(r, Fact::OneOf(vec![lv]), out);
                        }
                    }
                }
            }
            Expr::Call { func, args, .. } if matches!(&**func, Expr::Name(_)) => {
                let Expr::Name(name) = &**func else {
                    return;
                };
                // Only library functions: project code is not a known check.
                if self.get_var(name).is_some() || self.lookup_global(name).is_some() {
                    return;
                }
                let argv: Vec<Value> = args.iter().map(|a| self.eval(&a.value)).collect();
                let model = self.model();
                for (on, f) in model.refine_call(name, &argv, truth) {
                    if let FactOn::Arg(i) = on {
                        if let Some(a) = args.get(i) {
                            self.fact_on(&a.value, f, out);
                        }
                    }
                }
            }
            Expr::Call { func, args, .. } => {
                if let Expr::Attr(recv, name) = &**func {
                    let argv: Vec<Value> = args.iter().map(|a| self.eval(&a.value)).collect();
                    let rv = self.eval(recv);
                    let model = self.model();
                    for (on, f) in model.refine_method(&rv, name, &argv, truth) {
                        match on {
                            FactOn::Recv => self.fact_on(recv, f, out),
                            FactOn::Arg(i) => {
                                if let Some(a) = args.get(i) {
                                    self.fact_on(&a.value, f, out);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Attaches a fact to the variable an expression reads, looking through
    /// conversions like `str(p)` and attribute checks like `url.netloc`.
    fn fact_on(&mut self, e: &Expr, fact: Fact, out: &mut Vec<(Rc<str>, Fact)>) {
        match e {
            Expr::Name(n) => out.push((n.as_str().into(), fact)),
            Expr::Index(..) => {
                // `is_numeric($octet[0])`, `preg_match('/^\d+$/', $_GET['id'])`
                if let Some(key) = path_key(e) {
                    let key: Rc<str> = key.into();
                    if !self.path_vals.iter().any(|(k, _)| *k == key) {
                        let v = self.eval(e);
                        self.path_vals.push((key.clone(), v));
                    }
                    out.push((key, fact));
                }
            }
            Expr::Attr(base, field) => {
                if let Expr::Name(n) = &**base {
                    if let Some(Value::Obj(o)) = self.get_var(n) {
                        let model = self.model();
                        for (var, bits) in model.refine_attr(&o, field, &fact) {
                            out.push((var, Fact::Safe(bits)));
                        }
                    }
                }
            }
            Expr::Call { func, args, .. } if args.len() == 1 => {
                // str(x), os.path.realpath(x), x.lower() ...
                if let Some(inner) = args.first() {
                    let through = match &**func {
                        Expr::Name(n) => matches!(n.as_str(), "str" | "String" | "strval"),
                        Expr::Attr(_, m) => {
                            matches!(m.as_str(), "realpath" | "abspath" | "normpath" | "resolve")
                        }
                        _ => false,
                    };
                    if through {
                        let normalizing = matches!(&**func, Expr::Attr(_, m) if m != "str");
                        if let Some(var) = root_var(&inner.value) {
                            if normalizing
                                && matches!(fact, Fact::StartsWithValue | Fact::StartsWith(_))
                            {
                                out.push((var, Fact::Safe(ctx::PATH)));
                            } else {
                                out.push((var, fact));
                            }
                        }
                    }
                }
            }
            Expr::Call { func, args, .. } if args.is_empty() => {
                // `x.resolve().startswith(base)`, `x.toString().equals(s)`:
                // facts carry over through conversions that keep the text,
                // and a prefix check on a normalized path confines it.
                // Chains such as `f.getCanonicalFile().toPath()` count too.
                let mut normalized = false;
                let mut cur = e;
                while let Expr::Call { func, args, .. } = cur {
                    let Expr::Attr(recv, method) = &**func else {
                        return;
                    };
                    if !args.is_empty() {
                        return;
                    }
                    let identity = matches!(
                        method.as_str(),
                        "toString" | "intern" | "__str__" | "toPath" | "toFile" | "getPath"
                    );
                    let normalizing = matches!(
                        method.as_str(),
                        "resolve"
                            | "absolute"
                            | "getCanonicalPath"
                            | "getCanonicalFile"
                            | "toRealPath"
                            | "normalize"
                    );
                    if !identity && !normalizing {
                        return;
                    }
                    normalized |= normalizing;
                    cur = recv;
                }
                if let Some(var) = root_var(cur) {
                    if !normalized {
                        out.push((var, fact));
                    } else if matches!(fact, Fact::StartsWithValue | Fact::StartsWith(_)) {
                        out.push((var, Fact::Safe(ctx::PATH)));
                    }
                }
            }
            _ => {}
        }
    }

    // ----- expressions -----

    pub fn eval(&mut self, e: &Expr) -> Value {
        if self.depth >= MAX_EVAL_DEPTH {
            self.cutoffs += 1;
            return Value::clean();
        }
        self.depth += 1;
        let v = self.eval_inner(e);
        self.depth -= 1;
        v
    }

    fn eval_inner(&mut self, e: &Expr) -> Value {
        self.steps += 1;
        match e {
            Expr::Lit(c) => const_value(c),
            Expr::Name(n) => match self.get_var(n).or_else(|| self.lookup_global(n)) {
                Some(v) => v,
                None => {
                    let model = self.model();
                    model.builtin(self, n)
                }
            },
            Expr::Attr(base, name) => {
                let b = self.eval(base);
                self.get_attr(&b, name)
            }
            Expr::Index(base, key) => {
                if self.frame_ref().paths {
                    if let Some(p) = path_key(e) {
                        if let Some(v) = self
                            .frame_ref()
                            .env
                            .as_ref()
                            .and_then(|env| env.get(p.as_str()))
                        {
                            return v.clone();
                        }
                    }
                }
                let b = self.eval(base);
                let k = self.eval(key);
                self.index(&b, &k)
            }
            Expr::Slice {
                value,
                lower,
                upper,
            } => {
                let v = self.eval(value);
                let lo = lower.as_ref().map(|l| self.slice_bound(value, l));
                let hi = upper.as_ref().map(|u| self.slice_bound(value, u));
                let (lo_v, lo_known) = match lo {
                    None => (None, true),
                    Some(i) => (i, i.is_some()),
                };
                let (hi_v, hi_known) = match hi {
                    None => (None, true),
                    Some(i) => (i, i.is_some()),
                };
                slice_value(&v, lo_v, hi_v, lo_known, hi_known)
            }
            Expr::Call { func, args, span } => self.eval_call(func, args, *span),
            Expr::New { class, args, span } => {
                let argv = self.eval_args(args, *span);
                match self.get_var(class).or_else(|| self.lookup_global(class)) {
                    Some(c @ Value::Class(_)) => self.call_value(&c, &argv, *span),
                    Some(Value::Ref(p, t)) => {
                        let model = self.model();
                        model.call_ref(self, &p, &t, &argv, *span)
                    }
                    _ => {
                        let model = self.model();
                        model.call_ref(self, class, &Taint::clean(), &argv, *span)
                    }
                }
            }
            // The right operand runs only when the left one decided nothing:
            // `ok(f) && use(f)`, `!ok(f) || use(f)`.
            Expr::Bin(op @ (BinOp::And | BinOp::Or), l, r) => {
                let lv = self.eval(l);
                let and = *op == BinOp::And;
                match lv.truthy() {
                    Some(t) if t != and => lv,
                    Some(_) => self.eval(r),
                    None => {
                        let saved = self.frame().env.clone();
                        self.refine(l, and);
                        let rv = self.eval(r);
                        self.frame().env = saved;
                        join(&lv, &rv)
                    }
                }
            }
            Expr::Bin(op, l, r) => {
                let lv = self.eval(l);
                let rv = self.eval(r);
                self.binop(*op, &lv, &rv)
            }
            Expr::Un(op, inner) => {
                let v = self.eval(inner);
                match (op, &v) {
                    (UnOp::Not, v) => match v.truthy() {
                        Some(b) => Value::Bool(!b),
                        None => Value::clean(),
                    },
                    (UnOp::Neg, Value::Int(i)) => Value::Int(i.wrapping_neg()),
                    (UnOp::Neg, Value::Float(f)) => Value::Float(-f),
                    (UnOp::Pos, v) => v.clone(),
                    (UnOp::BitNot, Value::Int(i)) => Value::Int(!i),
                    (_, v) => Value::Unknown(v.taint().with_safe(ctx::ALL)),
                }
            }
            Expr::Concat(parts) => {
                let mut vals: Vec<Value> = Vec::with_capacity(parts.len());
                for p in parts {
                    let v = self.eval(p);
                    let model = self.model();
                    vals.push(model.stringify(self, v));
                }
                concat(&vals)
            }
            Expr::Cond { test, then, other } => {
                let t = self.eval(test);
                match t.truthy() {
                    Some(true) => self.eval(then),
                    Some(false) => self.eval(other),
                    None => {
                        let a = self.eval(then);
                        let b = self.eval(other);
                        join(&a, &b)
                    }
                }
            }
            Expr::List(items) => {
                let vals = items.iter().map(|i| self.eval(i)).collect();
                Value::list(vals)
            }
            Expr::Dict(pairs) => {
                let mut out: Vec<(Value, Value)> = Vec::new();
                for (k, v) in pairs {
                    let kv = self.eval(k);
                    let vv = self.eval(v);
                    match out.iter_mut().find(|(ek, _)| *ek == kv) {
                        Some(slot) => slot.1 = vv,
                        None => out.push((kv, vv)),
                    }
                }
                Value::Dict(Rc::new(out))
            }
            Expr::Cast(ty, inner) => {
                let v = self.eval(inner);
                let model = self.model();
                model.coerce(self, ty, v)
            }
            Expr::Lambda(f) => {
                let module = self.module();
                let closure = self
                    .closure_snapshot()
                    .or_else(|| Some(Rc::new(self.frame().env.clone().unwrap_or_default())));
                Value::Func(Rc::new(FuncVal {
                    qualname: "<lambda>".into(),
                    def: f.clone(),
                    module,
                    bound: None,
                    closure,
                    scope: self.frames.last().and_then(|fr| fr.scope.clone()),
                }))
            }
            Expr::Other(parts) => {
                let mut t = Taint::clean();
                for p in parts {
                    t = t.union(&self.eval(p).taint());
                }
                Value::Unknown(t)
            }
        }
    }

    /// A slice bound; `len(x) - k` on the sliced value counts from the end.
    fn slice_bound(&mut self, sliced: &Expr, bound: &Expr) -> Option<i64> {
        if let Expr::Bin(BinOp::Sub, l, r) = bound {
            if let Expr::Call { func, args, .. } = &**l {
                if matches!(&**func, Expr::Name(n) if n == "len" || n == "strlen")
                    && args.len() == 1
                    && format!("{:?}", args[0].value) == format!("{sliced:?}")
                {
                    if let Value::Int(k) = self.eval(r) {
                        return Some(-k);
                    }
                }
            }
        }
        self.eval(bound).as_int()
    }

    fn eval_args(&mut self, args: &[Arg], span: Span) -> Vec<ArgVal> {
        let mut out = Vec::with_capacity(args.len());
        for a in args {
            let value = self.eval(&a.value);
            if let Some(name) = a.name.as_deref().filter(|n| secret_name(n)) {
                self.sink(&WEAK_RANDOM, &value, span, name);
            }
            out.push(ArgVal {
                name: a.name.as_deref().map(Rc::from),
                value,
                spread: a.spread,
                var: match &a.value {
                    Expr::Name(n) => Some(n.as_str().into()),
                    _ => None,
                },
            });
        }
        out
    }

    fn eval_call(&mut self, func: &Expr, args: &[Arg], span: Span) -> Value {
        let argv = self.eval_args(args, span);
        if let Expr::Attr(recv_e, name) = func {
            let recv = self.eval(recv_e);
            let (v, new_recv) = self.call_method(&recv, name, &argv, span);
            if let Some(nr) = new_recv {
                self.assign_expr(recv_e, nr, span);
            }
            return v;
        }
        let f = self.eval(func);
        self.call_value(&f, &argv, span)
    }

    pub fn call_method(
        &mut self,
        recv: &Value,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>) {
        match recv {
            Value::OneOf(alts) => {
                let mut result: Option<Value> = None;
                let mut recvs: Vec<Value> = Vec::new();
                let mut changed = false;
                for a in alts.iter() {
                    let (v, nr) = self.call_method(a, name, args, span);
                    changed |= nr.is_some();
                    recvs.push(nr.unwrap_or_else(|| a.clone()));
                    result = Some(match result {
                        None => v,
                        Some(p) => join(&p, &v),
                    });
                }
                let new_recv =
                    changed.then(|| join_all(recvs.into_iter()).unwrap_or_else(Value::clean));
                (result.unwrap_or_else(Value::clean), new_recv)
            }
            Value::Obj(o) if o.def.is_some() && name.contains("::") => {
                // `parent::m()` in PHP: the method of that class, run on
                // this object.
                let (class, method) = name.split_once("::").unwrap_or(("", name));
                let found = match self.lookup_dotted(class) {
                    Some(Value::Class(c)) => self.find_overload(&c, method, Some(args.len())),
                    _ => None,
                };
                match found {
                    Some((m, owner)) => {
                        let fv = FuncVal {
                            qualname: format!("{}.{}", owner.qualname, m.name).into(),
                            def: m.clone(),
                            module: owner.module,
                            bound: if is_static(&m) {
                                None
                            } else {
                                Some(recv.clone())
                            },
                            closure: None,
                            scope: owner.scope.clone(),
                        };
                        self.call_user(&fv, args, span)
                    }
                    None => {
                        let model = self.model();
                        model.call_method(self, recv, method, args, span)
                    }
                }
            }
            Value::Obj(o) if o.def.is_some() => {
                let cv = o.def.clone().unwrap();
                if let Some(attr) = o.field(name).cloned() {
                    return (self.call_value(&attr, args, span), None);
                }
                if let Some((m, owner)) = self.find_overload(&cv, name, Some(args.len())) {
                    let fv = FuncVal {
                        qualname: format!("{}.{}", owner.qualname, m.name).into(),
                        def: m.clone(),
                        module: owner.module,
                        bound: if is_static(&m) {
                            None
                        } else {
                            Some(recv.clone())
                        },
                        closure: None,
                        scope: owner.scope.clone(),
                    };
                    return self.call_user(&fv, args, span);
                }
                if let Some(v) = self.call_implementations(o, &cv, name, args, span) {
                    return (v, None);
                }
                let model = self.model();
                model.call_method(self, recv, name, args, span)
            }
            Value::Ref(path, t) => {
                let callee = self.ref_attr(path, t, name);
                (self.call_value(&callee, args, span), None)
            }
            Value::Class(cv) => {
                if let Some((m, owner)) = self.find_overload(cv, name, Some(args.len())) {
                    let fv = FuncVal {
                        qualname: format!("{}.{}", owner.qualname, m.name).into(),
                        def: m.clone(),
                        module: owner.module,
                        bound: None,
                        closure: None,
                        scope: owner.scope.clone(),
                    };
                    return (self.call_user(&fv, args, span).0, None);
                }
                (Value::Unknown(args_taint(args)), None)
            }
            _ => {
                let model = self.model();
                model.call_method(self, recv, name, args, span)
            }
        }
    }

    /// Runs a project function; a hand-written escaper's result is also
    /// marked safe by its name.
    fn call_user(&mut self, fv: &FuncVal, args: &[ArgVal], span: Span) -> (Value, Option<Value>) {
        let (v, final_self) = self.call_function(fv, args, span);
        let bits = self.model().sanitizer_of(&fv.qualname);
        if bits != 0 {
            (v.sanitized(bits), final_self)
        } else {
            (v, final_self)
        }
    }

    /// A method an interface or abstract class only declares: the project
    /// classes implementing it run instead, when there are few of them
    /// (an injected `UserService` and its `UserServiceImpl`).
    fn call_implementations(
        &mut self,
        o: &Obj,
        cv: &Rc<ClassVal>,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> Option<Value> {
        const MAX_IMPLEMENTATIONS: usize = 4;
        let index = self.subclass_index();
        let mut found: Vec<(Rc<ClassVal>, Rc<Function>, Rc<ClassVal>)> = Vec::new();
        let mut todo = vec![cv.qualname.clone()];
        let mut visited: HashSet<Rc<str>> = HashSet::new();
        while let Some(q) = todo.pop() {
            if !visited.insert(q.clone()) || visited.len() > 64 {
                continue;
            }
            for sub in index.get(&q).into_iter().flatten() {
                todo.push(sub.qualname.clone());
                if !sub.def.methods.iter().any(|m| m.name == name) {
                    continue;
                }
                if let Some((m, owner)) = self.find_overload(sub, name, Some(args.len())) {
                    if !found.iter().any(|(_, f, _)| Rc::ptr_eq(f, &m)) {
                        found.push((sub.clone(), m, owner));
                    }
                }
            }
        }
        if found.is_empty() || found.len() > MAX_IMPLEMENTATIONS {
            return None;
        }
        let mut out: Option<Value> = None;
        for (sub, m, owner) in found {
            let recv = Value::Obj(Rc::new(Obj {
                class: sub.qualname.clone(),
                def: Some(sub),
                fields: o.fields.clone(),
                taint: o.taint.clone(),
            }));
            let fv = FuncVal {
                qualname: format!("{}.{}", owner.qualname, m.name).into(),
                bound: if is_static(&m) { None } else { Some(recv) },
                def: m,
                module: owner.module,
                closure: None,
                scope: owner.scope.clone(),
            };
            let (v, _) = self.call_user(&fv, args, span);
            out = Some(match out {
                None => v,
                Some(p) => join(&p, &v),
            });
        }
        out
    }

    /// The project classes deriving directly from each class, by qualified
    /// name. Test code is left out: it does not run in production.
    fn subclass_index(&mut self) -> SubclassIndex {
        if let Some(index) = &self.subclasses {
            return index.clone();
        }
        let mut index: HashMap<Rc<str>, Vec<Rc<ClassVal>>> = HashMap::new();
        for m in 0..self.project.modules.len() {
            let info = &self.project.modules[m];
            if info.is_test || info.lang != crate::Language::Java {
                continue;
            }
            let names: Vec<String> = info
                .ir
                .body
                .iter()
                .filter_map(|s| match s {
                    Stmt::ClassDef(c) => Some(c.name.clone()),
                    _ => None,
                })
                .collect();
            let Some(globals) = self.module_globals(m) else {
                continue;
            };
            for n in names {
                let Some(Value::Class(cv)) = globals.get(n.as_str()).cloned() else {
                    continue;
                };
                for base in &cv.def.bases {
                    let saved = self.frames.len();
                    let mut frame = Frame::new(cv.module, None, Some(Env::new()));
                    frame.scope = cv.scope.clone();
                    self.frames.push(frame);
                    let bv = self.lookup_dotted(base);
                    self.frames.truncate(saved);
                    if let Some(Value::Class(b)) = bv {
                        index
                            .entry(b.qualname.clone())
                            .or_default()
                            .push(cv.clone());
                    }
                }
            }
        }
        let index = Rc::new(index);
        self.subclasses = Some(index.clone());
        index
    }

    /// A callback passed as a value: a closure, or a function named by a
    /// string (PHP `array_map('absint', ...)`).
    pub fn callable(&mut self, v: &Value) -> Option<Value> {
        match v {
            Value::Func(_) => Some(v.clone()),
            Value::Str(_) => {
                let name = v.as_str()?;
                let name = name.trim_start_matches('\\');
                if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return None;
                }
                Some(self.eval(&Expr::Name(name.to_string())))
            }
            _ => None,
        }
    }

    pub fn call_value(&mut self, f: &Value, args: &[ArgVal], span: Span) -> Value {
        // A name can resolve to alternatives that include itself again.
        if self.depth >= MAX_EVAL_DEPTH {
            self.cutoffs += 1;
            return Value::Unknown(f.taint().union(&args_taint(args)));
        }
        self.depth += 1;
        let v = self.call_value_inner(f, args, span);
        self.depth -= 1;
        v
    }

    fn call_value_inner(&mut self, f: &Value, args: &[ArgVal], span: Span) -> Value {
        match f {
            Value::Func(fv) => self.call_user(fv, args, span).0,
            Value::Class(cv) => self.construct(cv, args, span),
            Value::Ref(path, t) => {
                if let Some(v) = self.resolve_project_ref(path) {
                    if !matches!(v, Value::Ref(..)) {
                        return self.call_value(&v, args, span);
                    }
                }
                let model = self.model();
                model.call_ref(self, path, t, args, span)
            }
            Value::OneOf(alts) => {
                let mut out: Option<Value> = None;
                for a in alts.iter() {
                    let v = self.call_value(a, args, span);
                    out = Some(match out {
                        None => v,
                        Some(p) => join(&p, &v),
                    });
                }
                out.unwrap_or_else(Value::clean)
            }
            other => Value::Unknown(other.taint().union(&args_taint(args))),
        }
    }

    fn construct(&mut self, cv: &Rc<ClassVal>, args: &[ArgVal], span: Span) -> Value {
        let obj = Value::Obj(Rc::new(Obj {
            class: cv.qualname.clone(),
            def: Some(cv.clone()),
            fields: Vec::new(),
            taint: Taint::clean(),
        }));
        match self
            .find_method(cv, "__init__")
            .or_else(|| self.find_method(cv, &cv.def.name))
        {
            Some((init, owner)) => {
                let fv = FuncVal {
                    qualname: format!("{}.__init__", owner.qualname).into(),
                    def: init,
                    module: owner.module,
                    bound: Some(obj.clone()),
                    closure: None,
                    scope: owner.scope.clone(),
                };
                let (_, final_self) = self.call_function(&fv, args, span);
                final_self.unwrap_or(obj)
            }
            None => obj,
        }
    }

    /// Whether a project object's class or its project bases define `name`.
    pub fn has_method(&mut self, v: &Value, name: &str) -> bool {
        match v {
            Value::Obj(o) => match o.def.clone() {
                Some(cv) => self.find_method(&cv, name).is_some(),
                None => false,
            },
            _ => false,
        }
    }

    /// Finds a method in a class or its bases defined in the project.
    fn find_method(
        &mut self,
        cv: &Rc<ClassVal>,
        name: &str,
    ) -> Option<(Rc<Function>, Rc<ClassVal>)> {
        self.find_overload(cv, name, None)
    }

    /// Finds a method; with `nargs`, the overload taking that many
    /// arguments when the class has several (Java, C++).
    fn find_overload(
        &mut self,
        cv: &Rc<ClassVal>,
        name: &str,
        nargs: Option<usize>,
    ) -> Option<(Rc<Function>, Rc<ClassVal>)> {
        let mut todo = vec![cv.clone()];
        let mut visited = 0;
        while let Some(c) = todo.pop() {
            visited += 1;
            if visited > 16 {
                break;
            }
            let mut found = c.def.methods.iter().filter(|m| m.name == name);
            if let Some(first) = found.next() {
                let arity = |m: &Function| {
                    m.params.len() - usize::from(!is_static(m) && !m.params.is_empty())
                };
                let pick = match nargs {
                    Some(n) => std::iter::once(first)
                        .chain(found)
                        .rfind(|m| arity(m) == n)
                        .unwrap_or(first),
                    None => first,
                };
                return Some((pick.clone(), c));
            }
            for base in &c.def.bases {
                let saved = self.frames.len();
                self.frames
                    .push(Frame::new(c.module, None, Some(Env::new())));
                self.frames.last_mut().unwrap().scope = c.scope.clone();
                let bv = self.lookup_dotted(base);
                self.frames.truncate(saved);
                if let Some(Value::Class(b)) = bv {
                    todo.push(b);
                }
            }
        }
        None
    }

    /// A field declared in the body of the class or of a project base
    /// class, evaluated where that class is defined. A field without a
    /// value takes what its declared type implies (an injected service).
    fn field_value(&mut self, cv: &Rc<ClassVal>, name: &str) -> Option<Value> {
        let mut todo = vec![cv.clone()];
        let mut visited = 0;
        while let Some(c) = todo.pop() {
            visited += 1;
            if visited > 16 {
                break;
            }
            let saved = self.frames.len();
            let mut frame = Frame::new(c.module, None, Some(Env::new()));
            frame.scope = c.scope.clone();
            self.frames.push(frame);
            if let Some((value, ty)) = class_field(&c.def, name) {
                let mut v = match value {
                    Some(e) => self.eval(e),
                    None => self.constructor_value(&c.def, name),
                };
                if let Some(ty) = ty {
                    let model = self.model();
                    v = model.coerce(self, ty, v);
                }
                self.frames.truncate(saved);
                return Some(v);
            }
            for base in &c.def.bases {
                if let Some(Value::Class(b)) = self.lookup_dotted(base) {
                    todo.push(b);
                }
            }
            self.frames.truncate(saved);
        }
        None
    }

    /// What the constructors of a class assign to a field declared without
    /// a value (`this.random = new Random()`), their parameters unknown.
    fn constructor_value(&mut self, class: &Class, name: &str) -> Value {
        let mut vals = Vec::new();
        for m in class.methods.iter().filter(|m| m.name == "__init__") {
            let Some(this) = m.params.first() else {
                continue;
            };
            for s in &m.body {
                let Stmt::Assign {
                    target: Target::Attr(base, field),
                    value,
                    ..
                } = s
                else {
                    continue;
                };
                if field == name && matches!(&**base, Expr::Name(n) if *n == this.name) {
                    for p in &m.params {
                        self.set_var(&p.name, Value::clean());
                    }
                    vals.push(self.eval(value));
                }
            }
        }
        join_all(vals.into_iter()).unwrap_or_else(Value::clean)
    }

    /// Names of the library classes a project class derives from.
    pub fn external_bases(&mut self, cv: &Rc<ClassVal>) -> Vec<String> {
        let mut out = Vec::new();
        let mut todo = vec![cv.clone()];
        let mut visited = 0;
        while let Some(c) = todo.pop() {
            visited += 1;
            if visited > 16 {
                break;
            }
            for base in &c.def.bases {
                let saved = self.frames.len();
                self.frames
                    .push(Frame::new(c.module, None, Some(Env::new())));
                self.frames.last_mut().unwrap().scope = c.scope.clone();
                let bv = self.lookup_dotted(base);
                self.frames.truncate(saved);
                match bv {
                    Some(Value::Class(b)) => todo.push(b),
                    Some(Value::Ref(p, _)) => out.push(p.to_string()),
                    _ => out.push(base.clone()),
                }
            }
        }
        out
    }

    fn lookup_dotted(&mut self, dotted: &str) -> Option<Value> {
        if let Some(c) = self.lookup_global(dotted) {
            return Some(c);
        }
        let mut parts = dotted.split('.');
        let first = parts.next()?;
        let mut v = self.get_var(first)?;
        for p in parts {
            v = self.get_attr(&v, p);
        }
        Some(v)
    }

    /// Runs a user function with the given arguments. Returns its result and,
    /// for a bound method, the final value of `self`.
    pub fn call_function(
        &mut self,
        fv: &FuncVal,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>) {
        let recursive = self.frames.iter().any(|f| {
            f.func
                .as_ref()
                .map(|d| Rc::ptr_eq(d, &fv.def))
                .unwrap_or(false)
        });
        if recursive || self.frames.len() >= MAX_DEPTH || self.steps > MAX_STEPS {
            self.cutoffs += 1;
            let t =
                args_taint(args).union(&fv.bound.as_ref().map(|b| b.taint()).unwrap_or_default());
            return (Value::Unknown(t), fv.bound.clone());
        }
        if self.quiet && self.frames.len() >= QUIET_DEPTH {
            let t =
                args_taint(args).union(&fv.bound.as_ref().map(|b| b.taint()).unwrap_or_default());
            if !t.is_tainted() {
                return (Value::Unknown(t), fv.bound.clone());
            }
        }
        let key = self.memo_key(fv, args);
        if let Some(hit) = key.as_ref().and_then(|k| self.memo.get(k)) {
            return hit.clone();
        }
        let cutoffs = self.cutoffs;
        let result = self.run_function(fv, args, span);
        if let Some(k) = key {
            if self.cutoffs == cutoffs {
                if self.memo.len() >= MAX_MEMO {
                    self.memo.clear();
                }
                self.memo.insert(k, result.clone());
            }
        }
        result
    }

    /// Identifies a call with no user data in its callee, receiver or
    /// arguments; None for calls whose result must be computed each time.
    fn memo_key(&self, fv: &FuncVal, args: &[ArgVal]) -> Option<String> {
        use std::fmt::Write;
        if fv.closure.is_some() {
            return None;
        }
        let mut key = String::new();
        let route = self.current_route().map(|r| r.path.as_str()).unwrap_or("");
        let _ = write!(
            key,
            "{:p}/{}/{}/{}:{route}",
            Rc::as_ptr(&fv.def),
            fv.module,
            u8::from(self.quiet),
            route.len()
        );
        match &fv.bound {
            Some(b) => {
                key.push('<');
                fingerprint(b, &mut key)?;
                key.push('>');
            }
            None => key.push('-'),
        }
        for a in args {
            let name = a.name.as_deref().unwrap_or("");
            let _ = write!(
                key,
                ",{}{}:{name}",
                if a.spread { "*" } else { "" },
                name.len()
            );
            fingerprint(&a.value, &mut key)?;
        }
        Some(key)
    }

    fn run_function(
        &mut self,
        fv: &FuncVal,
        args: &[ArgVal],
        span: Span,
    ) -> (Value, Option<Value>) {
        let caller_module = self.module();
        let mut env = Env::new();
        let params = &fv.def.params;
        let mut idx = 0;
        let mut self_name = None;
        if let Some(b) = &fv.bound {
            if let Some(p) = params.first() {
                env.insert(p.name.as_str().into(), b.clone());
                self_name = Some(Rc::from(p.name.as_str()));
                idx = 1;
            }
        }
        let mut spread_taint: Option<Taint> = None;
        let mut positional = args.iter().filter(|a| a.name.is_none());
        for p in &params[idx..] {
            if let Some(a) = args
                .iter()
                .find(|a| a.name.as_deref() == Some(p.name.as_str()))
            {
                env.insert(p.name.as_str().into(), a.value.clone());
                continue;
            }
            if p.variadic {
                let rest: Vec<&ArgVal> = positional.by_ref().collect();
                let v = if rest.iter().any(|a| a.spread) {
                    Value::Unknown(
                        rest.iter()
                            .fold(Taint::clean(), |t, a| t.union(&a.value.taint())),
                    )
                } else {
                    Value::list(rest.iter().map(|a| a.value.clone()).collect())
                };
                env.insert(p.name.as_str().into(), v);
                continue;
            }
            match positional.next() {
                Some(a) if a.spread => {
                    spread_taint = Some(spread_taint.unwrap_or_default().union(&a.value.taint()));
                    env.insert(p.name.as_str().into(), Value::Unknown(a.value.taint()));
                }
                Some(a) => {
                    env.insert(p.name.as_str().into(), a.value.clone());
                }
                None => {
                    if let Some(t) = &spread_taint {
                        env.insert(p.name.as_str().into(), Value::Unknown(t.clone()));
                    }
                }
            }
        }
        let mut frame = Frame::new(fv.module, Some(fv.def.clone()), Some(env));
        frame.closure = fv.closure.clone();
        frame.scope = Scope::of_body(&fv.def.body, fv.scope.clone());
        frame.self_name = self_name;
        frame.span = span;
        self.frames.push(frame);
        // Defaults of missing parameters, evaluated in the callee's module.
        for p in &params[idx..] {
            let missing = self
                .frames
                .last()
                .and_then(|f| f.env.as_ref())
                .map(|e| !e.contains_key(p.name.as_str()))
                .unwrap_or(false);
            if missing {
                let v = p
                    .default
                    .as_ref()
                    .map(|d| self.eval(d))
                    .unwrap_or_else(Value::clean);
                self.set_var(&p.name, v);
            }
        }
        let model = self.model();
        let route = model.route(self, fv.module, &fv.def);
        self.frame().route = route;
        self.calls.push((caller_module, span));
        self.exec_block(&fv.def.body);
        self.calls.pop();
        if self.live() {
            self.capture_self();
        }
        let frame = self.frames.pop().expect("frame");
        let fell_through = frame.env.is_some();
        let ret = match (frame.ret, fell_through) {
            (Some(r), true) => join(&r, &Value::None),
            (Some(r), false) => r,
            (None, _) => Value::None,
        };
        (ret, frame.final_self.or_else(|| fv.bound.clone()))
    }

    pub fn get_attr(&mut self, base: &Value, name: &str) -> Value {
        match base {
            Value::Obj(o) => {
                if let Some(v) = o.field(name) {
                    return v.clone();
                }
                if let Some(cv) = o.def.clone() {
                    if let Some((m, owner)) = self.find_method(&cv, name) {
                        return Value::Func(Rc::new(FuncVal {
                            qualname: format!("{}.{}", owner.qualname, m.name).into(),
                            def: m.clone(),
                            module: owner.module,
                            bound: if is_static(&m) {
                                None
                            } else {
                                Some(base.clone())
                            },
                            closure: None,
                            scope: owner.scope.clone(),
                        }));
                    }
                    if let Some(v) = self.field_value(&cv, name) {
                        return v;
                    }
                }
                let model = self.model();
                model
                    .attr(self, base, name)
                    .unwrap_or_else(|| Value::Unknown(o.taint.clone()))
            }
            Value::Ref(path, t) => self.ref_attr(path, t, name),
            Value::Class(cv) => {
                if let Some((m, owner)) = self.find_method(cv, name) {
                    return Value::Func(Rc::new(FuncVal {
                        qualname: format!("{}.{}", owner.qualname, m.name).into(),
                        def: m.clone(),
                        module: owner.module,
                        bound: None,
                        closure: None,
                        scope: owner.scope.clone(),
                    }));
                }
                self.field_value(cv, name).unwrap_or_else(Value::clean)
            }
            Value::OneOf(alts) => {
                let vals: Vec<Value> = alts.iter().map(|a| self.get_attr(a, name)).collect();
                join_all(vals.into_iter()).unwrap_or_else(Value::clean)
            }
            other => {
                let model = self.model();
                model
                    .attr(self, other, name)
                    .unwrap_or_else(|| Value::Unknown(other.taint()))
            }
        }
    }

    /// Attribute of a reference: a project module member, a submodule, or
    /// whatever the language model knows about the library.
    pub fn ref_attr(&mut self, path: &str, taint: &Taint, name: &str) -> Value {
        if let Some(m) = self.project.module_index(path) {
            if let Some(g) = self.module_globals(m) {
                if let Some(v) = g.get(name) {
                    return v.clone();
                }
            }
        }
        let full = format!("{path}.{name}");
        if let Some(c) = self.java_class(&full) {
            return c;
        }
        if self.project.is_module_or_package(&full) {
            return Value::Ref(full.into(), Taint::clean());
        }
        if self.project.is_module_or_package(path) {
            return Value::clean();
        }
        let model = self.model();
        model.ref_attr(self, path, taint, name)
    }

    /// `a.b.c` as a value when `a.b` is a project module.
    fn resolve_project_ref(&mut self, path: &str) -> Option<Value> {
        let (module, member) = path.rsplit_once('.')?;
        let m = self.project.module_index(module)?;
        let g = self.module_globals(m)?;
        g.get(member).cloned()
    }

    /// A class of the project by qualified Java name.
    fn java_class(&mut self, qualified: &str) -> Option<Value> {
        let m = self.project.module_index(qualified)?;
        if self.project.modules[m].lang != crate::Language::Java {
            return None;
        }
        let last = qualified.rsplit('.').next().unwrap_or(qualified);
        self.module_globals(m)?.get(last).cloned()
    }

    /// The project class a Java type names in the current module, such as
    /// the declared type of an injected field.
    pub fn java_type_class(&mut self, ty: &str) -> Option<Rc<ClassVal>> {
        let name = ty.rsplit(' ').next().unwrap_or(ty);
        let simple = name.rsplit('.').next().unwrap_or(name);
        if name.ends_with("[]") || !simple.starts_with(|c: char| c.is_ascii_uppercase()) {
            return None;
        }
        let found = if name.contains('.') {
            self.lookup_dotted(name)
        } else {
            self.get_var(name).or_else(|| self.lookup_global(name))
        };
        match found {
            Some(Value::Class(c)) => Some(c),
            _ => None,
        }
    }

    /// A name no scope defines: in Java, a class of the same package or of
    /// a wildcard import, or a qualified class name.
    fn lookup_global(&mut self, name: &str) -> Option<Value> {
        let module = self.module();
        let m = &self.project.modules[module];
        if m.lang == crate::Language::Php {
            return self.php_lookup(name);
        }
        if m.lang != crate::Language::Java {
            return None;
        }
        if name.contains('.') {
            return self.java_class(name);
        }
        let mut candidates = Vec::new();
        if let Some(p) = &m.ir.package {
            candidates.push(format!("{p}.{name}"));
        }
        for s in &m.ir.body {
            if let Stmt::Import { alias, path } = s {
                if alias == "*" {
                    candidates.push(format!("{path}.{name}"));
                }
            }
        }
        candidates.into_iter().find_map(|c| self.java_class(&c))
    }

    /// The scope of a PHP module's top-level functions and classes, which
    /// PHP defines before the script runs.
    fn php_scope(&mut self, module: usize) -> Option<Rc<Scope>> {
        if self.project.modules[module].lang != crate::Language::Php {
            return None;
        }
        if let Some(s) = self.php_scopes.get(&module) {
            return s.clone();
        }
        let s = Scope::of_body(&self.project.modules[module].ir.body, None);
        self.php_scopes.insert(module, s.clone());
        s
    }

    fn php_index(&mut self) -> PhpIndex {
        if let Some(i) = &self.php_defs {
            return i.clone();
        }
        let mut index: HashMap<String, Vec<(usize, Def)>> = HashMap::new();
        for (i, m) in self.project.modules.iter().enumerate() {
            if m.lang != crate::Language::Php {
                continue;
            }
            for s in &m.ir.body {
                let (name, def) = match s {
                    Stmt::FuncDef(f) => (&f.name, Def::Func(f.clone())),
                    Stmt::ClassDef(c) => (&c.name, Def::Class(c.clone())),
                    _ => continue,
                };
                index
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push((i, def));
            }
        }
        let index = Rc::new(index);
        self.php_defs = Some(index.clone());
        index
    }

    /// A PHP function or class defined anywhere in the project. Names are
    /// case-insensitive; definitions in the module itself, then in its
    /// directory, then in non-test code win, and up to four alternatives
    /// are kept when several files define the name.
    fn php_lookup(&mut self, name: &str) -> Option<Value> {
        if name.starts_with('$') || self.model().library_over_project(name) {
            return None;
        }
        let index = self.php_index();
        let found = index.get(&name.to_ascii_lowercase())?;
        let here = self.module();
        let dir = |m: usize| {
            let p = &self.project.modules[m].path;
            p.rsplit_once('/')
                .map(|(d, _)| d.to_string())
                .unwrap_or_default()
        };
        let here_dir = dir(here);
        let here_test = self.project.modules[here].is_test;
        let rank = |m: usize| {
            if m == here {
                0
            } else if dir(m) == here_dir {
                1
            } else if self.project.modules[m].is_test && !here_test {
                3
            } else {
                2
            }
        };
        let best = found.iter().map(|(m, _)| rank(*m)).min()?;
        let picks: Vec<(usize, Def)> = found
            .iter()
            .filter(|(m, _)| rank(*m) == best)
            .take(4)
            .cloned()
            .collect();
        let mut vals = Vec::new();
        for (m, def) in picks {
            let scope = self.php_scope(m)?;
            vals.push(self.def_value(m, &def, &scope));
        }
        join_all(vals.into_iter())
    }

    /// `global $name` in a PHP function: the script's variable, as the
    /// script has set it so far, or as it ends.
    pub fn php_global(&mut self, name: &str) -> Value {
        let module = self.module();
        let live = self
            .frames
            .iter()
            .rev()
            .find(|f| f.module == module && f.func.is_none())
            .and_then(|f| f.env.as_ref().and_then(|e| e.get(name)).cloned());
        if let Some(v) = live {
            return v;
        }
        match &self.globals[module] {
            Globals::Done(env) => match env.get(name) {
                Some(v) => v.clone(),
                None => {
                    let model = self.model();
                    model.builtin(self, name)
                }
            },
            _ => Value::clean(),
        }
    }

    /// `define('NAME', value)`. PHP constants are global, so the value goes
    /// to the script's frame whichever function defines it.
    pub fn php_define(&mut self, name: &str, value: Value) {
        let module = self.module();
        let frame = self
            .frames
            .iter_mut()
            .rev()
            .find(|f| f.module == module && f.func.is_none());
        if let Some(env) = frame.and_then(|f| f.env.as_mut()) {
            env.insert(format!("#{name}").into(), value);
        }
    }

    /// A constant set by `define` or `const`: as defined on the way to this
    /// point, else as the project defines it with a literal value.
    pub fn php_const(&mut self, name: &str) -> Option<Value> {
        let key = format!("#{name}");
        for f in self.frames.iter().rev() {
            if let Some(v) = f.env.as_ref().and_then(|e| e.get(key.as_str())) {
                return Some(v.clone());
            }
        }
        if self.php_consts.is_none() {
            let mut found: HashMap<String, Vec<Value>> = HashMap::new();
            for m in &self.project.modules {
                if m.lang == crate::Language::Php {
                    literal_consts(&m.ir.body, &mut found);
                }
            }
            let index = found
                .into_iter()
                .filter_map(|(k, vals)| join_all(vals.into_iter()).map(|v| (k, v)))
                .collect();
            self.php_consts = Some(Rc::new(index));
        }
        self.php_consts.as_ref().and_then(|i| i.get(name).cloned())
    }

    /// A script variable this file uses without setting it, which the
    /// project sets everywhere to an object of one class: pages included by
    /// a front controller use the objects it made (`$db->query(...)`). The
    /// object is made here, once per run, and kept in the script's frame.
    pub fn php_object_var(&mut self, name: &str) -> Option<Value> {
        if self.php_objects.is_none() {
            let mut found: HashMap<String, Option<Expr>> = HashMap::new();
            for m in &self.project.modules {
                if m.lang == crate::Language::Php {
                    object_assignments(&m.ir.body, &mut found);
                }
            }
            let index = found
                .into_iter()
                .filter_map(|(k, e)| e.map(|e| (k, e)))
                .collect();
            self.php_objects = Some(Rc::new(index));
        }
        let expr = self.php_objects.as_ref()?.get(name)?.clone();
        if self.php_objects_building.iter().any(|b| b == name) {
            return None;
        }
        self.php_objects_building.push(name.to_string());
        let v = self.eval(&expr);
        self.php_objects_building.pop();
        if !matches!(v, Value::Obj(_)) {
            return None;
        }
        let module = self.module();
        let frame = self
            .frames
            .iter_mut()
            .find(|f| f.module == module && f.func.is_none());
        if let Some(env) = frame.and_then(|f| f.env.as_mut()) {
            env.insert(name.into(), v.clone());
        }
        Some(v)
    }

    /// `include $path` where the path is one of a few fixed names: each
    /// file's variables, joined.
    pub fn php_include_any(&mut self, paths: &[String]) -> bool {
        let mut joined: Option<Env> = None;
        let mut any = false;
        for p in paths {
            let Some(env) = self.php_included_env(p) else {
                continue;
            };
            any = true;
            let env = env.as_ref().clone();
            joined = Some(match joined {
                None => env,
                Some(acc) => join_env(Some(acc), Some(env)).unwrap_or_default(),
            });
        }
        for (k, v) in joined.unwrap_or_default().iter() {
            self.set_var(k, v.clone());
        }
        any
    }

    /// `include 'file.php'`: the variables the included script sets, by the
    /// path written, relative to the including file or to the project.
    /// Returns false when no project file matches.
    pub fn php_include(&mut self, written: &str) -> bool {
        match self.php_included_env(written) {
            Some(env) => {
                for (k, v) in env.iter() {
                    self.set_var(k, v.clone());
                }
                true
            }
            None => false,
        }
    }

    /// The variables and constants a project file included by `written`
    /// leaves behind; empty when it is the including file itself or still
    /// running.
    fn php_included_env(&mut self, written: &str) -> Option<Rc<Env>> {
        let here = &self.project.modules[self.module()].path;
        let dir = here.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let target = written
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        let mut candidates = vec![
            normalize_rel(&format!("{dir}/{target}")),
            normalize_rel(&target),
        ];
        candidates.retain(|c| !c.is_empty());
        let found = candidates
            .iter()
            .find_map(|c| self.project.module_index(c))
            .or_else(|| {
                // `__DIR__ . '/../lib/db.php'` is written with a prefix we
                // cannot see: match on the end of the path.
                let tail = format!("/{}", target.trim_start_matches("../"));
                let hits: Vec<usize> = self
                    .project
                    .modules
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| m.lang == crate::Language::Php && m.path.ends_with(&tail))
                    .map(|(i, _)| i)
                    .take(2)
                    .collect();
                (hits.len() == 1).then(|| hits[0])
            });
        let m = found?;
        if m == self.module() {
            return Some(Rc::new(Env::new()));
        }
        let Some(env) = self.module_globals(m) else {
            return Some(Rc::new(Env::new()));
        };
        let kept: Env = env
            .iter()
            .filter(|(k, _)| k.starts_with('$') || k.starts_with('#'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Some(Rc::new(kept))
    }

    fn import_value(&mut self, path: &str) -> Value {
        if self.project.modules[self.module()].lang == crate::Language::Java {
            if let Some(c) = self.java_class(path) {
                return c;
            }
            // `import static a.b.C.member`
            if let Some((class, member)) = path.rsplit_once('.') {
                if let Some(c) = self.java_class(class) {
                    return self.get_attr(&c, member);
                }
            }
            return Value::Ref(path.into(), Taint::clean());
        }
        let mut resolved = self.resolve_relative(path);
        // A script imports modules next to it first (`sys.path[0]`).
        if !path.starts_with('.') {
            let m = &self.project.modules[self.module()];
            if let Some((dir, _)) = m.name.rsplit_once('.') {
                let sibling = format!("{dir}.{resolved}");
                let first = resolved.split('.').next().unwrap_or("");
                if self.project.module_index(&sibling).is_some()
                    || self.project.is_module_or_package(&format!("{dir}.{first}"))
                {
                    resolved = sibling;
                }
            }
        }
        if self.project.is_module_or_package(&resolved) {
            return Value::Ref(resolved.into(), Taint::clean());
        }
        if let Some(v) = self.resolve_project_ref(&resolved) {
            return v;
        }
        Value::Ref(resolved.into(), Taint::clean())
    }

    fn resolve_relative(&self, path: &str) -> String {
        let dots = path.chars().take_while(|c| *c == '.').count();
        if dots == 0 {
            return path.to_string();
        }
        let m = &self.project.modules[self.module()];
        let mut base: Vec<&str> = m.name.split('.').collect();
        if !m.is_package {
            base.pop();
        }
        for _ in 1..dots {
            base.pop();
        }
        let rest = &path[dots..];
        if rest.is_empty() {
            base.join(".")
        } else if base.is_empty() {
            rest.to_string()
        } else {
            format!("{}.{}", base.join("."), rest)
        }
    }

    pub fn index(&mut self, base: &Value, key: &Value) -> Value {
        match (base, key) {
            (Value::OneOf(alts), _) => {
                let vals: Vec<Value> = alts.iter().map(|a| self.index(a, key)).collect();
                join_all(vals.into_iter()).unwrap_or_else(Value::clean)
            }
            (Value::List(items), Value::Int(i)) => {
                let n = items.len() as i64;
                let i = if *i < 0 { n + i } else { *i };
                if i >= 0 && i < n {
                    items[i as usize].clone()
                } else {
                    Value::clean()
                }
            }
            (Value::List(_), _) => base.element(),
            (Value::Str(segs), Value::Int(i)) => {
                let hi = if *i == -1 { None } else { Some(i + 1) };
                slice_str(segs, Some(*i), hi, true, true)
            }
            (Value::Dict(pairs), k) if is_const(k) => pairs
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(Value::clean),
            (Value::Dict(pairs), _) => {
                join_all(pairs.iter().map(|(_, v)| v.clone())).unwrap_or_else(Value::clean)
            }
            _ => {
                let model = self.model();
                model
                    .index(self, base, key)
                    .unwrap_or_else(|| Value::Unknown(base.taint()))
            }
        }
    }

    pub fn binop(&mut self, op: BinOp, l: &Value, r: &Value) -> Value {
        if let Value::OneOf(alts) = l {
            let vals: Vec<Value> = alts.iter().map(|a| self.binop(op, a, r)).collect();
            return join_all(vals.into_iter()).unwrap_or_else(Value::clean);
        }
        if let Value::OneOf(alts) = r {
            if !matches!(op, BinOp::In | BinOp::NotIn) {
                let vals: Vec<Value> = alts.iter().map(|a| self.binop(op, l, a)).collect();
                return join_all(vals.into_iter()).unwrap_or_else(Value::clean);
            }
        }
        let model = self.model();
        if let Some(v) = model.binop(self, op, l, r) {
            return v;
        }
        generic_binop(op, l, r)
    }
}

impl Frame {
    fn new(module: usize, func: Option<Rc<Function>>, env: Option<Env>) -> Frame {
        Frame {
            module,
            func,
            env,
            closure: None,
            scope: None,
            ret: None,
            self_name: None,
            exit_env: None,
            final_self: None,
            loops: Vec::new(),
            paths: false,
            route: None,
            span: Span::default(),
        }
    }
}

/// Taint that reaches a sink of `context`, checking string pieces in their
/// quoting context.
/// Describes `v` as a call argument so that equal descriptions behave the
/// same; None when it holds user data or is too large to compare.
fn fingerprint(v: &Value, out: &mut String) -> Option<()> {
    use std::fmt::Write;
    if out.len() > 4096 {
        return None;
    }
    match v {
        Value::Unknown(t) => {
            if t.is_tainted() {
                return None;
            }
            out.push('?');
        }
        Value::None => out.push('N'),
        Value::Bool(b) => out.push(if *b { 'T' } else { 'F' }),
        Value::Int(i) => {
            let _ = write!(out, "i{i};");
        }
        Value::Float(f) => {
            let _ = write!(out, "f{};", f.to_bits());
        }
        Value::Str(segs) => {
            out.push('s');
            for seg in segs.iter() {
                match seg {
                    Seg::Lit(t) => {
                        let _ = write!(out, "{}:{t}", t.len());
                    }
                    Seg::Dyn(t) => {
                        if t.is_tainted() {
                            return None;
                        }
                        let _ = write!(out, "d{};", t.safe);
                    }
                }
            }
            out.push(';');
        }
        Value::List(items) => {
            out.push('[');
            for i in items.iter() {
                fingerprint(i, out)?;
            }
            out.push(']');
        }
        Value::Dict(items) => {
            out.push('{');
            for (k, v) in items.iter() {
                fingerprint(k, out)?;
                fingerprint(v, out)?;
            }
            out.push('}');
        }
        Value::Ref(p, t) => {
            if t.is_tainted() {
                return None;
            }
            let _ = write!(out, "r{}:{p}", p.len());
        }
        Value::Obj(o) => {
            if o.taint.is_tainted() {
                return None;
            }
            let _ = write!(out, "o{}:{}", o.class.len(), o.class);
            if let Some(d) = &o.def {
                let _ = write!(out, "@{:p}/{}", Rc::as_ptr(&d.def), d.module);
            }
            out.push('(');
            for (k, v) in &o.fields {
                let _ = write!(out, "{}:{k}", k.len());
                fingerprint(v, out)?;
            }
            out.push(')');
        }
        Value::Func(f) => {
            if f.closure.is_some() {
                return None;
            }
            let _ = write!(out, "F{:p}/{}", Rc::as_ptr(&f.def), f.module);
            match &f.bound {
                Some(b) => {
                    out.push('<');
                    fingerprint(b, out)?;
                    out.push('>');
                }
                None => out.push('-'),
            }
        }
        Value::Class(c) => {
            let _ = write!(out, "C{:p}/{}", Rc::as_ptr(&c.def), c.module);
        }
        Value::OneOf(alts) => {
            out.push('|');
            for a in alts.iter() {
                fingerprint(a, out)?;
            }
            out.push('|');
        }
    }
    Some(())
}

pub fn reaching(value: &Value, context: u32) -> Option<Taint> {
    match value {
        Value::Str(segs) => {
            for (t, quote) in quote_contexts(segs) {
                if !t.reaches(context) {
                    continue;
                }
                // LDAP filters have no quoted literals, and a backslash
                // escapes a quote only in SQL and code literals.
                let escaped =
                    t.safe & ctx::ESCAPED_QUOTES != 0 && context & (ctx::SQL | ctx::CODE) != 0;
                let quoted_safe = match quote {
                    Some('\'') => {
                        (t.safe & ctx::NO_SQUOTE != 0
                            && context & (ctx::SQL | ctx::XPATH | ctx::CODE | ctx::SHELL) != 0)
                            || escaped
                    }
                    Some('"') => {
                        (t.safe & ctx::NO_DQUOTE != 0
                            && context & (ctx::SQL | ctx::XPATH | ctx::CODE) != 0)
                            || escaped
                    }
                    _ => false,
                };
                if !quoted_safe {
                    return Some(t);
                }
            }
            None
        }
        Value::OneOf(alts) | Value::List(alts) => alts.iter().find_map(|a| reaching(a, context)),
        other => {
            let t = other.taint();
            t.reaches(context).then_some(t)
        }
    }
}

/// `$name = new Class(...)` in a module's script code (not in functions),
/// by variable; `None` when the project assigns objects of different
/// classes to the name.
fn object_assignments(body: &[Stmt], out: &mut HashMap<String, Option<Expr>>) {
    for s in body {
        match s {
            Stmt::Assign {
                target: Target::Name(n),
                value: e @ Expr::New { class, .. },
                ..
            } if n.starts_with('$') => {
                let entry = out.entry(n.clone()).or_insert_with(|| Some(e.clone()));
                if let Some(Expr::New { class: c, .. }) = entry {
                    if !c.eq_ignore_ascii_case(class) {
                        *entry = None;
                    }
                }
            }
            Stmt::If { then, other, .. } => {
                object_assignments(then, out);
                object_assignments(other, out);
            }
            Stmt::Try {
                body,
                handlers,
                finally,
            } => {
                object_assignments(body, out);
                for h in handlers {
                    object_assignments(h, out);
                }
                object_assignments(finally, out);
            }
            _ => {}
        }
    }
}

/// PHP constants given a literal value anywhere in a module:
/// `const NAME = 'x';` (lowered to `#NAME`) and `define('NAME', 'x')`, also
/// under `if (!defined('NAME'))`.
fn literal_consts(body: &[Stmt], out: &mut HashMap<String, Vec<Value>>) {
    for s in body {
        match s {
            Stmt::Assign {
                target: Target::Name(n),
                value: Expr::Lit(c),
                ..
            } if n.starts_with('#') => {
                out.entry(n[1..].to_string())
                    .or_default()
                    .push(const_value(c));
            }
            Stmt::Expr(Expr::Call { func, args, .. }, _) => {
                if let (Expr::Name(f), [name, value, ..]) = (func.as_ref(), args.as_slice()) {
                    if let (true, Expr::Lit(Const::Str(n)), Expr::Lit(c)) =
                        (f.eq_ignore_ascii_case("define"), &name.value, &value.value)
                    {
                        out.entry(n.clone()).or_default().push(const_value(c));
                    }
                }
            }
            Stmt::If { then, other, .. } => {
                literal_consts(then, out);
                literal_consts(other, out);
            }
            _ => {}
        }
    }
}

pub fn const_value(c: &Const) -> Value {
    match c {
        Const::Int(i) => Value::Int(*i),
        Const::Float(f) => Value::Float(*f),
        Const::Str(s) => Value::str(s.clone()),
        Const::Bool(b) => Value::Bool(*b),
        Const::None => Value::None,
    }
}

pub fn is_const(v: &Value) -> bool {
    match v {
        Value::Int(_) | Value::Float(_) | Value::Bool(_) | Value::None => true,
        Value::Str(_) => v.as_str().is_some(),
        _ => false,
    }
}

/// Equality of two values when it can be decided.
/// The type of a value when it is certain: strings with unknown parts are
/// still strings. Lists and dicts share one kind (PHP arrays).
pub fn kind_of(v: &Value) -> Option<u8> {
    Some(match v {
        Value::None => 0,
        Value::Bool(_) => 1,
        Value::Int(_) => 2,
        Value::Float(_) => 3,
        Value::Str(_) => 4,
        Value::List(_) | Value::Dict(_) => 5,
        Value::Obj(_) => 6,
        Value::Func(_) | Value::Class(_) | Value::Unknown(_) | Value::Ref(..) | Value::OneOf(_) => {
            return None
        }
    })
}

pub fn values_eq(a: &Value, b: &Value) -> Option<bool> {
    match (a, b) {
        (Value::OneOf(alts), other) | (other, Value::OneOf(alts)) => {
            let results: Vec<Option<bool>> = alts.iter().map(|x| values_eq(x, other)).collect();
            if results.iter().all(|r| *r == Some(true)) {
                Some(true)
            } else if results.iter().all(|r| *r == Some(false)) {
                Some(false)
            } else {
                None
            }
        }
        (Value::Int(x), Value::Int(y)) => Some(x == y),
        (Value::Float(x), Value::Float(y)) => Some(x == y),
        (Value::Int(x), Value::Float(y)) | (Value::Float(y), Value::Int(x)) => {
            Some((*x as f64) == *y)
        }
        (Value::Bool(x), Value::Bool(y)) => Some(x == y),
        (Value::None, Value::None) => Some(true),
        (Value::None, v) | (v, Value::None) if is_const(v) => Some(false),
        (Value::Str(_), Value::Str(_)) => match (a.as_str(), b.as_str()) {
            (Some(x), Some(y)) => Some(x == y),
            _ => None,
        },
        (Value::Str(_), Value::Int(_) | Value::Float(_) | Value::Bool(_))
        | (Value::Int(_) | Value::Float(_) | Value::Bool(_), Value::Str(_)) => {
            if a.as_str().is_some() || b.as_str().is_some() {
                Some(false)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        Value::Bool(b) => Some(*b as i64 as f64),
        _ => None,
    }
}

/// Operators every language shares.
pub fn generic_binop(op: BinOp, l: &Value, r: &Value) -> Value {
    use BinOp::*;
    match op {
        Eq | NotEq => match values_eq(l, r) {
            Some(b) => Value::Bool(b == (op == Eq)),
            None => Value::clean(),
        },
        Is | IsNot => {
            let same = match (l, r) {
                (Value::None, Value::None) => Some(true),
                (Value::None, x) | (x, Value::None) => match x {
                    Value::Unknown(_) | Value::Ref(..) | Value::OneOf(_) => None,
                    _ => Some(false),
                },
                // Values of different kinds are never identical
                // (`false === "x"`, `1 === 1.0` in PHP).
                _ => match (kind_of(l), kind_of(r)) {
                    (Some(a), Some(b)) if a != b => Some(false),
                    _ => values_eq(l, r),
                },
            };
            match same {
                Some(b) => Value::Bool(b == (op == Is)),
                None => Value::clean(),
            }
        }
        Lt | LtE | Gt | GtE => {
            let ord = match (l, r) {
                (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
                _ => match (num(l), num(r)) {
                    (Some(a), Some(b)) => a.partial_cmp(&b),
                    _ => match (l.as_str(), r.as_str()) {
                        (Some(a), Some(b)) => Some(a.cmp(&b)),
                        _ => None,
                    },
                },
            };
            match ord {
                Some(o) => Value::Bool(match op {
                    Lt => o.is_lt(),
                    LtE => o.is_le(),
                    Gt => o.is_gt(),
                    _ => o.is_ge(),
                }),
                None => Value::clean(),
            }
        }
        In | NotIn => {
            let found = contains(r, l);
            match found {
                Some(b) => Value::Bool(b == (op == In)),
                None => Value::clean(),
            }
        }
        Add => match (l, r) {
            (Value::Int(a), Value::Int(b)) => a
                .checked_add(*b)
                .map(Value::Int)
                .unwrap_or_else(Value::clean),
            (Value::Str(_), _) | (_, Value::Str(_)) => concat(&[l.clone(), r.clone()]),
            (Value::List(a), Value::List(b)) => {
                Value::list(a.iter().chain(b.iter()).cloned().collect())
            }
            _ => match (num(l), num(r)) {
                (Some(a), Some(b)) => Value::Float(a + b),
                _ => numeric_or_unknown(l, r),
            },
        },
        Sub | Mul | Div | FloorDiv | Mod | Pow | BitAnd | BitOr | BitXor | Shl | Shr => {
            if let (Value::Int(a), Value::Int(b)) = (l, r) {
                let (a, b) = (*a, *b);
                let v = match op {
                    Sub => a.checked_sub(b),
                    Mul => a.checked_mul(b),
                    FloorDiv => (b != 0).then(|| a.div_euclid(b)),
                    Mod => (b != 0).then(|| a.rem_euclid(b)),
                    Pow => (0..=62)
                        .contains(&b)
                        .then(|| a.checked_pow(b as u32))
                        .flatten(),
                    BitAnd => Some(a & b),
                    BitOr => Some(a | b),
                    BitXor => Some(a ^ b),
                    Shl => (0..63)
                        .contains(&b)
                        .then(|| a.checked_shl(b as u32))
                        .flatten(),
                    Shr => (0..63).contains(&b).then(|| a >> b),
                    Div => {
                        return if b != 0 {
                            Value::Float(a as f64 / b as f64)
                        } else {
                            Value::clean()
                        }
                    }
                    _ => None,
                };
                return v.map(Value::Int).unwrap_or_else(Value::clean);
            }
            if op == Mul {
                if let (Some(s), Value::Int(n)) = (l.as_str(), r) {
                    if (0..=4096).contains(n) && s.len() * (*n as usize) <= 1 << 16 {
                        return Value::str(s.repeat(*n as usize));
                    }
                }
                if let (Value::Str(_), Value::Int(_)) = (l, r) {
                    return Value::tainted_str(l.taint());
                }
            }
            match (num(l), num(r)) {
                (Some(a), Some(b)) => match op {
                    Sub => Value::Float(a - b),
                    Mul => Value::Float(a * b),
                    Div if b != 0.0 => Value::Float(a / b),
                    _ => Value::clean(),
                },
                _ => numeric_or_unknown(l, r),
            }
        }
        And | Or => unreachable!("short-circuit operators are evaluated lazily"),
    }
}

/// Arithmetic on unknown operands: a number when one side is a number.
fn numeric_or_unknown(l: &Value, r: &Value) -> Value {
    let t = l.taint().union(&r.taint());
    if num(l).is_some() || num(r).is_some() {
        Value::Unknown(t.with_safe(ctx::ALL))
    } else {
        Value::Unknown(t)
    }
}

/// Whether `hay` contains `needle`, when that can be decided.
pub fn contains(hay: &Value, needle: &Value) -> Option<bool> {
    match hay {
        Value::Str(segs) => {
            let n = needle.as_str()?;
            str_contains(segs, &n)
        }
        Value::List(items) => {
            let mut maybe = false;
            for it in items.iter() {
                match values_eq(it, needle) {
                    Some(true) => return Some(true),
                    Some(false) => {}
                    None => maybe = true,
                }
            }
            if maybe {
                None
            } else {
                Some(false)
            }
        }
        Value::Dict(pairs) => {
            let keys = Value::List(Rc::new(pairs.iter().map(|(k, _)| k.clone()).collect()));
            contains(&keys, needle)
        }
        Value::OneOf(alts) => {
            let results: Vec<Option<bool>> = alts.iter().map(|a| contains(a, needle)).collect();
            let first = *results.first()?;
            results
                .iter()
                .all(|r| *r == first)
                .then_some(first)
                .flatten()
        }
        _ => None,
    }
}

pub fn slice_value(
    v: &Value,
    lo: Option<i64>,
    hi: Option<i64>,
    lo_known: bool,
    hi_known: bool,
) -> Value {
    match v {
        Value::Str(segs) => slice_str(segs, lo, hi, lo_known, hi_known),
        Value::List(items) if lo_known && hi_known => {
            let n = items.len() as i64;
            let fix = |i: i64| if i < 0 { (n + i).max(0) } else { i.min(n) };
            let a = fix(lo.unwrap_or(0));
            let b = fix(hi.unwrap_or(n));
            Value::list(if a < b {
                items[a as usize..b as usize].to_vec()
            } else {
                Vec::new()
            })
        }
        Value::OneOf(alts) => join_all(
            alts.iter()
                .map(|a| slice_value(a, lo, hi, lo_known, hi_known)),
        )
        .unwrap_or_else(Value::clean),
        Value::Unknown(t) => Value::Unknown(t.clone()),
        other => Value::Unknown(other.taint()),
    }
}

/// `base[key] = value` on containers the core models.
pub fn store_index(base: &Value, key: &Value, value: Value) -> Option<Value> {
    match base {
        Value::Dict(pairs) => {
            let mut pairs = pairs.as_ref().clone();
            if is_const(key) {
                match pairs.iter_mut().find(|(k, _)| k == key) {
                    Some(slot) => slot.1 = value,
                    None => pairs.push((key.clone(), value)),
                }
                Some(Value::Dict(Rc::new(pairs)))
            } else {
                // Unknown key: any entry may now hold the value.
                let t = pairs
                    .iter()
                    .fold(value.taint(), |t, (_, v)| t.union(&v.taint()));
                Some(Value::Unknown(t.union(&key.taint())))
            }
        }
        Value::List(items) => {
            if let Value::Int(i) = key {
                let n = items.len() as i64;
                let i = if *i < 0 { n + i } else { *i };
                if i >= 0 && i < n {
                    let mut items = items.as_ref().clone();
                    items[i as usize] = value;
                    return Some(Value::List(Rc::new(items)));
                }
            }
            let t = items.iter().fold(value.taint(), |t, v| t.union(&v.taint()));
            Some(Value::Unknown(t))
        }
        Value::Unknown(t) => Some(Value::Unknown(t.union(&value.taint()))),
        _ => None,
    }
}

pub fn join_env(a: Option<Env>, b: Option<Env>) -> Option<Env> {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(mut a), Some(b)) => {
            // A check on an element (`$a[0]`) holds after the branches only
            // when both made it.
            a.retain(|k, _| !k.contains('[') || b.contains_key(k));
            for (k, vb) in b {
                match a.get_mut(&k) {
                    Some(va) => {
                        if *va != vb {
                            *va = join(va, &vb);
                        }
                    }
                    None if k.contains('[') => {}
                    None => {
                        a.insert(k, vb);
                    }
                }
            }
            Some(a)
        }
    }
}

/// Variables a loop was still changing become unknown, keeping their taint.
fn widen_changed(mut state: Env, entry: Option<&Env>) -> Env {
    for (k, v) in state.iter_mut() {
        if entry.and_then(|e| e.get(k)) != Some(v) {
            *v = Value::Unknown(v.taint());
        }
    }
    state
}

fn env_eq(a: &Option<Env>, b: &Option<Env>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.len() == b.len() && a.iter().all(|(k, v)| b.get(k) == Some(v)),
        _ => false,
    }
}

/// The name under which a check on an array element is kept in the
/// environment: `$octet[0]`, `$_GET["id"]`. Only constant keys of a plain
/// variable.
fn path_key(e: &Expr) -> Option<String> {
    let Expr::Index(base, key) = e else {
        return None;
    };
    let Expr::Name(n) = &**base else {
        return None;
    };
    match &**key {
        Expr::Lit(Const::Int(i)) => Some(format!("{n}[{i}]")),
        Expr::Lit(Const::Str(k)) => Some(format!("{n}[{k:?}]")),
        _ => None,
    }
}

/// The variable an expression is rooted at (`x`, `x.y`, `x[0]`).
pub fn root_var(e: &Expr) -> Option<Rc<str>> {
    match e {
        Expr::Name(n) => Some(n.as_str().into()),
        _ => None,
    }
}

/// Truth of a constant a call result is compared with: `== 1`, `=== false`.
fn const_truth(e: &Expr) -> Option<bool> {
    match e {
        Expr::Lit(Const::Bool(b)) => Some(*b),
        Expr::Lit(Const::Int(1)) => Some(true),
        Expr::Lit(Const::Int(0)) => Some(false),
        _ => None,
    }
}

/// `a/./b/../c` -> `a/c`.
fn normalize_rel(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

fn is_static(f: &Function) -> bool {
    f.decorators
        .iter()
        .any(|d| matches!(d, Expr::Name(n) if n == "staticmethod"))
}

/// A field set in the class body: its value, and its declared type.
fn class_field<'c>(c: &'c Class, name: &str) -> Option<(Option<&'c Expr>, Option<&'c str>)> {
    c.fields.iter().rev().find_map(|s| match s {
        Stmt::Assign {
            target: Target::Name(n),
            value,
            ..
        } if n == name => Some((Some(value), None)),
        Stmt::Declare {
            name: n, value, ty, ..
        } if n == name => Some((value.as_ref(), Some(ty.as_str()))),
        _ => None,
    })
}

type Entry = (Rc<Function>, Option<Rc<Scope>>, Option<Rc<Class>>);

/// Every function and method, with the lexical scope it was defined in
/// (`None` at module level, where module globals serve the lookups).
fn collect_functions(
    body: &[Stmt],
    scope: Option<Rc<Scope>>,
    class: Option<Rc<Class>>,
    out: &mut Vec<Entry>,
) {
    for s in body {
        match s {
            Stmt::FuncDef(f) => {
                out.push((f.clone(), scope.clone(), class.clone()));
                let inner = Scope::of_body(&f.body, scope.clone());
                collect_functions(&f.body, inner, None, out);
            }
            Stmt::ClassDef(c) => {
                for m in &c.methods {
                    out.push((m.clone(), scope.clone(), Some(c.clone())));
                    let inner = Scope::of_body(&m.body, scope.clone());
                    collect_functions(&m.body, inner, None, out);
                }
            }
            Stmt::If { then, other, .. } => {
                collect_functions(then, scope.clone(), class.clone(), out);
                collect_functions(other, scope.clone(), class.clone(), out);
            }
            Stmt::Try {
                body,
                handlers,
                finally,
            } => {
                collect_functions(body, scope.clone(), class.clone(), out);
                for h in handlers {
                    collect_functions(h, scope.clone(), class.clone(), out);
                }
                collect_functions(finally, scope.clone(), class.clone(), out);
            }
            _ => {}
        }
    }
}
