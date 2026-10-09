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
/// Functions a C call through a struct member may run (see `c_call_member`).
const MAX_MEMBER_TARGETS: usize = 32;

/// An evaluated call argument.
#[derive(Debug, Clone)]
pub struct ArgVal {
    pub name: Option<Rc<str>>,
    pub value: Value,
    pub spread: bool,
    /// The variable passed, when the argument is a plain name.
    pub var: Option<Rc<str>>,
    /// C and C++: the variable or field a pointer argument points into
    /// (`buf` for `buf + n`, `(char *) buf` or `&buf[0]`), which functions
    /// that fill a buffer write.
    pub place: Option<Expr>,
    /// C: the argument is `&x`, a pointer that is not NULL whatever `x`
    /// holds.
    pub addressed: bool,
    /// C: the argument is NULL on every path to the call (see
    /// `Interp::null_source`).
    pub null_sure: bool,
}

impl ArgVal {
    pub fn plain(value: Value) -> ArgVal {
        ArgVal {
            name: None,
            value,
            spread: false,
            var: None,
            place: None,
            addressed: false,
            null_sure: false,
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
    /// Safe, and so is every variable holding only data from the same
    /// inputs: the check was on a canonical form of them (C `realpath`).
    SafeSources(u32),
    /// A C integer lies in `lo..=hi` (`x < 10`, `x >= 0`).
    Bounds(i64, i64),
    /// A C integer is not this value (`n != -1`).
    Not(i64),
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
    /// C pointer and reference parameters.
    outs: Vec<Out>,
    /// C globals where the function returned.
    exit_globals: Option<HashMap<Rc<str>, Value>>,
    /// `break` and `continue` statements run so far.
    jumps: usize,
    /// Branches being run whose condition the analysis could not decide.
    guesses: usize,
    /// Of those, branches it took on what a field or element holds, which
    /// code it did not follow may have changed (`if (ts->items == 0)`).
    on_memory: usize,
    /// Local variables last set to NULL for certain (see `null_source`),
    /// with `guesses` at the time.
    null_at: HashMap<Rc<str>, usize>,
    /// Pointer parameters given `&x`: not NULL until assigned.
    addressed: HashSet<Rc<str>>,
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
    /// Steps of all entries analyzed so far.
    pub work: usize,
    /// No more entries are started once `work` reaches it.
    pub work_limit: Option<usize>,
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
    memo: HashMap<String, Memo>,
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
    /// C fields a condition checks (`ctx.qry.path`), by their text.
    attr_vals: Vec<(Rc<str>, Expr)>,
    /// PHP script variables that the project sets to one class's object
    /// (`$db = new Database();` in index.php), by name.
    php_objects: Option<Rc<HashMap<String, Expr>>>,
    php_objects_building: Vec<String>,
    /// Top-level definitions of each PHP module, its functions' scope.
    php_scopes: HashMap<usize, Option<Rc<Scope>>>,
    /// See `c_index`.
    c_defs: Option<CIndex>,
    /// C and C++ global variables as the entry being analyzed has set them,
    /// by name: one program-wide store, as `extern` declarations share it.
    c_globals: HashMap<Rc<str>, Value>,
    /// Pointer and reference parameters a C function changed, by argument
    /// position, for the caller to write back (see `run_function`).
    c_outs: Vec<(usize, Value)>,
    /// A function of the project ran (or a summary of it replayed) since
    /// the flag was cleared: the call being made was followed.
    ran: bool,
    /// See `crate::cmembers`.
    c_members: Option<Rc<HashMap<String, Vec<String>>>>,
    /// Calls through a struct member run on a guess at its function (see
    /// `c_call_member`): findings in them need user data.
    guessed: usize,
    /// User data stored in `c_globals` in this entry, which C calls'
    /// results depend on (see `memo_key`), and whether there is any.
    c_globals_taint: Taint,
    c_globals_tainted: bool,
    /// The user data entries left in C globals (see `seed_c_globals`), and
    /// what the entries of the second round start with.
    c_summary: HashMap<Rc<str>, Value>,
    c_seed: HashMap<Rc<str>, Value>,
}

/// Top-level functions, classes and global variables of the C and C++
/// modules by name.
type CIndex = Rc<HashMap<String, Vec<CDef>>>;

/// A call's result: its value, the receiver it left, the C out
/// parameters it changed and the C globals it set.
/// A C pointer or reference parameter, through which the function may give
/// the caller a value.
struct Out {
    name: Rc<str>,
    /// Its value where the function returned having changed it.
    last: Option<Value>,
    /// Its value on entry.
    entry: Option<Value>,
    /// Whether the function assigned it.
    written: bool,
    /// Whether the function returned somewhere without changing it.
    kept: bool,
}

/// `Frame::null_at` and `Frame::addressed`.
type NullMarks = (HashMap<Rc<str>, usize>, HashSet<Rc<str>>);

/// What holds after two branches that both went on.
fn join_null_marks(a: NullMarks, b: NullMarks) -> NullMarks {
    let null_at =
        a.0.into_iter()
            .filter_map(|(k, at)| b.0.get(&k).map(|bt| (k, at.min(*bt))))
            .collect();
    let addressed = a.1.intersection(&b.1).cloned().collect();
    (null_at, addressed)
}

type Memo = (
    Value,
    Option<Value>,
    Rc<[(usize, Value)]>,
    Rc<[(Rc<str>, Value)]>,
);

#[derive(Clone)]
enum CDef {
    /// A function or variable of the module's top level.
    InModule(usize),
    /// A class, with the methods defined outside its body (`void A::f()`)
    /// merged into its declaration.
    Class(Rc<ClassVal>),
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
            work: 0,
            work_limit: None,
            quiet: false,
            notes: HashMap::new(),
            subclasses: None,
            external_sources: false,
            php_defs: None,
            php_consts: None,
            path_vals: Vec::new(),
            attr_vals: Vec::new(),
            php_objects: None,
            php_objects_building: Vec::new(),
            php_scopes: HashMap::new(),
            c_defs: None,
            c_globals: HashMap::new(),
            c_outs: Vec::new(),
            ran: false,
            c_members: None,
            guessed: 0,
            c_globals_taint: Taint::clean(),
            c_globals_tainted: false,
            c_summary: HashMap::new(),
            c_seed: HashMap::new(),

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
            if self.work_limit.is_some_and(|l| self.work >= l) {
                return;
            }
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
            self.work += self.steps;
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
        self.c_globals = self.c_seed.clone();
        self.c_globals_taint = self
            .c_seed
            .values()
            .fold(Taint::clean(), |t, v| t.union(&v.taint()));
        self.c_globals_tainted = self.c_globals_taint.is_tainted();
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
        if let Some(frame) = self.frames.pop() {
            self.globals_at_exit(&frame);
        }
        // Where this entry left user data in C globals.
        for (name, v) in std::mem::take(&mut self.c_globals) {
            if let Some(t) = tainted_part(&v) {
                let joined = match self.c_summary.remove(&name) {
                    Some(prev) => join(&prev, &t),
                    None => t,
                };
                self.c_summary.insert(name, joined);
            }
        }
    }

    /// The C globals a finished function leaves: those of every `return`
    /// joined with those where it ran off its end.
    fn globals_at_exit(&mut self, frame: &Frame) {
        if let Some(g) = &frame.exit_globals {
            self.c_globals = if frame.env.is_some() {
                join_globals(g.clone(), std::mem::take(&mut self.c_globals))
            } else {
                g.clone()
            };
        }
    }

    /// C programs keep request data in globals (`ctx.qry.path` set while
    /// parsing the query, read by the page handler a dispatch table runs).
    /// After every entry ran once, entries that read a global some entry
    /// filled with user data run again with that data in place. Returns
    /// whether there was any.
    pub fn seed_c_globals(&mut self) -> bool {
        if self.c_summary.is_empty() {
            return false;
        }
        self.c_seed = std::mem::take(&mut self.c_summary);
        true
    }

    // ----- reporting -----

    pub fn module(&self) -> usize {
        self.frames.last().map(|f| f.module).unwrap_or(0)
    }

    /// Library knowledge for the language of the code being run.
    fn model(&self) -> &'static dyn Model {
        crate::models::for_language(self.project.modules[self.module()].lang)
    }

    /// Whether the code being run is C or C++.
    fn in_c(&self) -> bool {
        matches!(
            self.project.modules[self.module()].lang,
            crate::Language::C | crate::Language::Cpp
        )
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

    /// Reports a finding with the input that controls it, when `taint`
    /// holds user data.
    pub fn flag_tainted(&mut self, rule: &'static Rule, span: Span, what: &str, taint: &Taint) {
        let module = self.module();
        let src = taint.sources.iter().find(|s| !s.weak_random).cloned();
        self.report(rule, module, span, what, src);
    }

    /// Reports a finding that does not depend on data flow.
    /// A finding without user data. Not made in a call that runs on a guess
    /// at which function a struct member holds, with arguments that may
    /// never meet that function.
    pub fn flag(&mut self, rule: &'static Rule, span: Span, what: &str) {
        if self.guessed > 0 {
            return;
        }
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
        if trace_reports() {
            let stack: Vec<String> = self
                .frames
                .iter()
                .map(|f| {
                    let name = f.func.as_ref().map_or("<top>", |func| func.name.as_str());
                    format!(
                        "{}:{}@{}",
                        self.project.modules[f.module].path, name, f.span.line
                    )
                })
                .collect();
            eprintln!(
                "[trace] {} line {}: {what}\n    {}",
                rule.id,
                span.line,
                stack.join("\n    ")
            );
        }
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
        if self.in_c() {
            if let Some(v) = self.c_globals.get(name) {
                return Some(v.clone());
            }
            if let Some(v) = self.this_field(name) {
                return Some(v);
            }
            let found = self.module_globals(module)?.get(name).cloned();
            // A class whose methods other files define.
            if let Some(Value::Class(_)) = found {
                if let Some(c @ Value::Class(_)) = self.c_lookup(name) {
                    return Some(c);
                }
            }
            return found;
        }
        let globals = self.module_globals(module)?;
        globals.get(name).cloned()
    }

    /// A name as code at this point sees it: a variable, or a function,
    /// class or global of the project.
    pub fn lookup_name(&mut self, name: &str) -> Option<Value> {
        self.get_var(name).or_else(|| self.lookup_global(name))
    }

    /// In a C++ method, a bare name that is a field of `this`: methods
    /// defined outside their class do not know the fields when lowered.
    fn this_field(&mut self, name: &str) -> Option<Value> {
        let frame = self.frames.last()?;
        let this = frame.self_name.as_ref()?;
        let Some(Value::Obj(o)) = frame.env.as_ref()?.get(this.as_ref()) else {
            return None;
        };
        if let Some(v) = o.field(name) {
            return Some(v.clone());
        }
        let cv = o.def.clone()?;
        let declares = |c: &ClassVal| {
            c.def
                .fields
                .iter()
                .any(|f| matches!(f, Stmt::Declare { name: n, .. } if n == name))
        };
        if declares(&cv) {
            return self.field_value(&cv, name).or_else(|| Some(Value::clean()));
        }
        // A method defined apart from its class (`A::run() {}` in a.cpp):
        // the fields are declared in the header.
        if let Some(Value::Class(whole)) = self.c_lookup(&cv.def.name) {
            if declares(&whole) {
                return self
                    .field_value(&whole, name)
                    .or_else(|| Some(Value::clean()));
            }
        }
        None
    }

    /// Whether `name` in a C++ method is a field of `this` (see
    /// `this_field`); the name of `this` when it is.
    fn is_local(&self, name: &str) -> bool {
        let Some(f) = self.frames.last() else {
            return false;
        };
        f.env.as_ref().is_some_and(|e| e.contains_key(name))
            || f.closure.as_ref().is_some_and(|e| e.contains_key(name))
    }

    fn this_field_of(&mut self, name: &str) -> Option<Rc<str>> {
        let this = self.frames.last()?.self_name.clone()?;
        self.this_field(name).map(|_| this)
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

    /// Sets `name`. A parameter given `&x` stays one: as a pointer and
    /// what it points to are one value, `*valp = NULL` sets it too.
    pub fn set_var(&mut self, name: &str, value: Value) {
        let f = self.frame();
        if matches!(value, Value::None) {
            let at = f.guesses;
            f.null_at.insert(name.into(), at);
        }
        if let Some(env) = f.env.as_mut() {
            env.insert(name.into(), value);
        }
    }

    /// What the frame knows of NULL pointers (see `null_here`), saved
    /// around a branch: like the variables, each branch sets its own.
    fn null_marks(&mut self) -> NullMarks {
        let f = self.frame();
        (f.null_at.clone(), f.addressed.clone())
    }

    fn set_null_marks(&mut self, marks: NullMarks) {
        let f = self.frame();
        (f.null_at, f.addressed) = marks;
    }

    /// Whether the local variable `name`, now NULL, is NULL on every path
    /// to here: no branch the analysis guessed at was entered since it was
    /// set (`p = NULL; if (prev == q) p->n++;` is not).
    pub fn null_here(&self, name: &str) -> bool {
        let Some(f) = self.frames.last() else {
            return false;
        };
        self.is_local(name) && f.null_at.get(name).is_some_and(|at| *at >= f.guesses)
    }

    /// Whether the parameter `name` was given `&x`, a pointer that is not
    /// NULL.
    pub fn addressed(&self, name: &str) -> bool {
        self.frames
            .last()
            .is_some_and(|f| f.addressed.contains(name))
    }

    /// Whether `e`, which is NULL, is NULL for certain: the NULL constant, a
    /// call's result, a local variable NULL on every path here, or a global
    /// this run set. Not a field or an element, which code the analysis
    /// did not follow may have set.
    fn null_source(&self, e: &Expr) -> bool {
        match e {
            Expr::Lit(Const::None) | Expr::Call { .. } => true,
            // `&p` passes `p`'s value on (see `UnOp::Addr`).
            Expr::Cast(_, x) | Expr::Un(UnOp::Addr, x) => self.null_source(x),
            Expr::Name(n) => {
                self.null_here(n) || (!self.is_local(n) && self.c_globals.contains_key(n.as_str()))
            }
            _ => false,
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
        // A branch taken on a field (see `exec_if`) is a guess for the rest
        // of the block.
        let depth = self.frames.len();
        let guesses = self.frames.last().map(|f| (f.guesses, f.on_memory));
        for s in stmts {
            if !self.live() {
                break;
            }
            self.steps += 1;
            if self.steps > MAX_STEPS {
                self.cutoffs += 1;
                break;
            }
            self.exec(s);
        }
        if let Some((g, m)) = guesses.filter(|_| self.frames.len() == depth) {
            let f = self.frame();
            (f.guesses, f.on_memory) = (g, m);
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
                let unsure = match target {
                    Target::Name(n) if self.in_c() && matches!(v, Value::None) => {
                        (!self.null_source(value)).then(|| n.clone())
                    }
                    _ => None,
                };
                self.assign(target, v, *span);
                if let Some(n) = unsure {
                    self.frame().null_at.remove(n.as_str());
                }
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
                let unsure = matches!(v, Value::None)
                    && !value.as_ref().is_some_and(|e| self.null_source(e));
                self.set_var(name, v);
                if unsure {
                    self.frame().null_at.remove(name.as_str());
                }
            }
            Stmt::Expr(e, span) => {
                self.frame().span = *span;
                self.eval(e);
                // `if (p == NULL) exit(1);`: nothing runs after exit().
                if self.in_c() && is_c_exit(e) {
                    self.frame().env = None;
                }
            }
            Stmt::Raw(e, span) => {
                self.frame().span = *span;
                let v = self.eval(e);
                let model = self.model();
                model.raw(self, &v, *span);
            }
            Stmt::If {
                test,
                then,
                other,
                span,
            } => {
                self.at(*span);
                self.exec_if(test, then, other)
            }
            Stmt::Loop {
                target,
                iter,
                test,
                body,
                span,
            } => self.exec_loop(target.as_ref(), iter.as_ref(), test.as_ref(), body, *span),
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
                let mut v = e.as_ref().map(|e| self.eval(e)).unwrap_or(Value::None);
                // `if (ts->items == 0) return NULL;` and `return s->bufr;`
                // return NULL only as far as the analysis knows the field.
                if matches!(v, Value::None)
                    && self.in_c()
                    && e.as_ref().is_some_and(|e| {
                        pointer_expr(e) && (self.frame_ref().on_memory > 0 || !self.null_source(e))
                    })
                {
                    v = Value::OneOf(Rc::new(vec![Value::None, Value::clean()]));
                }
                let func = self.frames.last().and_then(|f| f.func.clone());
                if let Some(func) = func.filter(|f| makes_secret(&f.name)) {
                    self.sink(&WEAK_RANDOM, &v, *span, &format!("{}()", func.name));
                }
                if let Some(route) = self.frames.last().and_then(|f| f.route.clone()) {
                    let model = self.model();
                    model.on_return(self, &route, &v, *span);
                }
                self.capture_self();
                let globals = (!self.c_globals.is_empty()).then(|| self.c_globals.clone());
                let f = self.frame();
                if let Some(g) = globals {
                    f.exit_globals = Some(match f.exit_globals.take() {
                        Some(prev) => join_globals(prev, g),
                        None => g,
                    });
                }
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
                f.jumps += 1;
                let env = f.env.take();
                if let Some(acc) = f.loops.last_mut() {
                    acc.breaks = join_env(acc.breaks.take(), env);
                }
            }
            Stmt::Continue => {
                let f = self.frame();
                f.jumps += 1;
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
        if let Some(env) = &f.env {
            for Out {
                name,
                last,
                entry,
                written,
                kept,
            } in f.outs.iter_mut()
            {
                // `if (!(tp = realloc(...))) return -1; *dp = tp;`: a path
                // that leaves the caller's pointer alone does not undo the
                // others, whose result the caller goes on with. A NULL
                // the function only checked for (`if (p == NULL) return 0;`)
                // is not one it gives back.
                let Some(mut v) = env
                    .get(name.as_ref())
                    .filter(|v| Some(*v) != entry.as_ref())
                    .filter(|v| *written || !matches!(v, Value::None))
                else {
                    *kept = true;
                    continue;
                };
                // Given back NULL as far as the analysis knows a field.
                let unsure;
                if f.on_memory > 0 && matches!(v, Value::None) {
                    unsure = Value::OneOf(Rc::new(vec![Value::None, Value::clean()]));
                    v = &unsure;
                }
                *last = Some(match last.take() {
                    None => v.clone(),
                    Some(prev) => join(&prev, v),
                });
            }
        }
    }

    /// Whether `e` is a parameter given `&x` while `x` is NULL. The pointer
    /// is not NULL though `x` is, and as the two are one value, a test of
    /// either (`if (value)`, `*value != NULL`) is a guess.
    fn addressed_null(&mut self, e: &Expr) -> bool {
        matches!(e, Expr::Name(n) if self.addressed(n) && matches!(self.get_var(n), Some(Value::None)))
    }

    /// The value of a condition.
    fn eval_test(&mut self, e: &Expr) -> Value {
        if self.addressed_null(e) {
            return Value::clean();
        }
        self.eval(e)
    }

    fn exec_if(&mut self, test: &Expr, then: &[Stmt], other: &[Stmt]) {
        let cond = self.eval_test(test);
        match cond.truthy() {
            Some(truth) => {
                // The analysis may not know what code it did not follow
                // stored in the field: a NULL set or returned from here on
                // (`if (q->head) return 1; *pbuf = NULL;`) is not NULL for
                // certain.
                if self.in_c() && reads_memory(test) {
                    self.frame().guesses += 1;
                    self.frame().on_memory += 1;
                }
                self.refine(test, truth);
                self.exec_block(if truth { then } else { other });
            }
            None => {
                let saved = self.frame().env.clone();
                let saved_globals = self.c_globals.clone();
                let saved_marks = self.null_marks();
                let jumps = self.frame().jumps;
                self.frame().guesses += 1;
                self.refine(test, true);
                self.exec_block(then);
                let after_then = self.frame().env.take();
                // A branch that returned left its globals with the frame.
                let then_returned = after_then.is_none() && self.frame().jumps == jumps;
                let then_globals = std::mem::replace(&mut self.c_globals, saved_globals);
                let then_marks = self.null_marks();
                self.set_null_marks(saved_marks);
                self.frame().env = saved;
                let jumps = self.frame().jumps;
                self.refine(test, false);
                self.exec_block(other);
                self.frame().guesses -= 1;
                let after_other = self.frame().env.take();
                let other_returned = after_other.is_none() && self.frame().jumps == jumps;
                self.frame().env = join_env(after_then, after_other);
                let other_globals = std::mem::take(&mut self.c_globals);
                let other_marks = self.null_marks();
                self.c_globals = match (then_returned, other_returned) {
                    (true, false) => other_globals,
                    (false, true) => then_globals,
                    _ => join_globals(then_globals, other_globals),
                };
                self.set_null_marks(match (then_returned, other_returned) {
                    (true, false) => other_marks,
                    (false, true) => then_marks,
                    _ => join_null_marks(then_marks, other_marks),
                });
            }
        }
    }

    /// A counter that the loop's test bounds and its body steps by one:
    /// `for (i = a; i < n; i++)`, `while (i >= 0) { ...; i--; }`.
    fn loop_counter(&mut self, test: &Expr, body: &[Stmt]) -> Option<Counter> {
        let Expr::Bin(op, l, r) = test else {
            return None;
        };
        let (var, op, bound) = match (underef(l), underef(r)) {
            (Expr::Name(v), b) => (v.as_str(), *op, b),
            (b, Expr::Name(v)) => (
                v.as_str(),
                match op {
                    BinOp::Lt => BinOp::Gt,
                    BinOp::LtE => BinOp::GtE,
                    BinOp::Gt => BinOp::Lt,
                    BinOp::GtE => BinOp::LtE,
                    other => *other,
                },
                b,
            ),
            _ => return None,
        };
        let mut writes = Vec::new();
        assigned_names(body, &mut writes);
        let step = single_step(body, var)?;
        if writes.iter().filter(|w| w.as_str() == var).count() != 1 {
            return None;
        }
        let mut read = Vec::new();
        expr_names(bound, &mut read);
        if read.iter().any(|n| writes.contains(n)) {
            return None;
        }
        let start = self.get_var(var)?.bounds()?;
        let limit = self.eval(bound);
        let taint = limit.taint();
        let (blo, bhi) = match &limit {
            Value::Unknown(_) => (i64::MIN, i64::MAX),
            other => other.bounds()?,
        };
        let (lo, hi) = match (step, op) {
            (1, BinOp::Lt) => (start.0, if bhi == i64::MAX { i64::MAX } else { bhi - 1 }),
            (1, BinOp::LtE) => (start.0, bhi),
            (1, BinOp::NotEq) if blo == bhi => (start.0, bhi - 1),
            (-1, BinOp::Gt) => (if blo == i64::MIN { i64::MIN } else { blo + 1 }, start.1),
            (-1, BinOp::GtE) => (blo, start.1),
            _ => return None,
        };
        if lo > hi || lo == i64::MIN && hi == i64::MAX {
            return None;
        }
        // From a constant start to a constant limit the loop takes every
        // value, the last one included.
        let inside = if start.0 == start.1 && blo == bhi {
            Value::range_reached(lo, hi, taint.clone())
        } else {
            Value::range(lo, hi, taint.clone())
        };
        let exit = match step {
            1 if hi != i64::MAX => Value::Int(hi + 1),
            -1 if lo != i64::MIN => Value::Int(lo - 1),
            _ => Value::Unknown(taint.clone()),
        };
        let inside_or_exit = join(&inside, &exit);
        Some(Counter {
            var: var.into(),
            inside,
            exit,
            inside_or_exit,
        })
    }

    fn exec_loop(
        &mut self,
        target: Option<&Target>,
        iter: Option<&Expr>,
        test: Option<&Expr>,
        body: &[Stmt],
        span: Span,
    ) {
        self.at(span);
        let element = iter.map(|e| {
            let it = self.eval(e);
            it.element()
        });
        // `for (i = 0; i < n; i++)` in C: the body sees every value of `i`.
        let counter = match (target, test) {
            (None, Some(t)) if self.in_c() => self.loop_counter(t, body),
            _ => None,
        };
        // C globals the body sets may also keep their value: it can run
        // no times.
        let globals_before = self.c_globals.clone();
        let entry = self.frame().env.clone();
        let mut state = entry.clone();
        let mut exits = None;
        let mut settled = true;
        // A counted loop whose test holds on entry runs at least once: it
        // ends after one of its passes, not before them.
        let mut first_true = false;
        let mut ends: Vec<Option<Env>> = Vec::new();
        self.frame().loops.push(LoopAcc {
            breaks: None,
            continues: None,
            is_switch: false,
        });
        for pass in 0..2 {
            self.frame().env = state.clone();
            // A body that may run no times is a guess.
            let mut guessed = false;
            if let Some(t) = test {
                self.at(span);
                let c = self.eval_test(t);
                match c.truthy() {
                    Some(false) => {
                        exits = join_env(exits, self.frame().env.take());
                        break;
                    }
                    Some(true) => first_true |= pass == 0,
                    None => {
                        exits = join_env(exits, self.frame().env.clone());
                        guessed = true;
                    }
                }
                if guessed {
                    self.frame().guesses += 1;
                }
                self.refine(t, true);
            }
            if let (Some(t), Some(el)) = (target, &element) {
                self.assign(t, el.clone(), Span::default());
            }
            if let Some(c) = &counter {
                self.set_var(&c.var, c.inside.clone());
            }
            self.exec_block(body);
            if guessed {
                self.frame().guesses -= 1;
            }
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
            if counter.is_some() {
                ends.push(end.clone());
            }
            // `for (i = 0; i < 1; i++)` runs its body exactly once.
            if first_true
                && counter
                    .as_ref()
                    .is_some_and(|c| matches!(c.inside, Value::Int(_)))
            {
                state = end;
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
        let broke = acc.breaks.is_some();
        if counter.is_some() && first_true && !ends.is_empty() {
            let first = ends.first().cloned().flatten();
            let all = ends.into_iter().fold(None, join_env);
            let all = match (&first, settled) {
                (Some(f), false) => all.map(|a| widen_changed(a, Some(f))),
                _ => all,
            };
            exits = None;
            state = all;
        }
        let mut out = join_env(exits, acc.breaks);
        if test.is_none() {
            // A for loop may run zero times or to completion.
            out = join_env(out, join_env(entry, state));
        } else if let Some(t) = test {
            // `while cond:` exits when the condition fails.
            self.at(span);
            if self.eval_in(state.clone(), t).truthy() != Some(true) {
                out = join_env(out, state);
            } else if !settled && !matches!(t, Expr::Lit(_)) {
                // `for ($i = 0; $i < 50; $i++)`: two passes saw only the
                // first values of `$i`, the loop ends with later ones.
                out = join_env(out, state.map(|s| widen_changed(s, entry.as_ref())));
            }
        }
        self.frame().env = out;
        if let Some(c) = counter {
            if self.live() {
                let v = if broke { c.inside_or_exit } else { c.exit };
                self.set_var(&c.var, v);
            }
        }
        let after = std::mem::take(&mut self.c_globals);
        self.c_globals = join_globals(globals_before, after);
    }

    /// Findings in a test point at it; IR built without a span keeps the
    /// statement's.
    fn at(&mut self, span: Span) {
        if span.line != 0 {
            self.frame().span = span;
        }
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
        let mut guessed = false;
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
            let globals_before = (matched != Some(true)).then(|| self.c_globals.clone());
            // A case after one the analysis could not decide is a guess too.
            guessed |= matched.is_none();
            if guessed {
                self.frame().guesses += 1;
            }
            self.exec_block(&case.body);
            if guessed {
                self.frame().guesses -= 1;
            }
            if let Some(before) = globals_before {
                let after = std::mem::take(&mut self.c_globals);
                self.c_globals = join_globals(before, after);
            }
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
                if let Some(f) = self.frames.last_mut() {
                    for out in f.outs.iter_mut().filter(|o| *o.name == **n) {
                        out.written = true;
                    }
                }
                self.forget_paths(n);
                if self.in_c() && self.live() && !self.is_local(n) {
                    // A field of `this`, or a global variable.
                    if let Some(this) = self.this_field_of(n) {
                        let t = Target::Attr(Box::new(Expr::Name(this.to_string())), n.clone());
                        return self.assign(&t, value, span);
                    }
                    if self.frame_ref().func.is_some() {
                        let t = value.taint();
                        if t.is_tainted() {
                            self.c_globals_tainted = true;
                            self.c_globals_taint = self.c_globals_taint.union(&t);
                        }
                        self.c_globals.insert(n.as_str().into(), value);
                        return;
                    }
                }
                self.set_var(n, value)
            }
            Target::Attr(obj, field) => {
                if secret_name(field) {
                    self.sink(&WEAK_RANDOM, &value, span, field);
                }
                let base = self.eval(obj);
                let base = self.c_deref(obj, base);
                match &base {
                    Value::Obj(o) => {
                        let mut o = (**o).clone();
                        o.set_field(field, value);
                        self.assign_expr(obj, Value::Obj(Rc::new(o)), span);
                    }
                    // `p->field = v` on an array or allocation of structs.
                    Value::Buf(b) => {
                        let mut o = match &b.content {
                            Value::Obj(o) => (**o).clone(),
                            other => {
                                let mut o = Obj::new("");
                                o.taint = other.taint();
                                o
                            }
                        };
                        o.set_field(field, value);
                        let nb = Buf {
                            content: Value::Obj(Rc::new(o)),
                            ..(**b).clone()
                        };
                        self.assign_expr(obj, Value::Buf(Rc::new(nb)), span);
                    }
                    // `p->field = v` on a struct the analysis has not seen
                    // made (`malloc`, a parameter).
                    Value::Unknown(t) if self.in_c() => {
                        let mut o = Obj::new("");
                        o.taint = t.clone();
                        o.set_field(field, value);
                        self.assign_expr(obj, Value::Obj(Rc::new(o)), span);
                    }
                    _ => {}
                }
            }
            Target::Index(base_e, key_e) => {
                if let Expr::Name(n) = underef(base_e) {
                    self.forget_paths(n);
                }
                let base = self.eval(base_e);
                let base = self.c_deref(base_e, base);
                let key = self.eval(key_e);
                let key_name = key.as_str().unwrap_or_default();
                let store = match underef(base_e) {
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

    /// `e`, with the value `v`, read through as a C pointer: reports a
    /// NULL one (see `cnull::deref`) and gives the value the program goes
    /// on with.
    fn c_deref(&mut self, e: &Expr, v: Value) -> Value {
        if !self.in_c() {
            return v;
        }
        crate::models::cnull::deref(self, Some(e), v, None)
    }

    /// Writes a changed receiver back to the place it was read from.
    pub fn assign_expr(&mut self, e: &Expr, value: Value, span: Span) {
        if let (Expr::Cast(ty, inner), true) = (e, self.in_c()) {
            let model = self.model();
            let value = model.coerce(self, ty, value);
            return self.assign_expr(inner, value, span);
        }
        if let Expr::Un(UnOp::Deref | UnOp::Addr, inner) = e {
            return self.assign_expr(inner, value, span);
        }
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
        let fields = std::mem::take(&mut self.attr_vals);
        for (var, facts) in by_var {
            let field = fields.iter().find(|(k, _)| *k == var).map(|(_, e)| e);
            let cur = match field {
                Some(e) => self.eval(e),
                None => match self.get_var(&var) {
                    Some(v) => v,
                    None => match paths.iter().find(|(k, _)| *k == var) {
                        Some((_, v)) => {
                            self.frame().paths = true;
                            v.clone()
                        }
                        None => continue,
                    },
                },
            };
            let mut bits = model.facts_safety(&facts, &cur);
            let mut narrowed = None;
            let numeric = narrow_numbers(&cur, &facts, self.in_c());
            for f in &facts {
                match f {
                    Fact::Safe(b) => bits |= b,
                    Fact::SafeSources(b) => {
                        bits |= b;
                        self.sanitize_same_sources(&cur.taint(), *b);
                    }
                    Fact::OneOf(vals) if !vals.is_empty() => {
                        narrowed = join_all(vals.iter().cloned());
                    }
                    _ => {}
                }
            }
            let bounded = narrowed.is_none() && numeric.is_some();
            let refined = match (narrowed, numeric) {
                (Some(n), _) => n,
                (None, Some(n)) if bits != 0 => n.sanitized(bits),
                (None, Some(n)) => n,
                (None, None) if bits != 0 => cur.sanitized(bits),
                (None, None) => continue,
            };
            let ranged = bounded && refined != cur;
            match field {
                // Only checks that make user data safe, or bound a number
                // or a pointer (`p->n > 0`, `p->buf != NULL`), write a field
                // back.
                Some(e) if (bits != 0 && cur.taint().is_tainted()) || ranged => {
                    self.assign_expr(e, refined, Span::default())
                }
                Some(_) => {}
                // A C global stays global: a local copy would hide what
                // calls store in it.
                None if self.in_c()
                    && !self.is_local(&var)
                    && !paths.iter().any(|(k, _)| *k == var)
                    && self.frame_ref().func.is_some()
                    && self.this_field(&var).is_none() =>
                {
                    self.c_globals.insert(var, refined);
                }
                // A field of `this` in a C++ method: the object keeps the
                // check (`if (data == NULL) exit(1);` in a constructor).
                None if self.in_c() && !self.is_local(&var) => match self.this_field_of(&var) {
                    Some(this) => {
                        let t =
                            Target::Attr(Box::new(Expr::Name(this.to_string())), var.to_string());
                        let span = self.span();
                        self.assign(&t, refined, span);
                    }
                    None => self.set_var(&var, refined),
                },
                None => self.set_var(&var, refined),
            }
        }
    }

    /// Marks safe the variables of this frame whose user data all comes
    /// from the inputs of `checked`.
    fn sanitize_same_sources(&mut self, checked: &Taint, bits: u32) {
        let same =
            |s: &Source, t: &Source| s.module == t.module && s.span == t.span && s.what == t.what;
        let Some(env) = self.frame().env.as_mut() else {
            return;
        };
        let names: Vec<Rc<str>> = env
            .iter()
            .filter(|(_, v)| {
                let t = v.taint();
                t.is_tainted()
                    && t.sources
                        .iter()
                        .all(|s| checked.sources.iter().any(|c| same(s, c)))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for n in names {
            if let Some(v) = env.get_mut(&n) {
                *v = v.sanitized(bits);
            }
        }
    }

    fn collect_facts(&mut self, e: &Expr, truth: bool, out: &mut Vec<(Rc<str>, Fact)>) {
        match e {
            Expr::Un(UnOp::Not, inner) => self.collect_facts(inner, !truth, out),
            Expr::Un(UnOp::Deref | UnOp::Addr, inner) => self.collect_facts(inner, truth, out),
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
            // `(n > 16) != 0`, as `expect_true(n > 16)` expands: the test
            // itself.
            Expr::Bin(op @ (BinOp::Eq | BinOp::NotEq), l, r)
                if self.in_c() && is_test(l) && matches!(**r, Expr::Lit(Const::Int(0))) =>
            {
                self.collect_facts(l, (*op == BinOp::NotEq) == truth, out);
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
                    // `p == q` makes `p` NULL only where `q` is NULL for
                    // certain (see `null_source`).
                    let c = self.in_c();
                    let known = |it: &Self, v: &Value, e: &Expr| {
                        is_const(v) && !(c && matches!(v, Value::None) && !it.null_source(e))
                    };
                    let rv = self.eval(r);
                    if known(self, &rv, r) {
                        self.fact_on(l, Fact::OneOf(vec![rv]), out);
                    } else {
                        let lv = self.eval(l);
                        if known(self, &lv, l) {
                            self.fact_on(r, Fact::OneOf(vec![lv]), out);
                        }
                    }
                } else if self.in_c() {
                    // `n != -1`: a C integer is not that value; `p != NULL`:
                    // a pointer is not NULL. A call the test made reports
                    // nothing more when run again here: `buf && read(fd,
                    // buf, n) != n`.
                    self.guessed += 1;
                    let sides = (self.eval(l), self.eval(r));
                    self.guessed -= 1;
                    match sides {
                        (_, Value::Int(k)) => self.fact_on(l, Fact::Not(k), out),
                        (Value::Int(k), _) => self.fact_on(r, Fact::Not(k), out),
                        (_, Value::None) => self.fact_on(l, Fact::Not(0), out),
                        (Value::None, _) => self.fact_on(r, Fact::Not(0), out),
                        _ => {}
                    }
                }
            }
            // `i < n`: in C both sides are bounded by the other.
            Expr::Bin(op @ (BinOp::Lt | BinOp::LtE | BinOp::Gt | BinOp::GtE), l, r)
                if self.in_c() =>
            {
                let op = if truth {
                    *op
                } else {
                    match op {
                        BinOp::Lt => BinOp::GtE,
                        BinOp::LtE => BinOp::Gt,
                        BinOp::Gt => BinOp::LtE,
                        _ => BinOp::Lt,
                    }
                };
                let lv = self.eval(l);
                let rv = self.eval(r);
                if let Some((c, d)) = rv.bounds() {
                    if let Some(b) = below(op, c, d) {
                        self.fact_on(l, b, out);
                    }
                }
                if let Some((a, b)) = lv.bounds() {
                    let mirrored = match op {
                        BinOp::Lt => BinOp::Gt,
                        BinOp::LtE => BinOp::GtE,
                        BinOp::Gt => BinOp::Lt,
                        _ => BinOp::LtE,
                    };
                    if let Some(f) = below(mirrored, a, b) {
                        self.fact_on(r, f, out);
                    }
                }
            }
            Expr::Call { func, args, .. } if matches!(&**func, Expr::Name(_)) => {
                let Expr::Name(name) = &**func else {
                    return;
                };
                // Only library functions: project code is not a known check,
                // except C helpers named for what they check (`starts_with`).
                if !self.in_c()
                    && (self.get_var(name).is_some() || self.lookup_global(name).is_some())
                {
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
            // `if (p)`, `if (n)`: not NULL, not zero.
            Expr::Name(_) | Expr::Attr(..) if truth && self.in_c() => {
                self.fact_on(e, Fact::Not(0), out);
            }
            // `if (!p)`: NULL, or zero.
            Expr::Name(_) | Expr::Attr(..) if self.in_c() => {
                self.fact_on(e, Fact::Bounds(0, 0), out);
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
        match underef(e) {
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
            Expr::Attr(..) if self.in_c() => {
                // `strstr(req->path, "..")`; `r->method == GET` only
                // narrows the field.
                if matches!(fact, Fact::OneOf(_)) {
                    return;
                }
                if let Some(key) = place_key(e) {
                    let key: Rc<str> = key.into();
                    if !self.attr_vals.iter().any(|(k, _)| *k == key) {
                        self.attr_vals.push((key.clone(), e.clone()));
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
                // A C global is NULL only where this run set it so: other
                // functions may have set it before this one runs.
                Some(Value::None)
                    if self.in_c()
                        && self.frame_ref().func.is_some()
                        && !self.is_local(n)
                        && !self.c_globals.contains_key(n.as_str()) =>
                {
                    Value::clean()
                }
                Some(v) => v,
                None => {
                    let model = self.model();
                    model.builtin(self, n)
                }
            },
            Expr::Attr(base, name) => {
                let b = self.eval(base);
                let b = self.c_deref(base, b);
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
                let b = self.c_deref(base, b);
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
                let lv = self.eval_test(l);
                let and = *op == BinOp::And;
                match lv.truthy() {
                    Some(t) if t != and => lv,
                    Some(_) => self.eval_test(r),
                    None => {
                        let saved = self.frame().env.clone();
                        let saved_marks = self.null_marks();
                        self.frame().guesses += 1;
                        self.refine(l, and);
                        // `a() || b(&x)`: what the right side stores may have
                        // happened; what the left side's check found holds
                        // only there.
                        let refined = self.in_c().then(|| self.frame().env.clone());
                        let rv = self.eval_test(r);
                        self.frame().guesses -= 1;
                        let after = self.frame().env.take();
                        self.frame().env = match (saved, refined.flatten(), after) {
                            (Some(mut saved), Some(refined), Some(after)) => {
                                for (k, v) in after {
                                    if refined.get(&k) != Some(&v) {
                                        let joined = match saved.get(&k) {
                                            Some(s) => join(s, &v),
                                            None => v,
                                        };
                                        saved.insert(k, joined);
                                    }
                                }
                                Some(saved)
                            }
                            (saved, ..) => saved,
                        };
                        self.set_null_marks(saved_marks);
                        join(&lv, &rv)
                    }
                }
            }
            Expr::Bin(op @ (BinOp::Eq | BinOp::NotEq), l, r)
                if self.in_c()
                    && match (&**l, &**r) {
                        (x, Expr::Lit(Const::None)) | (Expr::Lit(Const::None), x) => {
                            self.addressed_null(x)
                        }
                        _ => false,
                    } =>
            {
                Value::clean()
            }
            Expr::Bin(op, l, r) => {
                let lv = self.eval(l);
                let rv = self.eval(r);
                self.binop(*op, &lv, &rv)
            }
            Expr::Un(UnOp::Deref, inner) => {
                let v = self.eval(inner);
                self.c_deref(inner, v)
            }
            Expr::Un(UnOp::Addr, inner) => self.eval(inner),
            Expr::Un(op, inner) => {
                let v = self.eval_test(inner);
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
                let t = self.eval_test(test);
                match t.truthy() {
                    Some(true) => self.eval(then),
                    Some(false) => self.eval(other),
                    None => {
                        self.frame().guesses += 1;
                        let a = self.eval(then);
                        let b = self.eval(other);
                        self.frame().guesses -= 1;
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
        let c = self.in_c();
        for a in args {
            let value = self.eval(&a.value);
            if let Some(name) = a.name.as_deref().filter(|n| secret_name(n)) {
                self.sink(&WEAK_RANDOM, &value, span, name);
            }
            let null_sure = c && matches!(value, Value::None) && self.null_source(&a.value);
            out.push(ArgVal {
                name: a.name.as_deref().map(Rc::from),
                value,
                spread: a.spread,
                var: match underef(&a.value) {
                    Expr::Name(n) => Some(n.as_str().into()),
                    _ => None,
                },
                place: if c { c_place(&a.value) } else { None },
                addressed: match uncast(&a.value) {
                    Expr::Un(UnOp::Addr, _) => true,
                    // Passed on: `raxFind(r, s, n, value)`.
                    Expr::Name(n) => c && self.addressed(n),
                    _ => false,
                },
                null_sure,
            });
        }
        out
    }

    fn eval_call(&mut self, func: &Expr, args: &[Arg], span: Span) -> Value {
        let argv = self.eval_args(args, span);
        self.c_outs.clear();
        self.ran = false;
        let v = if let Expr::Attr(recv_e, name) = func {
            let recv = self.eval(recv_e);
            let recv = self.c_deref(recv_e, recv);
            let (v, new_recv) = self.call_method(&recv, name, &argv, span);
            if let Some(nr) = new_recv {
                self.assign_expr(recv_e, nr, span);
            }
            v
        } else {
            let f = self.eval(func);
            self.call_value(&f, &argv, span)
        };
        // Buffers and out-parameters a C function filled.
        for (i, value) in std::mem::take(&mut self.c_outs) {
            if let Some(place) = argv.get(i).and_then(|a| a.place.as_ref()) {
                self.assign_expr(place, value, span);
            }
        }
        // A function the analysis did not follow may set the pointer `&p`
        // points to: `raxFind(rax, key, len, &found)`.
        if !self.ran {
            for a in argv
                .iter()
                .filter(|a| a.addressed && matches!(a.value, Value::None))
            {
                if let Some(place) = &a.place {
                    if matches!(self.eval(place), Value::None) {
                        self.assign_expr(place, Value::clean(), span);
                    }
                }
            }
        }
        v
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
                if let Some(v) = self.c_call_member(recv, name, args, span) {
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
                if let Some(v) = self.c_call_member(recv, name, args, span) {
                    return (v, None);
                }
                let model = self.model();
                model.call_method(self, recv, name, args, span)
            }
        }
    }

    /// C: a call through a function pointer member, `cmd->fn()`. The
    /// object's own member when it holds a function, else every project
    /// function the program stores in members of that name, when there
    /// are few (see `crate::cmembers`).
    fn c_call_member(
        &mut self,
        recv: &Value,
        name: &str,
        args: &[ArgVal],
        span: Span,
    ) -> Option<Value> {
        if !self.in_c() {
            return None;
        }
        if let Value::Obj(o) = recv {
            if let Some(f @ (Value::Func(_) | Value::OneOf(_))) = o.field(name).cloned() {
                return Some(self.call_value(&f, args, span));
            }
        }
        let index = match &self.c_members {
            Some(i) => i.clone(),
            None => {
                let i = Rc::new(crate::cmembers::member_functions(self.project));
                self.c_members = Some(i.clone());
                i
            }
        };
        let targets = index.get(name)?;
        if targets.len() > MAX_MEMBER_TARGETS {
            return None;
        }
        let mut out: Option<Value> = None;
        for f in targets {
            // A function of this file is in its scope; c_lookup finds the
            // other files' ones.
            let found = match self.get_var(f) {
                Some(v @ Value::Func(_)) => Some(v),
                _ => self.c_lookup(f),
            };
            if let Some(fv) = found {
                self.guessed += 1;
                let v = self.call_value(&fv, args, span);
                self.guessed -= 1;
                out = Some(match out {
                    None => v,
                    Some(p) => join(&p, &v),
                });
            }
        }
        out
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
        if self.quiet && self.frames.len() >= QUIET_DEPTH && !self.c_globals_tainted {
            let t =
                args_taint(args).union(&fv.bound.as_ref().map(|b| b.taint()).unwrap_or_default());
            // A C array is followed a little further: its size is known only
            // where it was declared. So is a NULL pointer, or a result not
            // checked for NULL, which the callee may read through.
            let c = matches!(
                self.project.modules[fv.module].lang,
                crate::Language::C | crate::Language::Cpp
            );
            let sized = self.frames.len() < QUIET_DEPTH + 3
                && args.iter().any(|a| {
                    a.value.alternatives().iter().any(|v| match v {
                        Value::Buf(_) => true,
                        Value::None => c,
                        Value::Ref(n, _) => c && crate::models::cnull::unchecked(n).is_some(),
                        _ => false,
                    })
                });
            if !t.is_tainted() && !sized {
                // C globals the skipped function sets are no longer known:
                // a sentinel it would replace (`first_free = -1`) must not
                // stay exact.
                if c {
                    for g in set_globals(&fv.def) {
                        self.c_globals
                            .insert(g.into(), Value::Unknown(Taint::clean()));
                    }
                }
                return (Value::Unknown(t), fv.bound.clone());
            }
        }
        let key = self.memo_key(fv, args);
        if let Some((v, s, outs, set)) = key.as_ref().and_then(|k| self.memo.get(k)).cloned() {
            self.ran = true;
            merge_outs(&mut self.c_outs, &outs);
            // `first_free = i;` in a function called before with the same
            // arguments happens again.
            for (g, val) in set.iter() {
                let t = val.taint();
                if t.is_tainted() {
                    self.c_globals_tainted = true;
                    self.c_globals_taint = self.c_globals_taint.union(&t);
                }
                self.c_globals.insert(g.clone(), val.clone());
            }
            return (v, s);
        }
        let c_callee = matches!(
            self.project.modules[fv.module].lang,
            crate::Language::C | crate::Language::Cpp
        );
        let globals_before = (key.is_some() && c_callee).then(|| self.c_globals.clone());
        let cutoffs = self.cutoffs;
        let before = std::mem::take(&mut self.c_outs);
        let result = self.run_function(fv, args, span);
        let outs: Rc<[(usize, Value)]> = std::mem::replace(&mut self.c_outs, before).into();
        merge_outs(&mut self.c_outs, &outs);
        if let Some(k) = key {
            if self.cutoffs == cutoffs {
                if self.memo.len() >= MAX_MEMO {
                    self.memo.clear();
                }
                let set: Rc<[(Rc<str>, Value)]> = match &globals_before {
                    Some(b) => self
                        .c_globals
                        .iter()
                        .filter(|(g, v)| b.get(*g) != Some(*v))
                        .map(|(g, v)| (g.clone(), v.clone()))
                        .collect(),
                    None => Rc::from([]),
                };
                self.memo
                    .insert(k, (result.0.clone(), result.1.clone(), outs, set));
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
        // A guessed call reports less (see `flag`): its result is its own.
        let _ = write!(
            key,
            "{:p}/{}/{}{}/{}:{route}",
            Rc::as_ptr(&fv.def),
            fv.module,
            u8::from(self.quiet),
            u8::from(self.guessed > 0),
            route.len()
        );
        // C functions read globals, which may hold user data by now.
        if matches!(
            self.project.modules[fv.module].lang,
            crate::Language::C | crate::Language::Cpp
        ) {
            let _ = write!(key, "@{}", self.c_globals_taint.sources.len());
        }
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
            // `&p` and a NULL for certain run the callee differently.
            let _ = write!(
                key,
                ",{}{}{}{}:{name}",
                if a.spread { "*" } else { "" },
                if a.addressed { "&" } else { "" },
                if a.null_sure { "!" } else { "" },
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
        let mut sure_nulls: Vec<Rc<str>> = Vec::new();
        let mut addressed: HashSet<Rc<str>> = HashSet::new();
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
                    if a.null_sure {
                        sure_nulls.push(Rc::from(p.name.as_str()));
                    }
                    if a.addressed {
                        addressed.insert(Rc::from(p.name.as_str()));
                    }
                }
                None => {
                    if let Some(t) = &spread_taint {
                        env.insert(p.name.as_str().into(), Value::Unknown(t.clone()));
                    }
                }
            }
        }
        // C: what the function leaves in pointer and reference parameters
        // reaches the caller's variables.
        // `char *p` is a copy of the caller's pointer: moving it moves only
        // the callee's copy. Through `char **pp` the callee moves the caller's.
        let mut by_value: Vec<bool> = Vec::new();
        let outs: Vec<(usize, Rc<str>)> = if matches!(
            self.project.modules[fv.module].lang,
            crate::Language::C | crate::Language::Cpp
        ) {
            params[idx..]
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p.ty.as_deref()
                        .is_some_and(|t| t.contains(['*', '&', '[']) && !t.contains("const"))
                })
                .map(|(i, p)| {
                    let t = p.ty.as_deref().unwrap_or("");
                    by_value.push(t.matches(['*', '[']).count() == 1 && !t.contains('&'));
                    (i, Rc::from(p.name.as_str()))
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut frame = Frame::new(fv.module, Some(fv.def.clone()), Some(env));
        frame.closure = fv.closure.clone();
        frame.scope = Scope::of_body(&fv.def.body, fv.scope.clone());
        frame.self_name = self_name;
        frame.span = span;
        frame.null_at = sure_nulls.into_iter().map(|n| (n, 0)).collect();
        frame.addressed = addressed;
        frame.outs = outs
            .iter()
            .map(|(_, n)| Out {
                name: n.clone(),
                last: None,
                entry: frame.env.as_ref().and_then(|e| e.get(n.as_ref())).cloned(),
                written: false,
                kept: false,
            })
            .collect();
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
        self.ran = true;
        self.exec_block(&fv.def.body);
        self.calls.pop();
        if self.live() {
            self.capture_self();
        }
        let frame = self.frames.pop().expect("frame");
        self.globals_at_exit(&frame);
        let positional: Vec<&ArgVal> = args.iter().filter(|a| a.name.is_none()).collect();
        let mut changed = Vec::new();
        for (((i, _), out), copy) in outs.iter().zip(frame.outs).zip(by_value) {
            // NULL on the paths that changed the pointer, and what it was
            // on the others.
            let v = match (out.last, out.entry) {
                (Some(Value::None), Some(entry)) if out.kept => Some(join(&Value::None, &entry)),
                (v, _) => v,
            };
            if let (Some(v), Some(a)) = (v, positional.get(*i)) {
                // `*dst++ = c` moves the callee's copy of the pointer only:
                // the caller's still points where it did, at what the
                // callee wrote.
                let v = match &a.value {
                    Value::Buf(ob) if copy => same_pointer(&v, ob),
                    _ => v,
                };
                if v != a.value {
                    changed.push((*i, v));
                }
            }
        }
        merge_outs(&mut self.c_outs, &changed);
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
            // `p->field` where `p` points into an array of structs.
            Value::Buf(b) => {
                let content = b.content.clone();
                self.get_attr(&content, name)
            }
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
        if matches!(m.lang, crate::Language::C | crate::Language::Cpp) {
            return self.c_lookup(name);
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

    fn c_index(&mut self) -> CIndex {
        if let Some(i) = &self.c_defs {
            return i.clone();
        }
        let mut index: HashMap<String, Vec<CDef>> = HashMap::new();
        let mut classes: HashMap<&str, Vec<(usize, &Rc<Class>)>> = HashMap::new();
        for (i, m) in self.project.modules.iter().enumerate() {
            if !matches!(m.lang, crate::Language::C | crate::Language::Cpp) {
                continue;
            }
            for s in &m.ir.body {
                let name = match s {
                    Stmt::FuncDef(f) => &f.name,
                    Stmt::Declare { name, .. } => name,
                    Stmt::ClassDef(c) => {
                        classes.entry(c.name.as_str()).or_default().push((i, c));
                        continue;
                    }
                    _ => continue,
                };
                let defs = index.entry(name.clone()).or_default();
                if !defs
                    .iter()
                    .any(|d| matches!(d, CDef::InModule(m) if *m == i))
                {
                    defs.push(CDef::InModule(i));
                }
            }
        }
        for (name, defs) in classes {
            // The declaration (bases, fields) with every method body.
            let (module, _) = *defs
                .iter()
                .max_by_key(|(_, c)| c.methods.len())
                .expect("a class");
            let mut merged = Class {
                name: name.to_string(),
                bases: Vec::new(),
                fields: Vec::new(),
                methods: Vec::new(),
                span: defs[0].1.span,
            };
            for (_, c) in &defs {
                for b in &c.bases {
                    if !merged.bases.contains(b) {
                        merged.bases.push(b.clone());
                    }
                }
                merged.fields.extend(c.fields.iter().cloned());
                merged.methods.extend(c.methods.iter().cloned());
                if c.span.line > 0 && merged.span.line == 0 {
                    merged.span = c.span;
                }
            }
            let mname = &self.project.modules[module].name;
            let cv = ClassVal {
                qualname: format!("{mname}.{name}").into(),
                def: Rc::new(merged),
                module,
                scope: None,
            };
            index
                .entry(name.to_string())
                .or_default()
                .push(CDef::Class(Rc::new(cv)));
        }
        let index = Rc::new(index);
        self.c_defs = Some(index.clone());
        index
    }

    /// A C or C++ function, class or global variable defined in another
    /// file. Definitions in the module itself, then in its directory win;
    /// up to four alternatives are kept when several files define the name.
    fn c_lookup(&mut self, name: &str) -> Option<Value> {
        if self.model().library_over_project(name) {
            return None;
        }
        let index = self.c_index();
        let found = index.get(name)?;
        if let Some(c) = found.iter().find_map(|d| match d {
            CDef::Class(c) => Some(c.clone()),
            _ => None,
        }) {
            return Some(Value::Class(c));
        }
        let here = self.module();
        let dir = |m: usize| {
            let p = &self.project.modules[m].path;
            p.rsplit_once('/')
                .map(|(d, _)| d.to_string())
                .unwrap_or_default()
        };
        let here_dir = dir(here);
        let rank = |m: usize| {
            if m == here {
                0
            } else if dir(m) == here_dir {
                1
            } else {
                2
            }
        };
        let modules: Vec<usize> = found
            .iter()
            .filter_map(|d| match d {
                CDef::InModule(m) => Some(*m),
                _ => None,
            })
            .collect();
        let best = modules.iter().map(|m| rank(*m)).min()?;
        let mut vals = Vec::new();
        for m in modules.into_iter().filter(|m| rank(*m) == best).take(4) {
            if m == here {
                continue;
            }
            if let Some(v) = self.module_globals(m).and_then(|g| g.get(name).cloned()) {
                vals.push(v);
            }
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
            outs: Vec::new(),
            exit_globals: None,
            jumps: 0,
            guesses: 0,
            on_memory: 0,
            null_at: HashMap::new(),
            addressed: HashSet::new(),
        }
    }
}

/// The parts of a value holding user data: an object keeps only the
/// fields that do, so other fields read as unknown rather than as one
/// entry's final value.
fn tainted_part(v: &Value) -> Option<Value> {
    match v {
        Value::Obj(o) => {
            let fields: Vec<(Rc<str>, Value)> = o
                .fields
                .iter()
                .filter_map(|(k, f)| tainted_part(f).map(|t| (k.clone(), t)))
                .collect();
            if fields.is_empty() && !o.taint.is_tainted() {
                return None;
            }
            let mut out = Obj::new(&o.class);
            out.def = o.def.clone();
            out.taint = o.taint.clone();
            out.fields = fields;
            Some(Value::Obj(Rc::new(out)))
        }
        other => other.taint().is_tainted().then(|| other.clone()),
    }
}

/// C globals after either of two paths.
fn join_globals(
    mut a: HashMap<Rc<str>, Value>,
    b: HashMap<Rc<str>, Value>,
) -> HashMap<Rc<str>, Value> {
    for (k, v) in b {
        match a.get_mut(&k) {
            Some(prev) => {
                if *prev != v {
                    *prev = join(prev, &v);
                }
            }
            None => {
                a.insert(k, v);
            }
        }
    }
    a
}

/// Names a C function assigns that are neither its parameters nor its
/// locals: the globals it sets directly.
fn set_globals(def: &Function) -> Vec<String> {
    fn walk(body: &[Stmt], locals: &mut HashSet<String>, out: &mut Vec<String>) {
        for s in body {
            match s {
                Stmt::Declare { name, .. } => {
                    locals.insert(name.clone());
                }
                Stmt::Assign {
                    target: Target::Name(n),
                    ..
                } if !locals.contains(n) && !out.contains(n) => out.push(n.clone()),
                Stmt::If { then, other, .. } => {
                    walk(then, locals, out);
                    walk(other, locals, out);
                }
                Stmt::Loop { body, .. } => walk(body, locals, out),
                Stmt::Switch { cases, .. } => {
                    for c in cases {
                        walk(&c.body, locals, out);
                    }
                }
                Stmt::Try {
                    body,
                    handlers,
                    finally,
                } => {
                    walk(body, locals, out);
                    for h in handlers {
                        walk(h, locals, out);
                    }
                    walk(finally, locals, out);
                }
                _ => {}
            }
        }
    }
    let mut locals: HashSet<String> = def.params.iter().map(|p| p.name.clone()).collect();
    let mut out = Vec::new();
    walk(&def.body, &mut locals, &mut out);
    // A local declared after an assignment of the same name.
    out.retain(|n| !locals.contains(n));
    out
}

/// Adds out-parameter values of one more callee (see `Interp::c_outs`).
fn merge_outs(into: &mut Vec<(usize, Value)>, more: &[(usize, Value)]) {
    for (i, v) in more {
        match into.iter_mut().find(|(j, _)| j == i) {
            Some((_, prev)) => *prev = join(prev, v),
            None => into.push((*i, v.clone())),
        }
    }
}

/// The variable or field a C pointer expression points into.
fn c_place(e: &Expr) -> Option<Expr> {
    match e {
        Expr::Name(_) => Some(e.clone()),
        Expr::Attr(b, _) => c_place(b).map(|_| e.clone()),
        // `read(fd, &len, 1)` into `u_char len` stores a byte.
        Expr::Cast(t, x)
            if matches!(**x, Expr::Name(_))
                && crate::lower::c::small_int_range(t).is_some()
                && !t.contains(['*', '[']) =>
        {
            Some(e.clone())
        }
        Expr::Cast(_, x) | Expr::Un(UnOp::Deref | UnOp::Addr, x) => c_place(x),
        Expr::Bin(BinOp::Add | BinOp::Sub, l, _) => c_place(l),
        Expr::Index(b, _) => c_place(b),
        _ => None,
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
        Value::Range(lo, hi, t, r) => {
            if t.is_tainted() {
                return None;
            }
            let _ = write!(out, "R{lo}:{hi}:{r};");
        }
        Value::Buf(b) => {
            let _ = write!(
                out,
                "B{}:{}:{:?}:{}:{}@{}/{}:{}<",
                b.size, b.elem, b.off, b.len.0, b.len.1, b.module, b.at.line, b.at.column
            );
            fingerprint(&b.content, out)?;
            out.push('>');
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
        Value::Buf(b) => reaching(&b.content, context),
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
        Value::Int(_) | Value::Range(..) => 2,
        Value::Float(_) => 3,
        Value::Str(_) => 4,
        Value::List(_) | Value::Dict(_) => 5,
        Value::Obj(_) => 6,
        Value::Func(_)
        | Value::Class(_)
        | Value::Unknown(_)
        | Value::Ref(..)
        | Value::OneOf(_)
        | Value::Buf(_) => return None,
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
        // `(n > 16) != 0` in C, `False == 0` in Python and PHP.
        (Value::Bool(x), Value::Int(y)) | (Value::Int(y), Value::Bool(x)) => {
            Some(i64::from(*x) == *y)
        }
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
/// A C buffer stays the same buffer, with what it holds unknown.
fn widen_changed(mut state: Env, entry: Option<&Env>) -> Env {
    for (k, v) in state.iter_mut() {
        let before = entry.and_then(|e| e.get(k));
        if before != Some(v) {
            *v = match widened_buf(v, before) {
                Some(b) => b,
                None => Value::Unknown(v.taint()),
            };
        }
    }
    state
}

/// A loop counter's values inside the loop and after it.
struct Counter {
    var: Rc<str>,
    inside: Value,
    exit: Value,
    inside_or_exit: Value,
}

/// Variables a block assigns or declares, once per assignment. (`&x` is
/// not marked in the IR, so writes through pointers are not seen.)
fn assigned_names(body: &[Stmt], out: &mut Vec<String>) {
    for s in body {
        match s {
            Stmt::Assign { target, .. } => target_names(target, out),
            Stmt::Declare { name, .. } => out.push(name.clone()),
            Stmt::If { then, other, .. } => {
                assigned_names(then, out);
                assigned_names(other, out);
            }
            Stmt::Loop { target, body, .. } => {
                if let Some(t) = target {
                    target_names(t, out);
                }
                assigned_names(body, out);
            }
            Stmt::Switch { cases, .. } => {
                for c in cases {
                    assigned_names(&c.body, out);
                }
            }
            Stmt::Try {
                body,
                handlers,
                finally,
            } => {
                assigned_names(body, out);
                for h in handlers {
                    assigned_names(h, out);
                }
                assigned_names(finally, out);
            }
            _ => {}
        }
    }
}

fn target_names(t: &Target, out: &mut Vec<String>) {
    match t {
        Target::Name(n) => out.push(n.clone()),
        Target::Tuple(ts) => ts.iter().for_each(|t| target_names(t, out)),
        _ => {}
    }
}

/// Whether `e` may give a pointer, not a number computed from one: `NULL`,
/// `p`, `s->bufr`, `f()`, not `12 + digits10(v)`.
fn pointer_expr(e: &Expr) -> bool {
    matches!(
        uncast(e),
        Expr::Lit(Const::None)
            | Expr::Name(_)
            | Expr::Attr(..)
            | Expr::Index(..)
            | Expr::Un(UnOp::Deref, _)
            | Expr::Call { .. }
    )
}

/// `e` without the casts around it: `(void **)&p`.
fn uncast(e: &Expr) -> &Expr {
    match e {
        Expr::Cast(_, x) => uncast(x),
        e => e,
    }
}

/// Whether the test reads a field, an element or what a pointer points to,
/// besides through the calls it makes.
fn reads_memory(e: &Expr) -> bool {
    match e {
        Expr::Attr(..) | Expr::Index(..) | Expr::Un(UnOp::Deref, _) => true,
        Expr::Bin(_, l, r) => reads_memory(l) || reads_memory(r),
        Expr::Un(_, x) | Expr::Cast(_, x) => reads_memory(x),
        _ => false,
    }
}

fn expr_names(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Name(n) => out.push(n.clone()),
        Expr::Attr(b, _) => expr_names(b, out),
        Expr::Index(b, k) => {
            expr_names(b, out);
            expr_names(k, out);
        }
        Expr::Bin(_, l, r) => {
            expr_names(l, out);
            expr_names(r, out);
        }
        Expr::Un(_, x) | Expr::Cast(_, x) => expr_names(x, out),
        Expr::Call { args, .. } => args.iter().for_each(|a| expr_names(&a.value, out)),
        _ => {}
    }
}

/// +1 or -1 when the block's own statements step `var` by one, once.
fn single_step(body: &[Stmt], var: &str) -> Option<i64> {
    let mut found = None;
    for s in body {
        if let Stmt::Assign {
            target: Target::Name(n),
            value: Expr::Bin(op @ (BinOp::Add | BinOp::Sub), l, r),
            ..
        } = s
        {
            if n == var
                && matches!(&**l, Expr::Name(x) if x == var)
                && matches!(&**r, Expr::Lit(Const::Int(1)))
            {
                if found.is_some() {
                    return None;
                }
                found = Some(if *op == BinOp::Add { 1 } else { -1 });
            }
        }
    }
    found
}

/// The bounds `x OP v` puts on `x`, for `v` in `lo..=hi`.
fn below(op: BinOp, lo: i64, hi: i64) -> Option<Fact> {
    Some(match op {
        BinOp::Lt if hi != i64::MIN => {
            Fact::Bounds(i64::MIN, hi.saturating_sub(1).min(i64::MAX - 1))
        }
        BinOp::LtE => Fact::Bounds(i64::MIN, hi),
        BinOp::Gt if lo != i64::MAX => {
            Fact::Bounds(lo.saturating_add(1).max(i64::MIN + 1), i64::MAX)
        }
        BinOp::GtE => Fact::Bounds(lo, i64::MAX),
        _ => return None,
    })
}

/// A C number after checks that bound it; None when they change nothing.
/// `v` with its pointers into `orig`'s buffer moved back to where `orig`
/// points.
fn same_pointer(v: &Value, orig: &Rc<Buf>) -> Value {
    match v {
        Value::Buf(b) if b.same(orig) => Value::Buf(Rc::new(Buf {
            off: orig.off,
            ..(**b).clone()
        })),
        Value::OneOf(alts) => {
            join_all(alts.iter().map(|a| same_pointer(a, orig))).unwrap_or_else(|| v.clone())
        }
        _ => v.clone(),
    }
}

/// `CODE_ANALYSIS_TRACE=1` prints the call stack of every report, for
/// debugging the analysis.
fn trace_reports() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("CODE_ANALYSIS_TRACE").is_some())
}

/// A call of a C library function that ends the process.
fn is_c_exit(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n)
        if matches!(n.as_str(), "exit" | "_exit" | "_Exit" | "abort" | "quick_exit")))
}

/// `c` is C, where a pointer known not to be 0 is not NULL.
fn narrow_numbers(cur: &Value, facts: &[Fact], c: bool) -> Option<Value> {
    if !facts
        .iter()
        .any(|f| matches!(f, Fact::Bounds(..) | Fact::Not(_)))
    {
        return None;
    }
    let one = |v: &Value| -> Option<Value> {
        let (mut lo, mut hi, t) = match v {
            Value::Int(_) => return Some(v.clone()),
            Value::Range(a, b, t, _) => (*a, *b, t.clone()),
            Value::Unknown(t) => (i64::MIN, i64::MAX, t.clone()),
            // Checked for NULL.
            Value::Buf(b)
                if b.nullable.is_some() && facts.iter().any(|f| matches!(f, Fact::Not(0))) =>
            {
                return Some(Value::Buf(Rc::new(Buf {
                    nullable: None,
                    ..(**b).clone()
                })))
            }
            // `if (!p)`: what may be NULL is NULL there.
            Value::Buf(b) if c && facts.iter().any(|f| matches!(f, Fact::Bounds(0, 0))) => {
                return b.nullable.map(|_| Value::None)
            }
            // A result of `fopen()` checked for NULL is the stream it opened.
            Value::Ref(name, t) if c && crate::models::cnull::unchecked(name).is_some() => {
                if facts.iter().any(|f| matches!(f, Fact::Not(0))) {
                    return Some(Value::Unknown(t.clone()));
                }
                if facts.iter().any(|f| matches!(f, Fact::Bounds(0, 0))) {
                    return Some(Value::None);
                }
                return Some(v.clone());
            }
            _ => return Some(v.clone()),
        };
        for _ in 0..2 {
            for f in facts {
                match f {
                    Fact::Bounds(a, b) => {
                        lo = lo.max(*a);
                        hi = hi.min(*b);
                    }
                    Fact::Not(k) if *k == lo && lo != i64::MAX => lo += 1,
                    Fact::Not(k) if *k == hi && hi != i64::MIN => hi -= 1,
                    _ => {}
                }
            }
        }
        // A path no value takes.
        (lo <= hi).then(|| Value::range(lo, hi, t))
    };
    let out = match cur {
        Value::OneOf(alts) => {
            let not_null = c && facts.iter().any(|f| matches!(f, Fact::Not(0)));
            let kept: Vec<Value> = alts
                .iter()
                .filter(|a| !(not_null && matches!(a, Value::None)))
                .filter(|a| match a.bounds() {
                    Some((x, y)) if x == y => facts.iter().all(|f| match f {
                        Fact::Bounds(lo, hi) => *lo <= x && x <= *hi,
                        Fact::Not(k) => *k != x,
                        _ => true,
                    }),
                    _ => true,
                })
                .filter_map(one)
                .collect();
            join_all(kept.into_iter())?
        }
        other => one(other)?,
    };
    (out != *cur).then_some(out)
}

/// A buffer, or one of several pointers into the same buffer, after a
/// loop: the pointer stays where it was only if every path left it there.
fn widened_buf(v: &Value, before: Option<&Value>) -> Option<Value> {
    let alts = v.alternatives();
    let first = match alts.first()? {
        Value::Buf(b) => b.clone(),
        _ => return None,
    };
    let mut off = first.off;
    for a in &alts {
        match a {
            Value::Buf(b) if b.same(&first) => {
                if b.off != off {
                    off = None;
                }
            }
            _ => return None,
        }
    }
    if let Some(Value::Buf(b)) = before {
        if b.same(&first) && b.off != off {
            off = None;
        }
    }
    Some(Value::Buf(Rc::new(Buf {
        off,
        len: (0, UNBOUNDED),
        len_sure: false,
        content: Value::Unknown(v.taint()),
        ..(*first).clone()
    })))
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
    let Expr::Name(n) = underef(base) else {
        return None;
    };
    match &**key {
        Expr::Lit(Const::Int(i)) => Some(format!("{n}[{i}]")),
        Expr::Lit(Const::Str(k)) => Some(format!("{n}[{k:?}]")),
        _ => None,
    }
}

/// `ctx.qry.path` for a chain of fields on a name.
fn place_key(e: &Expr) -> Option<String> {
    match underef(e) {
        Expr::Name(n) => Some(n.clone()),
        Expr::Attr(b, f) => place_key(b).map(|k| format!("{k}.{f}")),
        _ => None,
    }
}

/// The variable an expression is rooted at (`x`, `x.y`, `x[0]`).
pub fn root_var(e: &Expr) -> Option<Rc<str>> {
    match underef(e) {
        Expr::Name(n) => Some(n.as_str().into()),
        _ => None,
    }
}

/// Truth of a constant a call result is compared with: `== 1`, `=== false`.
fn const_truth(e: &Expr) -> Option<bool> {
    match e {
        Expr::Lit(Const::Bool(b)) => Some(*b),
        Expr::Lit(Const::Int(1)) => Some(true),
        Expr::Lit(Const::Int(0)) | Expr::Lit(Const::None) => Some(false),
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

/// A comparison or a logical combination of them: true or false.
fn is_test(e: &Expr) -> bool {
    match e {
        Expr::Bin(op, ..) => matches!(
            op,
            BinOp::Lt
                | BinOp::LtE
                | BinOp::Gt
                | BinOp::GtE
                | BinOp::Eq
                | BinOp::NotEq
                | BinOp::And
                | BinOp::Or
        ),
        Expr::Un(UnOp::Not, _) => true,
        _ => false,
    }
}
