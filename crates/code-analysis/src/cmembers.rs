//! C function pointers kept in struct members: which project functions a
//! call like `conn->type->read(conn, buf, n)` or `c->fn(c, ev, data)` can
//! reach when the analysis did not see the object being filled. A member
//! gets a function by assignment (`c->fn = handler`), by a struct
//! initializer (`{"objects", objects_fn}`, `{.read = sock_read}`), or by a
//! parameter stored in it (`c->fn = fn` in `mg_listen(..., fn, ...)`)
//! that callers pass a function to, followed through wrappers.

use crate::ir::{Class, Expr, Function, Stmt, Target};
use crate::project::Project;
use crate::Language;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Project functions by the member names they are stored in.
pub fn member_functions(project: &Project) -> HashMap<String, Vec<String>> {
    let mut functions: HashSet<&str> = HashSet::new();
    let mut structs: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut bodies: Vec<&Function> = Vec::new();
    let mut top: Vec<&Stmt> = Vec::new();
    for m in &project.modules {
        if !matches!(m.lang, Language::C | Language::Cpp) {
            continue;
        }
        for s in &m.ir.body {
            match s {
                Stmt::FuncDef(f) => {
                    functions.insert(&f.name);
                    bodies.push(f);
                }
                Stmt::ClassDef(c) => {
                    let fields = field_names(c);
                    let slot = structs.entry(&c.name).or_default();
                    if fields.len() > slot.len() {
                        *slot = fields;
                    }
                    bodies.extend(c.methods.iter().map(Rc::as_ref));
                }
                other => top.push(other),
            }
        }
    }
    let mut found = Found {
        functions: &functions,
        structs: &structs,
        members: HashMap::new(),
        params: HashSet::new(),
        calls: Vec::new(),
    };
    for s in top {
        found.stmt(s, None);
    }
    for f in &bodies {
        for s in &f.body {
            found.stmt(s, Some(f));
        }
    }
    // Parameters stored in members, through the functions that pass them on.
    for _ in 0..6 {
        let mut grew = false;
        for (caller, callee, k, arg) in &found.calls {
            let stored: Vec<String> = found
                .params
                .iter()
                .filter(|(f, i, _)| f == callee && i == k)
                .map(|(_, _, m)| m.clone())
                .collect();
            for member in stored {
                if functions.contains(arg.as_str()) {
                    grew |= add(&mut found.members, &member, arg);
                } else if let Some(j) = caller.and_then(|c| param_index(c, arg)) {
                    let name = caller.map(|c| c.name.clone()).unwrap_or_default();
                    grew |= found.params.insert((name, j, member));
                }
            }
        }
        if !grew {
            break;
        }
    }
    found.members
}

fn field_names(c: &Class) -> Vec<&str> {
    c.fields
        .iter()
        .filter_map(|f| match f {
            Stmt::Declare { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

fn param_index(f: &Function, name: &str) -> Option<usize> {
    f.params.iter().position(|p| p.name == name)
}

fn add(members: &mut HashMap<String, Vec<String>>, member: &str, func: &str) -> bool {
    let list = members.entry(member.to_string()).or_default();
    if list.iter().any(|f| f == func) {
        return false;
    }
    list.push(func.to_string());
    true
}

struct Found<'a> {
    functions: &'a HashSet<&'a str>,
    structs: &'a HashMap<&'a str, Vec<&'a str>>,
    members: HashMap<String, Vec<String>>,
    /// (function, parameter index, member) for `x->member = param`.
    params: HashSet<(String, usize, String)>,
    /// Calls passing a plain name: (caller, callee, argument index, name).
    calls: Vec<(Option<&'a Function>, String, usize, String)>,
}

impl<'a> Found<'a> {
    fn stmt(&mut self, s: &'a Stmt, func: Option<&'a Function>) {
        match s {
            Stmt::Assign { target, value, .. } => {
                if let (Target::Attr(_, member), Expr::Name(n)) = (target, value) {
                    if self.functions.contains(n.as_str()) {
                        add(&mut self.members, member, n);
                    } else if let Some(i) = func.and_then(|f| param_index(f, n)) {
                        let name = func.map(|f| f.name.clone()).unwrap_or_default();
                        self.params.insert((name, i, member.clone()));
                    }
                }
                self.expr(value, func);
            }
            Stmt::Declare {
                ty, value: Some(v), ..
            } => {
                self.initializer(ty, v);
                self.expr(v, func);
            }
            Stmt::Expr(e, _) | Stmt::Raw(e, _) => self.expr(e, func),
            Stmt::Return(Some(e), _) => self.expr(e, func),
            Stmt::If { test, then, other } => {
                self.expr(test, func);
                for s in then.iter().chain(other) {
                    self.stmt(s, func);
                }
            }
            Stmt::Loop {
                iter, test, body, ..
            } => {
                for e in iter.iter().chain(test) {
                    self.expr(e, func);
                }
                for s in body {
                    self.stmt(s, func);
                }
            }
            Stmt::Switch { subject, cases, .. } => {
                self.expr(subject, func);
                for c in cases {
                    for s in &c.body {
                        self.stmt(s, func);
                    }
                }
            }
            Stmt::Try {
                body,
                handlers,
                finally,
            } => {
                for s in body.iter().chain(handlers.iter().flatten()).chain(finally) {
                    self.stmt(s, func);
                }
            }
            _ => {}
        }
    }

    fn expr(&mut self, e: &'a Expr, func: Option<&'a Function>) {
        match e {
            Expr::Call { func: f, args, .. } => {
                if let Expr::Name(callee) = &**f {
                    for (k, a) in args.iter().enumerate() {
                        if let Expr::Name(n) = &a.value {
                            self.calls.push((func, callee.clone(), k, n.clone()));
                        }
                    }
                }
                self.expr(f, func);
                for a in args {
                    self.expr(&a.value, func);
                }
            }
            Expr::New { args, .. } => {
                for a in args {
                    self.expr(&a.value, func);
                }
            }
            Expr::Attr(b, _) | Expr::Un(_, b) | Expr::Cast(_, b) => self.expr(b, func),
            Expr::Index(a, b) | Expr::Bin(_, a, b) => {
                self.expr(a, func);
                self.expr(b, func);
            }
            Expr::Cond { test, then, other } => {
                self.expr(test, func);
                self.expr(then, func);
                self.expr(other, func);
            }
            Expr::List(items) | Expr::Concat(items) | Expr::Other(items) => {
                for i in items {
                    self.expr(i, func);
                }
            }
            Expr::Dict(pairs) => {
                for (k, v) in pairs {
                    self.expr(k, func);
                    self.expr(v, func);
                }
            }
            _ => {}
        }
    }

    /// `struct S x = {...}` and arrays of them.
    fn initializer(&mut self, ty: &str, value: &Expr) {
        let base: String = ty
            .split(['[', '*', '&'])
            .next()
            .unwrap_or("")
            .split_whitespace()
            .filter(|w| !matches!(*w, "const" | "struct" | "union" | "static" | "volatile"))
            .collect::<Vec<_>>()
            .join(" ");
        let Some(fields) = self.structs.get(base.as_str()) else {
            return;
        };
        let fields = fields.clone();
        let one = |v: &Expr, members: &mut HashMap<String, Vec<String>>| match v {
            Expr::List(items) => {
                for (f, item) in fields.iter().zip(items) {
                    if let Expr::Name(n) = item {
                        if self.functions.contains(n.as_str()) {
                            add(members, f, n);
                        }
                    }
                }
            }
            Expr::Dict(pairs) => {
                for (k, item) in pairs {
                    let member = match k {
                        Expr::Lit(crate::ir::Const::Str(s)) => Some(s.as_str()),
                        Expr::Lit(crate::ir::Const::Int(i)) => usize::try_from(*i)
                            .ok()
                            .and_then(|i| fields.get(i).copied()),
                        _ => None,
                    };
                    if let (Some(m), Expr::Name(n)) = (member, item) {
                        if self.functions.contains(n.as_str()) {
                            add(members, m, n);
                        }
                    }
                }
            }
            _ => {}
        };
        let mut members = std::mem::take(&mut self.members);
        match value {
            Expr::List(items) if ty.contains('[') => {
                for i in items {
                    one(i, &mut members);
                }
            }
            v => one(v, &mut members),
        }
        self.members = members;
    }
}
