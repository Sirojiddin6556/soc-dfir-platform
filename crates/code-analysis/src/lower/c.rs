//! C and C++ front end (tree-sitter-c, tree-sitter-cpp). The source is
//! run through [`super::cpre`] first, so macros are expanded and only the
//! Linux side of `#ifdef _WIN32` remains.
//!
//! Pointers are not modelled as addresses: `&x` and `*p` stand for the
//! value itself, which is what taint needs (`recv(s, buf + n, ...)` fills
//! `buf`, `*p` reads what `p` points at). C++ methods take `this` as their
//! first parameter and constructors are named `__init__`, as in the other
//! front ends; a method defined outside its class (`void A::f() {}`) is
//! emitted in a class definition of its own, which the interpreter merges
//! with the declaration by name.
//!
//! A few constructs become calls the C model implements: `std::cin >> x`
//! assigns `__c_stdin()` to `x`, `new T[n]` calls `__c_new_array`, and
//! `delete p` calls `__c_delete`.

use super::{named_children, span, test_span, text};
use crate::ir::*;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

pub fn lower(root: Node, src: &str) -> Module {
    let l = Lower {
        src,
        depth: Cell::new(0),
        hoisted: RefCell::new(Vec::new()),
        post: RefCell::new(Vec::new()),
        class_stack: RefCell::new(Vec::new()),
        outside: RefCell::new(Vec::new()),
        classes: RefCell::new(Vec::new()),
        locals: RefCell::new(Vec::new()),
        aliases: RefCell::new(Vec::new()),
        gotos: RefCell::new(Vec::new()),
        unions: union_types(root, src),
        types: RefCell::new(vec![HashMap::new()]),
        arrays: RefCell::new(vec![HashMap::new()]),
        deep: RefCell::new(vec![HashSet::new()]),
        declared: RefCell::new(vec![HashMap::new()]),
    };
    let mut body = Vec::new();
    l.top_level(root, &mut body);
    // Methods defined outside their class, grouped by class.
    let mut extra: HashMap<String, Vec<Rc<Function>>> = HashMap::new();
    let mut order = Vec::new();
    for (class, f) in l.outside.take() {
        if !extra.contains_key(&class) {
            order.push(class.clone());
        }
        extra.entry(class).or_default().push(f);
    }
    let mut classes = l.classes.take();
    for c in classes.iter_mut() {
        if let Some(ms) = extra.remove(&c.name) {
            c.methods.extend(ms);
        }
    }
    for name in order {
        if let Some(ms) = extra.remove(&name) {
            classes.push(Class {
                name,
                bases: Vec::new(),
                fields: Vec::new(),
                methods: ms,
                span: Span::default(),
            });
        }
    }
    let mut out: Vec<Stmt> = classes
        .into_iter()
        .map(|c| Stmt::ClassDef(Rc::new(c)))
        .collect();
    // Functions exist before any code runs; global variables follow.
    let (funcs, rest): (Vec<Stmt>, Vec<Stmt>) = body
        .into_iter()
        .partition(|s| matches!(s, Stmt::FuncDef(_)));
    out.extend(funcs);
    out.extend(rest);
    Module {
        body: out,
        package: None,
    }
}

struct Lower<'s> {
    src: &'s str,
    depth: Cell<u32>,
    /// Assignments used as values, run before the statement holding them.
    hoisted: RefCell<Vec<Stmt>>,
    /// Postfix updates (`*p++ = c`), run after the statement holding them:
    /// the statement sees the old value.
    post: RefCell<Vec<Stmt>>,
    /// Classes being lowered, innermost last: their field names, so a
    /// method's bare `x` reads `this->x`.
    class_stack: RefCell<Vec<(String, Vec<String>)>>,
    /// `void A::f() {}`: (class, method).
    outside: RefCell<Vec<(String, Rc<Function>)>>,
    classes: RefCell<Vec<Class>>,
    /// Parameters and locals of the functions being lowered, innermost
    /// last: they hide fields of the same name.
    locals: RefCell<Vec<Vec<String>>>,
    /// Per function being lowered: references and pointers to a local
    /// that are never pointed elsewhere (`T &r = x;`, `T *p = &x;`), which
    /// stand for the variable itself.
    aliases: RefCell<Vec<HashMap<String, String>>>,
    /// Union types of the file: all their members share one field.
    unions: HashSet<String>,
    /// Per function being lowered: the code from each label of its body
    /// to its end, for `goto` (`None` when too long to copy).
    gotos: RefCell<Vec<LabelTails>>,
    /// Declared types of variables, file scope first, then the functions
    /// being lowered.
    types: RefCell<Vec<HashMap<String, String>>>,
    /// Byte sizes of the arrays declared in the same scopes, for
    /// `sizeof(buf)`; None for variables that are not arrays.
    arrays: RefCell<Vec<HashMap<String, Option<Expr>>>>,
    /// Pointers to pointers (`char **pp`) in the same scopes: with `&x`
    /// read as `x`, `*pp = p` sets the pointer `pp` stands for.
    deep: RefCell<Vec<HashSet<String>>>,
    /// Full declared types (`u_char *`, `char[10]`) in the same scopes.
    declared: RefCell<Vec<HashMap<String, String>>>,
}

/// Names of the union types a file defines (`union U {...}`,
/// `typedef union {...} U;`).
fn union_types(root: Node, src: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut todo = vec![root];
    while let Some(n) = todo.pop() {
        if n.kind() == "union_specifier" && n.child_by_field_name("body").is_some() {
            if let Some(name) = n.child_by_field_name("name") {
                out.insert(text(name, src).to_string());
            }
            if let Some(p) = n.parent().filter(|p| p.kind() == "type_definition") {
                for d in crate::lower::field_children(p, "declarator") {
                    out.insert(text(d, src).trim().to_string());
                }
            }
        }
        if todo.len() < 100_000 {
            todo.extend(named_children(n));
        }
    }
    out
}

/// `const struct U *` -> `U`.
fn base_type(ty: &str) -> String {
    ty.split_whitespace()
        .filter(|w| !matches!(*w, "const" | "struct" | "union" | "volatile" | "class"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(['*', '&', ' '])
        .to_string()
}

/// The statements from each label of a function to its end.
type LabelTails = HashMap<String, Option<Rc<Vec<Stmt>>>>;

const MAX_DEPTH: u32 = 400;
/// Statements a `goto` may copy from its label to the function's end.
const MAX_GOTO_TAIL: usize = 200;

/// Statements in `s`, nested ones included.
fn stmt_size(s: &Stmt) -> usize {
    1 + match s {
        Stmt::If { then, other, .. } => then.iter().chain(other).map(stmt_size).sum(),
        Stmt::Loop { body, .. } => body.iter().map(stmt_size).sum(),
        Stmt::Switch { cases, .. } => cases
            .iter()
            .flat_map(|c| c.body.iter())
            .map(stmt_size)
            .sum(),
        Stmt::Try {
            body,
            handlers,
            finally,
        } => body
            .iter()
            .chain(handlers.iter().flatten())
            .chain(finally)
            .map(stmt_size)
            .sum(),
        _ => 0,
    }
}

/// Bytes of a type for `sizeof`, on a 64-bit Linux build.
pub(crate) fn size_of_type(ty: &str) -> Option<i64> {
    let t = ty.trim();
    if t.ends_with('*') {
        return Some(8);
    }
    Some(match t {
        "char" | "signed char" | "unsigned char" | "bool" | "int8_t" | "uint8_t" => 1,
        "short" | "unsigned short" | "short int" | "int16_t" | "uint16_t" => 2,
        "int" | "unsigned int" | "unsigned" | "signed int" | "float" | "int32_t" | "uint32_t"
        | "wchar_t" => 4,
        "long" | "unsigned long" | "long int" | "long long" | "unsigned long long" | "double"
        | "size_t" | "ssize_t" | "int64_t" | "uint64_t" | "intptr_t" | "uintptr_t"
        | "ptrdiff_t" => 8,
        _ => return None,
    })
}

fn call(name: &str, args: Vec<Expr>, sp: Span) -> Expr {
    Expr::Call {
        func: Box::new(Expr::Name(name.into())),
        args: args.into_iter().map(positional).collect(),
        span: sp,
    }
}

fn positional(value: Expr) -> Arg {
    Arg {
        name: None,
        value,
        spread: false,
    }
}

/// Text of a C escape sequence (`\n`, `\x41`, `\0`).
fn unescape(seq: &str) -> String {
    let body = seq.strip_prefix('\\').unwrap_or(seq);
    match body {
        "n" => "\n".into(),
        "t" => "\t".into(),
        "r" => "\r".into(),
        "v" => "\u{b}".into(),
        "f" => "\u{c}".into(),
        "a" => "\u{7}".into(),
        "b" => "\u{8}".into(),
        "e" => "\u{1b}".into(),
        _ => {
            if let Some(h) = body.strip_prefix('x') {
                return u32::from_str_radix(h, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(String::from)
                    .unwrap_or_default();
            }
            if body.chars().all(|c| c.is_digit(8)) && !body.is_empty() {
                return u32::from_str_radix(body, 8)
                    .ok()
                    .and_then(char::from_u32)
                    .map(String::from)
                    .unwrap_or_default();
            }
            body.to_string()
        }
    }
}

impl<'s> Lower<'s> {
    fn text(&self, n: Node) -> &'s str {
        text(n, self.src)
    }

    // ----- top level -----

    fn top_level(&self, node: Node, out: &mut Vec<Stmt>) {
        for c in named_children(node) {
            self.top_item(c, out);
        }
    }

    fn top_item(&self, c: Node, out: &mut Vec<Stmt>) {
        match c.kind() {
            "function_definition" => self.function_definition(c, out),
            "declaration" => self.declaration(c, out),
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                self.class(c);
            }
            // `namespace n { ... }`, `extern "C" { ... }` or `extern "C" f() {}`
            "namespace_definition" | "linkage_specification" => {
                if let Some(b) = c.child_by_field_name("body") {
                    if b.kind() == "declaration_list" {
                        self.top_level(b, out);
                    } else {
                        self.top_item(b, out);
                    }
                }
            }
            "declaration_list" | "template_declaration" | "export_declaration" => {
                self.top_level(c, out)
            }
            "type_definition" => self.type_definition(c),
            "expression_statement" => self.stmt(c, out),
            _ => {}
        }
    }

    /// The name a declarator declares, and its type suffix (`*`, `[100]`).
    fn declarator_name(&self, d: Node) -> (String, String) {
        let mut suffix = String::new();
        let mut cur = d;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 32 {
                break;
            }
            match cur.kind() {
                "identifier" | "field_identifier" | "type_identifier" | "operator_name"
                | "destructor_name" => return (self.text(cur).to_string(), suffix),
                "qualified_identifier" => {
                    return (self.text(cur).to_string(), suffix);
                }
                "pointer_declarator" | "abstract_pointer_declarator" => suffix.push('*'),
                "reference_declarator" => suffix.push('&'),
                "array_declarator" => {
                    let size = cur
                        .child_by_field_name("size")
                        .map(|s| self.text(s).to_string())
                        .unwrap_or_default();
                    suffix.push_str(&format!("[{size}]"));
                }
                "init_declarator"
                | "function_declarator"
                | "parenthesized_declarator"
                | "attributed_declarator" => {}
                _ => {}
            }
            let next = cur.child_by_field_name("declarator").or_else(|| {
                named_children(cur)
                    .into_iter()
                    .find(|c| c.kind().contains("declarator") || c.kind() == "identifier")
            });
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        (String::new(), suffix)
    }

    /// A member declaration that declares a method (`int f(int);`), as
    /// opposed to a function pointer (`int (*f)(int);`).
    fn declares_method(&self, d: Node) -> bool {
        self.find_function_declarator(d)
            .and_then(|f| f.child_by_field_name("declarator"))
            .is_some_and(|n| n.kind() != "parenthesized_declarator")
    }

    fn find_function_declarator<'t>(&self, d: Node<'t>) -> Option<Node<'t>> {
        let mut cur = d;
        for _ in 0..16 {
            if cur.kind() == "function_declarator" {
                return Some(cur);
            }
            cur = cur.child_by_field_name("declarator")?;
        }
        None
    }

    fn params(&self, fd: Node) -> Vec<Param> {
        let Some(list) = fd.child_by_field_name("parameters") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (i, p) in named_children(list).into_iter().enumerate() {
            match p.kind() {
                "parameter_declaration" | "optional_parameter_declaration" => {
                    let ty = p
                        .child_by_field_name("type")
                        .map(|t| self.text(t).to_string())
                        .unwrap_or_default();
                    if ty == "void" && p.child_by_field_name("declarator").is_none() {
                        continue;
                    }
                    let (name, suffix) = p
                        .child_by_field_name("declarator")
                        .map(|d| self.declarator_name(d))
                        .unwrap_or_default();
                    let name = if name.is_empty() {
                        format!("__arg{i}")
                    } else {
                        name
                    };
                    let default = p.child_by_field_name("default_value").map(|v| self.expr(v));
                    out.push(Param {
                        name,
                        ty: Some(format!("{ty}{suffix}")),
                        default,
                        variadic: false,
                    });
                }
                "variadic_parameter" | "variadic_parameter_declaration" => out.push(Param {
                    name: "__va_args".into(),
                    ty: None,
                    default: None,
                    variadic: true,
                }),
                _ => {}
            }
        }
        out
    }

    fn function_definition(&self, node: Node, out: &mut Vec<Stmt>) {
        let Some(d) = node.child_by_field_name("declarator") else {
            return;
        };
        let Some(fd) = self.find_function_declarator(d) else {
            return;
        };
        let Some(name_node) = fd.child_by_field_name("declarator") else {
            return;
        };
        let full = self.text(name_node).trim().to_string();
        // `A::f` outside the class body, `ns::f` in a namespace.
        let (class, name) = match full.rsplit_once("::") {
            Some((scope, n)) if name_node.kind() == "qualified_identifier" => {
                let scope = scope
                    .rsplit("::")
                    .next()
                    .unwrap_or(scope)
                    .trim()
                    .to_string();
                (Some(scope), n.trim().to_string())
            }
            _ => (None, full),
        };
        let current_class = self.class_stack.borrow().last().map(|c| c.0.clone());
        let class = class.or(current_class);
        let mut params = self.params(fd);
        let mut body = Vec::new();
        if let Some(cls) = &class {
            params.insert(
                0,
                Param {
                    name: "this".into(),
                    ty: Some(cls.clone()),
                    default: None,
                    variadic: false,
                },
            );
            // `A(int a) : x(a) {}`
            for c in named_children(node) {
                if c.kind() == "field_initializer_list" {
                    for fi in named_children(c) {
                        let parts = named_children(fi);
                        let (Some(f), Some(args)) = (parts.first(), parts.last()) else {
                            continue;
                        };
                        let value = named_children(*args)
                            .first()
                            .map(|a| self.expr(*a))
                            .unwrap_or(Expr::Lit(Const::None));
                        body.push(Stmt::Assign {
                            target: Target::Attr(
                                Box::new(Expr::Name("this".into())),
                                self.text(*f).to_string(),
                            ),
                            value,
                            span: span(fi),
                        });
                    }
                }
            }
        }
        self.locals
            .borrow_mut()
            .push(params.iter().map(|p| p.name.clone()).collect());
        self.types.borrow_mut().push(
            params
                .iter()
                .map(|p| (p.name.clone(), base_type(p.ty.as_deref().unwrap_or(""))))
                .collect(),
        );
        // Parameters are pointers even when written `char buf[]`.
        self.arrays
            .borrow_mut()
            .push(params.iter().map(|p| (p.name.clone(), None)).collect());
        self.deep.borrow_mut().push(
            params
                .iter()
                .filter(|p| p.ty.as_deref().is_some_and(is_deep_pointer))
                .map(|p| p.name.clone())
                .collect(),
        );
        self.declared.borrow_mut().push(
            params
                .iter()
                .map(|p| (p.name.clone(), p.ty.clone().unwrap_or_default()))
                .collect(),
        );
        if let Some(b) = node.child_by_field_name("body") {
            self.aliases.borrow_mut().push(self.find_aliases(b));
            self.gotos.borrow_mut().push(HashMap::new());
            self.label_tails(b);
            self.block(b, &mut body);
            self.gotos.borrow_mut().pop();
            self.aliases.borrow_mut().pop();
        }
        self.types.borrow_mut().pop();
        self.arrays.borrow_mut().pop();
        self.deep.borrow_mut().pop();
        self.declared.borrow_mut().pop();
        self.locals.borrow_mut().pop();
        let fname = match &class {
            Some(cls) if name == *cls || name.rsplit("::").next() == Some(cls.as_str()) => {
                "__init__".to_string()
            }
            _ => name,
        };
        let f = Rc::new(Function {
            name: fname,
            params,
            body,
            decorators: Vec::new(),
            span: span(node),
        });
        let inside_class = !self.class_stack.borrow().is_empty();
        match class {
            Some(cls) if !inside_class => self.outside.borrow_mut().push((cls, f)),
            Some(_) => out.push(Stmt::FuncDef(f)),
            None => out.push(Stmt::FuncDef(f)),
        }
    }

    /// A C++ class (or a struct with methods): lowered into `self.classes`.
    /// `typedef struct {...} T;`: the struct is lowered as class `T`.
    fn type_definition(&self, node: Node) {
        let Some(t) = node.child_by_field_name("type") else {
            return;
        };
        if !matches!(
            t.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            return;
        }
        let alias = crate::lower::field_children(node, "declarator")
            .into_iter()
            .find(|d| d.kind() == "type_identifier")
            .map(|d| self.text(d).to_string());
        if let Some(n) = t.child_by_field_name("name") {
            self.class(t);
            // `typedef struct _S {...} S;` names the struct twice.
            match alias {
                Some(a) if a != self.text(n) => {
                    self.class_named(t, Some(a));
                }
                _ => {}
            }
            return;
        }
        if let Some(a) = alias {
            self.class_named(t, Some(a));
        }
    }

    fn class(&self, node: Node) -> Option<String> {
        self.class_named(node, None)
    }

    fn class_named(&self, node: Node, typedef: Option<String>) -> Option<String> {
        let name = match typedef {
            Some(n) => n,
            None => node.child_by_field_name("name").map(|n| {
                let t = self.text(n);
                t.rsplit("::").next().unwrap_or(t).to_string()
            })?,
        };
        let body = node.child_by_field_name("body")?;
        let mut bases = Vec::new();
        for c in named_children(node) {
            if c.kind() == "base_class_clause" {
                for b in named_children(c) {
                    if matches!(
                        b.kind(),
                        "type_identifier" | "qualified_identifier" | "template_type"
                    ) {
                        let t = self.text(b);
                        let t = t.split('<').next().unwrap_or(t);
                        bases.push(t.rsplit("::").next().unwrap_or(t).trim().to_string());
                    }
                }
            }
        }
        // Field names first, so method bodies can refer to them.
        let mut field_names = Vec::new();
        for m in named_children(body) {
            if m.kind() == "field_declaration" {
                for d in crate::lower::field_children(m, "declarator") {
                    if !self.declares_method(d) {
                        let (n, _) = self.declarator_name(d);
                        if !n.is_empty() {
                            field_names.push(n);
                        }
                    }
                }
            }
        }
        self.class_stack
            .borrow_mut()
            .push((name.clone(), field_names));
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        for m in named_children(body) {
            match m.kind() {
                "function_definition" => {
                    let mut tmp = Vec::new();
                    self.function_definition(m, &mut tmp);
                    for s in tmp {
                        if let Stmt::FuncDef(f) = s {
                            methods.push(f);
                        }
                    }
                }
                "template_declaration" => {
                    for c in named_children(m) {
                        if c.kind() == "function_definition" {
                            let mut tmp = Vec::new();
                            self.function_definition(c, &mut tmp);
                            for s in tmp {
                                if let Stmt::FuncDef(f) = s {
                                    methods.push(f);
                                }
                            }
                        }
                    }
                }
                "field_declaration" => {
                    let ty = m
                        .child_by_field_name("type")
                        .map(|t| self.text(t).to_string())
                        .unwrap_or_default();
                    if let Some(t) = m.child_by_field_name("type") {
                        if matches!(t.kind(), "class_specifier" | "struct_specifier") {
                            self.class(t);
                        }
                    }
                    for d in crate::lower::field_children(m, "declarator") {
                        if self.declares_method(d) {
                            continue;
                        }
                        let (n, suffix) = self.declarator_name(d);
                        if n.is_empty() {
                            continue;
                        }
                        let value = m.child_by_field_name("default_value").map(|v| self.expr(v));
                        fields.push(Stmt::Declare {
                            name: n,
                            ty: format!("{ty}{suffix}"),
                            value,
                            span: span(m),
                        });
                    }
                }
                "class_specifier" | "struct_specifier" => {
                    self.class(m);
                }
                _ => {}
            }
        }
        self.class_stack.borrow_mut().pop();
        self.classes.borrow_mut().push(Class {
            name: name.clone(),
            bases,
            fields,
            methods,
            span: span(node),
        });
        Some(name)
    }

    // ----- statements -----

    fn block(&self, node: Node, out: &mut Vec<Stmt>) {
        if node.kind() == "compound_statement" {
            let start = out.len();
            for c in named_children(node) {
                self.stmt(c, out);
            }
            // C++ objects made in the block are destroyed where it ends.
            let made: Vec<String> = out[start..]
                .iter()
                .filter_map(|s| match s {
                    Stmt::Declare {
                        name,
                        value: Some(Expr::New { .. }),
                        ..
                    } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            let end = span(node);
            let end = Span {
                line: end.end_line,
                column: 1,
                end_line: end.end_line,
            };
            for name in made.into_iter().rev() {
                out.push(Stmt::Expr(
                    call("__c_destroy", vec![Expr::Name(name)], end),
                    end,
                ));
            }
        } else {
            self.stmt(node, out);
        }
    }

    fn stmts(&self, node: Option<Node>) -> Vec<Stmt> {
        let mut out = Vec::new();
        if let Some(n) = node {
            self.block(n, &mut out);
        }
        out
    }

    fn stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let saved = self.hoisted.take();
        let saved_post = self.post.take();
        let mut mine = Vec::new();
        self.stmt_inner(node, &mut mine);
        let hoisted = self.hoisted.replace(saved);
        let post = self.post.replace(saved_post);
        out.extend(hoisted);
        // A condition's update is run before the statement: its body
        // must see the new value.
        if matches!(node.kind(), "expression_statement" | "declaration") {
            out.extend(mine);
            out.extend(post);
        } else {
            out.extend(post);
            out.extend(mine);
        }
    }

    fn stmt_inner(&self, node: Node, out: &mut Vec<Stmt>) {
        let d = self.depth.get();
        if d > MAX_DEPTH {
            return;
        }
        self.depth.set(d + 1);
        self.stmt_kind(node, out);
        self.depth.set(d);
    }

    fn condition(&self, node: Option<Node>, out: &mut Vec<Stmt>) -> Expr {
        let Some(n) = node else {
            return Expr::Lit(Const::Bool(true));
        };
        match n.kind() {
            "parenthesized_expression" => named_children(n)
                .last()
                .map(|e| self.expr(*e))
                .unwrap_or(Expr::Lit(Const::Bool(true))),
            // C++ `if (T x = f())`, `if (init; cond)`.
            "condition_clause" => {
                let mut value = Expr::Lit(Const::Bool(true));
                for c in named_children(n) {
                    match c.kind() {
                        "declaration" | "init_statement" => {
                            let mut decl = Vec::new();
                            self.declaration(c, &mut decl);
                            if let Some(Stmt::Declare { name, .. }) = decl.last() {
                                value = Expr::Name(name.clone());
                            }
                            out.extend(decl);
                        }
                        _ => {
                            let field = c.kind();
                            if field == "comment" {
                                continue;
                            }
                            value = self.expr(c);
                        }
                    }
                }
                value
            }
            _ => self.expr(n),
        }
    }

    fn stmt_kind(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "compound_statement" => self.block(node, out),
            "declaration" => self.declaration(node, out),
            "expression_statement" => {
                for c in named_children(node) {
                    self.expr_stmt(c, out);
                }
            }
            "if_statement" => {
                let mut pre = Vec::new();
                let test = self.condition(node.child_by_field_name("condition"), &mut pre);
                out.extend(pre);
                let then = self.stmts(node.child_by_field_name("consequence"));
                let other = match node.child_by_field_name("alternative") {
                    Some(a) => {
                        // `else_clause` wraps the statement in newer grammars.
                        let inner = if a.kind() == "else_clause" {
                            named_children(a).into_iter().next()
                        } else {
                            Some(a)
                        };
                        self.stmts(inner)
                    }
                    None => Vec::new(),
                };
                out.push(Stmt::If {
                    test,
                    then,
                    other,
                    span: test_span(node),
                });
            }
            "while_statement" => {
                let mut pre = Vec::new();
                let test = self.condition(node.child_by_field_name("condition"), &mut pre);
                out.extend(pre);
                let body = self.stmts(node.child_by_field_name("body"));
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
                char_checks(out, span(node));
            }
            "do_statement" => {
                // The body runs once before the condition is tested.
                let mut body = self.stmts(node.child_by_field_name("body"));
                let mut pre = Vec::new();
                let test = self.condition(node.child_by_field_name("condition"), &mut pre);
                body.extend(pre);
                body.push(Stmt::If {
                    test: Expr::Un(UnOp::Not, Box::new(test)),
                    then: vec![Stmt::Break],
                    other: Vec::new(),
                    span: test_span(node),
                });
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(Expr::Lit(Const::Bool(true))),
                    body,
                    span: sp,
                });
            }
            "for_statement" => {
                if let Some(init) = node.child_by_field_name("initializer") {
                    if init.kind() == "declaration" {
                        self.declaration(init, out);
                    } else {
                        self.expr_stmt(init, out);
                    }
                }
                let test = match node.child_by_field_name("condition") {
                    Some(c) => {
                        let mut pre = Vec::new();
                        let t = self.condition(Some(c), &mut pre);
                        out.extend(pre);
                        t
                    }
                    None => Expr::Lit(Const::Bool(true)),
                };
                let mut body = self.stmts(node.child_by_field_name("body"));
                if let Some(u) = node.child_by_field_name("update") {
                    let mut upd = Vec::new();
                    self.expr_stmt(u, &mut upd);
                    body.extend(upd);
                }
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
                char_checks(out, span(node));
            }
            "for_range_loop" => {
                let (name, _) = node
                    .child_by_field_name("declarator")
                    .map(|d| self.declarator_name(d))
                    .unwrap_or_default();
                let iter = node
                    .child_by_field_name("right")
                    .map(|r| self.expr(r))
                    .unwrap_or(Expr::Lit(Const::None));
                let body = self.stmts(node.child_by_field_name("body"));
                out.push(Stmt::Loop {
                    target: Some(Target::Name(name)),
                    iter: Some(iter),
                    test: None,
                    body,
                    span: sp,
                });
            }
            "switch_statement" => {
                let mut pre = Vec::new();
                let subject = self.condition(node.child_by_field_name("condition"), &mut pre);
                out.extend(pre);
                let mut cases = Vec::new();
                if let Some(b) = node.child_by_field_name("body") {
                    for c in named_children(b) {
                        if c.kind() != "case_statement" {
                            continue;
                        }
                        let value = c.child_by_field_name("value");
                        let patterns = value.map(|v| vec![self.expr(v)]).unwrap_or_default();
                        let mut body = Vec::new();
                        for s in named_children(c) {
                            if Some(s.id()) == value.map(|v| v.id()) {
                                continue;
                            }
                            self.stmt(s, &mut body);
                        }
                        cases.push(Case { patterns, body });
                    }
                }
                out.push(Stmt::Switch {
                    subject,
                    cases,
                    fallthrough: true,
                });
            }
            "return_statement" => {
                let value = named_children(node).first().map(|e| self.expr(*e));
                out.push(Stmt::Return(value, sp));
            }
            "break_statement" => out.push(Stmt::Break),
            "continue_statement" => out.push(Stmt::Continue),
            "labeled_statement" => {
                for c in named_children(node) {
                    if c.kind() != "statement_identifier" {
                        self.stmt(c, out);
                    }
                }
            }
            "type_definition" => self.type_definition(node),
            // `goto err;` runs the code from `err:` to the end of the
            // function, which `label_tails` lowered.
            "goto_statement" => {
                let label = node
                    .child_by_field_name("label")
                    .map(|l| self.text(l).to_string())
                    .unwrap_or_default();
                let tail = self
                    .gotos
                    .borrow()
                    .last()
                    .and_then(|g| g.get(&label).cloned());
                match tail {
                    Some(Some(stmts)) => {
                        out.extend(stmts.iter().cloned());
                        out.push(Stmt::Return(None, span(node)));
                    }
                    // Too long to copy: the path ends here.
                    Some(None) => out.push(Stmt::Return(None, span(node))),
                    // A label in a nested block, or one being lowered.
                    None => {}
                }
            }
            "empty_statement" => {}
            "try_statement" => {
                let body = self.stmts(node.child_by_field_name("body"));
                let mut handlers = Vec::new();
                for c in named_children(node) {
                    if c.kind() == "catch_clause" {
                        handlers.push(self.stmts(c.child_by_field_name("body")));
                    }
                }
                out.push(Stmt::Try {
                    body,
                    handlers,
                    finally: Vec::new(),
                });
            }
            "throw_statement" => {
                for c in named_children(node) {
                    out.push(Stmt::Expr(self.expr(c), span(c)));
                }
                out.push(Stmt::Return(None, sp));
            }
            "function_definition" => self.function_definition(node, out),
            "class_specifier" | "struct_specifier" => {
                self.class(node);
            }
            _ => {
                // An expression where a statement is expected.
                if node.is_named() && !node.kind().contains("comment") {
                    let e = self.expr(node);
                    out.push(Stmt::Expr(e, sp));
                }
            }
        }
    }

    fn declaration(&self, node: Node, out: &mut Vec<Stmt>) {
        let type_node = node.child_by_field_name("type");
        let ty = type_node
            .map(|t| self.text(t).to_string())
            .unwrap_or_default();
        if let Some(t) = type_node {
            if matches!(t.kind(), "class_specifier" | "struct_specifier")
                && t.child_by_field_name("body").is_some()
            {
                self.class(t);
            }
        }
        // `extern int x;` refers to a variable another file defines.
        let is_extern = named_children(node)
            .iter()
            .any(|c| c.kind() == "storage_class_specifier" && self.text(*c) == "extern");
        if is_extern
            && !named_children(node)
                .iter()
                .any(|c| c.kind() == "init_declarator")
        {
            return;
        }
        for d in crate::lower::field_children(node, "declarator") {
            // Prototypes declare nothing to run, but inside a function
            // `T x(a, b);` with variables for arguments makes an object.
            if d.kind() == "function_declarator" {
                if let Some(s) = self.constructed(&ty, d) {
                    out.push(s);
                }
                continue;
            }
            if d.kind() != "init_declarator" && self.find_function_declarator(d).is_some() {
                continue;
            }
            let sp = span(d);
            let (name, suffix) = self.declarator_name(d);
            if name.is_empty() {
                continue;
            }
            if let Some(l) = self.locals.borrow_mut().last_mut() {
                l.push(name.clone());
            }
            if let Some(t) = self.types.borrow_mut().last_mut() {
                t.insert(name.clone(), base_type(&ty));
            }
            let full_ty = format!("{ty}{suffix}");
            if let Some(t) = self.declared.borrow_mut().last_mut() {
                t.insert(name.clone(), full_ty.clone());
            }
            if let Some(d) = self.deep.borrow_mut().last_mut() {
                if is_deep_pointer(&full_ty) {
                    d.insert(name.clone());
                } else {
                    d.remove(&name);
                }
            }
            let value = if d.kind() == "init_declarator" {
                match d.child_by_field_name("value") {
                    // `Foo f(1, 2);` and `std::string s(data);`
                    Some(v) if v.kind() == "argument_list" => Some(Expr::New {
                        class: self.class_name(&ty),
                        args: named_children(v)
                            .into_iter()
                            .map(|a| positional(self.expr(a)))
                            .collect(),
                        span: sp,
                    }),
                    Some(v) => Some(self.expr(v)),
                    None => None,
                }
            } else {
                None
            };
            let array = self.array_size(d);
            let var = name.clone();
            out.push(Stmt::Declare {
                name,
                ty: full_ty,
                value,
                span: sp,
            });
            if array.is_none() {
                if let Some(a) = self.arrays.borrow_mut().last_mut() {
                    a.insert(var.clone(), None);
                }
                // `char *p[5];`: five pointers, each kept apart.
                if d.kind() != "init_declarator" {
                    if let Some(n) = self.pointer_array_size(d) {
                        out.push(Stmt::Expr(
                            call("__c_slots", vec![Expr::Name(var.clone()), n], sp),
                            sp,
                        ));
                    }
                }
            }
            // `char b[50];`: the model learns the array's size.
            if let Some(count) = array {
                let base = base_type(&ty);
                let elem = match size_of_type(&base) {
                    Some(n) => Expr::Lit(Const::Int(n)),
                    None => call("sizeof", vec![Expr::Lit(Const::Str(base))], sp),
                };
                let bytes = count
                    .as_ref()
                    .map(|c| Expr::Bin(BinOp::Mul, Box::new(c.clone()), Box::new(elem.clone())));
                if let Some(a) = self.arrays.borrow_mut().last_mut() {
                    a.insert(var.clone(), bytes);
                }
                let count = count.unwrap_or(Expr::Lit(Const::None));
                out.push(Stmt::Expr(
                    call("__c_array", vec![Expr::Name(var), count, elem], sp),
                    sp,
                ));
            }
        }
    }

    /// The element count of `*p[N]`, an array of pointers.
    fn pointer_array_size(&self, d: Node) -> Option<Expr> {
        if d.kind() != "pointer_declarator" {
            return None;
        }
        let a = d.child_by_field_name("declarator")?;
        if a.kind() != "array_declarator"
            || a.child_by_field_name("declarator")?.kind() != "identifier"
        {
            return None;
        }
        a.child_by_field_name("size").map(|s| self.expr(s))
    }

    /// The element count of a one-dimensional array declarator: `b[50]`
    /// gives `Some(Some(50))`, `s[]` gives `Some(None)`. None for
    /// pointers, arrays of pointers and arrays of arrays.
    fn array_size(&self, d: Node) -> Option<Option<Expr>> {
        let mut cur = d;
        let mut found = None;
        for _ in 0..32 {
            match cur.kind() {
                "identifier" => return found,
                "array_declarator" => {
                    if found.is_some() {
                        return None;
                    }
                    found = Some(cur.child_by_field_name("size").map(|s| self.expr(s)));
                }
                "init_declarator" => {}
                _ => return None,
            }
            cur = cur.child_by_field_name("declarator")?;
        }
        None
    }

    /// `T x(a, b);` in a function body, which C++ parses as a prototype
    /// when the arguments are names: a declaration of `x` made by `new T(a, b)`
    /// when every argument is a variable of the function.
    fn constructed(&self, ty: &str, d: Node) -> Option<Stmt> {
        let locals = self.locals.borrow();
        let names = locals.last()?;
        let var = d.child_by_field_name("declarator")?;
        if var.kind() != "identifier" {
            return None;
        }
        let mut args = Vec::new();
        for p in named_children(d.child_by_field_name("parameters")?) {
            if p.kind() != "parameter_declaration" || p.child_by_field_name("declarator").is_some()
            {
                return None;
            }
            let arg = self.text(p.child_by_field_name("type")?);
            if !names.iter().any(|n| n == arg) {
                return None;
            }
            args.push(positional(Expr::Name(self.alias_of(arg))));
        }
        drop(locals);
        let name = self.text(var).to_string();
        if let Some(l) = self.locals.borrow_mut().last_mut() {
            l.push(name.clone());
        }
        let sp = span(d);
        Some(Stmt::Declare {
            name,
            ty: ty.to_string(),
            value: Some(Expr::New {
                class: self.class_name(ty),
                args,
                span: sp,
            }),
            span: sp,
        })
    }

    /// `std::basic_string<char>` -> `basic_string`.
    fn class_name(&self, ty: &str) -> String {
        let t = ty.split('<').next().unwrap_or(ty).trim();
        t.rsplit("::").next().unwrap_or(t).trim().to_string()
    }

    /// An expression used as a statement: assignments and updates become
    /// assignments, `cin >> x` reads into `x`.
    fn expr_stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "assignment_expression" => self.assignment(node, out),
            "update_expression" => {
                if let Some(a) = node.child_by_field_name("argument") {
                    let op = node
                        .child_by_field_name("operator")
                        .map(|o| self.text(o))
                        .unwrap_or("++");
                    let target = self.target(a);
                    let cur = self.expr(a);
                    out.push(Stmt::Assign {
                        target,
                        value: Expr::Bin(
                            if op == "--" { BinOp::Sub } else { BinOp::Add },
                            Box::new(cur),
                            Box::new(Expr::Lit(Const::Int(1))),
                        ),
                        span: sp,
                    });
                }
            }
            "comma_expression" => {
                for c in named_children(node) {
                    self.expr_stmt(c, out);
                }
            }
            "parenthesized_expression" => {
                for c in named_children(node) {
                    self.expr_stmt(c, out);
                }
            }
            "binary_expression" if self.is_stream_read(node) => {
                let mut targets = Vec::new();
                self.stream_targets(node, &mut targets);
                for t in targets {
                    out.push(Stmt::Assign {
                        target: self.target(t),
                        value: call("__c_stdin", Vec::new(), sp),
                        span: sp,
                    });
                }
            }
            _ => {
                let e = self.expr(node);
                out.push(Stmt::Expr(e, sp));
            }
        }
    }

    fn assignment(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        let (Some(l), Some(r)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("=");
        let right = self.expr(r);
        let value = match op.strip_suffix('=').filter(|o| !o.is_empty()) {
            Some(o) => match bin_op(o) {
                Some(b) => Expr::Bin(b, Box::new(self.expr(l)), Box::new(right)),
                None => right,
            },
            None => right,
        };
        // `u_char ch; ch = *p;`: the variable holds a byte.
        let small = (op == "=" && l.kind() == "identifier")
            .then(|| self.declared_type(self.text(l)))
            .flatten()
            .filter(|t| small_int_range(t).is_some());
        let value = match small {
            Some(t) => Expr::Cast(t, Box::new(value)),
            None => value,
        };
        out.push(Stmt::Assign {
            target: self.target(l),
            value,
            span: sp,
        });
    }

    fn is_stream_read(&self, node: Node) -> bool {
        let mut cur = node;
        for _ in 0..64 {
            if cur.kind() != "binary_expression" {
                break;
            }
            let op = cur
                .child_by_field_name("operator")
                .map(|o| self.text(o))
                .unwrap_or("");
            if op != ">>" {
                return false;
            }
            match cur.child_by_field_name("left") {
                Some(l) => cur = l,
                None => return false,
            }
        }
        let t = self.text(cur);
        let t = t.rsplit("::").next().unwrap_or(t);
        matches!(t, "cin" | "wcin")
    }

    fn stream_targets<'t>(&self, node: Node<'t>, out: &mut Vec<Node<'t>>) {
        if node.kind() == "binary_expression" {
            if let Some(l) = node.child_by_field_name("left") {
                self.stream_targets(l, out);
            }
            if let Some(r) = node.child_by_field_name("right") {
                out.push(r);
            }
        }
    }

    fn target(&self, node: Node) -> Target {
        match node.kind() {
            "identifier" => {
                let n = self.alias_of(self.text(node));
                match self.field_of_class(&n) {
                    Some(f) => Target::Attr(Box::new(Expr::Name("this".into())), f),
                    None => Target::Name(n),
                }
            }
            "field_expression" => {
                let base = node
                    .child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Lit(Const::None));
                let field = node
                    .child_by_field_name("field")
                    .map(|f| self.text(f).to_string())
                    .unwrap_or_default();
                Target::Attr(Box::new(base), self.member_name(node, field))
            }
            "subscript_expression" => {
                let base = node
                    .child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Lit(Const::None));
                Target::Index(Box::new(base), Box::new(self.subscript_index(node)))
            }
            // `*p = v` writes where `p` points: an element of it, or the
            // variable a fixed pointer points to.
            "pointer_expression" => match node.child_by_field_name("argument") {
                Some(a)
                    if a.kind() == "identifier"
                        && (self.alias_of(self.text(a)) != self.text(a)
                            || self.is_deep(self.text(a))) =>
                {
                    self.target(a)
                }
                Some(a) => {
                    Target::Index(Box::new(self.expr(a)), Box::new(Expr::Lit(Const::Int(0))))
                }
                None => Target::Other,
            },
            "parenthesized_expression" | "cast_expression" => match named_children(node).last() {
                Some(inner) if node.kind() == "parenthesized_expression" => self.target(*inner),
                _ => match node.child_by_field_name("value") {
                    Some(v) => self.target(v),
                    None => Target::Other,
                },
            },
            "qualified_identifier" => {
                let t = self.text(node);
                Target::Name(t.rsplit("::").next().unwrap_or(t).to_string())
            }
            _ => Target::Other,
        }
    }

    /// Whether `name` is a pointer to a pointer here.
    fn is_deep(&self, name: &str) -> bool {
        self.deep.borrow().last().is_some_and(|d| d.contains(name))
    }

    /// The declared type of `name`, innermost scope first.
    fn declared_type(&self, name: &str) -> Option<String> {
        self.declared
            .borrow()
            .iter()
            .rev()
            .find_map(|m| m.get(name).cloned())
    }

    /// The integer type read through `node`: `u_char` for `u_char *p`,
    /// `p + 1`, `p++`, `(u_char *) q` and `*pp` of `u_char **pp`; `int`
    /// for `int a[4]`.
    fn pointee_int(&self, node: Node) -> Option<String> {
        pointee_int_type(&self.pointer_type(node)?)
    }

    /// The declared type of a pointer expression: `char **` for `pp`,
    /// `pp + 1` and `pp++`, `char *` for `*pp` and `pp[i]`.
    fn pointer_type(&self, node: Node) -> Option<String> {
        let arg = || node.child_by_field_name("argument");
        match node.kind() {
            "identifier" => self.declared_type(self.text(node)),
            "parenthesized_expression" => named_children(node)
                .last()
                .and_then(|n| self.pointer_type(*n)),
            "update_expression" => self.pointer_type(arg()?),
            "binary_expression" => {
                let op = node.child_by_field_name("operator").map(|o| self.text(o));
                if !matches!(op, Some("+" | "-")) {
                    return None;
                }
                self.pointer_type(node.child_by_field_name("left")?)
            }
            "cast_expression" => Some(self.text(node.child_by_field_name("type")?).to_string()),
            "pointer_expression"
                if node.child_by_field_name("operator").map(|o| self.text(o)) == Some("*") =>
            {
                deref_type(&self.pointer_type(arg()?)?)
            }
            "subscript_expression" => deref_type(&self.pointer_type(arg()?)?),
            _ => None,
        }
    }

    /// `p[i]` or `*p` as a place, for `&p[i]` and `&*p`: the element, not
    /// the integer read from it.
    fn place(&self, node: Node) -> Expr {
        match node.kind() {
            "subscript_expression" => {
                let base = node
                    .child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Index(Box::new(base), Box::new(self.subscript_index(node)))
            }
            "pointer_expression"
                if node.child_by_field_name("operator").map(|o| self.text(o)) == Some("*") =>
            {
                node.child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "parenthesized_expression" => match named_children(node).last() {
                Some(inner) => self.place(*inner),
                None => Expr::Other(Vec::new()),
            },
            _ => self.expr(node),
        }
    }

    fn subscript_index(&self, node: Node) -> Expr {
        if let Some(i) = node.child_by_field_name("index") {
            return self.expr(i);
        }
        if let Some(list) = node.child_by_field_name("indices") {
            if let Some(first) = named_children(list).first() {
                return self.expr(*first);
            }
        }
        Expr::Lit(Const::Int(0))
    }

    /// Lowers the code from each label of a function body to the body's
    /// end, last label first, so a `goto` in that code to a later label
    /// finds its tail.
    fn label_tails(&self, body: Node) {
        let items = named_children(body);
        for (k, item) in items.iter().enumerate().rev() {
            if item.kind() != "labeled_statement" {
                continue;
            }
            let Some(label) = item.child_by_field_name("label") else {
                continue;
            };
            let mut tail = Vec::new();
            for c in &items[k..] {
                self.stmt(*c, &mut tail);
            }
            let size: usize = tail.iter().map(stmt_size).sum();
            let entry = (size <= MAX_GOTO_TAIL).then(|| Rc::new(tail));
            if let Some(g) = self.gotos.borrow_mut().last_mut() {
                g.insert(self.text(label).to_string(), entry);
            }
        }
    }

    /// The variable a reference or fixed pointer stands for (see `aliases`).
    fn alias_of(&self, name: &str) -> String {
        let aliases = self.aliases.borrow();
        let mut n = name;
        for _ in 0..4 {
            match aliases.last().and_then(|a| a.get(n)) {
                Some(t) => n = t,
                None => break,
            }
        }
        n.to_string()
    }

    /// The field `x.f` reads: every member of a union is the same storage.
    fn member_name(&self, node: Node, field: String) -> String {
        let Some(arg) = node.child_by_field_name("argument") else {
            return field;
        };
        if arg.kind() != "identifier" {
            return field;
        }
        let var = self.alias_of(self.text(arg));
        let types = self.types.borrow();
        match types.iter().rev().find_map(|t| t.get(&var)) {
            Some(ty) if self.unions.contains(ty) => "__union".into(),
            _ => field,
        }
    }

    /// References and pointers to locals in a function body that are never
    /// pointed elsewhere.
    fn find_aliases(&self, body: Node) -> HashMap<String, String> {
        let mut refs = HashMap::new();
        let mut pointers = HashMap::new();
        let mut moved = HashSet::new();
        let mut todo = vec![body];
        while let Some(n) = todo.pop() {
            match n.kind() {
                "init_declarator" => {
                    if let (Some(d), Some(v)) = (
                        n.child_by_field_name("declarator"),
                        n.child_by_field_name("value"),
                    ) {
                        let (name, suffix) = self.declarator_name(d);
                        let address_of = v.kind() == "pointer_expression"
                            && v.child_by_field_name("operator")
                                .is_some_and(|o| self.text(o) == "&");
                        let target = if address_of {
                            v.child_by_field_name("argument")
                        } else {
                            Some(v)
                        };
                        if let Some(t) = target.filter(|t| t.kind() == "identifier") {
                            let t = self.text(t).to_string();
                            if suffix.contains('&') && !address_of {
                                refs.insert(name, t);
                            } else if suffix.starts_with('*') && address_of {
                                pointers.insert(name, t);
                            }
                        }
                    }
                }
                "assignment_expression" => {
                    if let Some(l) = n.child_by_field_name("left") {
                        if l.kind() == "identifier" {
                            moved.insert(self.text(l).to_string());
                        }
                    }
                }
                "update_expression" => {
                    if let Some(a) = n.child_by_field_name("argument") {
                        if a.kind() == "identifier" {
                            moved.insert(self.text(a).to_string());
                        }
                    }
                }
                _ => {}
            }
            if todo.len() < 100_000 {
                todo.extend(named_children(n));
            }
        }
        pointers.retain(|p, _| !moved.contains(p));
        refs.extend(pointers);
        refs
    }

    /// A bare name inside a method that is a field of its class.
    fn field_of_class(&self, name: &str) -> Option<String> {
        if self
            .locals
            .borrow()
            .last()
            .is_some_and(|l| l.iter().any(|n| n == name))
        {
            return None;
        }
        let stack = self.class_stack.borrow();
        let (_, fields) = stack.last()?;
        fields.iter().find(|f| *f == name).cloned()
    }

    // ----- expressions -----

    fn expr(&self, node: Node) -> Expr {
        let d = self.depth.get();
        if d > MAX_DEPTH {
            return Expr::Other(Vec::new());
        }
        self.depth.set(d + 1);
        let e = self.expr_kind(node);
        self.depth.set(d);
        e
    }

    fn string_literal(&self, node: Node) -> String {
        let mut s = String::new();
        for c in named_children(node) {
            match c.kind() {
                "string_content" => s.push_str(self.text(c)),
                "escape_sequence" => s.push_str(&unescape(self.text(c))),
                "raw_string_content" => s.push_str(self.text(c)),
                _ => {}
            }
        }
        s
    }

    fn expr_kind(&self, node: Node) -> Expr {
        let sp = span(node);
        match node.kind() {
            "identifier" => {
                let n = self.text(node);
                match n {
                    "NULL" => Expr::Lit(Const::None),
                    "TRUE" => Expr::Lit(Const::Bool(true)),
                    "FALSE" => Expr::Lit(Const::Bool(false)),
                    _ => {
                        let n = self.alias_of(n);
                        match self.field_of_class(&n) {
                            Some(f) => Expr::Attr(Box::new(Expr::Name("this".into())), f),
                            None => Expr::Name(n),
                        }
                    }
                }
            }
            "field_identifier" | "type_identifier" | "namespace_identifier" => {
                Expr::Name(self.text(node).to_string())
            }
            "qualified_identifier" => {
                let t = self.text(node);
                let last = t.rsplit("::").next().unwrap_or(t);
                let last = last.split('<').next().unwrap_or(last).trim();
                Expr::Name(last.to_string())
            }
            "template_function" => node
                .child_by_field_name("name")
                .map(|n| self.expr(n))
                .unwrap_or(Expr::Other(Vec::new())),
            "this" => Expr::Name("this".into()),
            "true" => Expr::Lit(Const::Bool(true)),
            "false" => Expr::Lit(Const::Bool(false)),
            "null" | "nullptr" => Expr::Lit(Const::None),
            "number_literal" => {
                let t = self.text(node).replace('\'', "");
                if let Some(i) = super::cpre::parse_int(&t) {
                    Expr::Lit(Const::Int(i))
                } else {
                    let f = t.trim_end_matches(['f', 'F', 'l', 'L']);
                    match f.parse::<f64>() {
                        Ok(v) => Expr::Lit(Const::Float(v)),
                        Err(_) => Expr::Other(Vec::new()),
                    }
                }
            }
            "char_literal" => {
                let mut s = String::new();
                for c in named_children(node) {
                    match c.kind() {
                        "character" => s.push_str(self.text(c)),
                        "escape_sequence" => s.push_str(&unescape(self.text(c))),
                        _ => {}
                    }
                }
                Expr::Lit(Const::Int(s.chars().next().map(|c| c as i64).unwrap_or(0)))
            }
            "string_literal" | "raw_string_literal" => {
                Expr::Lit(Const::Str(self.string_literal(node)))
            }
            "concatenated_string" => {
                let parts: Vec<Expr> = named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect();
                if parts.iter().all(|p| matches!(p, Expr::Lit(Const::Str(_)))) {
                    let s: String = parts
                        .iter()
                        .map(|p| match p {
                            Expr::Lit(Const::Str(s)) => s.as_str(),
                            _ => "",
                        })
                        .collect();
                    Expr::Lit(Const::Str(s))
                } else {
                    Expr::Concat(parts)
                }
            }
            "parenthesized_expression" => named_children(node)
                .last()
                .map(|e| self.expr(*e))
                .unwrap_or(Expr::Other(Vec::new())),
            "binary_expression" => {
                let l = node.child_by_field_name("left");
                let r = node.child_by_field_name("right");
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                if op == ">>" && self.is_stream_read(node) {
                    let mut out = Vec::new();
                    self.expr_stmt(node, &mut out);
                    self.hoisted.borrow_mut().extend(out);
                    return Expr::Name("cin".into());
                }
                let (Some(l), Some(r)) = (l, r) else {
                    return Expr::Other(Vec::new());
                };
                let le = self.expr(l);
                let re = self.expr(r);
                match bin_op(op) {
                    Some(b) => Expr::Bin(b, Box::new(le), Box::new(re)),
                    None => Expr::Other(vec![le, re]),
                }
            }
            "unary_expression" => {
                let arg = node
                    .child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()));
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                match op {
                    "!" | "not" => Expr::Un(UnOp::Not, Box::new(arg)),
                    "-" => Expr::Un(UnOp::Neg, Box::new(arg)),
                    "+" => Expr::Un(UnOp::Pos, Box::new(arg)),
                    "~" | "compl" => Expr::Un(UnOp::BitNot, Box::new(arg)),
                    _ => arg,
                }
            }
            // `&x` and `*p` stand for the value itself; `*p` of an integer
            // pointer is that integer type, so `u_char` reads stay bytes.
            "pointer_expression" => {
                let Some(a) = node.child_by_field_name("argument") else {
                    return Expr::Other(Vec::new());
                };
                let op = node.child_by_field_name("operator").map(|o| self.text(o));
                if op == Some("&") {
                    // `read(fd, &len, 1)`: what is stored in a `u_char` is a byte.
                    let small = (a.kind() == "identifier")
                        .then(|| self.declared_type(self.text(a)))
                        .flatten()
                        .filter(|t| small_int_range(t).is_some());
                    if let Some(t) = small {
                        return Expr::Cast(t, Box::new(self.expr(a)));
                    }
                    return self.place(a);
                }
                let v = self.expr(a);
                match self.pointee_int(a) {
                    Some(t) => Expr::Cast(t, Box::new(v)),
                    None => v,
                }
            }
            "field_expression" => {
                let base = node
                    .child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()));
                let field = node
                    .child_by_field_name("field")
                    .map(|f| {
                        let t = self.text(f);
                        t.rsplit("::").next().unwrap_or(t).to_string()
                    })
                    .unwrap_or_default();
                Expr::Attr(Box::new(base), self.member_name(node, field))
            }
            "subscript_expression" => {
                let v = self.place(node);
                match node
                    .child_by_field_name("argument")
                    .and_then(|a| self.pointee_int(a))
                {
                    Some(t) => Expr::Cast(t, Box::new(v)),
                    None => v,
                }
            }
            "call_expression" => {
                // `likely(x)` and `expect_true(x)` macros end in
                // `__builtin_expect(x, 1)`, which is `x`.
                let builtin = node.child_by_field_name("function").is_some_and(|f| {
                    matches!(
                        self.text(f),
                        "__builtin_expect" | "__builtin_expect_with_probability"
                    )
                });
                let first = node
                    .child_by_field_name("arguments")
                    .and_then(|a| named_children(a).into_iter().next());
                if let (true, Some(first)) = (builtin, first) {
                    return self.expr(first);
                }
                let args: Vec<Arg> = node
                    .child_by_field_name("arguments")
                    .map(|a| {
                        named_children(a)
                            .into_iter()
                            .map(|c| positional(self.expr(c)))
                            .collect()
                    })
                    .unwrap_or_default();
                let func = node
                    .child_by_field_name("function")
                    .map(|f| self.expr(f))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Call {
                    func: Box::new(func),
                    args,
                    span: sp,
                }
            }
            "cast_expression" => {
                let ty = node
                    .child_by_field_name("type")
                    .map(|t| self.text(t).to_string())
                    .unwrap_or_default();
                let v = node
                    .child_by_field_name("value")
                    .map(|v| self.expr(v))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Cast(ty, Box::new(v))
            }
            "sizeof_expression" => {
                if let Some(t) = node.child_by_field_name("type") {
                    let ty = self.text(t);
                    if let Some(n) = size_of_type(ty) {
                        return Expr::Lit(Const::Int(n));
                    }
                    return call("sizeof", vec![Expr::Lit(Const::Str(ty.to_string()))], sp);
                }
                // `sizeof buf` and `sizeof(buf)` of an array declared here.
                let mut inner = node.child_by_field_name("value");
                while let Some(n) = inner.filter(|n| n.kind() == "parenthesized_expression") {
                    inner = named_children(n).into_iter().next();
                }
                if let Some(n) = inner.filter(|n| n.kind() == "identifier") {
                    let name = self.text(n);
                    let found = self
                        .arrays
                        .borrow()
                        .iter()
                        .rev()
                        .find_map(|a| a.get(name).cloned())
                        .flatten();
                    if let Some(bytes) = found {
                        return bytes;
                    }
                }
                let v = node
                    .child_by_field_name("value")
                    .map(|v| self.expr(v))
                    .unwrap_or(Expr::Other(Vec::new()));
                // `sizeof(*p)`, `sizeof(p[0])`
                if let Expr::Cast(t, _) = &v {
                    if let Some(n) = size_of_type(&base_type(t)) {
                        return Expr::Lit(Const::Int(n));
                    }
                }
                call("sizeof", vec![v], sp)
            }
            "conditional_expression" => {
                let test = node
                    .child_by_field_name("condition")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Lit(Const::Bool(true)));
                let then = node
                    .child_by_field_name("consequence")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Lit(Const::None));
                let other = node
                    .child_by_field_name("alternative")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Lit(Const::None));
                Expr::Cond {
                    test: Box::new(test),
                    then: Box::new(then),
                    other: Box::new(other),
                }
            }
            "assignment_expression" => {
                let mut out = Vec::new();
                self.assignment(node, &mut out);
                self.hoisted.borrow_mut().extend(out);
                node.child_by_field_name("left")
                    .map(|l| self.expr(l))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "update_expression" => {
                let mut out = Vec::new();
                self.expr_stmt(node, &mut out);
                let postfix = match (
                    node.child_by_field_name("argument"),
                    node.child_by_field_name("operator"),
                ) {
                    (Some(a), Some(o)) => a.start_byte() < o.start_byte(),
                    _ => false,
                };
                if postfix {
                    self.post.borrow_mut().extend(out);
                } else {
                    self.hoisted.borrow_mut().extend(out);
                }
                node.child_by_field_name("argument")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "comma_expression" => {
                let parts = named_children(node);
                let mut out = Vec::new();
                for p in parts.iter().take(parts.len().saturating_sub(1)) {
                    self.expr_stmt(*p, &mut out);
                }
                self.hoisted.borrow_mut().extend(out);
                parts
                    .last()
                    .map(|p| self.expr(*p))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            // `{a, b}` is a list; `{.name = a, [2] = b}` a dict by member
            // name or position, which the C model turns into a struct.
            "initializer_list" => {
                let items = named_children(node);
                if !items.iter().any(|c| c.kind() == "initializer_pair") {
                    return Expr::List(items.into_iter().map(|c| self.expr(c)).collect());
                }
                let mut pairs = Vec::new();
                for (i, c) in items.into_iter().enumerate() {
                    if c.kind() != "initializer_pair" {
                        pairs.push((Expr::Lit(Const::Int(i as i64)), self.expr(c)));
                        continue;
                    }
                    let key = match c.child_by_field_name("designator") {
                        Some(d) if d.kind() == "field_designator" => named_children(d)
                            .first()
                            .map(|f| Expr::Lit(Const::Str(self.text(*f).to_string())))
                            .unwrap_or(Expr::Lit(Const::Int(i as i64))),
                        Some(d) if d.kind() == "subscript_designator" => named_children(d)
                            .first()
                            .map(|e| self.expr(*e))
                            .unwrap_or(Expr::Lit(Const::Int(i as i64))),
                        _ => Expr::Lit(Const::Int(i as i64)),
                    };
                    let value = c
                        .child_by_field_name("value")
                        .map(|v| self.expr(v))
                        .unwrap_or(Expr::Other(Vec::new()));
                    pairs.push((key, value));
                }
                Expr::Dict(pairs)
            }
            "compound_literal_expression" => node
                .child_by_field_name("value")
                .map(|v| self.expr(v))
                .unwrap_or(Expr::Other(Vec::new())),
            "new_expression" => {
                let ty = node
                    .child_by_field_name("type")
                    .map(|t| self.text(t).to_string())
                    .unwrap_or_default();
                if let Some(d) = node.child_by_field_name("declarator") {
                    let len = d
                        .child_by_field_name("length")
                        .map(|l| self.expr(l))
                        .unwrap_or(Expr::Lit(Const::Int(1)));
                    return call("__c_new_array", vec![Expr::Lit(Const::Str(ty)), len], sp);
                }
                let args: Vec<Arg> = node
                    .child_by_field_name("arguments")
                    .map(|a| {
                        named_children(a)
                            .into_iter()
                            .map(|c| positional(self.expr(c)))
                            .collect()
                    })
                    .unwrap_or_default();
                Expr::New {
                    class: self.class_name(&ty),
                    args,
                    span: sp,
                }
            }
            "delete_expression" => {
                let v = named_children(node)
                    .last()
                    .map(|v| self.expr(*v))
                    .unwrap_or(Expr::Other(Vec::new()));
                call("__c_delete", vec![v], sp)
            }
            "lambda_expression" => {
                let params = node
                    .child_by_field_name("declarator")
                    .map(|d| self.params(d))
                    .unwrap_or_default();
                let mut body = Vec::new();
                let mut names: Vec<String> =
                    self.locals.borrow().last().cloned().unwrap_or_default();
                names.extend(params.iter().map(|p| p.name.clone()));
                self.locals.borrow_mut().push(names);
                if let Some(b) = node.child_by_field_name("body") {
                    self.block(b, &mut body);
                }
                self.locals.borrow_mut().pop();
                Expr::Lambda(Rc::new(Function {
                    name: "<lambda>".into(),
                    params,
                    body,
                    decorators: Vec::new(),
                    span: sp,
                }))
            }
            _ => Expr::Other(
                named_children(node)
                    .into_iter()
                    .filter(|c| !c.kind().ends_with("type") && !c.kind().contains("declarator"))
                    .map(|c| self.expr(c))
                    .collect(),
            ),
        }
    }
}

/// Characters a check loop can rule out, the ones the rules care about.
const NOTABLE: &[char] = &[
    '.', '/', '\\', '\'', '"', '<', '>', ';', '|', '&', '$', '`', '\n', '%', ' ', '(', ')',
];

/// How a loop walks a string: a pointer moved one character at a time
/// (`for (p = s; *p; ++p)`) or an index into it (`s[i]`, `i++`).
enum Cursor {
    Pointer(String),
    Index(Expr, String),
}

impl Cursor {
    /// `*p`, `p[0]`, `s[i]`
    fn current(&self, e: &Expr) -> bool {
        match (self, uncast(e)) {
            (Cursor::Pointer(p), Expr::Name(n)) => n == p,
            (Cursor::Pointer(p), Expr::Index(b, k)) => {
                is_name(b, p) && matches!(**k, Expr::Lit(Const::Int(0)))
            }
            (Cursor::Index(s, i), Expr::Index(b, k)) => same_place(b, s) && is_name(k, i),
            _ => false,
        }
    }

    /// `*(p + 1)`, `p[1]`, `s[i + 1]`
    fn next(&self, e: &Expr) -> bool {
        match (self, uncast(e)) {
            (Cursor::Pointer(p), Expr::Bin(BinOp::Add, b, k)) => {
                is_name(b, p) && matches!(**k, Expr::Lit(Const::Int(1)))
            }
            (Cursor::Pointer(p), Expr::Index(b, k)) => {
                is_name(b, p) && matches!(**k, Expr::Lit(Const::Int(1)))
            }
            (Cursor::Index(s, i), Expr::Index(b, k)) => {
                same_place(b, s)
                    && matches!(&**k, Expr::Bin(BinOp::Add, a, one)
                        if is_name(a, i) && matches!(**one, Expr::Lit(Const::Int(1))))
            }
            _ => false,
        }
    }

    /// The character `e` compares the current one with: `*p == '.'`.
    fn compared(&self, e: &Expr, op: BinOp) -> Option<char> {
        let Expr::Bin(o, l, r) = e else {
            return None;
        };
        if *o != op {
            return None;
        }
        let (side, lit) = if self.current(l) { (l, r) } else { (r, l) };
        if !self.current(side) {
            return None;
        }
        char_lit(lit)
    }

    /// Strings that cannot be in the walked string once the loop ends,
    /// given that it leaves the function when `cond` holds.
    fn absent(&self, cond: &Expr) -> Vec<String> {
        if let Expr::Bin(BinOp::Or, a, b) = cond {
            let mut v = self.absent(a);
            v.extend(self.absent(b));
            return v;
        }
        if let Some(c) = self.compared(cond, BinOp::Eq) {
            return vec![c.to_string()];
        }
        let mut terms = Vec::new();
        and_terms(cond, &mut terms);
        if terms.len() < 2 {
            return Vec::new();
        }
        // `*p == '.' && *(p + 1) == '.'`
        let first = terms.iter().find_map(|t| self.compared(t, BinOp::Eq));
        let second = terms.iter().find_map(|t| match t {
            Expr::Bin(BinOp::Eq, l, r) if self.next(l) => char_lit(r),
            Expr::Bin(BinOp::Eq, l, r) if self.next(r) => char_lit(l),
            _ => None,
        });
        if terms.len() == 2 {
            if let (Some(a), Some(b)) = (first, second) {
                return vec![format!("{a}{b}")];
            }
        }
        // `!isalnum(*p) && *p != '-' && *p != '/'`: only letters, digits
        // and the listed characters pass.
        let mut allowed = Vec::new();
        for t in &terms {
            if let Some(c) = self.compared(t, BinOp::NotEq) {
                allowed.push(c);
                continue;
            }
            let class = matches!(t, Expr::Un(UnOp::Not, inner)
                if matches!(&**inner, Expr::Call { func, args, .. }
                    if matches!(&**func, Expr::Name(n) if matches!(n.as_str(),
                        "isalnum" | "isalpha" | "isdigit" | "isxdigit" | "islower" | "isupper"
                        | "iswalnum" | "iswalpha" | "iswdigit"))
                    && args.len() == 1 && self.current(&args[0].value)));
            if !class {
                return Vec::new();
            }
        }
        NOTABLE
            .iter()
            .filter(|c| !allowed.contains(c))
            .map(|c| c.to_string())
            .collect()
    }
}

fn is_name(e: &Expr, name: &str) -> bool {
    matches!(e, Expr::Name(n) if n == name)
}

/// `s`, `req->path`, `ctx.qry.path`: a place a loop can walk.
fn same_place(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Name(x), Expr::Name(y)) => x == y,
        (Expr::Attr(x, f), Expr::Attr(y, g)) => f == g && same_place(x, y),
        _ => false,
    }
}

fn is_place(e: &Expr) -> bool {
    match e {
        Expr::Name(_) => true,
        Expr::Attr(b, _) => is_place(b),
        _ => false,
    }
}

/// `e` without the integer type a read through a pointer gives it.
fn uncast(e: &Expr) -> &Expr {
    match e {
        Expr::Cast(_, inner) => uncast(inner),
        e => e,
    }
}

fn char_lit(e: &Expr) -> Option<char> {
    match e {
        Expr::Lit(Const::Int(i)) => u32::try_from(*i).ok().and_then(char::from_u32),
        Expr::Lit(Const::Str(s)) if s.chars().count() == 1 => s.chars().next(),
        _ => None,
    }
}

fn and_terms<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
    match e {
        Expr::Bin(BinOp::And, a, b) => {
            and_terms(a, out);
            and_terms(b, out);
        }
        other => out.push(other),
    }
}

/// `x = x + 1`
fn is_increment(s: &Stmt, name: &str) -> bool {
    matches!(s, Stmt::Assign { target: Target::Name(n), value: Expr::Bin(BinOp::Add, a, one), .. }
        if n == name && is_name(a, name) && matches!(**one, Expr::Lit(Const::Int(1))))
}

/// Assignments to `name` in `body`, nested ones included.
fn assignments(body: &[Stmt], name: &str) -> usize {
    body.iter()
        .map(|s| match s {
            Stmt::Assign {
                target: Target::Name(n),
                ..
            } => usize::from(n == name),
            Stmt::If { then, other, .. } => assignments(then, name) + assignments(other, name),
            Stmt::Loop { body, .. } => assignments(body, name),
            Stmt::Switch { cases, .. } => cases.iter().map(|c| assignments(&c.body, name)).sum(),
            _ => 0,
        })
        .sum()
}

/// The value `name` last got before the loop.
fn last_value<'s>(before: &'s [Stmt], name: &str) -> Option<&'s Expr> {
    before.iter().rev().find_map(|s| match s {
        Stmt::Assign {
            target: Target::Name(n),
            value,
            ..
        } if n == name => Some(Some(value)),
        Stmt::Declare { name: n, value, .. } if n == name => Some(value.as_ref()),
        _ => None,
    })?
}

/// Statements that leave the function: `return`, `exit(1)`, and a
/// `goto` to a label whose statements run to the end.
fn leaves(then: &[Stmt]) -> bool {
    match then.last() {
        Some(Stmt::Return(..)) => true,
        Some(Stmt::Expr(Expr::Call { func, .. }, _)) => matches!(&**func, Expr::Name(n)
            if matches!(n.as_str(), "exit" | "_exit" | "_Exit" | "abort" | "quick_exit")),
        _ => false,
    }
}

/// A loop that walks a string a character at a time and leaves the
/// function on unwanted ones (`for (p = s; *p; ++p) if (*p == '.' &&
/// *(p + 1) == '.') goto err;`): after it the string holds none of them.
/// That is said as `if (strstr(s, "..") || ...) return;` after the loop
/// so the checks narrow it like a library search would.
fn char_checks(out: &mut Vec<Stmt>, sp: Span) {
    let Some((
        Stmt::Loop {
            test: Some(test),
            body,
            iter: None,
            ..
        },
        before,
    )) = out.split_last()
    else {
        return;
    };
    let checks: Vec<&Expr> = body
        .iter()
        .filter_map(|s| match s {
            Stmt::If {
                test, then, other, ..
            } if other.is_empty() && leaves(then) => Some(test),
            _ => None,
        })
        .collect();
    if checks.is_empty() {
        return;
    }
    let step = body.iter().find_map(|s| match s {
        Stmt::Assign {
            target: Target::Name(n),
            ..
        } if is_increment(s, n) && assignments(body, n) == 1 => Some(n.clone()),
        _ => None,
    });
    let Some(step) = step else {
        return;
    };
    let (cursor, string) = match last_value(before, &step) {
        Some(v) if is_place(v) && !is_name(v, &step) => (Cursor::Pointer(step.clone()), v.clone()),
        Some(Expr::Lit(Const::Int(0))) => {
            // The string indexed by `i` in the loop's test or checks.
            let mut found = None;
            for e in std::iter::once(test).chain(checks.iter().copied()) {
                found = found.or_else(|| indexed_by(e, &step));
            }
            match found {
                Some(s) => (Cursor::Index(s.clone(), step.clone()), s),
                None => return,
            }
        }
        _ => return,
    };
    let mut absent: Vec<String> = Vec::new();
    for c in checks {
        for a in cursor.absent(c) {
            if !absent.contains(&a) {
                absent.push(a);
            }
        }
    }
    let test = absent
        .into_iter()
        .map(|a| call("strstr", vec![string.clone(), Expr::Lit(Const::Str(a))], sp))
        .reduce(|a, b| Expr::Bin(BinOp::Or, Box::new(a), Box::new(b)));
    if let Some(test) = test {
        out.push(Stmt::If {
            test,
            then: vec![Stmt::Return(None, sp)],
            other: Vec::new(),
            span: sp,
        });
    }
}

/// `s` in `s[i]` somewhere in `e`.
fn indexed_by(e: &Expr, i: &str) -> Option<Expr> {
    match e {
        Expr::Index(b, k) if is_name(k, i) && is_place(b) => Some((**b).clone()),
        Expr::Bin(_, a, b) => indexed_by(a, i).or_else(|| indexed_by(b, i)),
        Expr::Un(_, a) | Expr::Cast(_, a) => indexed_by(a, i),
        Expr::Call { args, .. } => args.iter().find_map(|a| indexed_by(&a.value, i)),
        _ => None,
    }
}

fn bin_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "%" => BinOp::Mod,
        "&" | "bitand" => BinOp::BitAnd,
        "|" | "bitor" => BinOp::BitOr,
        "^" | "xor" => BinOp::BitXor,
        "<<" => BinOp::Shl,
        ">>" => BinOp::Shr,
        "==" => BinOp::Eq,
        "!=" | "not_eq" => BinOp::NotEq,
        "<" => BinOp::Lt,
        "<=" => BinOp::LtE,
        ">" => BinOp::Gt,
        ">=" => BinOp::GtE,
        "&&" | "and" => BinOp::And,
        "||" | "or" => BinOp::Or,
        _ => return None,
    })
}

/// `char **`, `T * const *`: a pointer to a pointer, not an array of them.
fn is_deep_pointer(ty: &str) -> bool {
    !ty.contains('[') && ty.matches('*').count() >= 2
}

/// The values of a small integer type: 0 to 255 for `u_char`.
pub(crate) fn small_int_range(ty: &str) -> Option<(i64, i64)> {
    let t = plain_type(ty);
    Some(match t.as_str() {
        "char" | "signed char" | "int8_t" | "gint8" | "s8" | "__s8" | "INT8" | "CHAR" => {
            (-128, 127)
        }
        "unsigned char" | "u_char" | "uchar" | "uint8_t" | "u_int8_t" | "guint8" | "guchar"
        | "u8" | "__u8" | "UINT8" | "UCHAR" | "BYTE" => (0, 255),
        "short" | "short int" | "signed short" | "signed short int" | "int16_t" | "gint16"
        | "s16" | "__s16" | "INT16" | "SHORT" => (-32768, 32767),
        "unsigned short" | "unsigned short int" | "u_short" | "ushort" | "uint16_t"
        | "u_int16_t" | "guint16" | "u16" | "__u16" | "UINT16" | "USHORT" | "WORD" => (0, 65535),
        _ => return None,
    })
}

/// 32-bit unsigned types: `(unsigned int) ~0` is 4294967295, not -1.
pub(crate) fn is_unsigned32(ty: &str) -> bool {
    matches!(
        plain_type(ty).as_str(),
        "unsigned"
            | "unsigned int"
            | "uint32_t"
            | "u_int32_t"
            | "u_int"
            | "uint"
            | "guint32"
            | "u32"
            | "__u32"
            | "UINT"
            | "UINT32"
            | "DWORD"
    )
}

/// Integer types, small or not, whose values a pointer to them reads.
pub(crate) fn is_int_type(ty: &str) -> bool {
    if small_int_range(ty).is_some() {
        return true;
    }
    matches!(
        plain_type(ty).as_str(),
        "int"
            | "signed"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "long int"
            | "unsigned long"
            | "unsigned long int"
            | "long long"
            | "unsigned long long"
            | "size_t"
            | "ssize_t"
            | "off_t"
            | "int32_t"
            | "uint32_t"
            | "u_int32_t"
            | "int64_t"
            | "uint64_t"
            | "u_int64_t"
            | "u_int"
            | "u_long"
            | "uint"
            | "ulong"
            | "intptr_t"
            | "uintptr_t"
            | "ptrdiff_t"
            | "wchar_t"
    )
}

/// `const unsigned  char` as `unsigned char`.
fn plain_type(ty: &str) -> String {
    ty.split_whitespace()
        .filter(|w| !matches!(*w, "const" | "volatile" | "static" | "register" | "extern"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `char *` for `char **` and `char *[4]`, `char[8]` for `char[4][8]`:
/// the type one pointer or array level down.
fn deref_type(ty: &str) -> Option<String> {
    if ty.contains('(') {
        return None;
    }
    if let (Some(open), Some(close)) = (ty.find('['), ty.find(']')) {
        return (open < close).then(|| format!("{}{}", &ty[..open], &ty[close + 1..]));
    }
    let star = ty.rfind('*')?;
    Some(format!("{}{}", &ty[..star], &ty[star + 1..]))
}

/// `u_char` for `u_char *` and `u_char[8]`: an integer type one pointer or
/// array level down.
fn pointee_int_type(ty: &str) -> Option<String> {
    if ty.contains(['(', '&']) || ty.matches(['*', '[']).count() != 1 {
        return None;
    }
    let base = plain_type(ty.split(['*', '[']).next()?);
    is_int_type(&base).then_some(base)
}
