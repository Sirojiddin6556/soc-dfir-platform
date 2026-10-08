//! Java front end (tree-sitter-java).
//!
//! Classes become [`Class`] definitions at the top of the module, nested and
//! anonymous ones included. Instance methods take `this` as their first
//! parameter, like Python's `self`, so the interpreter binds receivers the
//! same way for both languages. Bare names are resolved here, where the
//! declarations are visible: a local stays a name, a field becomes
//! `this.field` or `Class.field`, a call to a method of the class becomes
//! `this.method(...)` or `Class.method(...)`.

use super::{children, named_children, span, test_span, text};
use crate::ir::*;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

pub fn lower(root: Node, src: &str) -> Module {
    let l = Lower {
        src,
        depth: Cell::new(0),
        classes: RefCell::new(Vec::new()),
        class_stack: RefCell::new(Vec::new()),
        scopes: RefCell::new(Vec::new()),
        static_ctx: Cell::new(true),
        hoisted: RefCell::new(Vec::new()),
        static_imports: RefCell::new(HashSet::new()),
        anon: Cell::new(0),
    };
    let mut body = Vec::new();
    let mut package = None;
    for child in named_children(root) {
        match child.kind() {
            "package_declaration" => {
                package = named_children(child)
                    .into_iter()
                    .find(|c| matches!(c.kind(), "identifier" | "scoped_identifier"))
                    .map(|c| dotted(l.text(c)));
            }
            "import_declaration" => {
                if let Some(s) = l.import(child) {
                    body.push(s);
                }
            }
            _ => {}
        }
    }
    for child in named_children(root) {
        if is_type_declaration(child.kind()) {
            l.class(child, None);
        }
    }
    body.extend(l.classes.take());
    Module { body, package }
}

/// What lowering needs to know about the class whose members it is in.
#[derive(Default)]
struct ClassInfo {
    name: String,
    /// Instance and static fields with their declared types.
    fields: HashMap<String, String>,
    static_fields: HashSet<String>,
    /// Method name -> every overload is static.
    methods: HashMap<String, bool>,
}

struct Lower<'s> {
    src: &'s str,
    depth: Cell<u32>,
    /// Lowered classes, nested and local ones included.
    classes: RefCell<Vec<Stmt>>,
    class_stack: RefCell<Vec<ClassInfo>>,
    /// Local variables in scope with their declared types.
    scopes: RefCell<Vec<HashMap<String, String>>>,
    /// Inside a static method or initializer: there is no `this`.
    static_ctx: Cell<bool>,
    /// Assignments found inside expressions, run before their statement.
    hoisted: RefCell<Vec<Stmt>>,
    static_imports: RefCell<HashSet<String>>,
    anon: Cell<u32>,
}

/// Deeper syntax is replaced by an opaque expression, as in the Python
/// front end.
const MAX_DEPTH: u32 = 400;

fn is_type_declaration(kind: &str) -> bool {
    matches!(
        kind,
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

fn dotted(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

impl<'s> Lower<'s> {
    fn text(&self, node: Node) -> &'s str {
        text(node, self.src)
    }

    // ----- declarations -----

    fn import(&self, node: Node) -> Option<Stmt> {
        let is_static = children(node).iter().any(|c| c.kind() == "static");
        let wildcard = children(node).iter().any(|c| c.kind() == "asterisk");
        let path = named_children(node)
            .into_iter()
            .find(|c| matches!(c.kind(), "identifier" | "scoped_identifier"))
            .map(|c| dotted(self.text(c)))?;
        if wildcard {
            return Some(Stmt::Import {
                alias: "*".into(),
                path,
            });
        }
        let alias = path.rsplit('.').next().unwrap_or(&path).to_string();
        if is_static {
            self.static_imports.borrow_mut().insert(alias.clone());
        }
        Some(Stmt::Import { alias, path })
    }

    /// Simple or qualified name of a type, without type arguments.
    fn type_name(&self, node: Node) -> String {
        match node.kind() {
            "generic_type" => named_children(node)
                .into_iter()
                .find(|c| c.kind() != "type_arguments")
                .map(|c| self.type_name(c))
                .unwrap_or_default(),
            "array_type" => {
                let el = node
                    .child_by_field_name("element")
                    .map(|e| self.type_name(e))
                    .unwrap_or_default();
                format!("{el}[]")
            }
            "annotated_type" => named_children(node)
                .into_iter()
                .rfind(|c| !c.kind().contains("annotation"))
                .map(|c| self.type_name(c))
                .unwrap_or_default(),
            "scoped_type_identifier" => {
                let mut parts: Vec<String> = Vec::new();
                for c in named_children(node) {
                    if !c.kind().contains("annotation") {
                        parts.push(self.type_name(c));
                    }
                }
                parts.join(".")
            }
            _ => dotted(self.text(node)),
        }
    }

    fn is_static(&self, node: Node) -> bool {
        named_children(node)
            .into_iter()
            .find(|c| c.kind() == "modifiers")
            .map(|m| children(m).iter().any(|c| c.kind() == "static"))
            .unwrap_or(false)
    }

    fn annotations(&self, node: Node) -> Vec<Expr> {
        let Some(mods) = named_children(node)
            .into_iter()
            .find(|c| c.kind() == "modifiers")
        else {
            return Vec::new();
        };
        named_children(mods)
            .into_iter()
            .filter_map(|a| self.annotation(a))
            .collect()
    }

    fn annotation(&self, node: Node) -> Option<Expr> {
        let name = node
            .child_by_field_name("name")
            .map(|n| dotted(self.text(n)))?;
        match node.kind() {
            "marker_annotation" => Some(Expr::Name(name)),
            "annotation" => {
                let mut args = Vec::new();
                if let Some(list) = node.child_by_field_name("arguments") {
                    for a in named_children(list) {
                        if a.kind() == "element_value_pair" {
                            let key = a.child_by_field_name("key").map(|k| self.text(k));
                            let value = a
                                .child_by_field_name("value")
                                .map(|v| self.element_value(v))
                                .unwrap_or(Expr::Other(Vec::new()));
                            args.push(Arg {
                                name: key.map(str::to_string),
                                value,
                                spread: false,
                            });
                        } else {
                            args.push(Arg {
                                name: None,
                                value: self.element_value(a),
                                spread: false,
                            });
                        }
                    }
                }
                Some(Expr::Call {
                    func: Box::new(Expr::Name(name)),
                    args,
                    span: span(node),
                })
            }
            _ => None,
        }
    }

    fn element_value(&self, node: Node) -> Expr {
        match node.kind() {
            "element_value_array_initializer" => Expr::List(
                named_children(node)
                    .into_iter()
                    .map(|c| self.element_value(c))
                    .collect(),
            ),
            "annotation" | "marker_annotation" => {
                self.annotation(node).unwrap_or(Expr::Other(Vec::new()))
            }
            _ => self.expr(node),
        }
    }

    /// Lowers a class and the classes nested in it into `self.classes`;
    /// returns the name it was given.
    fn class(&self, node: Node, anon_base: Option<String>) -> String {
        let name = match &anon_base {
            Some(base) => {
                self.anon.set(self.anon.get() + 1);
                format!(
                    "{}$anon{}",
                    base.rsplit('.').next().unwrap_or(base),
                    self.anon.get()
                )
            }
            None => node
                .child_by_field_name("name")
                .map(|n| self.text(n).to_string())
                .unwrap_or_default(),
        };
        let mut bases = Vec::new();
        if let Some(base) = anon_base {
            bases.push(base);
        }
        if let Some(sup) = node.child_by_field_name("superclass") {
            for t in named_children(sup) {
                bases.push(self.type_name(t));
            }
        }
        let mut type_lists = Vec::new();
        if let Some(i) = node.child_by_field_name("interfaces") {
            type_lists.extend(named_children(i));
        }
        for c in named_children(node) {
            if c.kind() == "extends_interfaces" {
                type_lists.extend(named_children(c));
            }
        }
        for list in type_lists {
            for t in named_children(list) {
                bases.push(self.type_name(t));
            }
        }
        let body = if anon_base_is_body(node) {
            Some(node)
        } else {
            node.child_by_field_name("body")
        };
        let members = body.map(|b| self.members(b)).unwrap_or_default();

        // Declarations first: members may use each other in any order.
        let mut info = ClassInfo {
            name: name.clone(),
            ..Default::default()
        };
        if node.kind() == "record_declaration" {
            if let Some(params) = node.child_by_field_name("parameters") {
                for p in named_children(params) {
                    if let Some(n) = p.child_by_field_name("name") {
                        let ty = p
                            .child_by_field_name("type")
                            .map(|t| self.type_name(t))
                            .unwrap_or_default();
                        info.fields.insert(self.text(n).to_string(), ty);
                    }
                }
            }
        }
        let is_interface = node.kind() == "interface_declaration";
        for m in &members {
            match m.kind() {
                "field_declaration" | "constant_declaration" => {
                    let ty = m
                        .child_by_field_name("type")
                        .map(|t| self.type_name(t))
                        .unwrap_or_default();
                    let is_static =
                        is_interface || m.kind() == "constant_declaration" || self.is_static(*m);
                    for d in named_children(*m) {
                        if d.kind() != "variable_declarator" {
                            continue;
                        }
                        if let Some(n) = d.child_by_field_name("name") {
                            let n = self.text(n).to_string();
                            if is_static {
                                info.static_fields.insert(n.clone());
                            }
                            info.fields.insert(n, ty.clone());
                        }
                    }
                }
                "enum_constant" => {
                    if let Some(n) = m.child_by_field_name("name") {
                        let n = self.text(n).to_string();
                        info.static_fields.insert(n.clone());
                        info.fields.insert(n, name.clone());
                    }
                }
                "method_declaration" => {
                    if let Some(n) = m.child_by_field_name("name") {
                        let st = self.is_static(*m);
                        info.methods
                            .entry(self.text(n).to_string())
                            .and_modify(|all| *all &= st)
                            .or_insert(st);
                    }
                }
                _ => {}
            }
        }
        self.class_stack.borrow_mut().push(info);

        let mut fields = Vec::new();
        let mut methods = Vec::new();
        for m in &members {
            match m.kind() {
                "field_declaration" | "constant_declaration" => {
                    let is_static =
                        is_interface || m.kind() == "constant_declaration" || self.is_static(*m);
                    let saved = self.static_ctx.replace(is_static);
                    self.scopes.borrow_mut().push(HashMap::new());
                    self.declaration(*m, &mut fields);
                    self.scopes.borrow_mut().pop();
                    self.static_ctx.set(saved);
                }
                "enum_constant" => {
                    if let Some(n) = m.child_by_field_name("name") {
                        let n = self.text(n).to_string();
                        fields.push(Stmt::Declare {
                            name: n.clone(),
                            ty: name.clone(),
                            value: Some(Expr::Lit(Const::Str(n))),
                            span: span(*m),
                        });
                    }
                }
                "method_declaration" => {
                    if let Some(f) = self.method(*m, &name) {
                        methods.push(Rc::new(f));
                    }
                }
                "constructor_declaration" | "compact_constructor_declaration" => {
                    methods.push(Rc::new(self.constructor(*m, &name)));
                }
                "static_initializer" | "block" => {
                    let saved = self.static_ctx.replace(m.kind() == "static_initializer");
                    self.scopes.borrow_mut().push(HashMap::new());
                    for b in named_children(*m) {
                        self.stmt(b, &mut fields);
                    }
                    self.scopes.borrow_mut().pop();
                    self.static_ctx.set(saved);
                }
                k if is_type_declaration(k) => {
                    self.class(*m, None);
                }
                _ => {}
            }
        }
        self.class_stack.borrow_mut().pop();
        self.classes
            .borrow_mut()
            .push(Stmt::ClassDef(Rc::new(Class {
                name: name.clone(),
                bases,
                fields,
                methods,
                span: span(node),
            })));
        name
    }

    /// Members of a class, enum or interface body.
    fn members<'t>(&self, body: Node<'t>) -> Vec<Node<'t>> {
        let mut out = Vec::new();
        for c in named_children(body) {
            if c.kind() == "enum_body_declarations" {
                out.extend(named_children(c));
            } else {
                out.push(c);
            }
        }
        out
    }

    fn params(&self, node: Node, out: &mut Vec<Param>) {
        let Some(list) = node.child_by_field_name("parameters") else {
            return;
        };
        for p in named_children(list) {
            let (name, ty) = match p.kind() {
                "formal_parameter" => (
                    p.child_by_field_name("name")
                        .map(|n| self.text(n).to_string()),
                    p.child_by_field_name("type").map(|t| self.type_name(t)),
                ),
                "spread_parameter" => {
                    let decl = named_children(p)
                        .into_iter()
                        .find(|c| c.kind() == "variable_declarator");
                    let ty = named_children(p)
                        .into_iter()
                        .find(|c| !matches!(c.kind(), "variable_declarator" | "modifiers"))
                        .map(|t| format!("{}[]", self.type_name(t)));
                    (
                        decl.and_then(|d| d.child_by_field_name("name"))
                            .map(|n| self.text(n).to_string()),
                        ty,
                    )
                }
                _ => (None, None),
            };
            let Some(name) = name else { continue };
            let ty = ty.unwrap_or_default();
            // Parameter annotations (`@RequestParam`) are kept in front of
            // the type for the framework models.
            let notes: Vec<String> = self
                .annotations(p)
                .iter()
                .filter_map(|a| match a {
                    Expr::Name(n) => Some(format!("@{n}")),
                    Expr::Call { func, .. } => match &**func {
                        Expr::Name(n) => Some(format!("@{n}")),
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            let full_ty = if notes.is_empty() {
                ty.clone()
            } else {
                format!("{} {ty}", notes.join(" "))
            };
            self.declare_local(&name, &ty);
            out.push(Param {
                name,
                ty: Some(full_ty),
                default: None,
                variadic: false,
            });
        }
    }

    fn method(&self, node: Node, class: &str) -> Option<Function> {
        // Abstract and interface methods have no body to run; calls to them
        // fall back to the generic propagation of the library models.
        let body = node.child_by_field_name("body")?;
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
            .unwrap_or_default();
        let is_static = self.is_static(node);
        let mut decorators = self.annotations(node);
        if is_static {
            decorators.push(Expr::Name("staticmethod".into()));
        }
        Some(self.function(node, name, class, is_static, decorators, body))
    }

    fn constructor(&self, node: Node, class: &str) -> Function {
        let decorators = self.annotations(node);
        match node.child_by_field_name("body") {
            Some(body) => self.function(node, "__init__".into(), class, false, decorators, body),
            None => Function {
                name: "__init__".into(),
                params: vec![this_param(class)],
                body: Vec::new(),
                decorators,
                span: span(node),
            },
        }
    }

    fn function(
        &self,
        node: Node,
        name: String,
        class: &str,
        is_static: bool,
        decorators: Vec<Expr>,
        body: Node,
    ) -> Function {
        let saved_scopes = self.scopes.take();
        let saved_static = self.static_ctx.replace(is_static);
        self.scopes.borrow_mut().push(HashMap::new());
        let mut params = Vec::new();
        if !is_static {
            params.push(this_param(class));
        }
        self.params(node, &mut params);
        let mut stmts = Vec::new();
        for c in named_children(body) {
            self.stmt(c, &mut stmts);
        }
        self.static_ctx.set(saved_static);
        self.scopes.replace(saved_scopes);
        Function {
            name,
            params,
            body: stmts,
            decorators,
            span: span(node),
        }
    }

    // ----- scopes and names -----

    fn declare_local(&self, name: &str, ty: &str) {
        if let Some(s) = self.scopes.borrow_mut().last_mut() {
            s.insert(name.to_string(), ty.to_string());
        }
    }

    fn local_type(&self, name: &str) -> Option<String> {
        self.scopes
            .borrow()
            .iter()
            .rev()
            .find_map(|s| s.get(name).cloned())
    }

    fn field_type(&self, name: &str) -> Option<String> {
        self.class_stack
            .borrow()
            .iter()
            .rev()
            .find_map(|c| c.fields.get(name).cloned())
    }

    /// A bare identifier: local, field of this or an enclosing class, or a
    /// type / package name.
    fn name_ref(&self, id: &str, as_object: bool) -> Expr {
        if self.local_type(id).is_some() {
            return Expr::Name(id.to_string());
        }
        let stack = self.class_stack.borrow();
        for (depth, c) in stack.iter().rev().enumerate() {
            if !c.fields.contains_key(id) {
                continue;
            }
            if c.static_fields.contains(id) {
                return Expr::Attr(Box::new(Expr::Name(c.name.clone())), id.to_string());
            }
            if depth == 0 && !self.static_ctx.get() {
                return Expr::Attr(Box::new(Expr::Name("this".into())), id.to_string());
            }
        }
        let inherited_field = !as_object
            && !self.static_ctx.get()
            && !stack.is_empty()
            && id.chars().next().is_some_and(|c| c.is_ascii_lowercase());
        if inherited_field {
            return Expr::Attr(Box::new(Expr::Name("this".into())), id.to_string());
        }
        Expr::Name(id.to_string())
    }

    /// The callee of `name(args)` written without a receiver.
    fn bare_callee(&self, name: &str) -> Expr {
        if self.local_type(name).is_some() {
            return Expr::Name(name.to_string());
        }
        let stack = self.class_stack.borrow();
        for (depth, c) in stack.iter().rev().enumerate() {
            if let Some(all_static) = c.methods.get(name) {
                if *all_static || self.static_ctx.get() || depth > 0 {
                    return Expr::Attr(Box::new(Expr::Name(c.name.clone())), name.to_string());
                }
                return Expr::Attr(Box::new(Expr::Name("this".into())), name.to_string());
            }
        }
        if self.static_imports.borrow().contains(name) || self.static_ctx.get() || stack.is_empty()
        {
            return Expr::Name(name.to_string());
        }
        // Inherited from a superclass.
        Expr::Attr(Box::new(Expr::Name("this".into())), name.to_string())
    }

    /// Whether an expression is certainly a `String`, which makes `+`
    /// concatenation.
    fn is_string(&self, node: Node) -> bool {
        match node.kind() {
            "string_literal" => true,
            "parenthesized_expression" => named_children(node)
                .first()
                .is_some_and(|c| self.is_string(*c)),
            "binary_expression" => {
                node.child_by_field_name("operator")
                    .is_some_and(|o| self.text(o) == "+")
                    && [
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|c| self.is_string(c))
            }
            "identifier" => {
                let id = self.text(node);
                self.local_type(id)
                    .or_else(|| self.field_type(id))
                    .is_some_and(|t| is_string_type(&t))
            }
            "field_access" => node
                .child_by_field_name("field")
                .and_then(|f| self.field_type(self.text(f)))
                .is_some_and(|t| is_string_type(&t)),
            "method_invocation" => node.child_by_field_name("name").is_some_and(|n| {
                matches!(
                    self.text(n),
                    "toString"
                        | "substring"
                        | "trim"
                        | "toUpperCase"
                        | "toLowerCase"
                        | "replace"
                        | "replaceAll"
                        | "concat"
                        | "getParameter"
                        | "getHeader"
                        | "valueOf"
                        | "format"
                        | "join"
                )
            }),
            _ => false,
        }
    }

    fn is_numeric(&self, node: Node) -> bool {
        match node.kind() {
            "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal" => true,
            "parenthesized_expression" => named_children(node)
                .first()
                .is_some_and(|c| self.is_numeric(*c)),
            "identifier" => {
                let id = self.text(node);
                self.local_type(id)
                    .or_else(|| self.field_type(id))
                    .is_some_and(|t| is_numeric_type(&t))
            }
            "binary_expression" => [
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ]
            .into_iter()
            .flatten()
            .all(|c| self.is_numeric(c)),
            _ => false,
        }
    }

    // ----- statements -----

    fn block_of(&self, node: Option<Node>) -> Vec<Stmt> {
        let mut out = Vec::new();
        if let Some(n) = node {
            self.scopes.borrow_mut().push(HashMap::new());
            if n.kind() == "block" {
                for c in named_children(n) {
                    self.stmt(c, &mut out);
                }
            } else {
                self.stmt(n, &mut out);
            }
            self.scopes.borrow_mut().pop();
        }
        out
    }

    fn stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        if self.depth.get() >= MAX_DEPTH {
            return;
        }
        self.depth.set(self.depth.get() + 1);
        let saved = self.hoisted.take();
        let start = out.len();
        self.stmt_inner(node, out);
        let hoisted = self.hoisted.replace(saved);
        if !hoisted.is_empty() {
            out.splice(start..start, hoisted);
        }
        self.depth.set(self.depth.get() - 1);
    }

    fn stmt_inner(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "block" => {
                self.scopes.borrow_mut().push(HashMap::new());
                for c in named_children(node) {
                    self.stmt(c, out);
                }
                self.scopes.borrow_mut().pop();
            }
            "local_variable_declaration" => self.declaration(node, out),
            "expression_statement" => {
                for c in named_children(node) {
                    self.expr_stmt(c, out);
                }
            }
            "if_statement" => {
                let test = self.cond(node.child_by_field_name("condition"));
                let then = self.block_of(node.child_by_field_name("consequence"));
                let other = self.block_of(node.child_by_field_name("alternative"));
                out.push(Stmt::If {
                    test,
                    then,
                    other,
                    span: test_span(node),
                });
            }
            "while_statement" | "do_statement" => {
                let test = self.cond(node.child_by_field_name("condition"));
                let body = self.block_of(node.child_by_field_name("body"));
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
            }
            "for_statement" => {
                self.scopes.borrow_mut().push(HashMap::new());
                let mut cursor = node.walk();
                for init in node.children_by_field_name("init", &mut cursor) {
                    if init.kind() == "local_variable_declaration" {
                        self.declaration(init, out);
                    } else {
                        self.expr_stmt(init, out);
                    }
                }
                let test = node
                    .child_by_field_name("condition")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Lit(Const::Bool(true)));
                let mut body = self.block_of(node.child_by_field_name("body"));
                let mut cursor = node.walk();
                for u in node.children_by_field_name("update", &mut cursor) {
                    self.expr_stmt(u, &mut body);
                }
                self.scopes.borrow_mut().pop();
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
            }
            "enhanced_for_statement" => {
                let iter = node
                    .child_by_field_name("value")
                    .map(|v| self.expr(v))
                    .unwrap_or(Expr::Other(Vec::new()));
                self.scopes.borrow_mut().push(HashMap::new());
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_string())
                    .unwrap_or_default();
                let ty = node
                    .child_by_field_name("type")
                    .map(|t| self.type_name(t))
                    .unwrap_or_default();
                self.declare_local(&name, &ty);
                let body = self.block_of(node.child_by_field_name("body"));
                self.scopes.borrow_mut().pop();
                out.push(Stmt::Loop {
                    target: Some(Target::Name(name)),
                    iter: Some(iter),
                    test: None,
                    body,
                    span: span(node),
                });
            }
            "switch_expression" => out.push(self.switch(node)),
            "try_statement" | "try_with_resources_statement" => {
                self.scopes.borrow_mut().push(HashMap::new());
                let mut body = Vec::new();
                if let Some(res) = node.child_by_field_name("resources") {
                    for r in named_children(res) {
                        self.resource(r, &mut body);
                    }
                }
                body.extend(self.block_of(node.child_by_field_name("body")));
                self.scopes.borrow_mut().pop();
                let mut handlers = Vec::new();
                let mut finally = Vec::new();
                for c in named_children(node) {
                    match c.kind() {
                        "catch_clause" => {
                            self.scopes.borrow_mut().push(HashMap::new());
                            let mut h = Vec::new();
                            for p in named_children(c) {
                                if p.kind() == "catch_formal_parameter" {
                                    if let Some(n) = p.child_by_field_name("name") {
                                        let n = self.text(n).to_string();
                                        self.declare_local(&n, "Exception");
                                        h.push(Stmt::Assign {
                                            target: Target::Name(n),
                                            value: Expr::Other(Vec::new()),
                                            span: span(p),
                                        });
                                    }
                                }
                            }
                            h.extend(self.block_of(c.child_by_field_name("body")));
                            self.scopes.borrow_mut().pop();
                            handlers.push(h);
                        }
                        "finally_clause" => {
                            for b in named_children(c) {
                                finally.extend(self.block_of(Some(b)));
                            }
                        }
                        _ => {}
                    }
                }
                out.push(Stmt::Try {
                    body,
                    handlers,
                    finally,
                });
            }
            "return_statement" => {
                let value = named_children(node).first().map(|c| self.expr(*c));
                out.push(Stmt::Return(value, sp));
            }
            "throw_statement" => {
                for c in named_children(node) {
                    out.push(Stmt::Expr(self.expr(c), span(c)));
                }
                out.push(Stmt::Return(None, sp));
            }
            "break_statement" => out.push(Stmt::Break),
            "continue_statement" => out.push(Stmt::Continue),
            "labeled_statement" => {
                for c in named_children(node) {
                    if c.kind() != "identifier" {
                        self.stmt(c, out);
                    }
                }
            }
            "synchronized_statement" => {
                for c in named_children(node) {
                    if c.kind() == "block" {
                        self.stmt(c, out);
                    } else {
                        out.push(Stmt::Expr(self.expr(c), span(c)));
                    }
                }
            }
            "assert_statement" | "yield_statement" => {
                for c in named_children(node) {
                    out.push(Stmt::Expr(self.expr(c), span(c)));
                }
            }
            "explicit_constructor_invocation" => {
                let args = node
                    .child_by_field_name("arguments")
                    .map(|a| self.args(a))
                    .unwrap_or_default();
                out.push(Stmt::Expr(
                    Expr::Other(args.into_iter().map(|a| a.value).collect()),
                    sp,
                ));
            }
            k if is_type_declaration(k) => {
                self.class(node, None);
            }
            _ => {}
        }
    }

    fn resource(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ) {
            (Some(n), Some(v)) => {
                let name = self.text(n).to_string();
                let ty = node
                    .child_by_field_name("type")
                    .map(|t| self.type_name(t))
                    .unwrap_or_default();
                let value = self.expr(v);
                self.declare_local(&name, &ty);
                out.push(Stmt::Declare {
                    name,
                    ty,
                    value: Some(value),
                    span: sp,
                });
            }
            _ => {
                for c in named_children(node) {
                    out.push(Stmt::Expr(self.expr(c), sp));
                }
            }
        }
    }

    /// Local variable, field or constant declaration with its declarators.
    fn declaration(&self, node: Node, out: &mut Vec<Stmt>) {
        let ty = node
            .child_by_field_name("type")
            .map(|t| self.type_name(t))
            .unwrap_or_default();
        for d in named_children(node) {
            if d.kind() != "variable_declarator" {
                continue;
            }
            let Some(n) = d.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(n).to_string();
            let dims = d.child_by_field_name("dimensions").is_some();
            let ty = if dims { format!("{ty}[]") } else { ty.clone() };
            let value = d.child_by_field_name("value").map(|v| self.expr(v));
            self.declare_local(&name, &ty);
            out.push(Stmt::Declare {
                name,
                ty,
                value,
                span: span(d),
            });
        }
    }

    /// An expression used as a statement: assignments and updates become
    /// [`Stmt::Assign`].
    fn expr_stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "assignment_expression" => {
                if let Some(s) = self.assignment(node) {
                    out.push(s);
                }
            }
            "update_expression" => {
                if let Some(operand) = named_children(node).first() {
                    let target = self.target(*operand);
                    let value = Expr::Bin(
                        if self.text(node).contains("--") {
                            BinOp::Sub
                        } else {
                            BinOp::Add
                        },
                        Box::new(self.expr(*operand)),
                        Box::new(Expr::Lit(Const::Int(1))),
                    );
                    out.push(Stmt::Assign {
                        target,
                        value,
                        span: sp,
                    });
                }
            }
            "parenthesized_expression" => {
                for c in named_children(node) {
                    self.expr_stmt(c, out);
                }
            }
            _ => out.push(Stmt::Expr(self.expr(node), sp)),
        }
    }

    fn assignment(&self, node: Node) -> Option<Stmt> {
        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("=");
        let target = self.target(left);
        let rhs = self.expr(right);
        let value = match op {
            "=" => rhs,
            "+=" => {
                if self.is_numeric(left) && self.is_numeric(right) {
                    Expr::Bin(BinOp::Add, Box::new(self.expr(left)), Box::new(rhs))
                } else if self.is_string(left) || self.is_string(right) {
                    concat(vec![self.expr(left), rhs])
                } else {
                    Expr::Bin(BinOp::Add, Box::new(self.expr(left)), Box::new(rhs))
                }
            }
            other => {
                let op = bin_op(other.trim_end_matches('='));
                match op {
                    Some(op) => Expr::Bin(op, Box::new(self.expr(left)), Box::new(rhs)),
                    None => Expr::Other(vec![self.expr(left), rhs]),
                }
            }
        };
        Some(Stmt::Assign {
            target,
            value,
            span: span(node),
        })
    }

    fn target(&self, node: Node) -> Target {
        match node.kind() {
            "identifier" => match self.name_ref(self.text(node), false) {
                Expr::Name(n) => Target::Name(n),
                Expr::Attr(o, f) => Target::Attr(o, f),
                _ => Target::Other,
            },
            "field_access" => {
                let obj = node
                    .child_by_field_name("object")
                    .map(|o| self.object(o))
                    .unwrap_or(Expr::Name("this".into()));
                let field = node
                    .child_by_field_name("field")
                    .map(|f| self.text(f).to_string())
                    .unwrap_or_default();
                Target::Attr(Box::new(obj), field)
            }
            "array_access" => {
                let array = node
                    .child_by_field_name("array")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()));
                let index = node
                    .child_by_field_name("index")
                    .map(|i| self.expr(i))
                    .unwrap_or(Expr::Other(Vec::new()));
                Target::Index(Box::new(array), Box::new(index))
            }
            "parenthesized_expression" => named_children(node)
                .first()
                .map(|c| self.target(*c))
                .unwrap_or(Target::Other),
            _ => Target::Other,
        }
    }

    fn switch(&self, node: Node) -> Stmt {
        let subject = self.cond(node.child_by_field_name("condition"));
        let mut cases = Vec::new();
        let mut fallthrough = false;
        if let Some(body) = node.child_by_field_name("body") {
            for group in named_children(body) {
                let rule = group.kind() == "switch_rule";
                if !rule && group.kind() != "switch_block_statement_group" {
                    continue;
                }
                fallthrough |= !rule;
                let mut patterns = Vec::new();
                let mut is_default = false;
                let mut stmts = Vec::new();
                self.scopes.borrow_mut().push(HashMap::new());
                for c in named_children(group) {
                    if c.kind() == "switch_label" {
                        let exprs: Vec<Node> = named_children(c)
                            .into_iter()
                            .filter(|e| !matches!(e.kind(), "guard" | "pattern"))
                            .collect();
                        if exprs.is_empty() {
                            is_default = true;
                        }
                        for e in exprs {
                            patterns.push(self.expr(e));
                        }
                    } else if rule && c.kind() == "expression_statement" {
                        // `case X -> expr;`
                        for e in named_children(c) {
                            self.expr_stmt(e, &mut stmts);
                        }
                    } else {
                        self.stmt(c, &mut stmts);
                    }
                }
                self.scopes.borrow_mut().pop();
                if is_default {
                    patterns.clear();
                }
                cases.push(Case {
                    patterns,
                    body: stmts,
                });
            }
        }
        Stmt::Switch {
            subject,
            cases,
            fallthrough,
        }
    }

    fn cond(&self, node: Option<Node>) -> Expr {
        match node {
            Some(n) if n.kind() == "parenthesized_expression" => named_children(n)
                .first()
                .map(|c| self.expr(*c))
                .unwrap_or(Expr::Other(Vec::new())),
            Some(n) => self.expr(n),
            None => Expr::Other(Vec::new()),
        }
    }

    // ----- expressions -----

    fn args(&self, list: Node) -> Vec<Arg> {
        named_children(list)
            .into_iter()
            .map(|a| Arg {
                name: None,
                value: self.expr(a),
                spread: false,
            })
            .collect()
    }

    /// The receiver of `x.f` or `x.m()`: a bare identifier there may also
    /// be a class or the start of a package name.
    fn object(&self, node: Node) -> Expr {
        match node.kind() {
            "identifier" => self.name_ref(self.text(node), true),
            "super" | "this" => Expr::Name("this".into()),
            _ => self.expr(node),
        }
    }

    fn expr(&self, node: Node) -> Expr {
        if self.depth.get() >= MAX_DEPTH {
            return Expr::Other(Vec::new());
        }
        self.depth.set(self.depth.get() + 1);
        let e = self.expr_inner(node);
        self.depth.set(self.depth.get() - 1);
        e
    }

    fn expr_inner(&self, node: Node) -> Expr {
        let sp = span(node);
        match node.kind() {
            "identifier" => self.name_ref(self.text(node), false),
            "this" | "super" => Expr::Name("this".into()),
            "parenthesized_expression" => named_children(node)
                .first()
                .map(|c| self.expr(*c))
                .unwrap_or(Expr::Other(Vec::new())),
            "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal" => match parse_int(self.text(node)) {
                Some(i) => Expr::Lit(Const::Int(i)),
                None => Expr::Other(Vec::new()),
            },
            "decimal_floating_point_literal" | "hex_floating_point_literal" => {
                let t = self
                    .text(node)
                    .trim_end_matches(['f', 'F', 'd', 'D'])
                    .replace('_', "");
                match t.parse::<f64>() {
                    Ok(f) => Expr::Lit(Const::Float(f)),
                    Err(_) => Expr::Other(Vec::new()),
                }
            }
            "string_literal" => self.string(node),
            "character_literal" => {
                let t = self.text(node);
                let inner = t
                    .strip_prefix('\'')
                    .and_then(|t| t.strip_suffix('\''))
                    .unwrap_or(t);
                Expr::Lit(Const::Str(unescape(inner)))
            }
            "true" => Expr::Lit(Const::Bool(true)),
            "false" => Expr::Lit(Const::Bool(false)),
            "null_literal" => Expr::Lit(Const::None),
            "class_literal" => Expr::Lit(Const::Str(format!(
                "{}.class",
                named_children(node)
                    .first()
                    .map(|t| self.type_name(*t))
                    .unwrap_or_default()
            ))),
            "field_access" => {
                let field = node
                    .child_by_field_name("field")
                    .map(|f| self.text(f).to_string())
                    .unwrap_or_default();
                if field == "this" {
                    // `Outer.this`
                    return Expr::Name("this".into());
                }
                let obj = node
                    .child_by_field_name("object")
                    .map(|o| self.object(o))
                    .unwrap_or(Expr::Name("this".into()));
                if field == "length"
                    && !matches!(obj, Expr::Name(ref n) if n.starts_with(char::is_uppercase))
                {
                    // Array length: a number.
                    return Expr::Call {
                        func: Box::new(Expr::Name("len".into())),
                        args: vec![Arg {
                            name: None,
                            value: obj,
                            spread: false,
                        }],
                        span: sp,
                    };
                }
                Expr::Attr(Box::new(obj), field)
            }
            "method_invocation" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_string())
                    .unwrap_or_default();
                let args = node
                    .child_by_field_name("arguments")
                    .map(|a| self.args(a))
                    .unwrap_or_default();
                let func = match node.child_by_field_name("object") {
                    Some(o) => Expr::Attr(Box::new(self.object(o)), name),
                    None => self.bare_callee(&name),
                };
                Expr::Call {
                    func: Box::new(func),
                    args,
                    span: sp,
                }
            }
            "object_creation_expression" => {
                let ty = node
                    .child_by_field_name("type")
                    .map(|t| self.type_name(t))
                    .unwrap_or_default();
                let args = node
                    .child_by_field_name("arguments")
                    .map(|a| self.args(a))
                    .unwrap_or_default();
                let body = named_children(node)
                    .into_iter()
                    .find(|c| c.kind() == "class_body");
                let class = match body {
                    Some(b) => self.class(b, Some(ty)),
                    None => ty,
                };
                Expr::New {
                    class,
                    args,
                    span: sp,
                }
            }
            "array_creation_expression" => match node.child_by_field_name("value") {
                Some(init) => self.expr(init),
                None => {
                    let mut cursor = node.walk();
                    let dims: Vec<Expr> = node
                        .children_by_field_name("dimensions", &mut cursor)
                        .flat_map(named_children)
                        .map(|d| self.expr(d))
                        .collect();
                    Expr::Other(dims)
                }
            },
            "array_initializer" => Expr::List(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
            "array_access" => {
                let array = node
                    .child_by_field_name("array")
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()));
                let index = node
                    .child_by_field_name("index")
                    .map(|i| self.expr(i))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Index(Box::new(array), Box::new(index))
            }
            "assignment_expression" => {
                // `(line = reader.readLine()) != null`: run the assignment
                // before the statement, then use the variable.
                let left = node.child_by_field_name("left");
                if let Some(s) = self.assignment(node) {
                    self.hoisted.borrow_mut().push(s);
                }
                left.map(|l| self.expr(l))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "update_expression" => Expr::Other(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
            "binary_expression" => {
                let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return Expr::Other(Vec::new());
                };
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                if op == "+" && (self.is_string(l) || self.is_string(r)) {
                    return concat(vec![self.expr(l), self.expr(r)]);
                }
                match bin_op(op) {
                    Some(b) => Expr::Bin(b, Box::new(self.expr(l)), Box::new(self.expr(r))),
                    None => Expr::Other(vec![self.expr(l), self.expr(r)]),
                }
            }
            "unary_expression" => {
                let operand = node
                    .child_by_field_name("operand")
                    .map(|o| self.expr(o))
                    .unwrap_or(Expr::Other(Vec::new()));
                let op = match node.child_by_field_name("operator").map(|o| self.text(o)) {
                    Some("!") => UnOp::Not,
                    Some("-") => UnOp::Neg,
                    Some("~") => UnOp::BitNot,
                    _ => UnOp::Pos,
                };
                Expr::Un(op, Box::new(operand))
            }
            "ternary_expression" => {
                let part = |f: &str| {
                    node.child_by_field_name(f)
                        .map(|c| self.expr(c))
                        .unwrap_or(Expr::Other(Vec::new()))
                };
                Expr::Cond {
                    test: Box::new(part("condition")),
                    then: Box::new(part("consequence")),
                    other: Box::new(part("alternative")),
                }
            }
            "cast_expression" => {
                let mut cursor = node.walk();
                let ty = node
                    .children_by_field_name("type", &mut cursor)
                    .next()
                    .map(|t| self.type_name(t))
                    .unwrap_or_default();
                let value = node
                    .child_by_field_name("value")
                    .map(|v| self.expr(v))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Cast(ty, Box::new(value))
            }
            "instanceof_expression" => {
                let left = node
                    .child_by_field_name("left")
                    .map(|l| self.expr(l))
                    .unwrap_or(Expr::Other(Vec::new()));
                if let Some(n) = node.child_by_field_name("name") {
                    // `x instanceof Foo f` binds f.
                    let name = self.text(n).to_string();
                    let ty = node
                        .child_by_field_name("right")
                        .map(|t| self.type_name(t))
                        .unwrap_or_default();
                    self.declare_local(&name, &ty);
                    self.hoisted.borrow_mut().push(Stmt::Assign {
                        target: Target::Name(name),
                        value: left.clone(),
                        span: sp,
                    });
                }
                Expr::Other(vec![left])
            }
            "lambda_expression" => Expr::Lambda(Rc::new(self.lambda(node))),
            "switch_expression" => {
                // The value of a switch expression: any of its results.
                let mut values = Vec::new();
                if let Some(body) = node.child_by_field_name("body") {
                    for group in named_children(body) {
                        for c in named_children(group) {
                            match c.kind() {
                                "switch_label" => {}
                                "expression_statement" => {
                                    for e in named_children(c) {
                                        values.push(self.expr(e));
                                    }
                                }
                                k if k.ends_with("expression") || k == "identifier" => {
                                    values.push(self.expr(c))
                                }
                                _ => {
                                    let mut stmts = Vec::new();
                                    self.stmt(c, &mut stmts);
                                    collect_yields(&stmts, &mut values);
                                }
                            }
                        }
                    }
                }
                values.insert(0, self.cond(node.child_by_field_name("condition")));
                Expr::Other(values)
            }
            _ => Expr::Other(
                named_children(node)
                    .into_iter()
                    .filter(|c| !c.kind().ends_with("type") && c.kind() != "type_arguments")
                    .map(|c| self.expr(c))
                    .collect(),
            ),
        }
    }

    fn lambda(&self, node: Node) -> Function {
        self.scopes.borrow_mut().push(HashMap::new());
        let mut params = Vec::new();
        if let Some(p) = node.child_by_field_name("parameters") {
            match p.kind() {
                "identifier" => {
                    let n = self.text(p).to_string();
                    self.declare_local(&n, "");
                    params.push(Param {
                        name: n,
                        ty: None,
                        default: None,
                        variadic: false,
                    });
                }
                "inferred_parameters" => {
                    for c in named_children(p) {
                        let n = self.text(c).to_string();
                        self.declare_local(&n, "");
                        params.push(Param {
                            name: n,
                            ty: None,
                            default: None,
                            variadic: false,
                        });
                    }
                }
                _ => {
                    for c in named_children(p) {
                        if let Some(n) = c.child_by_field_name("name") {
                            let n = self.text(n).to_string();
                            let ty = c
                                .child_by_field_name("type")
                                .map(|t| self.type_name(t))
                                .unwrap_or_default();
                            self.declare_local(&n, &ty);
                            params.push(Param {
                                name: n,
                                ty: Some(ty),
                                default: None,
                                variadic: false,
                            });
                        }
                    }
                }
            }
        }
        let mut body = Vec::new();
        if let Some(b) = node.child_by_field_name("body") {
            if b.kind() == "block" {
                for c in named_children(b) {
                    self.stmt(c, &mut body);
                }
            } else {
                let saved = self.hoisted.take();
                let e = self.expr(b);
                body.extend(self.hoisted.replace(saved));
                body.push(Stmt::Return(Some(e), span(b)));
            }
        }
        self.scopes.borrow_mut().pop();
        Function {
            name: "<lambda>".into(),
            params,
            body,
            decorators: Vec::new(),
            span: span(node),
        }
    }

    fn string(&self, node: Node) -> Expr {
        let mut parts: Vec<Expr> = Vec::new();
        let mut lit = String::new();
        let mut any = false;
        for c in named_children(node) {
            match c.kind() {
                "string_fragment" | "multiline_string_fragment" => {
                    lit.push_str(self.text(c));
                    any = true;
                }
                "escape_sequence" => {
                    lit.push_str(&unescape(self.text(c)));
                    any = true;
                }
                "string_interpolation" => {
                    if !lit.is_empty() {
                        parts.push(Expr::Lit(Const::Str(std::mem::take(&mut lit))));
                    }
                    for e in named_children(c) {
                        parts.push(self.expr(e));
                    }
                }
                _ => {}
            }
        }
        if !any && parts.is_empty() {
            // Older grammars give no fragments: take the text between quotes.
            let t = self.text(node);
            let inner = t
                .strip_prefix("\"\"\"")
                .and_then(|t| t.strip_suffix("\"\"\""))
                .or_else(|| t.strip_prefix('"').and_then(|t| t.strip_suffix('"')))
                .unwrap_or(t);
            return Expr::Lit(Const::Str(unescape(inner)));
        }
        if parts.is_empty() {
            return Expr::Lit(Const::Str(lit));
        }
        if !lit.is_empty() {
            parts.push(Expr::Lit(Const::Str(lit)));
        }
        Expr::Concat(parts)
    }
}

fn anon_base_is_body(node: Node) -> bool {
    node.kind() == "class_body"
}

fn this_param(class: &str) -> Param {
    Param {
        name: "this".into(),
        ty: Some(class.to_string()),
        default: None,
        variadic: false,
    }
}

fn collect_yields(stmts: &[Stmt], out: &mut Vec<Expr>) {
    for s in stmts {
        match s {
            Stmt::Expr(e, _) => out.push(e.clone()),
            Stmt::If { then, other, .. } => {
                collect_yields(then, out);
                collect_yields(other, out);
            }
            _ => {}
        }
    }
}

fn is_string_type(t: &str) -> bool {
    matches!(
        t,
        "String" | "java.lang.String" | "CharSequence" | "StringBuilder" | "StringBuffer"
    )
}

pub(crate) fn is_numeric_type(t: &str) -> bool {
    matches!(
        t,
        "int"
            | "long"
            | "short"
            | "byte"
            | "double"
            | "float"
            | "Integer"
            | "Long"
            | "Short"
            | "Byte"
            | "Double"
            | "Float"
            | "java.lang.Integer"
            | "java.lang.Long"
            | "java.lang.Double"
            | "BigInteger"
            | "BigDecimal"
    )
}

/// `a + b` where one side is a string, flattened.
fn concat(parts: Vec<Expr>) -> Expr {
    let mut out = Vec::new();
    for p in parts {
        match p {
            Expr::Concat(inner) => out.extend(inner),
            other => out.push(other),
        }
    }
    Expr::Concat(out)
}

fn bin_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "%" => BinOp::Mod,
        "&" => BinOp::BitAnd,
        "|" => BinOp::BitOr,
        "^" => BinOp::BitXor,
        "<<" => BinOp::Shl,
        ">>" | ">>>" => BinOp::Shr,
        "==" => BinOp::Eq,
        "!=" => BinOp::NotEq,
        "<" => BinOp::Lt,
        "<=" => BinOp::LtE,
        ">" => BinOp::Gt,
        ">=" => BinOp::GtE,
        "&&" => BinOp::And,
        "||" => BinOp::Or,
        _ => return None,
    })
}

fn parse_int(t: &str) -> Option<i64> {
    let t = t.replace('_', "");
    let t = t.trim_end_matches(['l', 'L']);
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok().map(|v| v as i64);
    }
    if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        return u64::from_str_radix(b, 2).ok().map(|v| v as i64);
    }
    if t.len() > 1 && t.starts_with('0') {
        return i64::from_str_radix(&t[1..], 8).ok();
    }
    t.parse().ok()
}

/// Java escape sequences: `\n`, `\t`, `\"`, `\\`, octal and `\uXXXX`.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some('u') => {
                while chars.peek() == Some(&'u') {
                    chars.next();
                }
                let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(d @ '0'..='7') => {
                let mut v = d.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.peek().and_then(|c| c.to_digit(8)) {
                        Some(n) if v * 8 + n <= 0o377 => {
                            v = v * 8 + n;
                            chars.next();
                        }
                        _ => break,
                    }
                }
                out.push(char::from_u32(v).unwrap_or('\0'));
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
