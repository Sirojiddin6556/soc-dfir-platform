//! JavaScript / TypeScript front end (tree-sitter-javascript and
//! tree-sitter-typescript). It lowers `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`,
//! `.mts`, `.cts` and `.tsx` into the shared IR. TypeScript type syntax that
//! carries no runtime behaviour (interfaces, type aliases, annotations) is
//! dropped; parameter and class decorators are kept, since frameworks such as
//! NestJS use them to mark request data.

use super::{last_name, named_children, span, text};
use crate::ir::*;
use std::cell::Cell;
use std::rc::Rc;
use tree_sitter::Node;

pub fn lower(root: Node, src: &str) -> Module {
    let l = Lower {
        src,
        depth: Cell::new(0),
        temp: Cell::new(0),
    };
    Module {
        body: l.block(root),
        package: None,
    }
}

struct Lower<'s> {
    src: &'s str,
    depth: Cell<u32>,
    temp: Cell<u32>,
}

/// Deeper syntax is replaced by an opaque expression: generated code with
/// thousands of nested operators would otherwise exhaust the stack.
const MAX_DEPTH: u32 = 400;

impl<'s> Lower<'s> {
    fn text(&self, node: Node) -> &'s str {
        text(node, self.src)
    }

    fn temp_name(&self) -> String {
        let n = self.temp.get();
        self.temp.set(n + 1);
        format!("__js_d{n}")
    }

    fn block(&self, node: Node) -> Vec<Stmt> {
        let mut out = Vec::new();
        for child in named_children(node) {
            self.stmt(child, &mut out);
        }
        out
    }

    /// A statement position that may be a block or a single statement.
    fn stmt_body(&self, node: Option<Node>) -> Vec<Stmt> {
        let Some(node) = node else { return Vec::new() };
        if node.kind() == "statement_block" {
            self.block(node)
        } else {
            let mut out = Vec::new();
            self.stmt(node, &mut out);
            out
        }
    }

    fn stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        if self.depth.get() >= MAX_DEPTH {
            return;
        }
        self.depth.set(self.depth.get() + 1);
        self.stmt_inner(node, out);
        self.depth.set(self.depth.get() - 1);
    }

    fn stmt_inner(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "lexical_declaration" | "variable_declaration" => {
                for d in named_children(node) {
                    if d.kind() == "variable_declarator" {
                        self.declarator(d, out);
                    }
                }
            }
            "expression_statement" => {
                if let Some(child) = named_children(node).into_iter().next() {
                    self.expr_stmt(child, out);
                }
            }
            "if_statement" => out.push(self.if_stmt(node)),
            "for_statement" => {
                if let Some(init) = node.child_by_field_name("initializer") {
                    // `for (let i = ...)` / `for (x = ...)`.
                    self.stmt(init, out);
                }
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: node.child_by_field_name("condition").map(|c| self.expr(c)),
                    body: {
                        let mut body = self.stmt_body(node.child_by_field_name("body"));
                        if let Some(inc) = node.child_by_field_name("increment") {
                            body.push(Stmt::Expr(self.expr(inc), span(inc)));
                        }
                        body
                    },
                    span: sp,
                });
            }
            "for_in_statement" => {
                // Covers both `for..of` and `for..in`.
                out.push(Stmt::Loop {
                    target: node.child_by_field_name("left").map(|l| self.target(l)),
                    iter: node.child_by_field_name("right").map(|r| self.expr(r)),
                    test: None,
                    body: self.stmt_body(node.child_by_field_name("body")),
                    span: sp,
                });
            }
            "while_statement" => out.push(Stmt::Loop {
                target: None,
                iter: None,
                test: node.child_by_field_name("condition").map(|c| self.expr(c)),
                body: self.stmt_body(node.child_by_field_name("body")),
                span: sp,
            }),
            "do_statement" => out.push(Stmt::Loop {
                target: None,
                iter: None,
                test: node.child_by_field_name("condition").map(|c| self.expr(c)),
                body: self.stmt_body(node.child_by_field_name("body")),
                span: sp,
            }),
            "switch_statement" => out.push(self.switch_stmt(node)),
            "try_statement" => out.push(self.try_stmt(node)),
            "return_statement" => {
                let v = named_children(node)
                    .into_iter()
                    .next()
                    .map(|c| self.expr(c));
                out.push(Stmt::Return(v, sp));
            }
            "throw_statement" => {
                if let Some(c) = named_children(node).into_iter().next() {
                    out.push(Stmt::Expr(self.expr(c), sp));
                }
            }
            "break_statement" => out.push(Stmt::Break),
            "continue_statement" => out.push(Stmt::Continue),
            "function_declaration" | "generator_function_declaration" => {
                out.push(Stmt::FuncDef(Rc::new(self.function(node, None))))
            }
            "class_declaration" | "abstract_class_declaration" => {
                out.push(Stmt::ClassDef(Rc::new(self.class(node))))
            }
            "labeled_statement" => {
                if let Some(b) = node.child_by_field_name("body") {
                    self.stmt(b, out);
                } else if let Some(b) = named_children(node).into_iter().next_back() {
                    self.stmt(b, out);
                }
            }
            "statement_block" => out.extend(self.block(node)),
            "import_statement" => self.import_stmt(node, out),
            "export_statement" => {
                // `export { ... }` / `export default X` / `export const ...`.
                if let Some(decl) = node.child_by_field_name("declaration") {
                    self.stmt(decl, out);
                } else if let Some(v) = node.child_by_field_name("value") {
                    out.push(Stmt::Expr(self.expr(v), sp));
                } else {
                    for c in named_children(node) {
                        if is_stmt_kind(c.kind()) {
                            self.stmt(c, out);
                        }
                    }
                }
            }
            // Type-only TypeScript constructs carry no runtime behaviour.
            "interface_declaration"
            | "type_alias_declaration"
            | "ambient_declaration"
            | "import_alias"
            | "empty_statement" => {}
            "enum_declaration" => {}
            _ => {
                // Any other statement: keep its sub-expressions so data still
                // flows through them.
                for c in named_children(node) {
                    if is_stmt_kind(c.kind()) {
                        self.stmt(c, out);
                    } else {
                        out.push(Stmt::Expr(self.expr(c), span(c)));
                    }
                }
            }
        }
    }

    fn expr_stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "assignment_expression" => {
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                // `this.handle = (req, res) => {...}`: a named handler.
                if let Some(r) = right {
                    if is_func_literal(r.kind()) {
                        if let Some(name) = left.map(|l| self.func_name_from(l)) {
                            if !name.is_empty() {
                                out.push(Stmt::FuncDef(Rc::new(self.func_expr(r, name))));
                                return;
                            }
                        }
                    }
                }
                let target = self.target_opt(left);
                let value = self.expr_opt(right);
                out.push(Stmt::Assign {
                    target,
                    value,
                    span: sp,
                });
            }
            "augmented_assignment_expression" => {
                let target = self.target_opt(node.child_by_field_name("left"));
                let left = self.expr_opt(node.child_by_field_name("left"));
                let right = self.expr_opt(node.child_by_field_name("right"));
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("+=");
                let value = match op {
                    "+=" => Expr::Concat(vec![left, right]),
                    _ => match bin_op(op.trim_end_matches('=')) {
                        Some(b) => Expr::Bin(b, Box::new(left), Box::new(right)),
                        None => Expr::Other(vec![left, right]),
                    },
                };
                out.push(Stmt::Assign {
                    target,
                    value,
                    span: sp,
                });
            }
            _ => out.push(Stmt::Expr(self.expr(node), sp)),
        }
    }

    fn declarator(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        let name = node.child_by_field_name("name");
        let value = node.child_by_field_name("value");
        // `const handler = (req, res) => {...}`: a named function, so it is
        // reachable by name and analyzed as its own entry point.
        if let (Some(nm), Some(v)) = (name, value) {
            if is_func_literal(v.kind()) && matches!(nm.kind(), "identifier") {
                out.push(Stmt::FuncDef(Rc::new(
                    self.func_expr(v, self.text(nm).to_string()),
                )));
                return;
            }
        }
        match name.map(|n| n.kind()) {
            Some("object_pattern") => self.destructure_object(name.unwrap(), value, sp, out),
            Some("array_pattern") => out.push(Stmt::Assign {
                target: self.target(name.unwrap()),
                value: self.expr_opt(value),
                span: sp,
            }),
            _ => out.push(Stmt::Assign {
                target: self.target_opt(name),
                value: self.expr_opt(value),
                span: sp,
            }),
        }
    }

    /// `const { a, b: c } = expr` becomes `a = expr.a; c = expr.b`, with a
    /// temporary when the right side is not a plain reference so it is read
    /// once.
    fn destructure_object(&self, pat: Node, value: Option<Node>, sp: Span, out: &mut Vec<Stmt>) {
        let base = match value {
            None => Expr::Lit(Const::None),
            Some(v) => {
                let e = self.expr(v);
                if matches!(e, Expr::Name(_) | Expr::Attr(..) | Expr::Index(..)) {
                    e
                } else {
                    let tmp = self.temp_name();
                    out.push(Stmt::Assign {
                        target: Target::Name(tmp.clone()),
                        value: e,
                        span: sp,
                    });
                    Expr::Name(tmp)
                }
            }
        };
        for prop in named_children(pat) {
            match prop.kind() {
                "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
                    let key = self.text(prop).to_string();
                    out.push(Stmt::Assign {
                        target: Target::Name(key.clone()),
                        value: Expr::Attr(Box::new(base.clone()), key),
                        span: sp,
                    });
                }
                "pair_pattern" => {
                    let key = prop
                        .child_by_field_name("key")
                        .map(|k| self.text(k).to_string())
                        .unwrap_or_default();
                    let local = prop.child_by_field_name("value");
                    out.push(Stmt::Assign {
                        target: self.target_opt(local),
                        value: Expr::Attr(Box::new(base.clone()), key),
                        span: sp,
                    });
                }
                "rest_pattern" => {
                    if let Some(id) = named_children(prop).into_iter().next() {
                        out.push(Stmt::Assign {
                            target: self.target(id),
                            value: base.clone(),
                            span: sp,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    fn if_stmt(&self, node: Node) -> Stmt {
        let test = self.expr_opt(node.child_by_field_name("condition"));
        let then = self.stmt_body(node.child_by_field_name("consequence"));
        let other = match node.child_by_field_name("alternative") {
            Some(alt) => {
                // `else_clause` wraps a statement or another `if`.
                let inner = alt
                    .child_by_field_name("body")
                    .or_else(|| named_children(alt).into_iter().next());
                self.stmt_body(inner)
            }
            None => Vec::new(),
        };
        Stmt::If {
            test,
            then,
            other,
            span: span(node),
        }
    }

    fn switch_stmt(&self, node: Node) -> Stmt {
        let subject = self.expr_opt(node.child_by_field_name("value"));
        let mut cases = Vec::new();
        if let Some(body) = node.child_by_field_name("body") {
            for c in named_children(body) {
                match c.kind() {
                    "switch_case" => {
                        let patterns = c
                            .child_by_field_name("value")
                            .map(|v| vec![self.expr(v)])
                            .unwrap_or_default();
                        cases.push(Case {
                            patterns,
                            body: self.case_body(c),
                        });
                    }
                    "switch_default" => cases.push(Case {
                        patterns: Vec::new(),
                        body: self.case_body(c),
                    }),
                    _ => {}
                }
            }
        }
        Stmt::Switch {
            subject,
            cases,
            fallthrough: true,
        }
    }

    fn case_body(&self, node: Node) -> Vec<Stmt> {
        let mut out = Vec::new();
        for c in named_children(node) {
            if c.kind() == "switch_case" || c.kind() == "switch_default" {
                continue;
            }
            // The case value is a field, not a statement; skip it.
            if node.child_by_field_name("value") == Some(c) {
                continue;
            }
            self.stmt(c, &mut out);
        }
        out
    }

    fn try_stmt(&self, node: Node) -> Stmt {
        let body = self.stmt_body(node.child_by_field_name("body"));
        let mut handlers = Vec::new();
        let mut catches = Vec::new();
        if let Some(handler) = node.child_by_field_name("handler") {
            let h = self.stmt_body(handler.child_by_field_name("body"));
            let empty = h.is_empty();
            catches.push(Catch {
                types: Vec::new(),
                empty,
                span: span(handler),
            });
            handlers.push(h);
        }
        let finally = node
            .child_by_field_name("finalizer")
            .map(|f| self.stmt_body(f.child_by_field_name("body")))
            .unwrap_or_default();
        Stmt::Try {
            body,
            handlers,
            catches,
            finally,
        }
    }

    fn import_stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let source = node
            .child_by_field_name("source")
            .map(|s| string_value(s, self.src))
            .unwrap_or_default();
        let Some(clause) = named_children(node)
            .into_iter()
            .find(|c| c.kind() == "import_clause")
        else {
            return;
        };
        for c in named_children(clause) {
            match c.kind() {
                // `import express from 'express'`.
                "identifier" => out.push(Stmt::Import {
                    alias: self.text(c).to_string(),
                    path: source.clone(),
                }),
                // `import * as x from 'm'`.
                "namespace_import" => {
                    if let Some(id) = named_children(c).into_iter().next_back() {
                        out.push(Stmt::Import {
                            alias: self.text(id).to_string(),
                            path: source.clone(),
                        });
                    }
                }
                // `import { a, b as c } from 'm'`.
                "named_imports" => {
                    for spec in named_children(c) {
                        if spec.kind() != "import_specifier" {
                            continue;
                        }
                        let name = spec
                            .child_by_field_name("name")
                            .map(|n| self.text(n).to_string())
                            .unwrap_or_default();
                        let alias = spec
                            .child_by_field_name("alias")
                            .map(|a| self.text(a).to_string())
                            .unwrap_or_else(|| name.clone());
                        out.push(Stmt::Import {
                            alias,
                            path: if source.is_empty() {
                                name
                            } else {
                                format!("{source}.{name}")
                            },
                        });
                    }
                }
                _ => {}
            }
        }
    }

    // ----- functions and classes -----

    fn function(&self, node: Node, forced_name: Option<String>) -> Function {
        let name = forced_name.unwrap_or_else(|| {
            node.child_by_field_name("name")
                .map(|n| self.text(n).to_string())
                .unwrap_or_default()
        });
        let params = node
            .child_by_field_name("parameters")
            .map(|p| self.params(p))
            .unwrap_or_default();
        let body = self.function_body(node.child_by_field_name("body"));
        Function {
            name,
            params,
            body,
            decorators: self.decorators(node),
            span: span(node),
        }
    }

    /// A class method. Like Java and PHP, an instance method takes an
    /// implicit `this` as its first parameter so the interpreter binds the
    /// receiver; a static method is marked so it does not.
    fn method(&self, node: Node) -> Function {
        let mut f = self.function(node, None);
        if self.is_static_method(node) {
            f.decorators.push(Expr::Name("staticmethod".to_string()));
        } else {
            f.params.insert(
                0,
                Param {
                    name: "this".to_string(),
                    ty: None,
                    default: None,
                    variadic: false,
                },
            );
        }
        f
    }

    fn is_static_method(&self, node: Node) -> bool {
        super::children(node)
            .into_iter()
            .take_while(|c| c.kind() != "property_identifier")
            .any(|c| c.kind() == "static" || (!c.is_named() && self.text(c) == "static"))
    }

    /// An arrow or function expression as a value.
    fn lambda(&self, node: Node) -> Expr {
        Expr::Lambda(Rc::new(self.func_expr(node, String::new())))
    }

    /// An arrow or function expression, given a name so it can be analyzed as
    /// its own entry point (an Express handler assigned to `this.x` or a
    /// `const`).
    fn func_expr(&self, node: Node, name: String) -> Function {
        let params = match node.child_by_field_name("parameters") {
            Some(p) => self.params(p),
            None => match node.child_by_field_name("parameter") {
                // `x => ...`: a single parameter without parentheses.
                Some(p) => vec![Param {
                    name: self.text(p).to_string(),
                    ty: None,
                    default: None,
                    variadic: false,
                }],
                None => Vec::new(),
            },
        };
        let body = self.function_body(node.child_by_field_name("body"));
        Function {
            name,
            params,
            body,
            decorators: Vec::new(),
            span: span(node),
        }
    }

    fn function_body(&self, node: Option<Node>) -> Vec<Stmt> {
        let Some(node) = node else { return Vec::new() };
        if node.kind() == "statement_block" {
            self.block(node)
        } else {
            // An arrow with an expression body: its value is returned.
            vec![Stmt::Return(Some(self.expr(node)), span(node))]
        }
    }

    fn params(&self, node: Node) -> Vec<Param> {
        let mut out = Vec::new();
        for (i, p) in named_children(node).into_iter().enumerate() {
            out.push(self.param(p, i));
        }
        out
    }

    fn param(&self, node: Node, index: usize) -> Param {
        match node.kind() {
            "identifier" | "shorthand_property_identifier" => Param {
                name: self.text(node).to_string(),
                ty: None,
                default: None,
                variadic: false,
            },
            "required_parameter" | "optional_parameter" => {
                let pat = node.child_by_field_name("pattern");
                let name = pat
                    .map(|p| self.pattern_name(p, index))
                    .unwrap_or_else(|| format!("_arg{index}"));
                // A parameter decorator (NestJS `@Body() dto`) marks request
                // data; it takes priority over the declared type.
                let decorator = self.param_decorator(node);
                let ty = decorator.or_else(|| {
                    node.child_by_field_name("type")
                        .map(|t| self.text(t).trim_start_matches([':', ' ']).to_string())
                });
                Param {
                    name,
                    ty,
                    default: node.child_by_field_name("value").map(|v| self.expr(v)),
                    variadic: false,
                }
            }
            "rest_pattern" => {
                let name = named_children(node)
                    .into_iter()
                    .next()
                    .map(|n| self.pattern_name(n, index))
                    .unwrap_or_else(|| format!("_arg{index}"));
                Param {
                    name,
                    ty: None,
                    default: None,
                    variadic: true,
                }
            }
            "assignment_pattern" => {
                let left = node.child_by_field_name("left");
                let name = left
                    .map(|l| self.pattern_name(l, index))
                    .unwrap_or_else(|| format!("_arg{index}"));
                Param {
                    name,
                    ty: None,
                    default: node.child_by_field_name("right").map(|r| self.expr(r)),
                    variadic: false,
                }
            }
            "object_pattern" | "array_pattern" => Param {
                name: format!("_arg{index}"),
                ty: None,
                default: None,
                variadic: false,
            },
            _ => Param {
                name: format!("_arg{index}"),
                ty: None,
                default: None,
                variadic: false,
            },
        }
    }

    fn pattern_name(&self, node: Node, index: usize) -> String {
        match node.kind() {
            "identifier" | "shorthand_property_identifier" => self.text(node).to_string(),
            _ => format!("_arg{index}"),
        }
    }

    /// A parameter decorator such as `@Body()` or `@Query('id')`, as the
    /// marker `@Body` the model recognizes.
    fn param_decorator(&self, node: Node) -> Option<String> {
        for c in named_children(node) {
            if c.kind() == "decorator" {
                return Some(format!("@{}", decorator_name(c, self.src)));
            }
        }
        None
    }

    fn decorators(&self, node: Node) -> Vec<Expr> {
        let mut out = Vec::new();
        // Decorators attached as children of the declaration.
        for c in named_children(node) {
            if c.kind() == "decorator" {
                if let Some(inner) = named_children(c).into_iter().next() {
                    out.push(self.expr(inner));
                }
            }
        }
        out
    }

    fn class(&self, node: Node) -> Class {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
            .unwrap_or_default();
        let mut methods = Vec::new();
        let mut fields = Vec::new();
        if let Some(body) = node.child_by_field_name("body") {
            // Decorators appear as siblings preceding the member.
            let mut pending: Vec<Expr> = Vec::new();
            for c in named_children(body) {
                match c.kind() {
                    "decorator" => {
                        if let Some(inner) = named_children(c).into_iter().next() {
                            pending.push(self.expr(inner));
                        }
                    }
                    "method_definition" => {
                        let mut f = self.method(c);
                        let mut decs = std::mem::take(&mut pending);
                        decs.extend(std::mem::take(&mut f.decorators));
                        f.decorators = decs;
                        methods.push(Rc::new(f));
                    }
                    "field_definition" | "public_field_definition" => {
                        pending.clear();
                        let target = c
                            .child_by_field_name("name")
                            .map(|n| self.target(n))
                            .unwrap_or(Target::Other);
                        let value = self.expr_opt(c.child_by_field_name("value"));
                        fields.push(Stmt::Assign {
                            target,
                            value,
                            span: span(c),
                        });
                    }
                    _ => pending.clear(),
                }
            }
        }
        Class {
            name,
            bases: node
                .child_by_field_name("superclass")
                .map(|s| vec![last_name(self.text(s))])
                .unwrap_or_default(),
            fields,
            methods,
            span: span(node),
        }
    }

    // ----- expressions -----

    fn expr_opt(&self, node: Option<Node>) -> Expr {
        node.map(|n| self.expr(n))
            .unwrap_or(Expr::Other(Vec::new()))
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
        match node.kind() {
            "identifier"
            | "shorthand_property_identifier"
            | "property_identifier"
            | "private_property_identifier" => Expr::Name(self.text(node).to_string()),
            "this" => Expr::Name("this".to_string()),
            "super" => Expr::Name("super".to_string()),
            "number" => Expr::Lit(
                self.text(node)
                    .parse::<i64>()
                    .map(Const::Int)
                    .unwrap_or_else(|_| {
                        self.text(node)
                            .parse::<f64>()
                            .map(Const::Float)
                            .unwrap_or(Const::None)
                    }),
            ),
            "string" | "template_string" if node.kind() == "string" => {
                Expr::Lit(Const::Str(string_value(node, self.src)))
            }
            "string" => Expr::Lit(Const::Str(string_value(node, self.src))),
            "template_string" => self.template(node),
            "true" => Expr::Lit(Const::Bool(true)),
            "false" => Expr::Lit(Const::Bool(false)),
            "null" | "undefined" => Expr::Lit(Const::None),
            "regex" => Expr::Other(Vec::new()),
            "member_expression" => {
                let object = self.expr_opt(node.child_by_field_name("object"));
                let prop = node
                    .child_by_field_name("property")
                    .map(|p| self.text(p).to_string())
                    .unwrap_or_default();
                Expr::Attr(Box::new(object), prop)
            }
            "subscript_expression" => {
                let object = self.expr_opt(node.child_by_field_name("object"));
                let index = self.expr_opt(node.child_by_field_name("index"));
                Expr::Index(Box::new(object), Box::new(index))
            }
            "call_expression" => self.call(node),
            "new_expression" => {
                let class = node
                    .child_by_field_name("constructor")
                    .map(|c| last_name(self.text(c)))
                    .unwrap_or_default();
                let args = node
                    .child_by_field_name("arguments")
                    .map(|a| self.call_args(a))
                    .unwrap_or_default();
                Expr::New {
                    class,
                    args,
                    span: span(node),
                }
            }
            "binary_expression" => {
                let l = self.expr_opt(node.child_by_field_name("left"));
                let r = self.expr_opt(node.child_by_field_name("right"));
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("+");
                if op == "+" {
                    Expr::Concat(vec![l, r])
                } else {
                    match bin_op(op) {
                        Some(b) => Expr::Bin(b, Box::new(l), Box::new(r)),
                        None => Expr::Other(vec![l, r]),
                    }
                }
            }
            "unary_expression" => {
                let arg = self.expr_opt(node.child_by_field_name("argument"));
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                match op {
                    "!" => Expr::Un(UnOp::Not, Box::new(arg)),
                    "-" => Expr::Un(UnOp::Neg, Box::new(arg)),
                    "+" => Expr::Un(UnOp::Pos, Box::new(arg)),
                    "~" => Expr::Un(UnOp::BitNot, Box::new(arg)),
                    _ => Expr::Other(vec![arg]),
                }
            }
            "update_expression" => {
                Expr::Other(vec![self.expr_opt(node.child_by_field_name("argument"))])
            }
            "ternary_expression" => Expr::Cond {
                test: Box::new(self.expr_opt(node.child_by_field_name("condition"))),
                then: Box::new(self.expr_opt(node.child_by_field_name("consequence"))),
                other: Box::new(self.expr_opt(node.child_by_field_name("alternative"))),
            },
            "assignment_expression" => {
                // An assignment used as a value: keep both sides' data.
                let left = self.expr_opt(node.child_by_field_name("left"));
                let right = self.expr_opt(node.child_by_field_name("right"));
                Expr::Other(vec![left, right])
            }
            "augmented_assignment_expression" => {
                let left = self.expr_opt(node.child_by_field_name("left"));
                let right = self.expr_opt(node.child_by_field_name("right"));
                Expr::Other(vec![left, right])
            }
            "array" => Expr::List(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
            "object" => self.object(node),
            "arrow_function" | "function_expression" | "function" | "generator_function" => {
                self.lambda(node)
            }
            "parenthesized_expression" => named_children(node)
                .into_iter()
                .next()
                .map(|c| self.expr(c))
                .unwrap_or(Expr::Other(Vec::new())),
            "sequence_expression" => Expr::Other(vec![
                self.expr_opt(node.child_by_field_name("left")),
                self.expr_opt(node.child_by_field_name("right")),
            ]),
            "await_expression" | "yield_expression" | "spread_element" => named_children(node)
                .into_iter()
                .next()
                .map(|c| self.expr(c))
                .unwrap_or(Expr::Other(Vec::new())),
            // TypeScript expression wrappers carry the inner value through.
            "as_expression" | "satisfies_expression" | "non_null_expression" => {
                named_children(node)
                    .into_iter()
                    .next()
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "type_assertion" => named_children(node)
                .into_iter()
                .next_back()
                .map(|c| self.expr(c))
                .unwrap_or(Expr::Other(Vec::new())),
            "jsx_expression" => named_children(node)
                .into_iter()
                .next()
                .map(|c| self.expr(c))
                .unwrap_or(Expr::Other(Vec::new())),
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment" => self.jsx(node),
            _ => Expr::Other(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
        }
    }

    fn call(&self, node: Node) -> Expr {
        let func = node.child_by_field_name("function");
        let args_node = node.child_by_field_name("arguments");
        let args = match args_node {
            Some(a) if a.kind() == "arguments" => self.call_args(a),
            // A tagged template: `tag`...``.
            Some(a) => vec![Arg {
                name: None,
                value: self.expr(a),
                spread: false,
            }],
            None => Vec::new(),
        };
        Expr::Call {
            func: Box::new(self.expr_opt(func)),
            args,
            span: span(node),
        }
    }

    fn call_args(&self, node: Node) -> Vec<Arg> {
        let mut out = Vec::new();
        for c in named_children(node) {
            if c.kind() == "spread_element" {
                out.push(Arg {
                    name: None,
                    value: named_children(c)
                        .into_iter()
                        .next()
                        .map(|x| self.expr(x))
                        .unwrap_or(Expr::Other(Vec::new())),
                    spread: true,
                });
            } else {
                out.push(Arg {
                    name: None,
                    value: self.expr(c),
                    spread: false,
                });
            }
        }
        out
    }

    fn object(&self, node: Node) -> Expr {
        let mut pairs = Vec::new();
        for c in named_children(node) {
            match c.kind() {
                "pair" => {
                    let key = c
                        .child_by_field_name("key")
                        .map(|k| self.key_expr(k))
                        .unwrap_or(Expr::Other(Vec::new()));
                    let value = self.expr_opt(c.child_by_field_name("value"));
                    pairs.push((key, value));
                }
                "shorthand_property_identifier" => {
                    let name = self.text(c).to_string();
                    pairs.push((Expr::Lit(Const::Str(name.clone())), Expr::Name(name)));
                }
                "spread_element" => {
                    let inner = named_children(c)
                        .into_iter()
                        .next()
                        .map(|x| self.expr(x))
                        .unwrap_or(Expr::Other(Vec::new()));
                    pairs.push((Expr::Other(Vec::new()), inner));
                }
                "method_definition" => {
                    let name = c
                        .child_by_field_name("name")
                        .map(|n| self.text(n).to_string())
                        .unwrap_or_default();
                    pairs.push((
                        Expr::Lit(Const::Str(name)),
                        Expr::Lambda(Rc::new(self.function(c, None))),
                    ));
                }
                _ => {}
            }
        }
        Expr::Dict(pairs)
    }

    fn key_expr(&self, node: Node) -> Expr {
        match node.kind() {
            "property_identifier" | "shorthand_property_identifier" => {
                Expr::Lit(Const::Str(self.text(node).to_string()))
            }
            "string" => Expr::Lit(Const::Str(string_value(node, self.src))),
            "computed_property_name" => named_children(node)
                .into_iter()
                .next()
                .map(|c| self.expr(c))
                .unwrap_or(Expr::Other(Vec::new())),
            _ => Expr::Lit(Const::Str(self.text(node).to_string())),
        }
    }

    fn template(&self, node: Node) -> Expr {
        let mut parts = Vec::new();
        for c in named_children(node) {
            if c.kind() == "template_substitution" {
                if let Some(e) = named_children(c).into_iter().next() {
                    parts.push(self.expr(e));
                }
            }
        }
        // Literal fragments carry no data; a template with no substitutions
        // is a constant string.
        if parts.is_empty() {
            Expr::Lit(Const::Str(template_literal_text(node, self.src)))
        } else {
            Expr::Concat(parts)
        }
    }

    /// JSX: a React element. Its embedded expressions carry data, and a
    /// `dangerouslySetInnerHTML={{ __html: x }}` attribute is modeled as a
    /// call so the engine can flag unescaped HTML.
    fn jsx(&self, node: Node) -> Expr {
        let mut parts = Vec::new();
        self.jsx_collect(node, &mut parts);
        Expr::Other(parts)
    }

    fn jsx_collect(&self, node: Node, out: &mut Vec<Expr>) {
        for c in named_children(node) {
            match c.kind() {
                "jsx_opening_element" | "jsx_self_closing_element" => {
                    for attr in named_children(c) {
                        if attr.kind() == "jsx_attribute" {
                            self.jsx_attr(attr, out);
                        }
                    }
                }
                "jsx_expression" => {
                    if let Some(e) = named_children(c).into_iter().next() {
                        out.push(self.expr(e));
                    }
                }
                "jsx_element" | "jsx_fragment" => self.jsx_collect(c, out),
                _ => {}
            }
        }
    }

    fn jsx_attr(&self, attr: Node, out: &mut Vec<Expr>) {
        let name = named_children(attr)
            .into_iter()
            .next()
            .map(|n| self.text(n).to_string())
            .unwrap_or_default();
        let value = named_children(attr)
            .into_iter()
            .find(|c| c.kind() == "jsx_expression")
            .and_then(|e| named_children(e).into_iter().next());
        if name == "dangerouslySetInnerHTML" {
            // `{{ __html: x }}`: the inner object's value is the HTML.
            let html = value
                .map(|v| self.expr(v))
                .unwrap_or(Expr::Other(Vec::new()));
            out.push(Expr::Call {
                func: Box::new(Expr::Name("__jsx_dangerous_html".to_string())),
                args: vec![Arg {
                    name: None,
                    value: html,
                    spread: false,
                }],
                span: span(attr),
            });
        } else if let Some(v) = value {
            out.push(self.expr(v));
        }
    }

    // ----- targets -----

    fn target_opt(&self, node: Option<Node>) -> Target {
        node.map(|n| self.target(n)).unwrap_or(Target::Other)
    }

    fn target(&self, node: Node) -> Target {
        match node.kind() {
            "identifier" | "shorthand_property_identifier" | "property_identifier" => {
                Target::Name(self.text(node).to_string())
            }
            "member_expression" => {
                let object = self.expr_opt(node.child_by_field_name("object"));
                let prop = node
                    .child_by_field_name("property")
                    .map(|p| self.text(p).to_string())
                    .unwrap_or_default();
                Target::Attr(Box::new(object), prop)
            }
            "subscript_expression" => {
                let object = self.expr_opt(node.child_by_field_name("object"));
                let index = self.expr_opt(node.child_by_field_name("index"));
                Target::Index(Box::new(object), Box::new(index))
            }
            "array_pattern" => Target::Tuple(
                named_children(node)
                    .into_iter()
                    .map(|c| self.target(c))
                    .collect(),
            ),
            "parenthesized_expression" | "rest_pattern" | "assignment_pattern" => {
                named_children(node)
                    .into_iter()
                    .next()
                    .map(|c| self.target(c))
                    .unwrap_or(Target::Other)
            }
            _ => Target::Other,
        }
    }
}

fn is_func_literal(kind: &str) -> bool {
    matches!(
        kind,
        "arrow_function" | "function_expression" | "function" | "generator_function"
    )
}

impl Lower<'_> {
    /// The name to give a function literal assigned to a target: the variable
    /// or the last property (`this.handle` → "handle").
    fn func_name_from(&self, node: Node) -> String {
        match node.kind() {
            "identifier" | "property_identifier" | "shorthand_property_identifier" => {
                self.text(node).to_string()
            }
            "member_expression" => node
                .child_by_field_name("property")
                .map(|p| self.text(p).to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }
}

fn is_stmt_kind(kind: &str) -> bool {
    kind.ends_with("_statement")
        || kind.ends_with("_declaration")
        || matches!(kind, "statement_block")
}

/// The IR binary operator for a JavaScript operator, or `None` for `+`
/// (handled as string building) and operators the IR has no slot for.
fn bin_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "%" => BinOp::Mod,
        "**" => BinOp::Pow,
        "&" => BinOp::BitAnd,
        "|" => BinOp::BitOr,
        "^" => BinOp::BitXor,
        "<<" => BinOp::Shl,
        ">>" | ">>>" => BinOp::Shr,
        "==" | "===" => BinOp::Eq,
        "!=" | "!==" => BinOp::NotEq,
        "<" => BinOp::Lt,
        "<=" => BinOp::LtE,
        ">" => BinOp::Gt,
        ">=" => BinOp::GtE,
        "&&" => BinOp::And,
        "||" | "??" => BinOp::Or,
        "in" => BinOp::In,
        "instanceof" => BinOp::Is,
        _ => return None,
    })
}

/// The decorator's name: `@Body` → "Body", `@Query('id')` → "Query".
fn decorator_name(node: Node, src: &str) -> String {
    for c in named_children(node) {
        match c.kind() {
            "call_expression" => {
                if let Some(f) = c.child_by_field_name("function") {
                    return last_name(text(f, src));
                }
            }
            "identifier" | "member_expression" => return last_name(text(c, src)),
            _ => {}
        }
    }
    last_name(text(node, src).trim_start_matches('@'))
}

/// The text of a string literal without its quotes, joining fragments.
fn string_value(node: Node, src: &str) -> String {
    if node.kind() != "string" {
        let t = text(node, src);
        return t
            .trim_matches(|c| c == '"' || c == '\'' || c == '`')
            .to_string();
    }
    let mut out = String::new();
    for c in named_children(node) {
        if c.kind() == "string_fragment" {
            out.push_str(text(c, src));
        }
    }
    if out.is_empty() {
        // A single-fragment string whose fragment is unnamed, or an empty
        // literal: fall back to stripping the quotes.
        let t = text(node, src);
        return t
            .strip_prefix(['"', '\''])
            .and_then(|s| s.strip_suffix(['"', '\'']))
            .unwrap_or(t)
            .to_string();
    }
    out
}

/// A template string's literal text, used only when it has no substitutions.
fn template_literal_text(node: Node, src: &str) -> String {
    let t = text(node, src);
    t.strip_prefix('`')
        .and_then(|s| s.strip_suffix('`'))
        .unwrap_or(t)
        .to_string()
}
