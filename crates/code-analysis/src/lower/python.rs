//! Python front end (tree-sitter-python).

use super::{children, field_children, named_children, span, text};
use crate::ir::*;
use std::rc::Rc;
use tree_sitter::Node;

pub fn lower(root: Node, src: &str) -> Module {
    let l = Lower {
        src,
        depth: std::cell::Cell::new(0),
    };
    Module {
        body: l.block(root),
    }
}

struct Lower<'s> {
    src: &'s str,
    depth: std::cell::Cell<u32>,
}

/// Deeper syntax is replaced by an opaque expression: generated code with
/// thousands of nested operators would otherwise exhaust the stack.
const MAX_DEPTH: u32 = 400;

impl<'s> Lower<'s> {
    fn text(&self, node: Node) -> &'s str {
        text(node, self.src)
    }

    fn block(&self, node: Node) -> Vec<Stmt> {
        let mut out = Vec::new();
        for child in named_children(node) {
            self.stmt(child, &mut out);
        }
        out
    }

    fn opt_block(&self, node: Option<Node>) -> Vec<Stmt> {
        node.map(|n| self.block(n)).unwrap_or_default()
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
            "expression_statement" => {
                for child in named_children(node) {
                    match child.kind() {
                        "assignment" => self.assignment(child, out),
                        "augmented_assignment" => {
                            let target = self.target(child.child_by_field_name("left"));
                            let left = self.expr_opt(child.child_by_field_name("left"));
                            let right = self.expr_opt(child.child_by_field_name("right"));
                            let op = child
                                .child_by_field_name("operator")
                                .map(|o| self.text(o).trim_end_matches('='))
                                .unwrap_or("+");
                            let value = match bin_op(op) {
                                Some(BinOp::Add) => Expr::Concat(vec![left, right]),
                                Some(op) => Expr::Bin(op, Box::new(left), Box::new(right)),
                                None => Expr::Other(vec![left, right]),
                            };
                            out.push(Stmt::Assign {
                                target,
                                value,
                                span: sp,
                            });
                        }
                        _ => out.push(Stmt::Expr(self.expr(child), span(child))),
                    }
                }
            }
            "if_statement" => out.push(self.if_stmt(node)),
            "for_statement" => {
                out.push(Stmt::Loop {
                    target: Some(self.target(node.child_by_field_name("left"))),
                    iter: Some(self.expr_opt(node.child_by_field_name("right"))),
                    test: None,
                    body: self.opt_block(node.child_by_field_name("body")),
                });
                if let Some(alt) = node.child_by_field_name("alternative") {
                    out.extend(self.opt_block(alt.child_by_field_name("body")));
                }
            }
            "while_statement" => {
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(self.expr_opt(node.child_by_field_name("condition"))),
                    body: self.opt_block(node.child_by_field_name("body")),
                });
                if let Some(alt) = node.child_by_field_name("alternative") {
                    out.extend(self.opt_block(alt.child_by_field_name("body")));
                }
            }
            "try_statement" => {
                let mut body = self.opt_block(node.child_by_field_name("body"));
                let mut handlers = Vec::new();
                let mut finally = Vec::new();
                for child in named_children(node) {
                    match child.kind() {
                        "except_clause" | "except_group_clause" => {
                            let mut h = Vec::new();
                            for part in named_children(child) {
                                match part.kind() {
                                    "block" => h.extend(self.block(part)),
                                    "as_pattern" => {
                                        if let Some(alias) = part.child_by_field_name("alias") {
                                            h.push(Stmt::Assign {
                                                target: self
                                                    .target(named_children(alias).first().copied()),
                                                value: Expr::Other(Vec::new()),
                                                span: span(part),
                                            });
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            handlers.push(h);
                        }
                        "else_clause" => {
                            body.extend(self.opt_block(child.child_by_field_name("body")))
                        }
                        "finally_clause" => {
                            for part in named_children(child) {
                                if part.kind() == "block" {
                                    finally.extend(self.block(part));
                                }
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
            "with_statement" => {
                for clause in named_children(node) {
                    if clause.kind() != "with_clause" {
                        continue;
                    }
                    for item in named_children(clause) {
                        let Some(value) = item.child_by_field_name("value") else {
                            continue;
                        };
                        if value.kind() == "as_pattern" {
                            let inner = named_children(value).first().copied();
                            let alias = value
                                .child_by_field_name("alias")
                                .and_then(|a| named_children(a).first().copied());
                            out.push(Stmt::Assign {
                                target: self.target(alias),
                                value: self.expr_opt(inner),
                                span: span(item),
                            });
                        } else {
                            out.push(Stmt::Expr(self.expr(value), span(value)));
                        }
                    }
                }
                out.extend(self.opt_block(node.child_by_field_name("body")));
            }
            "return_statement" => {
                let value = named_children(node).first().map(|e| self.expr(*e));
                out.push(Stmt::Return(value, sp));
            }
            "break_statement" => out.push(Stmt::Break),
            "continue_statement" => out.push(Stmt::Continue),
            "raise_statement" | "assert_statement" => {
                for child in named_children(node) {
                    out.push(Stmt::Expr(self.expr(child), span(child)));
                }
                if node.kind() == "raise_statement" {
                    out.push(Stmt::Return(None, sp));
                }
            }
            "import_statement" => {
                for name in field_children(node, "name") {
                    match name.kind() {
                        "aliased_import" => {
                            let path = name
                                .child_by_field_name("name")
                                .map(|n| self.text(n))
                                .unwrap_or("");
                            let alias = name
                                .child_by_field_name("alias")
                                .map(|n| self.text(n))
                                .unwrap_or(path);
                            out.push(Stmt::Import {
                                alias: alias.to_string(),
                                path: path.to_string(),
                            });
                        }
                        _ => {
                            let path = self.text(name);
                            let first = path.split('.').next().unwrap_or(path);
                            out.push(Stmt::Import {
                                alias: first.to_string(),
                                path: first.to_string(),
                            });
                        }
                    }
                }
            }
            "import_from_statement" => {
                let module = node
                    .child_by_field_name("module_name")
                    .map(|n| self.text(n))
                    .unwrap_or("");
                for name in field_children(node, "name") {
                    let (path, alias) = match name.kind() {
                        "aliased_import" => {
                            let p = name
                                .child_by_field_name("name")
                                .map(|n| self.text(n))
                                .unwrap_or("");
                            let a = name
                                .child_by_field_name("alias")
                                .map(|n| self.text(n))
                                .unwrap_or(p);
                            (p, a)
                        }
                        _ => (self.text(name), self.text(name)),
                    };
                    let full = if module.is_empty() || module.ends_with('.') {
                        format!("{module}{path}")
                    } else {
                        format!("{module}.{path}")
                    };
                    out.push(Stmt::Import {
                        alias: alias.to_string(),
                        path: full,
                    });
                }
            }
            "function_definition" => {
                out.push(Stmt::FuncDef(Rc::new(self.function(node, Vec::new()))))
            }
            "class_definition" => out.push(Stmt::ClassDef(Rc::new(self.class(node)))),
            "decorated_definition" => {
                let decorators: Vec<Expr> = named_children(node)
                    .into_iter()
                    .filter(|c| c.kind() == "decorator")
                    .filter_map(|d| named_children(d).first().map(|e| self.expr(*e)))
                    .collect();
                if let Some(def) = node.child_by_field_name("definition") {
                    match def.kind() {
                        "function_definition" => {
                            out.push(Stmt::FuncDef(Rc::new(self.function(def, decorators))))
                        }
                        "class_definition" => out.push(Stmt::ClassDef(Rc::new(self.class(def)))),
                        _ => {}
                    }
                }
            }
            "match_statement" => {
                let subject = field_children(node, "subject")
                    .first()
                    .map(|s| self.expr(*s))
                    .unwrap_or(Expr::Other(Vec::new()));
                let mut cases = Vec::new();
                if let Some(body) = node.child_by_field_name("body") {
                    for clause in named_children(body) {
                        if clause.kind() != "case_clause" {
                            continue;
                        }
                        let mut patterns = Vec::new();
                        let mut wildcard = false;
                        for pat in named_children(clause) {
                            if pat.kind() == "case_pattern" {
                                self.case_pattern(pat, &mut patterns, &mut wildcard);
                            }
                        }
                        if wildcard {
                            patterns.clear();
                        }
                        cases.push(Case {
                            patterns,
                            body: self.opt_block(clause.child_by_field_name("consequence")),
                        });
                    }
                }
                out.push(Stmt::Switch {
                    subject,
                    cases,
                    fallthrough: false,
                });
            }
            "pass_statement"
            | "global_statement"
            | "nonlocal_statement"
            | "delete_statement"
            | "comment"
            | "future_import_statement" => {}
            "block" => out.extend(self.block(node)),
            _ => {
                // Unknown statement kinds still evaluate their expressions.
                let exprs: Vec<Expr> = named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect();
                if !exprs.is_empty() {
                    out.push(Stmt::Expr(Expr::Other(exprs), sp));
                }
            }
        }
    }

    fn case_pattern(&self, pat: Node, patterns: &mut Vec<Expr>, wildcard: &mut bool) {
        let kids = named_children(pat);
        if kids.is_empty() {
            // `case _:`
            *wildcard = true;
            return;
        }
        for kid in kids {
            match kid.kind() {
                "union_pattern" => {
                    for alt in named_children(kid) {
                        match alt.kind() {
                            "case_pattern" => self.case_pattern(alt, patterns, wildcard),
                            "dotted_name" if !self.text(alt).contains('.') => *wildcard = true,
                            _ => patterns.push(self.expr(alt)),
                        }
                    }
                }
                "string"
                | "integer"
                | "float"
                | "true"
                | "false"
                | "none"
                | "concatenated_string" => patterns.push(self.expr(kid)),
                // A bare name captures anything.
                "dotted_name" if !self.text(kid).contains('.') => *wildcard = true,
                "identifier" => *wildcard = true,
                _ => *wildcard = true,
            }
        }
    }

    fn if_stmt(&self, node: Node) -> Stmt {
        let test = self.expr_opt(node.child_by_field_name("condition"));
        let then = self.opt_block(node.child_by_field_name("consequence"));
        let alternatives = field_children(node, "alternative");
        Stmt::If {
            test,
            then,
            other: self.alternatives(&alternatives),
        }
    }

    fn alternatives(&self, alts: &[Node]) -> Vec<Stmt> {
        let Some((first, rest)) = alts.split_first() else {
            return Vec::new();
        };
        match first.kind() {
            "elif_clause" => vec![Stmt::If {
                test: self.expr_opt(first.child_by_field_name("condition")),
                then: self.opt_block(first.child_by_field_name("consequence")),
                other: self.alternatives(rest),
            }],
            "else_clause" => self.opt_block(first.child_by_field_name("body")),
            _ => Vec::new(),
        }
    }

    fn assignment(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        let left = node.child_by_field_name("left");
        let Some(right) = node.child_by_field_name("right") else {
            return; // bare annotation `x: int`
        };
        if right.kind() == "assignment" {
            // a = b = value: assign the inner chain first, then copy.
            self.assignment(right, out);
            let inner_left = right.child_by_field_name("left");
            out.push(Stmt::Assign {
                target: self.target(left),
                value: self.expr_opt(inner_left),
                span: sp,
            });
            return;
        }
        let target = self.target(left);
        let value = self.expr(right);
        // a, b = x, y with matching lengths: pairwise.
        if let (Target::Tuple(ts), Expr::List(vs)) = (&target, &value) {
            if ts.len() == vs.len() {
                for (t, v) in ts.iter().zip(vs.iter()) {
                    out.push(Stmt::Assign {
                        target: t.clone(),
                        value: v.clone(),
                        span: sp,
                    });
                }
                return;
            }
        }
        out.push(Stmt::Assign {
            target,
            value,
            span: sp,
        });
    }

    fn target(&self, node: Option<Node>) -> Target {
        let Some(node) = node else {
            return Target::Other;
        };
        match node.kind() {
            "identifier" => Target::Name(self.text(node).to_string()),
            "attribute" => Target::Attr(
                Box::new(self.expr_opt(node.child_by_field_name("object"))),
                node.child_by_field_name("attribute")
                    .map(|a| self.text(a).to_string())
                    .unwrap_or_default(),
            ),
            "subscript" => {
                let value = self.expr_opt(node.child_by_field_name("value"));
                let subs = field_children(node, "subscript");
                let index = match subs.first() {
                    Some(s) if s.kind() == "slice" => Expr::Other(Vec::new()),
                    Some(s) => self.expr(*s),
                    None => Expr::Other(Vec::new()),
                };
                Target::Index(Box::new(value), Box::new(index))
            }
            "pattern_list" | "tuple_pattern" | "list_pattern" | "tuple" | "list"
            | "expression_list" => Target::Tuple(
                named_children(node)
                    .into_iter()
                    .map(|c| self.target(Some(c)))
                    .collect(),
            ),
            "parenthesized_expression" => self.target(named_children(node).first().copied()),
            "list_splat_pattern" | "as_pattern_target" => {
                self.target(named_children(node).first().copied())
            }
            _ => Target::Other,
        }
    }

    fn function(&self, node: Node, decorators: Vec<Expr>) -> Function {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
            .unwrap_or_default();
        let mut params = Vec::new();
        if let Some(ps) = node.child_by_field_name("parameters") {
            for p in named_children(ps) {
                let (pname, ty, default) = match p.kind() {
                    "identifier" => (self.text(p).to_string(), None, None),
                    "typed_parameter" => (
                        named_children(p)
                            .first()
                            .map(|n| self.text(*n).to_string())
                            .unwrap_or_default(),
                        p.child_by_field_name("type")
                            .map(|t| self.text(t).to_string()),
                        None,
                    ),
                    "default_parameter" | "typed_default_parameter" => (
                        p.child_by_field_name("name")
                            .map(|n| self.text(n).to_string())
                            .unwrap_or_default(),
                        p.child_by_field_name("type")
                            .map(|t| self.text(t).to_string()),
                        p.child_by_field_name("value").map(|v| self.expr(v)),
                    ),
                    "list_splat_pattern" | "dictionary_splat_pattern" => (
                        named_children(p)
                            .first()
                            .map(|n| self.text(*n).to_string())
                            .unwrap_or_default(),
                        None,
                        None,
                    ),
                    _ => continue,
                };
                params.push(Param {
                    name: pname,
                    ty,
                    default,
                });
            }
        }
        Function {
            name,
            params,
            body: self.opt_block(node.child_by_field_name("body")),
            decorators,
            span: span(node),
        }
    }

    fn class(&self, node: Node) -> Class {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
            .unwrap_or_default();
        let bases = node
            .child_by_field_name("superclasses")
            .map(|s| {
                named_children(s)
                    .into_iter()
                    .map(|b| self.text(b).to_string())
                    .collect()
            })
            .unwrap_or_default();
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        if let Some(body) = node.child_by_field_name("body") {
            for stmt in self.block(body) {
                match stmt {
                    Stmt::FuncDef(f) => methods.push(f),
                    other => fields.push(other),
                }
            }
        }
        Class {
            name,
            bases,
            fields,
            methods,
            span: span(node),
        }
    }

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
            "identifier" => Expr::Name(self.text(node).to_string()),
            "attribute" => Expr::Attr(
                Box::new(self.expr_opt(node.child_by_field_name("object"))),
                node.child_by_field_name("attribute")
                    .map(|a| self.text(a).to_string())
                    .unwrap_or_default(),
            ),
            "subscript" => {
                let value = self.expr_opt(node.child_by_field_name("value"));
                let subs = field_children(node, "subscript");
                match subs.first() {
                    Some(s) if s.kind() == "slice" => {
                        // slice children: [lower] ':' [upper] [':' step]
                        let mut lower = None;
                        let mut upper = None;
                        let mut colons = 0;
                        for part in children(*s) {
                            if part.kind() == ":" {
                                colons += 1;
                            } else if part.is_named() {
                                let e = Box::new(self.expr(part));
                                match colons {
                                    0 => lower = Some(e),
                                    1 => upper = Some(e),
                                    _ => {}
                                }
                            }
                        }
                        Expr::Slice {
                            value: Box::new(value),
                            lower,
                            upper,
                        }
                    }
                    Some(s) => Expr::Index(Box::new(value), Box::new(self.expr(*s))),
                    None => value,
                }
            }
            "call" => {
                let func = self.expr_opt(node.child_by_field_name("function"));
                let mut args = Vec::new();
                if let Some(a) = node.child_by_field_name("arguments") {
                    if a.kind() == "generator_expression" {
                        args.push(Arg {
                            name: None,
                            value: self.expr(a),
                            spread: false,
                        });
                    } else {
                        for arg in named_children(a) {
                            match arg.kind() {
                                "keyword_argument" => args.push(Arg {
                                    name: arg
                                        .child_by_field_name("name")
                                        .map(|n| self.text(n).to_string()),
                                    value: self.expr_opt(arg.child_by_field_name("value")),
                                    spread: false,
                                }),
                                "list_splat" | "dictionary_splat" => args.push(Arg {
                                    name: None,
                                    value: self.expr_opt(named_children(arg).first().copied()),
                                    spread: true,
                                }),
                                _ => args.push(Arg {
                                    name: None,
                                    value: self.expr(arg),
                                    spread: false,
                                }),
                            }
                        }
                    }
                }
                Expr::Call {
                    func: Box::new(func),
                    args,
                    span: span(node),
                }
            }
            "string" => self.string(node),
            "concatenated_string" => {
                let parts: Vec<Expr> = named_children(node)
                    .into_iter()
                    .map(|s| self.string(s))
                    .collect();
                concat_or_literal(parts)
            }
            "integer" => parse_int(self.text(node))
                .map(|i| Expr::Lit(Const::Int(i)))
                .unwrap_or(Expr::Other(Vec::new())),
            "float" => self
                .text(node)
                .replace('_', "")
                .parse::<f64>()
                .map(|f| Expr::Lit(Const::Float(f)))
                .unwrap_or(Expr::Other(Vec::new())),
            "true" => Expr::Lit(Const::Bool(true)),
            "false" => Expr::Lit(Const::Bool(false)),
            "none" => Expr::Lit(Const::None),
            "binary_operator" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                let left = self.expr_opt(node.child_by_field_name("left"));
                let right = self.expr_opt(node.child_by_field_name("right"));
                match bin_op(op) {
                    Some(op) => Expr::Bin(op, Box::new(left), Box::new(right)),
                    None => Expr::Other(vec![left, right]),
                }
            }
            "boolean_operator" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                let left = self.expr_opt(node.child_by_field_name("left"));
                let right = self.expr_opt(node.child_by_field_name("right"));
                let op = if op == "and" { BinOp::And } else { BinOp::Or };
                Expr::Bin(op, Box::new(left), Box::new(right))
            }
            "comparison_operator" => self.comparison(node),
            "not_operator" => Expr::Un(
                UnOp::Not,
                Box::new(self.expr_opt(node.child_by_field_name("argument"))),
            ),
            "unary_operator" => {
                let op = match node.child_by_field_name("operator").map(|o| self.text(o)) {
                    Some("-") => UnOp::Neg,
                    Some("~") => UnOp::BitNot,
                    _ => UnOp::Pos,
                };
                Expr::Un(
                    op,
                    Box::new(self.expr_opt(node.child_by_field_name("argument"))),
                )
            }
            "conditional_expression" => {
                let kids = named_children(node);
                if kids.len() == 3 {
                    Expr::Cond {
                        then: Box::new(self.expr(kids[0])),
                        test: Box::new(self.expr(kids[1])),
                        other: Box::new(self.expr(kids[2])),
                    }
                } else {
                    Expr::Other(kids.into_iter().map(|k| self.expr(k)).collect())
                }
            }
            "parenthesized_expression" | "await" => {
                self.expr_opt(named_children(node).first().copied())
            }
            "list" | "tuple" | "set" | "expression_list" | "pattern_list" => Expr::List(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
            "dictionary" => {
                let mut pairs = Vec::new();
                let mut rest = Vec::new();
                for p in named_children(node) {
                    if p.kind() == "pair" {
                        pairs.push((
                            self.expr_opt(p.child_by_field_name("key")),
                            self.expr_opt(p.child_by_field_name("value")),
                        ));
                    } else {
                        rest.push(self.expr(p));
                    }
                }
                if rest.is_empty() {
                    Expr::Dict(pairs)
                } else {
                    rest.extend(pairs.into_iter().flat_map(|(k, v)| [k, v]));
                    Expr::Other(rest)
                }
            }
            "list_comprehension"
            | "set_comprehension"
            | "generator_expression"
            | "dictionary_comprehension" => {
                // The element expression plus every iterated source.
                let mut parts = Vec::new();
                for c in named_children(node) {
                    match c.kind() {
                        "for_in_clause" => {
                            parts.push(self.expr_opt(c.child_by_field_name("right")))
                        }
                        "if_clause" => {}
                        "pair" => {
                            parts.push(self.expr_opt(c.child_by_field_name("key")));
                            parts.push(self.expr_opt(c.child_by_field_name("value")));
                        }
                        _ => parts.push(self.expr(c)),
                    }
                }
                Expr::Other(parts)
            }
            "lambda" => {
                let params = node
                    .child_by_field_name("parameters")
                    .map(|ps| {
                        named_children(ps)
                            .into_iter()
                            .map(|p| Param {
                                name: self
                                    .text(p)
                                    .split(['=', ':'])
                                    .next()
                                    .unwrap_or("")
                                    .trim()
                                    .to_string(),
                                ty: None,
                                default: None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let body = self.expr_opt(node.child_by_field_name("body"));
                Expr::Lambda(Rc::new(Function {
                    name: "<lambda>".into(),
                    params,
                    body: vec![Stmt::Return(Some(body), span(node))],
                    decorators: Vec::new(),
                    span: span(node),
                }))
            }
            "named_expression" => self.expr_opt(node.child_by_field_name("value")),
            "keyword_argument" => self.expr_opt(node.child_by_field_name("value")),
            _ => Expr::Other(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
        }
    }

    fn comparison(&self, node: Node) -> Expr {
        // operands and operators alternate: a < b <= c  ==> (a < b) and (b <= c)
        let mut operands = Vec::new();
        let mut ops = Vec::new();
        for (i, child) in children(node).into_iter().enumerate() {
            if node.field_name_for_child(i as u32) == Some("operators") {
                let t: Vec<&str> = self.text(child).split_whitespace().collect();
                ops.push(t.join(" "));
            } else if child.is_named() {
                operands.push(self.expr(child));
            }
        }
        let mut result: Option<Expr> = None;
        for (i, op) in ops.iter().enumerate() {
            let (Some(l), Some(r)) = (operands.get(i), operands.get(i + 1)) else {
                break;
            };
            let cmp = match bin_op(op) {
                Some(op) => Expr::Bin(op, Box::new(l.clone()), Box::new(r.clone())),
                None => Expr::Other(vec![l.clone(), r.clone()]),
            };
            result = Some(match result {
                None => cmp,
                Some(prev) => Expr::Bin(BinOp::And, Box::new(prev), Box::new(cmp)),
            });
        }
        result.unwrap_or(Expr::Other(operands))
    }

    fn string(&self, node: Node) -> Expr {
        let mut parts: Vec<Expr> = Vec::new();
        let mut raw = false;
        let mut literal = String::new();
        for child in children(node) {
            match child.kind() {
                "string_start" => {
                    let prefix = self.text(child).to_ascii_lowercase();
                    raw = prefix.contains('r');
                }
                "string_content" => {
                    let t = self.text(child);
                    literal.push_str(&if raw { t.to_string() } else { unescape(t) });
                }
                "escape_sequence" => literal.push_str(&unescape(self.text(child))),
                "interpolation" => {
                    if !literal.is_empty() {
                        parts.push(Expr::Lit(Const::Str(std::mem::take(&mut literal))));
                    }
                    parts.push(self.expr_opt(child.child_by_field_name("expression")));
                }
                _ => {}
            }
        }
        if parts.is_empty() {
            return Expr::Lit(Const::Str(literal));
        }
        if !literal.is_empty() {
            parts.push(Expr::Lit(Const::Str(literal)));
        }
        Expr::Concat(parts)
    }
}

fn concat_or_literal(parts: Vec<Expr>) -> Expr {
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

pub(crate) fn bin_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "//" => BinOp::FloorDiv,
        "%" => BinOp::Mod,
        "**" => BinOp::Pow,
        "&" => BinOp::BitAnd,
        "|" => BinOp::BitOr,
        "^" => BinOp::BitXor,
        "<<" => BinOp::Shl,
        ">>" => BinOp::Shr,
        "==" => BinOp::Eq,
        "!=" | "<>" => BinOp::NotEq,
        "<" => BinOp::Lt,
        "<=" => BinOp::LtE,
        ">" => BinOp::Gt,
        ">=" => BinOp::GtE,
        "in" => BinOp::In,
        "not in" => BinOp::NotIn,
        "is" => BinOp::Is,
        "is not" => BinOp::IsNot,
        "and" => BinOp::And,
        "or" => BinOp::Or,
        _ => return None,
    })
}

pub(crate) fn parse_int(t: &str) -> Option<i64> {
    let t = t.replace('_', "");
    let t = t.trim_end_matches(['l', 'L']);
    let lower = t.to_ascii_lowercase();
    if let Some(h) = lower.strip_prefix("0x") {
        i64::from_str_radix(h, 16).ok()
    } else if let Some(o) = lower.strip_prefix("0o") {
        i64::from_str_radix(o, 8).ok()
    } else if let Some(b) = lower.strip_prefix("0b") {
        i64::from_str_radix(b, 2).ok()
    } else {
        lower.parse().ok()
    }
}

/// Minimal escape handling: enough for literal comparisons in conditions.
pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some('\n') => {}
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
