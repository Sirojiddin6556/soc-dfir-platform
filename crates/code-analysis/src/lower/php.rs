//! PHP front end (tree-sitter-php).
//!
//! Variables keep their `$` (`$id`), so they never collide with function
//! and constant names, which PHP keeps in separate namespaces. Instance
//! methods take `$this` as their first parameter and constructors are named
//! `__init__`, as in the other front ends. Names are reduced to their last
//! segment (`\App\Db\Conn` is `Conn`): functions and classes are found
//! project-wide, as autoloading and includes make them available.
//!
//! A few constructs become calls to helpers the PHP model implements:
//! `$a[] = $v` appends with `__php_append`, `foreach ($a as $k => $v)`
//! walks `__php_pairs($a)`, `include` and `require` call `include`, and
//! output (`echo`, `print`, backticks) calls `echo` or `shell_exec`.

use super::{children, named_children, span, test_span, text};
use crate::ir::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tree_sitter::Node;

pub fn lower(root: Node, src: &str) -> Module {
    let l = Lower {
        src,
        depth: Cell::new(0),
        classes: RefCell::new(Vec::new()),
        class_stack: RefCell::new(Vec::new()),
        anon: Cell::new(0),
        echo_next: Cell::new(false),
        in_static: Cell::new(false),
        hoisted: RefCell::new(Vec::new()),
    };
    let mut body = Vec::new();
    for child in named_children(root) {
        l.stmt(child, &mut body);
    }
    // Classes and top-level functions exist before the script runs.
    let mut out = l.classes.take();
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

struct ClassCtx {
    name: String,
    parent: Option<String>,
}

struct Lower<'s> {
    src: &'s str,
    depth: Cell<u32>,
    /// Lowered classes, hoisted to the top of the module: PHP declares
    /// them before the script runs.
    classes: RefCell<Vec<Stmt>>,
    class_stack: RefCell<Vec<ClassCtx>>,
    anon: Cell<u32>,
    /// The statement after `<?=` is echoed.
    echo_next: Cell<bool>,
    /// Lowering a static method, where `self::m()` has no `$this`.
    in_static: Cell<bool>,
    /// Assignments used as values (`($line = fgets($f)) !== false`), run
    /// before the statement that holds them.
    hoisted: RefCell<Vec<Stmt>>,
}

/// Deeper syntax is replaced by an opaque expression, as in the other
/// front ends.
const MAX_DEPTH: u32 = 400;

/// The last segment of a possibly qualified name: `\App\Db\Conn` -> `Conn`.
/// Functions that end the request: `die`, and WordPress's `wp_die` and
/// JSON responses.
fn never_returns(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "die" | "exit" | "wp_die" | "wp_send_json" | "wp_send_json_success" | "wp_send_json_error"
    )
}

fn last_segment(s: &str) -> String {
    s.trim().rsplit('\\').next().unwrap_or(s).trim().to_string()
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

fn str_lit(s: impl Into<String>) -> Expr {
    Expr::Lit(Const::Str(s.into()))
}

/// Text of a double-quoted escape sequence.
fn unescape(seq: &str) -> String {
    let body = &seq[1.min(seq.len())..];
    match body {
        "n" => "\n".into(),
        "t" => "\t".into(),
        "r" => "\r".into(),
        "v" => "\u{b}".into(),
        "e" => "\u{1b}".into(),
        "f" => "\u{c}".into(),
        "0" => "\0".into(),
        "\\" | "$" | "\"" => body.into(),
        _ => {
            if let Some(hex) = body.strip_prefix('x') {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    return (b as char).to_string();
                }
            }
            if let Some(code) = body.strip_prefix("u{").and_then(|b| b.strip_suffix('}')) {
                if let Some(c) = u32::from_str_radix(code, 16).ok().and_then(char::from_u32) {
                    return c.to_string();
                }
            }
            if body.chars().all(|c| c.is_digit(8)) && !body.is_empty() {
                if let Ok(b) = u8::from_str_radix(body, 8) {
                    return (b as char).to_string();
                }
            }
            seq.into()
        }
    }
}

impl<'s> Lower<'s> {
    fn text(&self, node: Node) -> &'s str {
        text(node, self.src)
    }

    fn class_name(&self) -> Option<String> {
        self.class_stack.borrow().last().map(|c| c.name.clone())
    }

    /// `self`, `static` and `parent` resolved against the enclosing class.
    fn scope_name(&self, raw: &str) -> String {
        let n = last_segment(raw);
        match n.to_ascii_lowercase().as_str() {
            "self" | "static" => self.class_name().unwrap_or(n),
            "parent" => self
                .class_stack
                .borrow()
                .last()
                .and_then(|c| c.parent.clone())
                .unwrap_or(n),
            _ => n,
        }
    }

    // ----- statements -----

    fn block(&self, node: Node) -> Vec<Stmt> {
        let mut out = Vec::new();
        self.stmt(node, &mut out);
        out
    }

    fn stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let saved = self.hoisted.take();
        let start = out.len();
        self.stmt_inner(node, out);
        let hoisted = self.hoisted.replace(saved);
        if !hoisted.is_empty() {
            out.splice(start..start, hoisted);
        }
    }

    fn stmt_inner(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "compound_statement" | "colon_block" | "declaration_list" => {
                for c in named_children(node) {
                    self.stmt(c, out);
                }
            }
            "namespace_definition" => {
                if let Some(body) = node.child_by_field_name("body") {
                    self.stmt(body, out);
                }
            }
            "declare_statement" => {
                for c in named_children(node) {
                    if c.kind() != "declare_directive" {
                        self.stmt(c, out);
                    }
                }
            }
            // Markup outside `<?php ... ?>` is output.
            "text" => {
                let t = self.text(node);
                if !t.is_empty() {
                    out.push(Stmt::Expr(call("echo", vec![str_lit(t)], sp), sp));
                }
            }
            "text_interpolation" => {
                for c in named_children(node) {
                    self.stmt(c, out);
                }
            }
            "php_tag" => self.echo_next.set(self.text(node) == "<?="),
            "expression_statement" => {
                let echo = self.echo_next.replace(false);
                if let Some(e) = named_children(node).into_iter().next() {
                    if echo {
                        let args = self.sequence(e);
                        out.push(Stmt::Expr(call("echo", args, sp), sp));
                    } else {
                        self.expr_stmt(e, out);
                    }
                }
            }
            "echo_statement" => {
                let args = named_children(node)
                    .into_iter()
                    .flat_map(|c| self.sequence(c))
                    .collect();
                out.push(Stmt::Expr(call("echo", args, sp), sp));
            }
            "return_statement" => {
                let value = named_children(node)
                    .into_iter()
                    .next()
                    .map(|e| self.expr(e));
                out.push(Stmt::Return(value, sp));
            }
            "exit_statement" => {
                let args: Vec<Expr> = named_children(node)
                    .into_iter()
                    .map(|e| self.expr(e))
                    .collect();
                if !args.is_empty() {
                    out.push(Stmt::Expr(call("die", args, sp), sp));
                }
                out.push(Stmt::Return(None, sp));
            }
            "if_statement" => out.push(self.if_stmt(node)),
            "while_statement" => {
                let test = self.cond(node);
                let body = self.body_of(node);
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
            }
            "do_statement" => {
                let body = self.body_of(node);
                out.extend(body.clone());
                let test = self.cond(node);
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
            }
            "for_statement" => {
                for init in node.children_by_field_name("initialize", &mut node.walk()) {
                    for e in self.sequence_nodes(init) {
                        self.expr_stmt(e, out);
                    }
                }
                let test = {
                    let mut cursor = node.walk();
                    let conds: Vec<Node> = node
                        .children_by_field_name("condition", &mut cursor)
                        .collect();
                    conds
                        .last()
                        .and_then(|c| self.sequence_nodes(*c).last().map(|e| self.expr(*e)))
                        .unwrap_or(Expr::Lit(Const::Bool(true)))
                };
                let mut body = self.body_of(node);
                for upd in node.children_by_field_name("update", &mut node.walk()) {
                    for e in self.sequence_nodes(upd) {
                        self.expr_stmt(e, &mut body);
                    }
                }
                out.push(Stmt::Loop {
                    target: None,
                    iter: None,
                    test: Some(test),
                    body,
                    span: test_span(node),
                });
            }
            "foreach_statement" => out.push(self.foreach(node)),
            "switch_statement" => {
                let subject = self.cond(node);
                let mut cases = Vec::new();
                if let Some(block) = node.child_by_field_name("body") {
                    for c in named_children(block) {
                        let (patterns, skip) = match c.kind() {
                            "case_statement" => (
                                c.child_by_field_name("value")
                                    .map(|v| vec![self.expr(v)])
                                    .unwrap_or_default(),
                                c.child_by_field_name("value").map(|v| v.id()),
                            ),
                            "default_statement" => (Vec::new(), None),
                            _ => continue,
                        };
                        let mut body = Vec::new();
                        for s in named_children(c) {
                            if Some(s.id()) != skip {
                                self.stmt(s, &mut body);
                            }
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
            "break_statement" => out.push(Stmt::Break),
            "continue_statement" => out.push(Stmt::Continue),
            "try_statement" => {
                let body = node
                    .child_by_field_name("body")
                    .map(|b| self.block(b))
                    .unwrap_or_default();
                let mut handlers = Vec::new();
                let mut finally = Vec::new();
                for c in named_children(node) {
                    match c.kind() {
                        "catch_clause" => {
                            let mut h = Vec::new();
                            if let Some(n) = c.child_by_field_name("name") {
                                h.push(Stmt::Assign {
                                    target: Target::Name(self.var_name(n)),
                                    value: Expr::Other(Vec::new()),
                                    span: span(c),
                                });
                            }
                            if let Some(b) = c.child_by_field_name("body") {
                                h.extend(self.block(b));
                            }
                            handlers.push(h);
                        }
                        "finally_clause" => {
                            if let Some(b) = c.child_by_field_name("body") {
                                finally = self.block(b);
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
            "function_definition" => {
                if let Some(f) = self.function(node, None) {
                    out.push(Stmt::FuncDef(Rc::new(f)));
                }
            }
            "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration" => {
                self.class(node);
            }
            "const_declaration" => {
                for el in named_children(node) {
                    if el.kind() == "const_element" {
                        let parts = named_children(el);
                        if let (Some(n), Some(v)) = (parts.first(), parts.last()) {
                            if n.id() != v.id() {
                                // Outside a class, a global constant.
                                let name = self.text(*n);
                                let name = if self.class_stack.borrow().is_empty() {
                                    format!("#{name}")
                                } else {
                                    name.to_string()
                                };
                                out.push(Stmt::Assign {
                                    target: Target::Name(name),
                                    value: self.expr(*v),
                                    span: span(el),
                                });
                            }
                        }
                    }
                }
            }
            "function_static_declaration" => {
                for d in named_children(node) {
                    if let Some(n) = d.child_by_field_name("name") {
                        let value = d
                            .child_by_field_name("value")
                            .map(|v| self.expr(v))
                            .unwrap_or(Expr::Lit(Const::None));
                        out.push(Stmt::Assign {
                            target: Target::Name(self.var_name(n)),
                            value,
                            span: span(d),
                        });
                    }
                }
            }
            // `global $db;` reads the variable of the main script.
            "global_declaration" => {
                for v in named_children(node) {
                    if v.kind() == "variable_name" {
                        let name = self.var_name(v);
                        out.push(Stmt::Assign {
                            target: Target::Name(name.clone()),
                            value: call("__php_global", vec![str_lit(name)], sp),
                            span: sp,
                        });
                    }
                }
            }
            "unset_statement"
            | "namespace_use_declaration"
            | "use_declaration"
            | "php_end_tag"
            | "empty_statement"
            | "named_label_statement"
            | "goto_statement"
            | "comment" => {}
            _ => {
                if node.kind().ends_with("_expression") || node.kind() == "variable_name" {
                    self.expr_stmt(node, out);
                }
            }
        }
    }

    /// An expression used as a statement: assignments become [`Stmt::Assign`].
    fn expr_stmt(&self, node: Node, out: &mut Vec<Stmt>) {
        let sp = span(node);
        match node.kind() {
            "assignment_expression" | "reference_assignment_expression" => {
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return;
                };
                let value = self.expr(right);
                self.assign(left, value, sp, out);
            }
            "augmented_assignment_expression" => {
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return;
                };
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                let cur = self.expr(left);
                let rhs = self.expr(right);
                let value = match op {
                    ".=" => Expr::Concat(vec![cur, rhs]),
                    "??=" => Expr::Bin(BinOp::Or, Box::new(cur), Box::new(rhs)),
                    _ => Expr::Bin(
                        bin_op(op.trim_end_matches('=')).unwrap_or(BinOp::Add),
                        Box::new(cur),
                        Box::new(rhs),
                    ),
                };
                self.assign(left, value, sp, out);
            }
            "update_expression" => {
                if let Some(arg) = node
                    .child_by_field_name("argument")
                    .or_else(|| named_children(node).into_iter().next())
                {
                    let value = Expr::Bin(
                        BinOp::Add,
                        Box::new(self.expr(arg)),
                        Box::new(Expr::Lit(Const::Int(1))),
                    );
                    self.assign(arg, value, sp, out);
                }
            }
            "throw_expression" => {
                let inner = named_children(node)
                    .into_iter()
                    .next()
                    .map(|e| self.expr(e));
                out.push(Stmt::Expr(Expr::Other(inner.into_iter().collect()), sp));
                out.push(Stmt::Return(None, sp));
            }
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => {
                let args = named_children(node)
                    .into_iter()
                    .map(|e| self.expr(e))
                    .collect();
                out.push(Stmt::Expr(call("include", args, sp), sp));
            }
            "exit_statement" => self.stmt(node, out),
            "parenthesized_expression" => {
                if let Some(e) = named_children(node).into_iter().next() {
                    self.expr_stmt(e, out);
                }
            }
            "name"
                if matches!(
                    self.text(node).to_ascii_lowercase().as_str(),
                    "die" | "exit"
                ) =>
            {
                out.push(Stmt::Return(None, sp));
            }
            _ => {
                let e = self.expr(node);
                let exits = matches!(&e, Expr::Call { func, .. }
                    if matches!(&**func, Expr::Name(n) if never_returns(n)));
                out.push(Stmt::Expr(e, sp));
                if exits {
                    out.push(Stmt::Return(None, sp));
                }
            }
        }
    }

    fn assign(&self, left: Node, value: Expr, sp: Span, out: &mut Vec<Stmt>) {
        // `$a[] = $v` appends.
        if left.kind() == "subscript_expression" && named_children(left).len() == 1 {
            if let Some(base) = named_children(left).into_iter().next() {
                let cur = self.expr(base);
                let appended = call("__php_append", vec![cur, value], sp);
                self.assign(base, appended, sp, out);
                return;
            }
        }
        let target = self.target(left);
        out.push(Stmt::Assign {
            target,
            value,
            span: sp,
        });
    }

    fn target(&self, node: Node) -> Target {
        match node.kind() {
            "variable_name" => Target::Name(self.var_name(node)),
            "subscript_expression" => {
                let parts = named_children(node);
                match (parts.first(), parts.get(1)) {
                    (Some(b), Some(k)) => {
                        Target::Index(Box::new(self.expr(*b)), Box::new(self.expr(*k)))
                    }
                    _ => Target::Other,
                }
            }
            "member_access_expression" | "nullsafe_member_access_expression" => {
                let obj = node.child_by_field_name("object").map(|o| self.expr(o));
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_string());
                match (obj, name) {
                    (Some(o), Some(n)) => Target::Attr(Box::new(o), n),
                    _ => Target::Other,
                }
            }
            "scoped_property_access_expression" => {
                let scope = node
                    .child_by_field_name("scope")
                    .map(|s| self.scope_name(self.text(s)));
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).trim_start_matches('$').to_string());
                match (scope, name) {
                    (Some(s), Some(n)) => Target::Attr(Box::new(Expr::Name(s)), n),
                    _ => Target::Other,
                }
            }
            "list_literal" | "array_creation_expression" => Target::Tuple(
                named_children(node)
                    .into_iter()
                    .map(|c| {
                        let el = if c.kind() == "array_element_initializer" {
                            named_children(c).into_iter().last()
                        } else {
                            Some(c)
                        };
                        el.map(|e| self.target(e)).unwrap_or(Target::Other)
                    })
                    .collect(),
            ),
            "by_ref" | "reference_modifier" => named_children(node)
                .into_iter()
                .next()
                .map(|c| self.target(c))
                .unwrap_or(Target::Other),
            _ => Target::Other,
        }
    }

    fn var_name(&self, node: Node) -> String {
        let t = self.text(node);
        if t.starts_with('$') {
            t.to_string()
        } else {
            format!("${t}")
        }
    }

    fn cond(&self, node: Node) -> Expr {
        node.child_by_field_name("condition")
            .map(|c| self.expr(c))
            .unwrap_or(Expr::Lit(Const::Bool(true)))
    }

    fn body_of(&self, node: Node) -> Vec<Stmt> {
        node.child_by_field_name("body")
            .map(|b| self.block(b))
            .unwrap_or_default()
    }

    fn if_stmt(&self, node: Node) -> Stmt {
        let test = self.cond(node);
        let then = self.body_of(node);
        // Alternatives chain: each `elseif` nests the rest.
        let alts: Vec<Node> = {
            let mut cursor = node.walk();
            node.children_by_field_name("alternative", &mut cursor)
                .collect()
        };
        let other = self.else_chain(&alts);
        Stmt::If {
            test,
            then,
            other,
            span: test_span(node),
        }
    }

    fn else_chain(&self, alts: &[Node]) -> Vec<Stmt> {
        let Some((first, rest)) = alts.split_first() else {
            return Vec::new();
        };
        match first.kind() {
            "else_if_clause" => {
                let test = self.cond(*first);
                let then = self.body_of(*first);
                vec![Stmt::If {
                    test,
                    then,
                    other: self.else_chain(rest),
                    span: test_span(*first),
                }]
            }
            _ => self.body_of(*first),
        }
    }

    fn foreach(&self, node: Node) -> Stmt {
        let parts: Vec<Node> = named_children(node)
            .into_iter()
            .filter(|c| Some(c.id()) != node.child_by_field_name("body").map(|b| b.id()))
            .collect();
        let body = self.body_of(node);
        let Some(subject) = parts.first() else {
            return Stmt::Loop {
                target: None,
                iter: None,
                test: None,
                body,
                span: span(node),
            };
        };
        let subject_e = self.expr(*subject);
        let sp = span(node);
        let (target, iter) = match parts.get(1) {
            Some(p) if p.kind() == "pair" => {
                let kv = named_children(*p);
                let k = kv.first().map(|k| self.target(*k)).unwrap_or(Target::Other);
                let v = kv.get(1).map(|v| self.target(*v)).unwrap_or(Target::Other);
                (
                    Target::Tuple(vec![k, v]),
                    call("__php_pairs", vec![subject_e], sp),
                )
            }
            Some(v) => (self.target(*v), call("array_values", vec![subject_e], sp)),
            None => (Target::Other, subject_e),
        };
        Stmt::Loop {
            target: Some(target),
            iter: Some(iter),
            test: None,
            body,
            span: sp,
        }
    }

    // ----- declarations -----

    fn params(&self, node: Node) -> Vec<Param> {
        let Some(list) = node.child_by_field_name("parameters") else {
            return Vec::new();
        };
        named_children(list)
            .into_iter()
            .filter_map(|p| {
                let name = p.child_by_field_name("name").map(|n| self.var_name(n))?;
                let ty = p
                    .child_by_field_name("type")
                    .map(|t| last_segment(self.text(t)));
                let default = p.child_by_field_name("default_value").map(|d| self.expr(d));
                let variadic = p.kind() == "variadic_parameter";
                Some(Param {
                    name,
                    ty,
                    default,
                    variadic,
                })
            })
            .collect()
    }

    /// A function, method or closure. `class` is set for methods.
    fn function(&self, node: Node, class: Option<&str>) -> Option<Function> {
        let body_node = node.child_by_field_name("body")?;
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
            .unwrap_or_else(|| "<closure>".into());
        let is_static = children(node).iter().any(|c| c.kind() == "static_modifier");
        let mut params = Vec::new();
        let mut decorators = Vec::new();
        let mut body = Vec::new();
        if let Some(cls) = class {
            if is_static {
                decorators.push(Expr::Name("staticmethod".into()));
            } else {
                params.push(Param {
                    name: "$this".into(),
                    ty: Some(cls.to_string()),
                    default: None,
                    variadic: false,
                });
            }
            // Constructor promotion: `__construct(private Db $db)`.
            if let Some(list) = node.child_by_field_name("parameters") {
                for p in named_children(list) {
                    if p.kind() == "property_promotion_parameter" {
                        if let Some(n) = p.child_by_field_name("name") {
                            let var = self.var_name(n);
                            body.push(Stmt::Assign {
                                target: Target::Attr(
                                    Box::new(Expr::Name("$this".into())),
                                    var.trim_start_matches('$').to_string(),
                                ),
                                value: Expr::Name(var),
                                span: span(p),
                            });
                        }
                    }
                }
            }
        }
        params.extend(self.params(node));
        let lowered_name = if class.is_some() && name.eq_ignore_ascii_case("__construct") {
            "__init__".to_string()
        } else {
            name
        };
        let outer_static = self.in_static.get();
        if class.is_some() {
            self.in_static.set(is_static);
        }
        if body_node.kind() == "compound_statement" {
            body.extend(self.block(body_node));
        } else {
            // Arrow function: `fn($x) => expr`.
            body.push(Stmt::Return(Some(self.expr(body_node)), span(body_node)));
        }
        self.in_static.set(outer_static);
        Some(Function {
            name: lowered_name,
            params,
            body,
            decorators,
            span: span(node),
        })
    }

    fn class(&self, node: Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
            .unwrap_or_else(|| {
                let n = self.anon.get() + 1;
                self.anon.set(n);
                format!("class@anon{n}")
            });
        let mut bases = Vec::new();
        for c in named_children(node) {
            match c.kind() {
                "base_clause" | "class_interface_clause" => {
                    for b in named_children(c) {
                        bases.push(last_segment(self.text(b)));
                    }
                }
                _ => {}
            }
        }
        let parent = named_children(node)
            .into_iter()
            .find(|c| c.kind() == "base_clause")
            .and_then(|c| named_children(c).into_iter().next())
            .map(|b| last_segment(self.text(b)));
        self.class_stack.borrow_mut().push(ClassCtx {
            name: name.clone(),
            parent,
        });
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        if let Some(body) = node.child_by_field_name("body") {
            for m in named_children(body) {
                match m.kind() {
                    "method_declaration" => {
                        if let Some(f) = self.function(m, Some(&name)) {
                            methods.push(Rc::new(f));
                        }
                    }
                    "property_declaration" => {
                        let ty = m
                            .child_by_field_name("type")
                            .map(|t| last_segment(self.text(t)));
                        for el in named_children(m) {
                            if el.kind() != "property_element" {
                                continue;
                            }
                            let Some(n) = el.child_by_field_name("name") else {
                                continue;
                            };
                            let field = self.text(n).trim_start_matches('$').to_string();
                            let value = el
                                .child_by_field_name("default_value")
                                .map(|d| self.expr(d));
                            fields.push(Stmt::Declare {
                                name: field,
                                ty: ty.clone().unwrap_or_default(),
                                value,
                                span: span(el),
                            });
                        }
                    }
                    "const_declaration" => self.stmt(m, &mut fields),
                    "use_declaration" => {
                        for t in named_children(m) {
                            if matches!(t.kind(), "name" | "qualified_name") {
                                bases.push(last_segment(self.text(t)));
                            }
                        }
                    }
                    "enum_case" => {
                        if let Some(n) = m.child_by_field_name("name") {
                            let value = m
                                .child_by_field_name("value")
                                .map(|v| self.expr(v))
                                .unwrap_or_else(|| str_lit(self.text(n)));
                            fields.push(Stmt::Assign {
                                target: Target::Name(self.text(n).to_string()),
                                value,
                                span: span(m),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        self.class_stack.borrow_mut().pop();
        self.classes
            .borrow_mut()
            .push(Stmt::ClassDef(Rc::new(Class {
                name,
                bases,
                fields,
                methods,
                span: span(node),
            })));
    }

    // ----- expressions -----

    /// The expressions of an `echo a, b` list.
    fn sequence(&self, node: Node) -> Vec<Expr> {
        self.sequence_nodes(node)
            .into_iter()
            .map(|n| self.expr(n))
            .collect()
    }

    fn sequence_nodes<'t>(&self, node: Node<'t>) -> Vec<Node<'t>> {
        if node.kind() == "sequence_expression" {
            named_children(node)
                .into_iter()
                .flat_map(|c| self.sequence_nodes(c))
                .collect()
        } else {
            vec![node]
        }
    }

    fn expr(&self, node: Node) -> Expr {
        let d = self.depth.get();
        if d >= MAX_DEPTH {
            return Expr::Other(Vec::new());
        }
        self.depth.set(d + 1);
        let e = self.expr_inner(node);
        self.depth.set(d);
        e
    }

    fn args(&self, node: Node) -> Vec<Arg> {
        let Some(list) = node.child_by_field_name("arguments").or_else(|| {
            named_children(node)
                .into_iter()
                .find(|c| c.kind() == "arguments")
        }) else {
            return Vec::new();
        };
        named_children(list)
            .into_iter()
            .map(|a| {
                if a.kind() != "argument" {
                    return positional(self.expr(a));
                }
                let name = a
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_string());
                let spread = children(a).iter().any(|c| c.kind() == "...")
                    || named_children(a)
                        .iter()
                        .any(|c| c.kind() == "variadic_unpacking");
                let value = named_children(a)
                    .into_iter()
                    .rev()
                    .find(|c| Some(c.id()) != a.child_by_field_name("name").map(|n| n.id()))
                    .map(|v| self.expr(v))
                    .unwrap_or(Expr::Lit(Const::None));
                Arg {
                    name,
                    value,
                    spread,
                }
            })
            .collect()
    }

    fn string_parts(&self, node: Node) -> Expr {
        let mut parts = Vec::new();
        for c in named_children(node) {
            match c.kind() {
                "string_content" | "string_value" => parts.push(str_lit(self.text(c))),
                "escape_sequence" => parts.push(str_lit(unescape(self.text(c)))),
                "heredoc_body" | "nowdoc_body" => {
                    if let Expr::Concat(inner) = self.string_parts(c) {
                        parts.extend(inner);
                    }
                }
                "heredoc_start" | "heredoc_end" => {}
                "nowdoc_string" => parts.push(str_lit(self.text(c))),
                // `"$a[key]"`: an unquoted key is a string.
                "subscript_expression" => {
                    let kids = named_children(c);
                    match (kids.first(), kids.get(1)) {
                        (Some(b), Some(k)) if k.kind() == "name" => parts.push(Expr::Index(
                            Box::new(self.expr(*b)),
                            Box::new(str_lit(self.text(*k))),
                        )),
                        _ => parts.push(self.expr(c)),
                    }
                }
                // `"${name}"`
                "dynamic_variable_name" => match named_children(c).first() {
                    Some(n) if n.kind() == "name" => {
                        parts.push(Expr::Name(format!("${}", self.text(*n))))
                    }
                    _ => parts.push(self.expr(c)),
                },
                _ => parts.push(self.expr(c)),
            }
        }
        Expr::Concat(parts)
    }

    fn expr_inner(&self, node: Node) -> Expr {
        let sp = span(node);
        match node.kind() {
            "variable_name" => Expr::Name(self.var_name(node)),
            "dynamic_variable_name" => Expr::Other(Vec::new()),
            "integer" => {
                let t = self.text(node).replace('_', "");
                let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    i64::from_str_radix(h, 16).ok()
                } else if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
                    i64::from_str_radix(b, 2).ok()
                } else if t.len() > 1 && t.starts_with('0') {
                    i64::from_str_radix(t.trim_start_matches("0o").trim_start_matches('0'), 8)
                        .ok()
                        .or(Some(0))
                } else {
                    t.parse().ok()
                };
                v.map(|v| Expr::Lit(Const::Int(v)))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "float" => self
                .text(node)
                .replace('_', "")
                .parse()
                .map(|v| Expr::Lit(Const::Float(v)))
                .unwrap_or(Expr::Other(Vec::new())),
            "boolean" => Expr::Lit(Const::Bool(self.text(node).eq_ignore_ascii_case("true"))),
            "null" => Expr::Lit(Const::None),
            "string" => {
                // Single quotes: only \' and \\ are escapes.
                let t = self.text(node);
                let inner = t
                    .strip_prefix(['b', 'B'])
                    .unwrap_or(t)
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''));
                match inner {
                    Some(s) => str_lit(s.replace("\\'", "'").replace("\\\\", "\\")),
                    None => self.string_parts(node),
                }
            }
            "encapsed_string" | "heredoc" | "nowdoc" => {
                let e = self.string_parts(node);
                match e {
                    Expr::Concat(mut parts) if parts.len() == 1 => parts.remove(0),
                    Expr::Concat(parts) if parts.is_empty() => str_lit(""),
                    other => other,
                }
            }
            "shell_command_expression" => {
                let cmd = self.string_parts(node);
                call("shell_exec", vec![cmd], sp)
            }
            "name" | "qualified_name" => Expr::Name(last_segment(self.text(node))),
            "parenthesized_expression" => named_children(node)
                .into_iter()
                .next()
                .map(|e| self.expr(e))
                .unwrap_or(Expr::Other(Vec::new())),
            "subscript_expression" => {
                let parts = named_children(node);
                match (parts.first(), parts.get(1)) {
                    (Some(b), Some(k)) => {
                        Expr::Index(Box::new(self.expr(*b)), Box::new(self.expr(*k)))
                    }
                    (Some(b), None) => self.expr(*b),
                    _ => Expr::Other(Vec::new()),
                }
            }
            "member_access_expression" | "nullsafe_member_access_expression" => {
                let obj = node
                    .child_by_field_name("object")
                    .map(|o| self.expr(o))
                    .unwrap_or(Expr::Other(Vec::new()));
                match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "name" => {
                        Expr::Attr(Box::new(obj), self.text(n).to_string())
                    }
                    _ => Expr::Other(vec![obj]),
                }
            }
            "scoped_property_access_expression" | "class_constant_access_expression" => {
                let parts = named_children(node);
                let scope = node
                    .child_by_field_name("scope")
                    .or_else(|| parts.first().copied())
                    .map(|s| self.scope_name(self.text(s)));
                let name = node
                    .child_by_field_name("name")
                    .or_else(|| parts.get(1).copied())
                    .map(|n| self.text(n).trim_start_matches('$').to_string());
                match (scope, name) {
                    (Some(s), Some(n)) if n == "class" => str_lit(s),
                    (Some(s), Some(n)) => Expr::Attr(Box::new(Expr::Name(s)), n),
                    _ => Expr::Other(Vec::new()),
                }
            }
            "function_call_expression" => {
                let func = node
                    .child_by_field_name("function")
                    .map(|f| self.expr(f))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Call {
                    func: Box::new(func),
                    args: self.args(node),
                    span: sp,
                }
            }
            "member_call_expression" | "nullsafe_member_call_expression" => {
                let obj = node
                    .child_by_field_name("object")
                    .map(|o| self.expr(o))
                    .unwrap_or(Expr::Other(Vec::new()));
                let args = self.args(node);
                match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "name" => Expr::Call {
                        func: Box::new(Expr::Attr(Box::new(obj), self.text(n).to_string())),
                        args,
                        span: sp,
                    },
                    _ => Expr::Other(
                        std::iter::once(obj)
                            .chain(args.into_iter().map(|a| a.value))
                            .collect(),
                    ),
                }
            }
            "scoped_call_expression" => {
                let scope_raw = node
                    .child_by_field_name("scope")
                    .map(|s| self.text(s).trim().to_string())
                    .unwrap_or_default();
                let scope = self.scope_name(&scope_raw);
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_string())
                    .unwrap_or_default();
                let method = if name.eq_ignore_ascii_case("__construct") {
                    "__init__".to_string()
                } else {
                    name
                };
                let args = self.args(node);
                // `parent::save()`, `self::helper()` in an instance method
                // run on this object, starting the lookup at that class:
                // `$this->{"Base::save"}()`.
                let relative = matches!(
                    scope_raw.to_ascii_lowercase().as_str(),
                    "parent" | "self" | "static"
                );
                if relative && self.class_name().is_some() && !self.in_static.get() {
                    return Expr::Call {
                        func: Box::new(Expr::Attr(
                            Box::new(Expr::Name("$this".into())),
                            format!("{scope}::{method}"),
                        )),
                        args,
                        span: sp,
                    };
                }
                Expr::Call {
                    func: Box::new(Expr::Attr(Box::new(Expr::Name(scope)), method)),
                    args,
                    span: sp,
                }
            }
            "object_creation_expression" => {
                let class_node = named_children(node).into_iter().find(|c| {
                    matches!(
                        c.kind(),
                        "name" | "qualified_name" | "variable_name" | "anonymous_class"
                    )
                });
                let class = match class_node {
                    Some(c) if c.kind() == "anonymous_class" => {
                        self.class(c);
                        let n = self.anon.get();
                        format!("class@anon{n}")
                    }
                    Some(c) if c.kind() != "variable_name" => self.scope_name(self.text(c)),
                    _ => "<dynamic>".into(),
                };
                Expr::New {
                    class,
                    args: self.args(node),
                    span: sp,
                }
            }
            "binary_expression" => {
                let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return Expr::Other(Vec::new());
                };
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o).to_ascii_lowercase())
                    .unwrap_or_default();
                let le = self.expr(l);
                let re = self.expr(r);
                match op.as_str() {
                    "." => Expr::Concat(vec![le, re]),
                    "??" => Expr::Bin(BinOp::Or, Box::new(le), Box::new(re)),
                    "instanceof" => Expr::Other(vec![le]),
                    o => match bin_op(o) {
                        Some(b) => Expr::Bin(b, Box::new(le), Box::new(re)),
                        None => Expr::Other(vec![le, re]),
                    },
                }
            }
            "unary_op_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or_else(|| children(node).first().map(|c| self.text(*c)).unwrap_or(""));
                let arg = node
                    .child_by_field_name("argument")
                    .or_else(|| named_children(node).into_iter().last())
                    .map(|a| self.expr(a))
                    .unwrap_or(Expr::Other(Vec::new()));
                match op {
                    "!" => Expr::Un(UnOp::Not, Box::new(arg)),
                    "-" => Expr::Un(UnOp::Neg, Box::new(arg)),
                    "+" => Expr::Un(UnOp::Pos, Box::new(arg)),
                    "~" => Expr::Un(UnOp::BitNot, Box::new(arg)),
                    _ => arg,
                }
            }
            "error_suppression_expression"
            | "clone_expression"
            | "reference_modifier"
            | "by_ref" => named_children(node)
                .into_iter()
                .next()
                .map(|e| self.expr(e))
                .unwrap_or(Expr::Other(Vec::new())),
            "cast_expression" => {
                let ty = node
                    .child_by_field_name("type")
                    .map(|t| self.text(t).to_ascii_lowercase())
                    .unwrap_or_default();
                let value = node
                    .child_by_field_name("value")
                    .map(|v| self.expr(v))
                    .unwrap_or(Expr::Other(Vec::new()));
                Expr::Cast(ty, Box::new(value))
            }
            "conditional_expression" => {
                let test = node
                    .child_by_field_name("condition")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Other(Vec::new()));
                let other = node
                    .child_by_field_name("alternative")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Other(Vec::new()));
                match node.child_by_field_name("body") {
                    Some(b) => Expr::Cond {
                        test: Box::new(test),
                        then: Box::new(self.expr(b)),
                        other: Box::new(other),
                    },
                    // `$a ?: $b`
                    None => Expr::Bin(BinOp::Or, Box::new(test), Box::new(other)),
                }
            }
            "array_creation_expression" => {
                let mut keyed = false;
                let mut items: Vec<(Option<Expr>, Expr)> = Vec::new();
                for el in named_children(node) {
                    if el.kind() != "array_element_initializer" {
                        continue;
                    }
                    let parts = named_children(el);
                    match parts.as_slice() {
                        [k, v] => {
                            keyed = true;
                            items.push((Some(self.expr(*k)), self.expr(*v)));
                        }
                        [v] => items.push((None, self.expr(*v))),
                        _ => {}
                    }
                }
                if keyed {
                    let mut next = 0i64;
                    Expr::Dict(
                        items
                            .into_iter()
                            .map(|(k, v)| match k {
                                Some(k) => {
                                    if let Expr::Lit(Const::Int(i)) = k {
                                        next = i + 1;
                                    }
                                    (k, v)
                                }
                                None => {
                                    let k = Expr::Lit(Const::Int(next));
                                    next += 1;
                                    (k, v)
                                }
                            })
                            .collect(),
                    )
                } else {
                    Expr::List(items.into_iter().map(|(_, v)| v).collect())
                }
            }
            "anonymous_function" | "arrow_function" | "anonymous_function_creation_expression" => {
                match self.function(node, None) {
                    Some(f) => Expr::Lambda(Rc::new(f)),
                    None => Expr::Other(Vec::new()),
                }
            }
            "print_intrinsic" => {
                let args = named_children(node)
                    .into_iter()
                    .map(|e| self.expr(e))
                    .collect();
                call("echo", args, sp)
            }
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => {
                let args = named_children(node)
                    .into_iter()
                    .map(|e| self.expr(e))
                    .collect();
                call("include", args, sp)
            }
            "exit_statement" => {
                let args = named_children(node)
                    .into_iter()
                    .map(|e| self.expr(e))
                    .collect();
                call("die", args, sp)
            }
            "match_expression" => {
                let subject = node
                    .child_by_field_name("condition")
                    .map(|c| self.expr(c))
                    .unwrap_or(Expr::Other(Vec::new()));
                let mut arms = Vec::new();
                if let Some(body) = node.child_by_field_name("body") {
                    for arm in named_children(body) {
                        if let Some(v) = arm.child_by_field_name("return_expression") {
                            arms.push(self.expr(v));
                        }
                    }
                }
                let mut all = vec![subject];
                all.extend(arms.iter().cloned());
                match arms.len() {
                    0 => Expr::Other(all),
                    _ => arms
                        .into_iter()
                        .reduce(|a, b| Expr::Bin(BinOp::Or, Box::new(a), Box::new(b)))
                        .unwrap_or(Expr::Other(Vec::new())),
                }
            }
            "assignment_expression"
            | "reference_assignment_expression"
            | "augmented_assignment_expression" => {
                // An assignment used as a value: run it before the
                // statement, then read the variable.
                let mut assign = Vec::new();
                self.expr_stmt(node, &mut assign);
                self.hoisted.borrow_mut().extend(assign);
                node.child_by_field_name("left")
                    .map(|l| self.expr(l))
                    .unwrap_or(Expr::Other(Vec::new()))
            }
            "sequence_expression" => self
                .sequence(node)
                .into_iter()
                .last()
                .unwrap_or(Expr::Other(Vec::new())),
            _ => Expr::Other(
                named_children(node)
                    .into_iter()
                    .map(|c| self.expr(c))
                    .collect(),
            ),
        }
    }
}

fn bin_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "%" => BinOp::Mod,
        "**" => BinOp::Pow,
        "&" => BinOp::BitAnd,
        "|" => BinOp::BitOr,
        "^" | "xor" => BinOp::BitXor,
        "<<" => BinOp::Shl,
        ">>" => BinOp::Shr,
        "==" => BinOp::Eq,
        "!=" | "<>" => BinOp::NotEq,
        "===" => BinOp::Is,
        "!==" => BinOp::IsNot,
        "<" => BinOp::Lt,
        "<=" => BinOp::LtE,
        ">" => BinOp::Gt,
        ">=" => BinOp::GtE,
        "&&" | "and" => BinOp::And,
        "||" | "or" => BinOp::Or,
        _ => return None,
    })
}
