//! A small language-neutral intermediate form. Each front end lowers its
//! syntax tree into it, so one interpreter and one set of rule hooks serve
//! every language. It keeps only what data-flow analysis needs: assignments,
//! calls, control flow and literal values.

use serde::Serialize;
use std::rc::Rc;

/// 1-based line and column of a node in the source file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Span {
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Const {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Eq,
    NotEq,
    Lt,
    LtE,
    Gt,
    GtE,
    In,
    NotIn,
    Is,
    IsNot,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
    Pos,
    BitNot,
    /// C `*p`: what a pointer points to. The interpreter keeps a pointer
    /// and what it points to as one value, so this only marks the read.
    Deref,
    /// C `&x`: a pointer to `x`, which is never NULL. Its value is `x`'s
    /// (see `Deref`).
    Addr,
}

#[derive(Debug, Clone)]
pub struct Arg {
    /// Keyword argument name (Python `f(x=1)`, PHP 8 named arguments).
    pub name: Option<String>,
    pub value: Expr,
    /// `*args` / `**kwargs` / `...$args`.
    pub spread: bool,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Lit(Const),
    Name(String),
    Attr(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Slice {
        value: Box<Expr>,
        lower: Option<Box<Expr>>,
        upper: Option<Box<Expr>>,
    },
    Call {
        func: Box<Expr>,
        args: Vec<Arg>,
        span: Span,
    },
    /// `new T(args)` in Java, PHP and C++.
    New {
        class: String,
        args: Vec<Arg>,
        span: Span,
    },
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Un(UnOp, Box<Expr>),
    /// String building: f-strings, PHP interpolation, `"a" + b` in Java.
    Concat(Vec<Expr>),
    Cond {
        test: Box<Expr>,
        then: Box<Expr>,
        other: Box<Expr>,
    },
    List(Vec<Expr>),
    Dict(Vec<(Expr, Expr)>),
    /// A cast or type conversion the language performs (`(int) $x`).
    Cast(String, Box<Expr>),
    Lambda(Rc<Function>),
    /// Anything else: its sub-expressions still carry data.
    Other(Vec<Expr>),
}

/// The variable a C `*p` reads through or `&x` points to, or `e` itself.
pub fn underef(e: &Expr) -> &Expr {
    match e {
        Expr::Un(UnOp::Deref | UnOp::Addr, x) => underef(x),
        e => e,
    }
}

#[derive(Debug, Clone)]
pub enum Target {
    Name(String),
    Attr(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Tuple(Vec<Target>),
    Other,
}

#[derive(Debug, Clone)]
pub struct Case {
    /// Literal patterns; empty means the default / wildcard case.
    pub patterns: Vec<Expr>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Assign {
        target: Target,
        value: Expr,
        span: Span,
    },
    /// A declaration with a static type (Java, C): records the type.
    Declare {
        name: String,
        ty: String,
        value: Option<Expr>,
        span: Span,
    },
    Expr(Expr, Span),
    /// `span` is where the test is, for findings in it.
    If {
        test: Expr,
        then: Vec<Stmt>,
        other: Vec<Stmt>,
        span: Span,
    },
    /// `for target in iter` (iter set) or `while test` (test set).
    Loop {
        target: Option<Target>,
        iter: Option<Expr>,
        test: Option<Expr>,
        body: Vec<Stmt>,
        span: Span,
    },
    Switch {
        subject: Expr,
        cases: Vec<Case>,
        /// C-like fall-through between cases without `break`.
        fallthrough: bool,
    },
    Try {
        body: Vec<Stmt>,
        handlers: Vec<Vec<Stmt>>,
        finally: Vec<Stmt>,
    },
    Return(Option<Expr>, Span),
    Break,
    Continue,
    /// Python `import a.b as c` / `from a import b as c`, Java imports:
    /// the local name and the dotted path it stands for.
    Import {
        alias: String,
        path: String,
    },
    FuncDef(Rc<Function>),
    ClassDef(Rc<Class>),
    /// PHP `include $x` and similar statements that act on an expression.
    Raw(Expr, Span),
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Option<String>,
    pub default: Option<Expr>,
    /// PHP `...$args`, Python `*args`: takes the remaining positional
    /// arguments as a list.
    pub variadic: bool,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
    /// Decorator / annotation names (`app.route`, `GetMapping`).
    pub decorators: Vec<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Class {
    pub name: String,
    pub bases: Vec<String>,
    pub fields: Vec<Stmt>,
    pub methods: Vec<Rc<Function>>,
    pub span: Span,
}

/// One source file after lowering.
#[derive(Debug, Clone, Default)]
pub struct Module {
    /// Top-level statements; functions and classes appear as definitions.
    pub body: Vec<Stmt>,
    /// Java package (`org.example.web`), which names the file's classes.
    pub package: Option<String>,
}
