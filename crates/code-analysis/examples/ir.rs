//! Prints the intermediate form of one file as pseudo-code, for debugging
//! front ends.
//!
//! cargo run -p code-analysis --example ir -- FILE

use code_analysis::ir::*;

fn main() {
    let path = std::env::args().nth(1).expect("file");
    let src = std::fs::read_to_string(&path).expect("read");
    let lang = code_analysis::project::language_of(std::path::Path::new(&path)).expect("language");
    let Some(m) = code_analysis::lower(lang, &src) else {
        eprintln!("язык пока не поддерживается");
        return;
    };
    if let Some(p) = &m.package {
        println!("package {p}");
    }
    let mut out = String::new();
    block(&m.body, 0, &mut out);
    print!("{out}");
}

fn block(stmts: &[Stmt], ind: usize, out: &mut String) {
    for s in stmts {
        stmt(s, ind, out);
    }
}

fn line(ind: usize, text: &str, out: &mut String) {
    out.push_str(&"    ".repeat(ind));
    out.push_str(text);
    out.push('\n');
}

fn func(f: &Function, ind: usize, out: &mut String) {
    let params: Vec<String> = f
        .params
        .iter()
        .map(|p| match &p.ty {
            Some(t) => format!("{}: {t}", p.name),
            None => p.name.clone(),
        })
        .collect();
    for d in &f.decorators {
        line(ind, &format!("@{}", expr(d)), out);
    }
    line(
        ind,
        &format!(
            "def {}({}):  # line {}",
            f.name,
            params.join(", "),
            f.span.line
        ),
        out,
    );
    block(&f.body, ind + 1, out);
}

fn stmt(s: &Stmt, ind: usize, out: &mut String) {
    match s {
        Stmt::Assign {
            target,
            value,
            span,
        } => line(
            ind,
            &format!("{} = {}  # {}", tgt(target), expr(value), span.line),
            out,
        ),
        Stmt::Declare {
            name,
            ty,
            value,
            span,
        } => line(
            ind,
            &format!(
                "{name}: {ty} = {}  # {}",
                value.as_ref().map(expr).unwrap_or_default(),
                span.line
            ),
            out,
        ),
        Stmt::Expr(e, span) => line(ind, &format!("{}  # {}", expr(e), span.line), out),
        Stmt::If { test, then, other } => {
            line(ind, &format!("if {}:", expr(test)), out);
            block(then, ind + 1, out);
            if !other.is_empty() {
                line(ind, "else:", out);
                block(other, ind + 1, out);
            }
        }
        Stmt::Loop {
            target,
            iter,
            test,
            body,
        } => {
            match (target, iter, test) {
                (Some(t), Some(i), _) => line(ind, &format!("for {} in {}:", tgt(t), expr(i)), out),
                (_, _, Some(t)) => line(ind, &format!("while {}:", expr(t)), out),
                _ => line(ind, "loop:", out),
            }
            block(body, ind + 1, out);
        }
        Stmt::Switch {
            subject,
            cases,
            fallthrough,
        } => {
            line(
                ind,
                &format!("switch {} (fallthrough={fallthrough}):", expr(subject)),
                out,
            );
            for c in cases {
                if c.patterns.is_empty() {
                    line(ind + 1, "default:", out);
                } else {
                    let p: Vec<String> = c.patterns.iter().map(expr).collect();
                    line(ind + 1, &format!("case {}:", p.join(", ")), out);
                }
                block(&c.body, ind + 2, out);
            }
        }
        Stmt::Try {
            body,
            handlers,
            finally,
        } => {
            line(ind, "try:", out);
            block(body, ind + 1, out);
            for h in handlers {
                line(ind, "except:", out);
                block(h, ind + 1, out);
            }
            if !finally.is_empty() {
                line(ind, "finally:", out);
                block(finally, ind + 1, out);
            }
        }
        Stmt::Return(e, span) => line(
            ind,
            &format!(
                "return {}  # {}",
                e.as_ref().map(expr).unwrap_or_default(),
                span.line
            ),
            out,
        ),
        Stmt::Break => line(ind, "break", out),
        Stmt::Continue => line(ind, "continue", out),
        Stmt::Import { alias, path } => line(ind, &format!("import {path} as {alias}"), out),
        Stmt::FuncDef(f) => func(f, ind, out),
        Stmt::ClassDef(c) => {
            line(
                ind,
                &format!("class {}({}):", c.name, c.bases.join(", ")),
                out,
            );
            block(&c.fields, ind + 1, out);
            for m in &c.methods {
                func(m, ind + 1, out);
            }
        }
        Stmt::Raw(e, span) => line(ind, &format!("raw {}  # {}", expr(e), span.line), out),
    }
}

fn tgt(t: &Target) -> String {
    match t {
        Target::Name(n) => n.clone(),
        Target::Attr(o, f) => format!("{}.{f}", expr(o)),
        Target::Index(b, k) => format!("{}[{}]", expr(b), expr(k)),
        Target::Tuple(ts) => format!("({})", ts.iter().map(tgt).collect::<Vec<_>>().join(", ")),
        Target::Other => "<?>".into(),
    }
}

fn args(a: &[Arg]) -> String {
    a.iter()
        .map(|a| {
            let v = expr(&a.value);
            let v = if a.spread { format!("*{v}") } else { v };
            match &a.name {
                Some(n) => format!("{n}={v}"),
                None => v,
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn expr(e: &Expr) -> String {
    match e {
        Expr::Lit(c) => match c {
            Const::Int(i) => i.to_string(),
            Const::Float(f) => f.to_string(),
            Const::Str(s) => format!("{s:?}"),
            Const::Bool(b) => b.to_string(),
            Const::None => "None".into(),
        },
        Expr::Name(n) => n.clone(),
        Expr::Attr(o, f) => format!("{}.{f}", expr(o)),
        Expr::Index(b, k) => format!("{}[{}]", expr(b), expr(k)),
        Expr::Slice {
            value,
            lower,
            upper,
        } => format!(
            "{}[{}:{}]",
            expr(value),
            lower.as_deref().map(expr).unwrap_or_default(),
            upper.as_deref().map(expr).unwrap_or_default()
        ),
        Expr::Call { func, args: a, .. } => format!("{}({})", expr(func), args(a)),
        Expr::New { class, args: a, .. } => format!("new {class}({})", args(a)),
        Expr::Bin(op, l, r) => format!("({} {op:?} {})", expr(l), expr(r)),
        Expr::Un(op, v) => format!("{op:?}({})", expr(v)),
        Expr::Concat(parts) => format!(
            "concat({})",
            parts.iter().map(expr).collect::<Vec<_>>().join(", ")
        ),
        Expr::Cond { test, then, other } => {
            format!("({} if {} else {})", expr(then), expr(test), expr(other))
        }
        Expr::List(items) => format!(
            "[{}]",
            items.iter().map(expr).collect::<Vec<_>>().join(", ")
        ),
        Expr::Dict(pairs) => format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", expr(k), expr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Expr::Cast(t, v) => format!("({t}) {}", expr(v)),
        Expr::Lambda(f) => format!(
            "lambda {}: <{} stmts>",
            f.params
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
            f.body.len()
        ),
        Expr::Other(parts) => format!(
            "other({})",
            parts.iter().map(expr).collect::<Vec<_>>().join(", ")
        ),
    }
}
