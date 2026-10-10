//! Behaviour of the JavaScript / TypeScript analysis on small programs.

use code_analysis::project::Project;

fn scan(files: &[(&str, &str)]) -> Vec<(String, u32)> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    code_analysis::analyze(&project)
        .findings
        .into_iter()
        .map(|f| (f.rule, f.line))
        .collect()
}

/// The distinct rule ids a single file triggers.
fn rules(path: &str, src: &str) -> Vec<String> {
    let mut r: Vec<String> = scan(&[(path, src)]).into_iter().map(|f| f.0).collect();
    r.sort();
    r.dedup();
    r
}

#[test]
fn express_query_concatenation_is_sql_injection_and_parameters_are_not() {
    let src = r#"
const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  db.query('SELECT * FROM u WHERE id = ' + req.query.id);   // injection
});
app.get('/b', (req, res) => {
  db.query('SELECT * FROM u WHERE id = $1', [req.query.id]); // parameterized
});
"#;
    let found = scan(&[("app.js", src)]);
    assert!(found.contains(&("sql-injection".to_string(), 5)));
    assert!(
        !found.iter().any(|(r, l)| r == "sql-injection" && *l == 8),
        "a parameterized query is not an injection"
    );
}

#[test]
fn express_covers_command_path_xss_and_redirect() {
    let src = r#"
const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const app = express();
app.post('/x', (req, res) => {
  cp.exec('ping ' + req.body.host);
  fs.readFile('/data/' + req.query.f, () => {});
  res.send('<b>' + req.query.name + '</b>');
  res.redirect(req.query.url);
});
"#;
    let r = rules("app.js", src);
    assert!(r.contains(&"command-injection".to_string()));
    assert!(r.contains(&"path-traversal".to_string()));
    assert!(r.contains(&"xss".to_string()));
    assert!(r.contains(&"open-redirect".to_string()));
}

#[test]
fn handler_assigned_to_a_field_is_analyzed() {
    // The NodeGoat style: a handler assigned to `this.x` inside a
    // constructor, registered elsewhere, must still be analyzed.
    let src = r#"
function Handler(db) {
  this.update = (req, res, next) => {
    const v = eval(req.body.amount);   // code injection
    return v;
  };
}
"#;
    assert!(rules("handler.js", src).contains(&"code-injection".to_string()));
}

#[test]
fn nest_controller_decorators_mark_request_data() {
    let src = r#"
import { Controller, Get, Post, Body, Query, Param } from '@nestjs/common';
@Controller('u')
export class UserController {
  constructor(private readonly repo: any) {}
  @Get(':id')
  find(@Param('id') id: string) {
    return this.repo.query('SELECT * FROM u WHERE id = ' + id);
  }
  @Post()
  create(@Body() dto: any) {
    return this.repo.execute('INSERT ' + dto.name);
  }
}
"#;
    let found = scan(&[("user.controller.ts", src)]);
    assert!(found.iter().filter(|(r, _)| r == "sql-injection").count() >= 2);
}

#[test]
fn numeric_conversion_sanitizes() {
    let src = r#"
const express = require('express');
const app = express();
app.get('/n', (req, res) => {
  const n = Number(req.query.n);
  db.query('SELECT * FROM u LIMIT ' + n);   // safe: numeric
});
"#;
    assert!(
        !rules("app.js", src).contains(&"sql-injection".to_string()),
        "a value passed through Number() is safe for SQL"
    );
}

#[test]
fn template_literals_build_tainted_queries() {
    let src = r#"
const express = require('express');
const app = express();
app.get('/t', (req, res) => {
  db.query(`SELECT * FROM u WHERE name = '${req.query.name}'`);
});
"#;
    assert!(rules("app.ts", src).contains(&"sql-injection".to_string()));
}

#[test]
fn clean_code_has_no_findings() {
    let src = r#"
const express = require('express');
const app = express();
app.get('/ok', (req, res) => {
  const id = Number(req.query.id);
  res.json({ id });
});
function add(a, b) { return a + b; }
"#;
    assert!(rules("app.js", src).is_empty());
}
