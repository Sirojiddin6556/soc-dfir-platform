//! Behaviour of the Python analysis on small programs.

use code_analysis::project::Project;

fn scan(files: &[(&str, &str)]) -> Vec<(String, u32, String)> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    code_analysis::analyze(&project)
        .findings
        .into_iter()
        .map(|f| (f.rule, f.line, f.file))
        .collect()
}

fn rules(src: &str) -> Vec<String> {
    let mut r: Vec<String> = scan(&[("app.py", src)]).into_iter().map(|f| f.0).collect();
    r.dedup();
    r
}

const FLASK: &str = "from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n";

#[test]
fn string_built_query_is_injection_and_parameters_are_not() {
    let src = format!(
        "{FLASK}
@app.route('/a')
def a():
    name = request.args.get('name')
    cur = sqlite3.connect('db').cursor()
    cur.execute(f\"SELECT * FROM users WHERE name = '{{name}}'\")
    return 'ok'

@app.route('/b')
def b():
    name = request.args.get('name')
    cur = sqlite3.connect('db').cursor()
    cur.execute('SELECT * FROM users WHERE name = ?', (name,))
    return 'ok'
"
    );
    let found = scan(&[("app.py", &src)]);
    let sqli: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "sql-injection")
        .map(|f| f.1)
        .collect();
    assert_eq!(sqli, vec![9], "{found:?}");
}

#[test]
fn constant_conditions_and_containers_decide_the_flow() {
    let src = format!(
        "{FLASK}
import os
@app.route('/a')
def a():
    p = request.form['x']
    num = 86
    bar = 'safe' if 7 * 18 + num > 200 else p
    os.system('echo ' + bar)
    lst = ['safe', p, 'moresafe']
    lst.pop(0)
    os.system('echo ' + lst[1])
    m = {{'a': 'x', 'b': p}}
    os.system('echo ' + m['a'])
    s = 'help' + p + 'snapes on a plane'
    os.system('echo ' + s[4:-17])
    return 'ok'
"
    );
    let found = scan(&[("app.py", &src)]);
    let lines: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "command-injection")
        .map(|f| f.1)
        .collect();
    // Only the slice that still holds the input is dangerous.
    assert_eq!(lines, vec![18], "{found:?}");
}

#[test]
fn sanitizers_apply_to_their_context_only() {
    let src = format!(
        "{FLASK}
import html
@app.route('/a')
def a():
    v = html.escape(request.args.get('v'))
    cur = sqlite3.connect('db').cursor()
    cur.execute('SELECT ' + v)
    return '<p>' + v + '</p>'
"
    );
    let r = rules(&src);
    assert!(r.contains(&"sql-injection".to_string()), "{r:?}");
    assert!(!r.contains(&"xss".to_string()), "{r:?}");
}

#[test]
fn shell_matters_for_subprocess() {
    let src = format!(
        "{FLASK}
import subprocess
@app.route('/a')
def a():
    host = request.args.get('host')
    subprocess.run(['ping', '-c', '1', host])
    subprocess.run(['sh', '-c', 'ping ' + host])
    subprocess.run('ping ' + host, shell=True)
    return 'ok'
"
    );
    let found = scan(&[("app.py", &src)]);
    let lines: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "command-injection")
        .map(|f| f.1)
        .collect();
    assert_eq!(lines, vec![10, 11], "{found:?}");
}

#[test]
fn flows_cross_modules_and_helpers_are_followed() {
    let app = "from flask import Flask, request\nfrom lib.db import find, find_safe\napp = Flask(__name__)\n
@app.route('/u')
def u():
    find(request.args['id'])
    find_safe(request.args['id'])
    return 'ok'
";
    let lib = "import sqlite3\n
def find(uid):
    sqlite3.connect('x').execute('SELECT * FROM t WHERE id = ' + uid)

def find_safe(uid):
    sqlite3.connect('x').execute('SELECT * FROM t WHERE id = ' + str(int(uid)))
";
    let found = scan(&[("app.py", app), ("lib/db.py", lib)]);
    let sqli: Vec<(u32, String)> = found
        .iter()
        .filter(|f| f.0 == "sql-injection")
        .map(|f| (f.1, f.2.clone()))
        .collect();
    assert_eq!(sqli, vec![(4, "lib/db.py".to_string())], "{found:?}");
}

#[test]
fn validation_guards_sanitize() {
    let src = format!(
        "{FLASK}
import re, lxml.etree
@app.route('/a')
def a():
    name = request.args.get('name')
    root = lxml.etree.parse('x.xml')
    if \"'\" in name:
        return 'bad'
    root.xpath(\"//user[@name='\" + name + \"']\")
    return 'ok'

@app.route('/b')
def b():
    uid = request.args.get('id')
    if not re.fullmatch(r'[0-9]+', uid):
        return 'bad'
    sqlite3.connect('x').execute('SELECT * FROM t WHERE id = ' + uid)
    return 'ok'

@app.route('/c')
def c():
    code = request.args.get('code')
    if not code.startswith(\"'\") or not code.endswith(\"'\") or \"'\" in code[1:-1]:
        return 'bad'
    return str(eval(code))
"
    );
    let r = rules(&src);
    assert!(!r.contains(&"xpath-injection".to_string()), "{r:?}");
    assert!(!r.contains(&"sql-injection".to_string()), "{r:?}");
    assert!(!r.contains(&"code-injection".to_string()), "{r:?}");
    // The same code without the checks is reported.
    let unguarded = src
        .replace("    if \"'\" in name:\n        return 'bad'\n", "")
        .replace(
            "    if not re.fullmatch(r'[0-9]+', uid):\n        return 'bad'\n",
            "",
        )
        .replace(
            "    if not re.fullmatch(r'[0-9]+', uid):",
            "    if not re.fullmatch(r'[0-9 ]+', uid):",
        )
        .replace("or \"'\" in code[1:-1]", "");
    let r = rules(&unguarded);
    for rule in ["xpath-injection", "sql-injection", "code-injection"] {
        assert!(r.contains(&rule.to_string()), "{rule} missing: {r:?}");
    }
}

#[test]
fn request_path_of_a_fixed_route_is_constant() {
    let src = format!(
        "{FLASK}
import os
@app.route('/files/list')
def a():
    os.system('ls ' + request.path.split('/')[1])
    return 'ok'

@app.route('/files/<name>')
def b(name):
    os.system('ls ' + request.path)
    return 'ok'

@app.route('/n/<int:n>')
def c(n):
    return 'value ' + str(n)
"
    );
    let found = scan(&[("app.py", &src)]);
    let lines: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "command-injection")
        .map(|f| f.1)
        .collect();
    assert_eq!(lines, vec![13], "{found:?}");
    assert!(!found.iter().any(|f| f.0 == "xss"), "{found:?}");
}

#[test]
fn django_views_and_http_server_handlers_have_sources() {
    let views = "from django.http import HttpResponse
from django.db import connection

def search(request):
    q = request.GET.get('q')
    with connection.cursor() as cur:
        cur.execute(\"SELECT * FROM t WHERE name LIKE '%\" + q + \"%'\")
    return HttpResponse('<h1>' + q + '</h1>')
";
    let server = "import http.server, subprocess
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        subprocess.run('nslookup ' + self.path[1:], shell=True)
        self.wfile.write(self.path.encode())
";
    let found = scan(&[("views.py", views), ("server.py", server)]);
    let got: Vec<(&str, &str)> = found.iter().map(|f| (f.2.as_str(), f.0.as_str())).collect();
    for want in [
        ("views.py", "sql-injection"),
        ("views.py", "xss"),
        ("server.py", "command-injection"),
        ("server.py", "xss"),
    ] {
        assert!(got.contains(&want), "{want:?} missing in {got:?}");
    }
}

#[test]
fn patterns_without_data_flow() {
    let src = "import hashlib, random, secrets, yaml, requests
from flask import Flask, make_response
app = Flask(__name__)
hashlib.md5(b'x')
hashlib.new('sha1')
hashlib.sha256(b'x')
hashlib.new('sha256')
token = random.randint(0, 10)
token2 = secrets.token_hex(16)
requests.get('https://example.com', verify=False)

@app.route('/c')
def c():
    r = make_response('ok')
    r.set_cookie('a', 'b')
    r.set_cookie('a', 'b', secure=True)
    return r
";
    let found = scan(&[("app.py", src)]);
    let lines =
        |rule: &str| -> Vec<u32> { found.iter().filter(|f| f.0 == rule).map(|f| f.1).collect() };
    assert_eq!(lines("weak-hash"), vec![4, 5]);
    assert_eq!(lines("weak-random"), vec![8]);
    assert_eq!(lines("tls-no-verify"), vec![10]);
    assert_eq!(lines("insecure-cookie"), vec![15]);
}

#[test]
fn yaml_loader_choice_matters() {
    let src = format!(
        "{FLASK}
import yaml, pickle, base64
@app.route('/a')
def a():
    d = request.get_data()
    yaml.safe_load(d)
    yaml.load(d, Loader=yaml.SafeLoader)
    yaml.load(d, Loader=yaml.Loader)
    pickle.loads(base64.b64decode(d))
    return 'ok'
"
    );
    let found = scan(&[("app.py", &src)]);
    let lines: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "unsafe-deserialization")
        .map(|f| f.1)
        .collect();
    assert_eq!(lines, vec![11, 12], "{found:?}");
}
