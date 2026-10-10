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
fn the_same_secret_in_many_files_is_one_finding() {
    let secret = "DB_PASSWORD = \"sup3r-s3cr3t-pw-9times\"\n";
    let other = "API_PASSWORD = \"a-different-s3cret-value\"\n";
    let project = Project::from_sources(vec![
        ("a.py".to_string(), secret.to_string()),
        ("b.py".to_string(), secret.to_string()),
        ("c.py".to_string(), secret.to_string()),
        ("d.py".to_string(), other.to_string()),
    ]);
    let secrets: Vec<_> = code_analysis::analyze(&project)
        .findings
        .into_iter()
        .filter(|f| f.rule == "hardcoded-secret")
        .collect();
    // The repeated value collapses to one finding that lists the other two
    // places; the distinct value stays its own finding.
    assert_eq!(secrets.len(), 2, "{secrets:#?}");
    let repeated = secrets
        .iter()
        .find(|f| f.other_sources.len() == 2)
        .expect("repeated secret groups its other locations");
    let files: Vec<&str> = std::iter::once(repeated.file.as_str())
        .chain(repeated.other_sources.iter().map(|l| l.file.as_str()))
        .collect();
    assert_eq!(files, vec!["a.py", "b.py", "c.py"]);
    assert!(secrets
        .iter()
        .any(|f| f.file == "d.py" && f.other_sources.is_empty()));
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

#[test]
fn weak_random_matters_only_for_secrets() {
    let src = "import random, secrets, string
from flask import Flask, make_response, session
app = Flask(__name__)

def generate_token():
    return ''.join(random.choices(string.ascii_letters, k=16))

def pick_color():
    return random.choice(['red', 'green'])

@app.route('/a')
def a():
    session['remember_me'] = str(random.random())[2:]
    otp = secrets.randbelow(10 ** 6)
    sample = random.sample(range(100), 5)
    r = make_response(pick_color() + str(sample) + str(otp))
    r.set_cookie('sid', str(random.getrandbits(64)), secure=True)
    return r
";
    let found = scan(&[("app.py", src)]);
    let lines: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "weak-random")
        .map(|f| f.1)
        .collect();
    // Reported where the predictable value is made, once each.
    assert_eq!(lines, vec![6, 13, 17], "{found:?}");
}

#[test]
fn framework_internals_are_not_findings() {
    let static_view = "import posixpath
from pathlib import Path
from django.http import FileResponse
from django.utils._os import safe_join

def serve(request, path, document_root=None):
    path = posixpath.normpath(path).lstrip('/')
    fullpath = Path(safe_join(document_root, path))
    return FileResponse(fullpath.open('rb'))

def raw(request, path):
    return FileResponse(open('/srv/' + request.GET['f'], 'rb'))
";
    let auth = "from importlib import import_module

def load_backend(request):
    path = request.session['_auth_user_backend']
    return import_module(path)
";
    let tests = "import unittest
def run(suite, result):
    suite.run(result, debug=True)
";
    let found = scan(&[
        ("views/static.py", static_view),
        ("auth.py", auth),
        ("tests/test_x.py", tests),
    ]);
    let got: Vec<(&str, u32, &str)> = found
        .iter()
        .map(|f| (f.2.as_str(), f.1, f.0.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![("views/static.py", 12, "path-traversal")],
        "{got:?}"
    );
}

#[test]
fn walrus_assignment_and_counting_loops_keep_the_flow() {
    let src = format!(
        "{FLASK}
@app.route('/a')
def a(*parts):
    cur = sqlite3.connect('db').cursor()
    if (name := request.args.get('name')):
        cur.execute(\"DELETE FROM users WHERE name = '\" + name + \"'\")
    i = 0
    while i < 10:
        i += 1
    cur.execute(\"SELECT * FROM t WHERE c = '\" + request.args['c'] + \"'\")
    return 'ok'

def first(*args):
    return args[0]

@app.route('/b')
def b():
    cur = sqlite3.connect('db').cursor()
    cur.execute(first('SELECT 1', request.args['x']))
    cur.execute(first(request.args['y'], 'SELECT 1'))
    return 'ok'
"
    );
    let found = scan(&[("app.py", &src)]);
    let sqli: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "sql-injection")
        .map(|f| f.1)
        .collect();
    assert_eq!(sqli, vec![9, 13, 23], "{found:?}");
}

#[test]
fn redirect_within_the_site_or_to_an_allowed_key_is_not_open() {
    let src = "from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
app = FastAPI()
CONTENT = {'news': 1, 'doctors': 2}

@app.post('/admin/{kind}/save')
async def save(kind: str):
    return RedirectResponse(f'/admin/{kind}', status_code=302)

@app.post('/go')
async def go(next: str):
    return RedirectResponse(next)

@app.post('/root')
async def root(next: str):
    return RedirectResponse('/' + next)

@app.post('/known')
async def known(kind: str):
    if kind not in CONTENT:
        raise HTTPException(404)
    return RedirectResponse(kind)
";
    let found = scan(&[("app.py", src)]);
    let lines: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == "open-redirect")
        .map(|f| f.1)
        .collect();
    assert_eq!(lines, vec![12, 16], "{found:?}");
}
