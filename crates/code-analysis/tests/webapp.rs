//! The web application model: endpoints, logins, CSRF, changes on GET,
//! and the checks on keys and passwords in any function.

use code_analysis::project::Project;

const RULES: &[&str] = &[
    "csrf",
    "state-change-get",
    "logout-get",
    "login-no-limit",
    "no-frame-protection",
    "static-session-token",
    "timing-unsafe-compare",
    "weak-password-hash",
    "mass-assignment",
    "stored-template-injection",
    "weak-hash",
    "predictable-salt",
    "public-form-no-limit",
    "content-spoofing",
    "unhandled-parse-error",
    "fail-open",
    "swallowed-startup-error",
    "db-file-in-workdir",
];

/// Findings of the model's rules as `rule file:line`, sorted.
fn scan(files: &[(&str, &str)]) -> Vec<String> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    let mut out: Vec<String> = code_analysis::analyze(&project)
        .findings
        .into_iter()
        .filter(|f| RULES.contains(&f.rule.as_str()))
        .map(|f| format!("{} {}:{}", f.rule, f.file, f.line))
        .collect();
    out.sort();
    out
}

/// A clinic site like the user's own test project: an admin cookie that
/// is an HMAC of a constant, forms saved without CSRF tokens, logout on
/// GET, a salted SHA-256 for the password, settings written whole.
const CLINIC: &str = r#"import hashlib
import hmac
import os
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from models import SessionLocal, Setting, Appointment, Admin

app = FastAPI(docs_url=None)
templates = Jinja2Templates(directory="templates")
SECRET = os.getenv("SESSION_SECRET", "")

def _make_session():
    return hmac.new(SECRET.encode(), b"admin", hashlib.sha256).hexdigest()

def _is_admin(request: Request):
    token = request.cookies.get("clinic_session")
    return token == _make_session()

@app.post("/contact")
def contact(name: str = Form(...)):
    db = SessionLocal()
    db.add(Appointment(name=name))
    db.commit()
    return RedirectResponse("/", status_code=303)

@app.get("/admin")
def admin(request: Request, error: str = ""):
    if not _is_admin(request):
        return templates.TemplateResponse("login.html", {"request": request, "error": error})
    return templates.TemplateResponse("admin.html", {"request": request})

@app.post("/admin/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or admin.password_hash != hashlib.sha256(("clinic" + password).encode()).hexdigest():
        return RedirectResponse("/admin?error=1", status_code=303)
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie("clinic_session", _make_session(), httponly=True, samesite="lax")
    return resp

@app.get("/admin/logout")
def logout():
    resp = RedirectResponse("/admin", status_code=303)
    resp.delete_cookie("clinic_session")
    return resp

@app.post("/admin/settings")
async def settings(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    form = await request.form()
    db = SessionLocal()
    for key, value in form.items():
        db.add(Setting(key=key, value=value))
    db.commit()
    return RedirectResponse("/admin", status_code=303)
"#;

#[test]
fn clinic_site_shows_its_session_csrf_and_password_flaws() {
    assert_eq!(
        scan(&[("main.py", CLINIC)]),
        vec![
            "content-spoofing main.py:30",
            "csrf main.py:49",
            "login-no-limit main.py:33",
            "logout-get main.py:43",
            "mass-assignment main.py:55",
            "no-frame-protection main.py:9",
            "public-form-no-limit main.py:20",
            "static-session-token main.py:40",
            "timing-unsafe-compare main.py:18",
            "weak-password-hash main.py:37",
        ]
    );
}

#[test]
fn templates_escape_what_a_fastapi_page_prints() {
    let project = Project::from_sources(vec![("main.py".into(), CLINIC.into())]);
    let report = code_analysis::analyze(&project);
    assert!(
        !report.findings.iter().any(|f| f.rule == "xss"),
        "{:?}",
        report.findings
    );
}

#[test]
fn flask_writes_only_on_post_and_login_is_not_logout() {
    let src = r#"from flask import Flask, request, session, redirect, render_template
from werkzeug.security import check_password_hash, generate_password_hash
app = Flask(__name__)

@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        db.execute("INSERT INTO user (username, password) VALUES (?, ?)", (request.form["username"], generate_password_hash(request.form["password"])))
        db.commit()
        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method != "POST":
        return render_template("login.html")
    user = db.execute("SELECT * FROM user WHERE username = ?", (request.form["username"],)).fetchone()
    if user is None or not check_password_hash(user["password"], request.form["password"]):
        return render_template("login.html")
    session.clear()
    session["user_id"] = user["id"]
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/<int:id>/delete", methods=("POST",))
def delete(id):
    if session.get("user_id") is None:
        return redirect("/login")
    db.execute("DELETE FROM post WHERE id = ?", (id,))
    db.commit()
    return redirect("/")
"#;
    assert_eq!(
        scan(&[("app.py", src)]),
        vec![
            "csrf app.py:29",
            "login-no-limit app.py:13",
            "logout-get app.py:24",
            "no-frame-protection app.py:3",
            "public-form-no-limit app.py:5",
        ]
    );
}

#[test]
fn protections_the_project_has_silence_the_rules() {
    let src = r#"from flask import Flask, request, session, render_template
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
app = Flask(__name__)
CSRFProtect(app)
limiter = Limiter(app)

@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

@app.route("/login", methods=["POST"])
def login():
    if check_password_hash(load(request.form["username"]), request.form["password"]):
        session["user"] = request.form["username"]
    return render_template("x.html")

@app.route("/save", methods=["POST"])
def save():
    if "user" not in session:
        return "no", 403
    db.session.add(Item(request.form["x"]))
    db.session.commit()
    return render_template("x.html")
"#;
    assert_eq!(scan(&[("app.py", src)]), Vec::<String>::new());
}

#[test]
fn json_apis_and_public_forms_need_no_csrf_token() {
    let src = r#"from flask import Flask, request, session, jsonify
app = Flask(__name__)

@app.route("/api/items", methods=["POST"])
def add_item():
    if "user" not in session:
        return jsonify(error="login"), 401
    data = request.get_json()
    db.session.add(Item(data["name"]))
    db.session.commit()
    return jsonify(ok=True)

@app.route("/register/user", methods=["POST"])
def register():
    db.session.add(User(request.form["name"]))
    db.session.commit()
    return jsonify(ok=True)
"#;
    // The public form needs no CSRF token, but a limit on requests.
    assert_eq!(
        scan(&[("app.py", src)]),
        vec!["public-form-no-limit app.py:13"]
    );
}

#[test]
fn django_checks_csrf_unless_a_view_is_exempt() {
    let src = r#"from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

@login_required
def delete(request, pk):
    if request.method == "POST":
        Post.objects.filter(pk=pk).delete()
    return redirect("/")

@csrf_exempt
@login_required
def save(request):
    if request.method == "POST":
        Post.objects.create(title=request.POST["title"])
    return redirect("/")
"#;
    let settings = "MIDDLEWARE = ['django.middleware.clickjacking.XFrameOptionsMiddleware']\n";
    assert_eq!(
        scan(&[("blog/views.py", src), ("site/settings.py", settings)]),
        vec!["csrf blog/views.py:13"]
    );
}

#[test]
fn php_pages_report_the_code_that_changes_data() {
    let delete = r#"<?php
session_start();
if (!isset($_SESSION['user'])) { header('Location: login.php'); exit; }
$db = mysqli_connect('localhost', 'app', getenv('DB_PASS'), 'app');
if (isset($_POST['id'])) {
    $id = (int) $_POST['id'];
    mysqli_query($db, "DELETE FROM posts WHERE id = $id");
}
?>
<form method="post"><input name="id"></form>
"#;
    let guarded = r#"<?php
session_start();
if (!isset($_SESSION['user'])) { exit; }
if (isset($_POST['id'])) {
    checkToken($_POST['user_token'], $_SESSION['session_token']);
    mysqli_query($db, "DELETE FROM posts WHERE id = " . (int) $_POST['id']);
}
"#;
    let remove = r#"<?php
session_start();
if (!isset($_SESSION['user'])) { exit; }
mysqli_query($db, "DELETE FROM posts WHERE id = " . (int) $_GET['id']);
"#;
    let login = r#"<?php
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $row = find_user($_POST['username']);
    if ($row && md5($_POST['password']) == $row['pass']) {
        $_SESSION['user'] = $row['name'];
    }
}
?>
<html><form method="post"></form></html>
"#;
    assert_eq!(
        scan(&[
            ("delete.php", delete),
            ("guarded.php", guarded),
            ("remove.php", remove),
            ("login.php", login),
        ]),
        vec![
            "csrf delete.php:7",
            "login-no-limit login.php:6",
            "no-frame-protection login.php:10",
            "state-change-get remove.php:4",
            "weak-password-hash login.php:5",
        ]
    );
}

#[test]
fn spring_without_spring_security_has_no_csrf_check() {
    let ctl = r#"package demo;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpSession;

@Controller
public class Items {
    @PostMapping("/items/save")
    public String save(@RequestParam String name, HttpSession session) {
        if (session.getAttribute("user") == null) return "login";
        repo.save(new Item(name));
        return "ok";
    }

    @GetMapping("/items/delete")
    public String delete(@RequestParam long id, HttpSession session) {
        if (session.getAttribute("user") == null) return "login";
        repo.deleteById(id);
        return "ok";
    }

    @PostMapping("/api/items")
    public String add(@RequestBody Item item, HttpSession session) {
        if (session.getAttribute("user") == null) return "login";
        repo.save(item);
        return "ok";
    }
}
"#;
    let security = r#"package demo;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class Security {
    void configure(HttpSecurity http) {
        http.authorizeRequests().anyRequest().authenticated();
    }
}
"#;
    assert_eq!(
        scan(&[("Items.java", ctl)]),
        vec!["csrf Items.java:8", "state-change-get Items.java:15",]
    );
    // Spring Security checks CSRF tokens by default; a GET that deletes
    // stays a finding.
    assert_eq!(
        scan(&[("Items.java", ctl), ("Security.java", security)]),
        vec!["state-change-get Items.java:15"]
    );
}

#[test]
fn keys_compare_in_constant_time_but_passwords_and_session_tokens_are_not_keys() {
    let src = r#"import hmac
from flask import Flask, request, session
app = Flask(__name__)
API_KEY = load_key()

def check_key():
    return request.headers.get("X-Api-Key") == API_KEY

def check_key_safely():
    return hmac.compare_digest(request.headers.get("X-Api-Key", ""), API_KEY)

def check_csrf():
    return request.form.get("csrf_token") == session["csrf_token"]

def check_signature(body):
    expected = hmac.new(API_KEY, body, "sha256").hexdigest()
    return request.headers["X-Signature"] == expected
"#;
    assert_eq!(
        scan(&[("app.py", src)]),
        vec![
            "timing-unsafe-compare app.py:17",
            "timing-unsafe-compare app.py:7"
        ]
    );
}

#[test]
fn passwords_need_a_slow_hash_and_other_data_does_not() {
    let src = r#"import hashlib

def hash_password(p):
    return hashlib.sha256(("salt" + p).encode()).hexdigest()

def store(user, password):
    user.pw = hashlib.md5(password.encode()).hexdigest()

def etag(body):
    return hashlib.sha256(body).hexdigest()
"#;
    assert_eq!(
        scan(&[("users.py", src)]),
        vec![
            "weak-password-hash users.py:4",
            "weak-password-hash users.py:7",
        ]
    );
}

#[test]
fn a_cookie_made_fresh_for_each_login_is_not_static() {
    let src = r#"import secrets
from flask import Flask, request, make_response
app = Flask(__name__)
TOKENS = set()

@app.route("/login", methods=["POST"])
def login():
    if check_password_hash(load(request.form["user"]), request.form["password"]):
        token = secrets.token_hex(32)
        TOKENS.add(token)
        resp = make_response("ok")
        resp.set_cookie("auth", token)
        return resp
    return "no"

@app.route("/me")
def me():
    return "yes" if request.cookies.get("auth") in TOKENS else "no"
"#;
    let found = scan(&[("app.py", src)]);
    assert!(
        !found.iter().any(|f| f.starts_with("static-session-token")),
        "{found:?}"
    );
}

#[test]
fn page_text_about_csrf_is_not_a_token_check() {
    let src = r#"<?php
session_start();
if (!isset($_SESSION['user'])) { exit; }
echo "<h2>Cross Site Request Forgery (CSRF)</h2>";
if (isset($_GET['passwd'])) {
    $stmt = $conn->prepare("UPDATE users set password=:pass where username=:user");
    $stmt->execute();
}
"#;
    assert_eq!(
        scan(&[("csrf/home.php", src)]),
        vec![
            "no-frame-protection csrf/home.php:4",
            "state-change-get csrf/home.php:6"
        ]
    );
}

#[test]
fn a_link_with_a_secret_key_may_change_data_on_get() {
    let src = r#"<?php
session_start();
if (!isset($_SESSION['user'])) { exit; }
$pending = get_pending_email($_SESSION['user']);
if (isset($_GET['key']) && hash_equals($pending['key'], $_GET['key'])) {
    $wpdb->query($wpdb->prepare("UPDATE users SET email = %s WHERE id = %d", $pending['email'], $_SESSION['user']));
}
"#;
    assert_eq!(scan(&[("confirm.php", src)]), Vec::<String>::new());
}

#[test]
fn a_servlet_that_drops_the_session_cookie_on_get_logs_out() {
    let src = r#"package demo;

import javax.servlet.http.*;

public class Logout extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        Cookie cookie = new Cookie("JSESSIONID", null);
        cookie.setMaxAge(0);
        resp.addCookie(cookie);
        resp.sendRedirect("/");
    }
}
"#;
    assert_eq!(
        scan(&[("Logout.java", src)]),
        vec!["logout-get Logout.java:8"]
    );
}

#[test]
fn a_hash_repeated_in_a_loop_is_stretched_not_fast() {
    let src = r#"<?php
function crypt_private($password, $salt, $count) {
    $hash = md5($salt . $password, TRUE);
    do {
        $hash = md5($hash . $password, TRUE);
    } while (--$count);
    return $hash;
}
"#;
    let found = scan(&[("phpass.php", src)]);
    assert!(
        !found.iter().any(|f| f.starts_with("weak-password-hash")),
        "{found:?}"
    );
}

#[test]
fn a_hash_helper_in_another_module_is_found_through_its_callers() {
    let models = r#"import os
from hashlib import sha256

SALT = "clinic"

def make_hash(s):
    return sha256((SALT + s).encode()).hexdigest()

def etag(body):
    return sha256(body).hexdigest()

def seed(db, Admin):
    db.add(Admin(username="admin", password_hash=make_hash(os.getenv("ADMIN", "x"))))
"#;
    let main = r#"from models import make_hash, etag

def login(admin, password, page):
    if admin.password_hash != make_hash(password):
        return None
    return etag(page)
"#;
    assert_eq!(
        scan(&[("models.py", models), ("main.py", main)]),
        vec!["weak-password-hash models.py:7"]
    );
    let project = Project::from_sources(vec![
        ("models.py".to_string(), models.to_string()),
        ("main.py".to_string(), main.to_string()),
    ]);
    let found = code_analysis::analyze(&project).findings;
    let f = found
        .iter()
        .find(|f| f.rule == "weak-password-hash")
        .unwrap();
    assert!(f.message.contains("make_hash()"), "{}", f.message);
    assert!(f.message.contains("«clinic»"), "{}", f.message);
}

#[test]
fn every_loop_over_form_fields_is_mass_assignment_unless_fields_are_checked() {
    let src = r#"from fastapi import FastAPI, Request
from models import SessionLocal, Setting, Admin
app = FastAPI()
ALLOWED = {"site_name", "phone"}

@app.post("/settings")
async def settings(request: Request):
    form = await request.form()
    db = SessionLocal()
    for k in form.keys():
        db.merge(Setting(k, form[k]))
    db.commit()

@app.post("/kv")
async def kv(request: Request):
    data = dict(await request.form())
    db = SessionLocal()
    for key in data:
        s = db.query(Setting).filter(Setting.key == key).first()
        if s:
            s.value = data[key]
    db.commit()

@app.post("/profile")
async def profile(request: Request):
    form = await request.form()
    admin = SessionLocal().query(Admin).first()
    for k, v in form.items():
        if k in ("csrf_token", "submit"):
            continue
        if hasattr(admin, k):
            setattr(admin, k, v)

@app.post("/safe")
async def safe(request: Request):
    form = await request.form()
    db = SessionLocal()
    for k, v in form.items():
        if k not in ALLOWED:
            continue
        s = db.query(Setting).filter(Setting.key == k).first()
        s.value = v
    db.commit()

@app.post("/tags")
async def tags(request: Request):
    body = await request.json()
    db = SessionLocal()
    for name in body["tags"]:
        db.add(Setting(name, "tag"))
    db.commit()
"#;
    let found: Vec<String> = scan(&[("main.py", src)])
        .into_iter()
        .filter(|f| f.starts_with("mass-assignment"))
        .collect();
    assert_eq!(
        found,
        vec![
            "mass-assignment main.py:10",
            "mass-assignment main.py:18",
            "mass-assignment main.py:28",
        ]
    );
}

#[test]
fn php_settings_saved_from_every_post_field() {
    let src = r#"<?php
session_start();
if (!isset($_SESSION['admin'])) { exit; }
foreach ($_POST as $k => $v) {
    update_option($k, $v);
}
foreach ($_POST as $k => $v) {
    if (in_array($k, $allowed)) {
        update_option($k, $v);
    }
}
"#;
    let found: Vec<String> = scan(&[("options.php", src)])
        .into_iter()
        .filter(|f| f.starts_with("mass-assignment"))
        .collect();
    assert_eq!(found, vec!["mass-assignment options.php:4"]);
}

#[test]
fn pages_rendered_through_a_helper_need_frame_protection() {
    let src = r#"from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
app = FastAPI()
templates = Jinja2Templates(directory="templates")

def page(request, name, **ctx):
    return templates.TemplateResponse(name, {"request": request, **ctx})

@app.get("/")
def index(request: Request):
    return page(request, "index.html")
"#;
    assert_eq!(
        scan(&[("main.py", src)]),
        vec!["no-frame-protection main.py:3"]
    );
    let api = r#"from fastapi import FastAPI
app = FastAPI()

@app.get("/items")
def items():
    return {"items": []}
"#;
    assert_eq!(scan(&[("api.py", api)]), Vec::<String>::new());
}

#[test]
fn templates_compiled_from_stored_data_are_reported() {
    let src = r#"from jinja2 import Template, Environment
from flask import Flask, render_template, request
from models import Setting, db
app = Flask(__name__)

@app.route("/")
def index():
    footer = Setting.query.filter_by(key="footer").first()
    html = Template(footer.value).render()
    row = db.execute("SELECT body FROM pages WHERE id = 1").fetchone()
    body = Environment().from_string(row["body"]).render()
    fixed = Template("Hello {{ name }}").render(name=footer.value)
    return render_template("index.html", footer=html, body=body, fixed=fixed)

def report(path):
    with open(path) as f:
        return Template(f.read()).render()
"#;
    let found: Vec<String> = scan(&[("app.py", src)])
        .into_iter()
        .filter(|f| f.starts_with("stored-template"))
        .collect();
    assert_eq!(
        found,
        vec![
            "stored-template-injection app.py:11",
            "stored-template-injection app.py:9",
        ]
    );
}

#[test]
fn a_password_as_an_hmac_key_or_a_request_edited_in_place_is_not_reported() {
    let src = r#"<?php
class Smtp {
    protected function hmac($data, $key) {
        if (strlen($key) > 64) {
            $key = pack('H*', md5($key));
        }
        return md5($key . $data);
    }
    public function auth($username, $password, $challenge) {
        return $username . ' ' . $this->hmac($challenge, $password);
    }
}
foreach ($_POST as $key => $val) {
    if (is_array($val)) {
        $_POST[$key] = array_shift($val);
    }
}
"#;
    assert_eq!(scan(&[("smtp.php", src)]), Vec::<String>::new());
}

#[test]
fn a_wordpress_referer_check_guards_a_get_that_changes_options() {
    let src = r#"<?php
if (!current_user_can('manage_options')) { wp_die('no'); }
$action = $_GET['action'];
if ($action === 'enable') {
    check_admin_referer('enable-theme_' . $_GET['theme']);
    update_option('allowedthemes', array($_GET['theme'] => true));
}
update_option('db_upgraded', false);
"#;
    assert_eq!(scan(&[("themes.php", src)]), Vec::<String>::new());
}

#[test]
fn a_constant_salt_is_reported_for_slow_hashes_too() {
    let models = r#"import hashlib, hmac, os
SALT = "shifo".encode()
ADMIN_PASS = os.getenv("ADMIN_PASS", "")

def make_hash(p):
    return hashlib.pbkdf2_hmac("sha256", p.encode(), SALT, 100000).hex()

def legacy_hash(pw):
    h = hashlib.sha256()
    h.update(("shifo" + pw).encode())
    return h.hexdigest()

def keyed(password):
    return hmac.new(b"shifo", password.encode(), hashlib.sha256).hexdigest()

ADMIN_HASH = make_hash(ADMIN_PASS)

def fresh(password):
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
"#;
    let main = r#"from models import legacy_hash
def login(user, password):
    return user.password_hash == legacy_hash(password)
"#;
    let java = r#"import javax.crypto.spec.PBEKeySpec;
class Passwords {
    private static final byte[] SALT = "shifo".getBytes();
    byte[] hash(char[] password) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, SALT, 65536, 128);
        return null;
    }
}
"#;
    let php = r#"<?php
$h = hash_pbkdf2("sha256", $_POST['password'], "shifo", 100000);
$ok = crypt($_POST['password'], $row['hash']) === $row['hash'];
"#;
    assert_eq!(
        scan(&[
            ("models.py", models),
            ("main.py", main),
            ("Passwords.java", java),
            ("login.php", php),
        ]),
        vec![
            "predictable-salt Passwords.java:5",
            "predictable-salt login.php:2",
            "predictable-salt models.py:6",
            "weak-hash login.php:3",
            "weak-password-hash models.py:10",
            "weak-password-hash models.py:14",
        ]
    );
}

#[test]
fn public_forms_need_a_limit_unless_a_login_or_limiter_guards_them() {
    let open = r#"from flask import Flask, request, redirect
app = Flask(__name__)

@app.route("/contact", methods=["POST"])
def contact():
    db.session.add(Message(request.form["text"]))
    db.session.commit()
    return redirect("/")
"#;
    assert_eq!(
        scan(&[("app.py", open)]),
        vec!["public-form-no-limit app.py:4"]
    );
    let guarded = r#"from flask import Flask, request, redirect, session
app = Flask(__name__)

@app.before_request
def require_login():
    if "user" not in session and request.endpoint != "login":
        return redirect("/login")

@app.route("/note", methods=["POST"])
def note():
    db.session.add(Note(request.form["text"]))
    db.session.commit()
    return redirect("/")
"#;
    assert_eq!(scan(&[("app.py", guarded)]), Vec::<String>::new());
    let captcha = r#"from flask import Flask, request, redirect
from flask_wtf import RecaptchaField
app = Flask(__name__)

@app.route("/contact", methods=["POST"])
def contact():
    db.session.add(Message(request.form["text"]))
    db.session.commit()
    return redirect("/")
"#;
    assert_eq!(scan(&[("app.py", captcha)]), Vec::<String>::new());
    // A PHP page behind the login that an included file checks: no
    // spam, but a form another site can post.
    let auth = "<?php session_start(); if (!isset($_SESSION['user'])) { header('Location: login.php'); exit; }\n";
    let page = "<?php\nrequire_once __DIR__ . '/auth.php';\nmysqli_query($db, \"INSERT INTO notes VALUES ('\" . mysqli_real_escape_string($db, $_POST['t']) . \"')\");\n";
    let public = "<?php\nmysqli_query($db, \"INSERT INTO guestbook VALUES ('\" . mysqli_real_escape_string($db, $_POST['t']) . \"')\");\n";
    assert_eq!(
        scan(&[
            ("auth.php", auth),
            ("notes.php", page),
            ("guestbook.php", public)
        ]),
        vec!["csrf notes.php:3", "public-form-no-limit guestbook.php:2"]
    );
}

#[test]
fn numbers_parsed_from_a_request_need_a_handler_or_a_check() {
    let src = r#"from flask import Flask, request
app = Flask(__name__)

@app.route("/items")
def items():
    page = int(request.args.get("page", 1))
    size = request.args.get("size", 10, type=int)
    raw = request.args.get("id", "")
    item = int(raw) if raw.isdigit() else 0
    try:
        limit = int(request.args["limit"])
    except ValueError:
        limit = 10
    return render_template("items.html", page=page)
"#;
    assert_eq!(
        scan(&[("app.py", src)]),
        vec![
            "no-frame-protection app.py:2",
            "unhandled-parse-error app.py:6"
        ]
    );
    let java = r#"import javax.servlet.http.*;
public class ItemServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        int id = Integer.parseInt(request.getParameter("id"));
        try {
            int page = Integer.parseInt(request.getParameter("page"));
        } catch (NumberFormatException e) {
            response.setStatus(400);
        }
    }
}
"#;
    assert_eq!(
        scan(&[("ItemServlet.java", java)]),
        vec!["unhandled-parse-error ItemServlet.java:4"]
    );
    // A handler for bad values answers every endpoint.
    let handled =
        format!("{src}\n@app.errorhandler(ValueError)\ndef bad(e):\n    return \"bad\", 400\n");
    assert_eq!(
        scan(&[("app.py", &handled)]),
        vec!["no-frame-protection app.py:2"]
    );
}

#[test]
fn empty_handlers_around_checks_and_startup_hide_failures() {
    let src = r#"import jwt
from fastapi import FastAPI
from db import SessionLocal, engine, Base
app = FastAPI()

@app.on_event("startup")
def startup():
    try:
        db = SessionLocal()
        db.close()
    except Exception:
        pass

def handle(token, payload, sig):
    try:
        verify_signature(payload, sig)
    except:
        pass
    try:
        ok = check_token(token)
    except Exception:
        ok = False
    try:
        cleanup_file.close()
    except Exception:
        pass
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        log.error(e)
    try:
        validate_token(token)
    except jwt.ExpiredSignatureError:
        pass
"#;
    assert_eq!(
        scan(&[("main.py", src)]),
        vec!["fail-open main.py:17", "swallowed-startup-error main.py:11",]
    );
    let java = r#"import java.sql.*;
class Db {
    Connection open() {
        try {
            return DriverManager.getConnection(System.getenv("DB_URL"));
        } catch (Exception e) {
        }
        return null;
    }
}
"#;
    assert_eq!(
        scan(&[("Db.java", java)]),
        vec!["swallowed-startup-error Db.java:6"]
    );
}

#[test]
fn database_files_relative_to_the_working_folder() {
    let py = r#"import sqlite3
from sqlalchemy import create_engine
DATABASE_URL = "sqlite:///./shifotech.db"
engine = create_engine(DATABASE_URL)
other = create_engine("sqlite:////var/lib/app/app.db")
mem = create_engine("sqlite:///:memory:")
conn = sqlite3.connect("users.db")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
"#;
    let settings = r#"from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
OTHER = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "db.sqlite3"}}
"#;
    let java = r#"class Db {
    static final String URL = "jdbc:sqlite:app.db";
    static final String MEM = "jdbc:h2:mem:test";
}
"#;
    let php = "<?php\n$db = new PDO('sqlite:data/site.db');\n$safe = new PDO('sqlite:../private/site.db');\n$mem = new SQLite3(':memory:');\n";
    assert_eq!(
        scan(&[
            ("app.py", py),
            ("settings.py", settings),
            ("Db.java", java),
            ("index.php", php),
        ]),
        vec![
            "db-file-in-workdir Db.java:2",
            "db-file-in-workdir app.py:3",
            "db-file-in-workdir app.py:7",
            "db-file-in-workdir index.php:2",
            "db-file-in-workdir settings.py:4",
        ]
    );
}

#[test]
fn messages_from_the_address_shown_as_the_sites_own() {
    let src = r#"from flask import Flask, request, render_template
app = Flask(__name__)

@app.route("/login")
def login():
    msg = request.args.get("msg", "")
    return render_template("login.html", message=msg)

@app.route("/search")
def search():
    return render_template("search.html", q=request.args.get("q", ""))
"#;
    assert_eq!(
        scan(&[("app.py", src)]),
        vec!["content-spoofing app.py:7", "no-frame-protection app.py:2"]
    );
    let php =
        "<?php\n$note = htmlspecialchars($_GET['notice']);\necho \"<p>\" . $note . \"</p>\";\n";
    assert_eq!(
        scan(&[("page.php", php)]),
        vec![
            "content-spoofing page.php:3",
            "no-frame-protection page.php:3"
        ]
    );
}
