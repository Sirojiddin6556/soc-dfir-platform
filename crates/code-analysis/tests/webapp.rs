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
    "weak-hash",
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
            "csrf main.py:49",
            "login-no-limit main.py:33",
            "logout-get main.py:43",
            "mass-assignment main.py:55",
            "no-frame-protection main.py:9",
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
    assert_eq!(scan(&[("app.py", src)]), Vec::<String>::new());
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
