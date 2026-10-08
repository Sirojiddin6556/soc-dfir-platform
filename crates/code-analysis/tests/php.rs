//! Behaviour of the PHP analysis on small programs: each test pairs code
//! that must be reported with a safe variant that must not be.

use code_analysis::project::Project;
use code_analysis::Options;

fn scan_with(files: &[(&str, &str)], options: Options) -> Vec<(String, u32, String)> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    code_analysis::analyze_with(&project, options)
        .findings
        .into_iter()
        .map(|f| (f.rule, f.line, f.file))
        .collect()
}

fn scan(files: &[(&str, &str)]) -> Vec<(String, u32, String)> {
    scan_with(files, Options::default())
}

/// Lines of `file` reported for `rule`.
fn lines(found: &[(String, u32, String)], rule: &str, file: &str) -> Vec<u32> {
    let mut l: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == rule && f.2 == file)
        .map(|f| f.1)
        .collect();
    l.sort();
    l
}

#[test]
fn concatenated_query_is_injection_and_escaped_or_numeric_input_is_not() {
    let src = r#"<?php
$c = mysqli_connect('db', 'u', 'p', 'app');
$id = $_GET['id'];
mysqli_query($c, "SELECT * FROM users WHERE id = '$id'");
$safe = mysqli_real_escape_string($c, $id);
mysqli_query($c, "SELECT * FROM users WHERE id = '$safe'");
mysqli_query($c, "SELECT * FROM users WHERE id = " . intval($id));
$st = $c->prepare("SELECT * FROM users WHERE id = ?");
$st->bind_param('s', $id);
$st->execute();
"#;
    let found = scan(&[("users.php", src)]);
    assert_eq!(
        lines(&found, "sql-injection", "users.php"),
        vec![4],
        "{found:?}"
    );
}

#[test]
fn redirect_to_user_url_is_open_redirect_but_fixed_host_or_local_path_is_not() {
    let src = r#"<?php
header("Location: " . $_GET['next']);
header("Location: https://example.org/" . $_GET['page']);
header("Location: /app/" . $_GET['page']);
header("Location: " . $_SERVER['PHP_SELF'] . "?done=1");
"#;
    let found = scan(&[("go.php", src)]);
    assert_eq!(
        lines(&found, "open-redirect", "go.php"),
        vec![2],
        "{found:?}"
    );
}

#[test]
fn assignment_inside_a_condition_keeps_its_value() {
    let src = r#"<?php
$c = mysqli_connect('db', 'u', 'p', 'app');
if ($name = $_POST['name']) {
    mysqli_query($c, "DELETE FROM users WHERE name = '$name'");
}
$r = mysqli_query($c, "SELECT name FROM users");
while ($row = mysqli_fetch_assoc($r)) {
    echo $row['name'];
}
"#;
    let found = scan(&[("del.php", src)]);
    assert_eq!(
        lines(&found, "sql-injection", "del.php"),
        vec![4],
        "{found:?}"
    );
    // Database rows are not user input unless asked for.
    assert_eq!(
        lines(&found, "xss", "del.php"),
        Vec::<u32>::new(),
        "{found:?}"
    );
    let found = scan_with(
        &[("del.php", src)],
        Options {
            external_sources: true,
            ..Options::default()
        },
    );
    assert_eq!(lines(&found, "xss", "del.php"), vec![8], "{found:?}");
}

#[test]
fn constants_from_define_and_const_are_known_across_includes() {
    let config = r#"<?php
define('UPLOAD_DIR', '/srv/uploads/');
const PING = 'ping -c 1 ';
"#;
    let page = r#"<?php
require_once 'config.php';
readfile(UPLOAD_DIR . basename($_GET['f']));
readfile(UPLOAD_DIR . $_GET['f']);
system(PING . escapeshellarg($_GET['host']));
system(PING . $_GET['host']);
"#;
    let found = scan(&[("config.php", config), ("page.php", page)]);
    assert_eq!(
        lines(&found, "path-traversal", "page.php"),
        vec![4],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "command-injection", "page.php"),
        vec![6],
        "{found:?}"
    );
}

#[test]
fn include_of_one_of_several_files_brings_back_the_variables_each_sets() {
    let index = r#"<?php
$page = isset($_GET['plain']) ? 'plain.php' : 'fancy.php';
include $page;
echo $greeting;
include isset($_GET['plain']) ? 'fancy.php' : 'quiet.php';
echo $greeting;
"#;
    let plain = r#"<?php
$greeting = "Hello " . $_GET['name'];
"#;
    let fancy = r#"<?php
$greeting = "<b>" . htmlspecialchars($_GET['name']) . "</b>";
"#;
    let quiet = r#"<?php
$greeting = "Hello";
"#;
    let found = scan(&[
        ("index.php", index),
        ("plain.php", plain),
        ("fancy.php", fancy),
        ("quiet.php", quiet),
    ]);
    assert_eq!(
        lines(&found, "file-inclusion", "index.php"),
        Vec::<u32>::new(),
        "{found:?}"
    );
    assert_eq!(lines(&found, "xss", "index.php"), vec![4], "{found:?}");
}

#[test]
fn code_after_a_counting_loop_is_reached() {
    let src = r#"<?php
$parts = array();
for ($i = 0; $i < 50; $i++) {
    $parts[] = $i;
}
echo $_GET['msg'];
$n = 0;
while ($n < 10) {
    $n++;
}
echo $_GET['other'];
while (true) {
    $n++;
}
echo $_GET['never'];
"#;
    let found = scan(&[("loop.php", src)]);
    assert_eq!(lines(&found, "xss", "loop.php"), vec![6, 11], "{found:?}");
}

#[test]
fn a_check_on_an_array_element_holds_for_that_element() {
    let src = r#"<?php
$octet = explode('.', $_GET['ip']);
if (ctype_digit($octet[0])) {
    system("ping -c 1 10.0.0." . $octet[0]);
    system("ping -c 1 10.0.0." . $octet[1]);
}
if (is_numeric($_GET["n"])) {
    system("seq " . $_GET["n"]);
}
"#;
    let found = scan(&[("ping.php", src)]);
    assert_eq!(
        lines(&found, "command-injection", "ping.php"),
        vec![5],
        "{found:?}"
    );
}

#[test]
fn upload_location_is_chosen_by_php_but_the_file_name_by_the_client() {
    let src = r#"<?php
move_uploaded_file($_FILES['f']['tmp_name'], '/srv/uploads/avatar.jpg');
move_uploaded_file($_FILES['f']['tmp_name'], '/srv/uploads/' . $_FILES['f']['name']);
"#;
    let found = scan(&[("upload.php", src)]);
    assert_eq!(
        lines(&found, "path-traversal", "upload.php"),
        vec![3],
        "{found:?}"
    );
}

#[test]
fn template_text_from_the_request_is_template_injection() {
    let src = r#"<?php
$twig = new Twig_Environment(new Twig_Loader_String());
echo $twig->render($_GET['tpl']);
$files = new Twig_Environment(new Twig_Loader_Filesystem('templates'));
echo $files->render('page.html', array('name' => $_GET['name']));
"#;
    let found = scan(&[("tpl.php", src)]);
    assert_eq!(
        lines(&found, "template-injection", "tpl.php"),
        vec![3],
        "{found:?}"
    );
}

#[test]
fn fetching_a_user_url_is_ssrf_but_a_fixed_site_is_not() {
    let src = r#"<?php
echo strlen(file_get_contents($_GET['url']));
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_POST['feed']);
curl_exec($ch);
echo strlen(file_get_contents('https://api.example.org/search?q=' . urlencode($_GET['q'])));
"#;
    let found = scan(&[("fetch.php", src)]);
    assert_eq!(lines(&found, "ssrf", "fetch.php"), vec![2, 4], "{found:?}");
}

#[test]
fn wordpress_escaping_prepared_queries_and_safe_redirects_are_understood() {
    let plugin = r#"<?php
function myplugin_page() {
    global $wpdb;
    $term = $_GET['s'];
    echo '<p>' . esc_html($term) . '</p>';
    echo '<a href="' . esc_url($_GET['link']) . '">x</a>';
    echo '<p>' . $term . '</p>';
    $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s", $term));
    $wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_title = '$term'");
    wp_safe_redirect($_GET['to']);
    wp_redirect($_GET['to']);
}
add_action('admin_menu', 'myplugin_page');
"#;
    let found = scan(&[("myplugin.php", plugin)]);
    assert_eq!(lines(&found, "xss", "myplugin.php"), vec![7], "{found:?}");
    assert_eq!(
        lines(&found, "sql-injection", "myplugin.php"),
        vec![9],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "open-redirect", "myplugin.php"),
        vec![11],
        "{found:?}"
    );
}

#[test]
fn one_finding_per_sink_lists_the_other_inputs_that_reach_it() {
    let db = r#"<?php
class Db {
    private $c;
    function __construct() { $this->c = mysqli_connect('db', 'u', 'p', 'app'); }
    function run($sql) { return mysqli_query($this->c, $sql); }
}
"#;
    let login = r#"<?php
require_once 'Db.php';
$db = new Db();
$db->run("SELECT * FROM users WHERE name = '" . $_POST['user'] . "'");
"#;
    let register = r#"<?php
require_once 'Db.php';
$db = new Db();
$db->run("INSERT INTO users (email) VALUES ('" . $_POST['email'] . "')");
"#;
    let project = Project::from_sources(vec![
        ("Db.php".into(), db.into()),
        ("login.php".into(), login.into()),
        ("register.php".into(), register.into()),
    ]);
    let report = code_analysis::analyze_with(&project, Options::default());
    let sqli: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule == "sql-injection")
        .collect();
    assert_eq!(sqli.len(), 1, "{:?}", report.findings);
    assert_eq!((sqli[0].file.as_str(), sqli[0].line), ("Db.php", 5));
    let mut inputs: Vec<&str> = sqli[0]
        .source
        .iter()
        .chain(sqli[0].other_sources.iter())
        .map(|l| l.file.as_str())
        .collect();
    inputs.sort();
    assert_eq!(inputs, vec!["login.php", "register.php"]);
}

#[test]
fn object_made_by_the_front_controller_is_used_by_included_pages() {
    let index = r#"<?php
require_once 'Store.php';
$store = new Store();
include 'pages/item.php';
"#;
    let store = r#"<?php
class Store {
    function find($id) {
        return mysqli_query(mysqli_connect('db', 'u', 'p', 'app'), "SELECT * FROM items WHERE id = " . $id);
    }
}
"#;
    // The page never assigns `$store`: it relies on the front controller.
    let item = r#"<?php
$store->find($_GET['id']);
$store->find((int) $_GET['id']);
"#;
    let found = scan(&[
        ("index.php", index),
        ("Store.php", store),
        ("pages/item.php", item),
    ]);
    assert_eq!(
        lines(&found, "sql-injection", "Store.php"),
        vec![4],
        "{found:?}"
    );
}

#[test]
fn argument_counts_type_checks_and_mapped_arrays_are_followed() {
    let src = r#"<?php
function build_url(...$args) {
    if (is_array($args[0])) {
        $uri = count($args) < 2 || false === $args[1] ? $_SERVER['QUERY_STRING'] : $args[1];
    } else {
        $uri = count($args) < 3 || false === $args[2] ? $_SERVER['QUERY_STRING'] : $args[2];
    }
    return $uri;
}
echo build_url('page', '2', 'list.php');
echo build_url(array('page' => 2), 'list.php');
echo build_url('page', '2');
$size = array_map('absint', $_POST['size']);
readfile('/srv/thumbs/' . $size['w'] . 'x' . $size['h'] . '.png');
$name = array_map('trim', $_POST['size']);
readfile('/srv/thumbs/' . $name['w'] . '.png');
"#;
    let found = scan(&[("url.php", src)]);
    assert_eq!(lines(&found, "xss", "url.php"), vec![12], "{found:?}");
    assert_eq!(
        lines(&found, "path-traversal", "url.php"),
        vec![16],
        "{found:?}"
    );
}

#[test]
fn an_object_storing_callbacks_to_itself_does_not_grow_without_end() {
    // Each call stores `[$this, 'check']` in a field of `$this`; without
    // care every round nests the object one level deeper.
    let src = r#"<?php
class Controller {
    private $schema;
    function schema() {
        $this->schema = array('id' => array('validate' => array($this, 'check'), 'prev' => $this->schema));
        return $this->schema;
    }
    function check($v) { return is_numeric($v); }
    function handle() {
        for ($i = 0; $i < 50; $i++) { $this->schema(); }
        echo $_GET['msg'];
    }
}
"#;
    let started = std::time::Instant::now();
    let found = scan(&[("c.php", src)]);
    assert_eq!(lines(&found, "xss", "c.php"), vec![11], "{found:?}");
    assert!(started.elapsed().as_secs() < 10);
}
