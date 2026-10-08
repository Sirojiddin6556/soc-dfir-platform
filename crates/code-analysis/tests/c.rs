//! Behaviour of the C and C++ analysis on small programs: each test pairs
//! code that must be reported with a safe variant that must not be.

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
fn socket_data_reaches_command_and_format_but_constants_do_not() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
void serve(void) {
    char buf[256];
    char cmd[300];
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int c = accept(s, NULL, NULL);
    recv(c, buf, sizeof(buf) - 1, 0);
    snprintf(cmd, sizeof(cmd), "ls %s", buf);
    system(cmd);
    system("ls /tmp");
    printf(buf);
    printf("%s", buf);
}
"#;
    let found = scan(&[("serve.c", src)]);
    assert_eq!(
        lines(&found, "command-injection", "serve.c"),
        vec![11],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "format-string", "serve.c"),
        vec![13],
        "{found:?}"
    );
}

#[test]
fn command_line_and_environment_are_sources_only_when_asked() {
    let src = r#"#include <stdlib.h>
int main(int argc, char **argv) {
    system(argv[1]);
    system(getenv("EDITOR"));
    return 0;
}
"#;
    let found = scan(&[("tool.c", src)]);
    assert!(
        lines(&found, "command-injection", "tool.c").is_empty(),
        "{found:?}"
    );
    let found = scan_with(
        &[("tool.c", src)],
        Options {
            external_sources: true,
            ..Options::default()
        },
    );
    assert_eq!(
        lines(&found, "command-injection", "tool.c"),
        vec![3, 4],
        "{found:?}"
    );
}

/// A CGI program that keeps the request in a global and dispatches
/// through a table of handlers, like cgit.
#[test]
fn request_global_reaches_handler_called_through_table() {
    let cgi = r#"#include <stdlib.h>
#include "cgi.h"
struct context ctx;
static void parse(void) {
    ctx.path = getenv("PATH_INFO");
    ctx.page = getenv("QUERY_STRING");
}
static void show_file(void) {
    fopen(ctx.path, "r");
}
static void show_about(void) {
    fopen("/srv/about.html", "r");
}
static struct cmd cmds[] = {
    {"file", show_file},
    {"about", show_about},
};
int main(void) {
    parse();
    for (int i = 0; i < 2; i++) {
        if (!strcmp(cmds[i].name, ctx.page))
            cmds[i].fn();
    }
    return 0;
}
"#;
    let header = r#"struct context { char *path; char *page; };
struct cmd { const char *name; void (*fn)(void); };
extern struct context ctx;
"#;
    let found = scan(&[("cgi.c", cgi), ("cgi.h", header)]);
    assert_eq!(
        lines(&found, "path-traversal", "cgi.c"),
        vec![9],
        "{found:?}"
    );
}

#[test]
fn canonical_path_under_base_is_safe_and_raw_prefix_check_is_not() {
    let src = r#"#include <stdlib.h>
#include <string.h>
void canonical(void) {
    char *name = getenv("PATH_INFO");
    char *full = realpath(name, NULL);
    if (full && strncmp(full, "/srv/www/", 9) == 0)
        fopen(full, "r");
}
void raw(void) {
    char *name = getenv("PATH_INFO");
    if (strncmp(name, "/srv/www/", 9) == 0)
        fopen(name, "r");
}
"#;
    let found = scan(&[("files.c", src)]);
    assert_eq!(
        lines(&found, "path-traversal", "files.c"),
        vec![12],
        "{found:?}"
    );
}

#[test]
fn checks_that_leave_through_goto_or_a_character_loop_make_path_safe() {
    let src = r#"#include <stdlib.h>
#include <string.h>
#include <ctype.h>
void searched(void) {
    char *path = getenv("PATH_INFO");
    if (strstr(path, "..") != NULL)
        goto err;
    fopen(path, "r");
    return;
err:
    puts("bad");
}
void walked(void) {
    char *path = getenv("PATH_INFO");
    char *p;
    for (p = path; *p; ++p) {
        if (*p == '.' && *(p + 1) == '.')
            goto err;
        if (!isalnum(*p) && *p != '/' && *p != '.' && *p != '-')
            goto err;
    }
    fopen(path, "r");
    return;
err:
    puts("bad");
}
void indexed(void) {
    char *path = getenv("PATH_INFO");
    for (int i = 0; path[i]; i++) {
        if (path[i] == '/' || path[i] == '\\')
            return;
    }
    fopen(path, "r");
}
void length_only(void) {
    char *path = getenv("PATH_INFO");
    if (strlen(path) > 64)
        goto err;
    fopen(path, "r");
    return;
err:
    puts("bad");
}
void else_branch(void) {
    char *path = getenv("PATH_INFO");
    if (strstr(path, "..") == NULL)
        fopen(path, "r");
    else
        fopen(path, "w");
}
"#;
    let found = scan(&[("check.c", src)]);
    assert_eq!(
        lines(&found, "path-traversal", "check.c"),
        vec![39, 49],
        "{found:?}"
    );
}

#[test]
fn check_on_struct_field_narrows_that_field_only() {
    let src = r#"#include <stdlib.h>
#include <string.h>
struct query { char *path; char *other; };
struct query q;
void handle(void) {
    char *p;
    q.path = getenv("PATH_INFO");
    q.other = getenv("QUERY_STRING");
    for (p = q.path; *p; p++) {
        if (*p == '.')
            return;
    }
    fopen(q.path, "r");
    fopen(q.other, "r");
}
"#;
    let found = scan(&[("query.c", src)]);
    assert_eq!(
        lines(&found, "path-traversal", "query.c"),
        vec![14],
        "{found:?}"
    );
}

#[test]
fn cpp_object_keeps_data_until_its_destructor_runs() {
    let src = r#"#include <cstdlib>
#include <sys/socket.h>
class Runner {
public:
    Runner(char *d) { data = d; }
    ~Runner() { system(data); }
private:
    char *data;
};
class Quiet {
public:
    Quiet(char *d) { data = d; }
    ~Quiet() { system("true"); }
private:
    char *data;
};
void serve() {
    char buf[128];
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int c = accept(s, NULL, NULL);
    recv(c, buf, sizeof(buf) - 1, 0);
    Runner r(buf);
    Quiet q(buf);
}
"#;
    let found = scan(&[("runner.cpp", src)]);
    assert_eq!(
        lines(&found, "command-injection", "runner.cpp"),
        vec![6],
        "{found:?}"
    );
}

#[test]
fn out_parameter_and_pointer_alias_carry_data_back() {
    let src = r#"#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
static void read_name(int c, char *out) {
    recv(c, out, 63, 0);
}
static void read_fixed(char *out) {
    strcpy(out, "report.txt");
}
void serve(void) {
    char name[64];
    char fixed[64];
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int c = accept(s, NULL, NULL);
    read_name(c, name);
    read_fixed(fixed);
    char *alias = name;
    fopen(alias, "r");
    fopen(fixed, "r");
}
"#;
    let found = scan(&[("names.c", src)]);
    assert_eq!(
        lines(&found, "path-traversal", "names.c"),
        vec![18],
        "{found:?}"
    );
}

/// Classes declared in a `.h` header and defined in separate `.cpp`
/// files, as in Juliet's flow 84: the header is C++ though named `.h`, so
/// the fields are the object's and not globals one class could leak into
/// the other through.
#[test]
fn class_from_header_keeps_its_fields_apart_from_other_classes() {
    let header = r#"namespace jobs {
class Bad {
public:
    Bad(char *copy);
    ~Bad();
private:
    char *data;
};
class Good {
public:
    Good(char *copy);
    ~Good();
private:
    char *data;
};
}
"#;
    let bad = r#"#include <cstdlib>
#include <sys/socket.h>
#include "jobs.h"
namespace jobs {
Bad::Bad(char *copy) {
    data = copy;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int c = accept(s, NULL, NULL);
    recv(c, data, 99, 0);
}
Bad::~Bad() {
    system(data);
}
}
"#;
    let good = r#"#include <cstdlib>
#include <cstring>
#include "jobs.h"
namespace jobs {
Good::Good(char *copy) {
    data = copy;
    strcpy(data, "ls");
}
Good::~Good() {
    system(data);
}
}
"#;
    let main = r#"#include "jobs.h"
namespace jobs {
void run_bad() {
    char buf[100] = "";
    Bad *b = new Bad(buf);
    delete b;
}
void run_good() {
    char buf[100] = "";
    Good *g = new Good(buf);
    delete g;
}
}
"#;
    let found = scan(&[
        ("jobs.h", header),
        ("bad.cpp", bad),
        ("good.cpp", good),
        ("main.cpp", main),
    ]);
    assert_eq!(
        lines(&found, "command-injection", "bad.cpp"),
        vec![12],
        "{found:?}"
    );
    assert!(
        lines(&found, "command-injection", "good.cpp").is_empty(),
        "{found:?}"
    );
}
