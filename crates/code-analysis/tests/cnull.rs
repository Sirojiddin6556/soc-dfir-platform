//! NULL pointers in C: reads through a pointer that is NULL, and through
//! results of `malloc` or `fopen` the program did not check. Each test
//! pairs code that must be reported with a safe variant that must not be.

use code_analysis::project::Project;
use code_analysis::Options;

fn scan(files: &[(&str, &str)]) -> Vec<(String, u32, String)> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    code_analysis::analyze_with(&project, Options::default())
        .findings
        .into_iter()
        .map(|f| (f.rule, f.line, f.file))
        .collect()
}

/// Lines of `file` reported for `rule`.
fn lines(found: &[(String, u32, String)], rule: &str, file: &str) -> Vec<u32> {
    let mut l: Vec<u32> = found
        .iter()
        .filter(|f| f.0 == rule && f.2 == file)
        .map(|f| f.1)
        .collect();
    l.sort();
    l.dedup();
    l
}

#[test]
fn pointer_null_where_it_is_read_is_reported() {
    let src = r#"#include <stdio.h>
struct two { int a; int b; };
int f(struct two *q, int *n, char *s) {
    struct two *p = NULL;
    int *i = NULL;
    printf("%d", p->a);
    if (q == NULL) return q->b;
    if (!n) return *n;
    if (!s) printf("%c", s[0]);
    if ((i != NULL) & (*i == 5)) return 1;
    if ((i != NULL) && (*i == 5)) return 2;
    if (q != NULL) return q->a;
    if (n) return *n;
    return 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        vec![6, 7, 8, 9, 10],
        "{found:?}"
    );
}

/// A pointer to a pointer holds what it points to: `*pp` reads the
/// pointer, which is not NULL, and `sizeof` does not run its operand.
#[test]
fn reading_the_pointer_a_pointer_points_to_is_not_reading_null() {
    let src = r#"#include <stdlib.h>
struct two { int a; int b; };
static int use(int **pp) {
    int *p = *pp;
    if (p == NULL) return 0;
    return *p;
}
int f(void) {
    int *p = NULL;
    int **pp = &p;
    int *q = *pp;
    struct two *t = NULL;
    int n = sizeof(t->a) + sizeof(*t);
    t = malloc(sizeof(*t));
    if (t == NULL) return use(&p);
    t->a = n;
    return use(&p);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "unchecked-null", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
}

#[test]
fn allocation_or_stream_used_before_a_check_is_reported() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct two { int a; int b; };
void f(const char *path, size_t n) {
    char *a = malloc(20);
    strcpy(a, "Initialize");
    struct two *t = calloc(1, sizeof(struct two));
    t->a = 1;
    char *b = malloc(n);
    b[0] = 0;
    FILE *fp = fopen(path, "r");
    fclose(fp);
    char *c = malloc(20);
    if (c == NULL) return;
    strcpy(c, "Initialize");
    char *d = malloc(n);
    if (!d) exit(1);
    d[0] = 0;
    FILE *g = fopen(path, "r");
    if (g != NULL) fclose(g);
    a[1] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "unchecked-null", "a.c"),
        vec![7, 9, 11, 13],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
}

/// A NULL passed down a chain of calls is reported where it is read.
#[test]
fn null_passed_to_a_function_that_reads_it_is_reported_there() {
    let sink = r#"#include <stdio.h>
void d(int *data) { printf("%d", *data); }
void c(int *data) { d(data); }
void b(int *data) { c(data); }
void safe(int *data) { if (data != NULL) printf("%d", *data); }
"#;
    let src = r#"void b(int *data);
void safe(int *data);
void a(void) {
    int *data = NULL;
    b(data);
    safe(data);
}
"#;
    let found = scan(&[("sink.c", sink), ("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "sink.c"),
        vec![2],
        "{found:?}"
    );
}

/// A global pointer may be set by another function before this one runs;
/// one the run set to NULL just before is NULL.
#[test]
fn global_pointer_is_null_only_where_the_run_set_it() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
struct two { int a; int b; };
static struct two *g = NULL;
static int *bad;
void init(void) { g = malloc(sizeof(struct two)); if (!g) exit(1); }
int use(void) { return g->a; }
int copy(void) { struct two *p = g; return p->b; }
static void sink(void) { int *data = bad; printf("%d", *data); }
void run(void) { int *data = NULL; bad = data; sink(); }
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        vec![9],
        "{found:?}"
    );
}

/// Code after a label that a `goto` jumps to reads the variables declared
/// before it with their types.
#[test]
fn null_read_after_a_goto_is_reported() {
    let src = r#"#include <stdio.h>
void f(void) {
    int *data;
    goto source;
source:
    data = NULL;
    goto sink;
sink:
    printf("%d", *data);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        vec![9],
        "{found:?}"
    );
}

/// `&x` given to a function points to `x`: the function's checks of the
/// pointer (`if (value != NULL) *value = ...`) are about the pointer, and
/// what it stores there on some paths may be what the caller reads.
#[test]
fn pointer_filled_through_an_out_parameter_is_not_null() {
    let src = r#"#include <stddef.h>
struct node { int key; void *data; };
static int walk(struct node *h, int len, void **value) {
    if (h->key != len) return 0;
    if (value != NULL) *value = h->data;
    return 1;
}
int find(struct node *h, int len, void **value) { return walk(h, len, value); }
int get(struct node *h, int len, char **out) {
    if (out != NULL) *out = NULL;
    if (h->key == 0) return -1;
    if (out != NULL) *out = h->data;
    return 0;
}
int use(struct node *root, int n) {
    struct node *found = NULL;
    char *name = NULL;
    find(root, n, (void **)&found);
    if (get(root, n, &name) != 0) return 0;
    return found->key + name[0];
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
}

/// What a field holds may have been set by code the analysis did not
/// follow: a NULL returned on a test of a field, or read from one, is not
/// NULL for certain.
#[test]
fn null_decided_by_a_field_is_not_certain() {
    let src = r#"#include <stddef.h>
struct stack { void **items; size_t n; };
struct buf { char *bufr; };
static void init(struct stack *s) { s->n = 0; }
static void *pop(struct stack *s) {
    if (s->n == 0) return NULL;
    s->n--;
    return s->items[s->n];
}
static char *ptr(struct buf *b) { return b->bufr; }
int f(struct buf *b) {
    struct stack s;
    struct buf d = { NULL };
    init(&s);
    struct stack *p = pop(&s);
    char *line = ptr(&d);
    return p->n + line[0];
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
}

/// Code a macro runs or a condition skips: a `FOREACH` macro loop, the
/// right side of `||`, a call told to read no bytes, and `&p` itself.
#[test]
fn reads_the_code_guards_are_not_reported() {
    let src = r#"#include <stddef.h>
#include <string.h>
struct item { char *name; int type; };
int put(const char *s);
int f(struct item *head, struct item *r, char *dst) {
    struct item *item = NULL;
    int err = 0;
    char *none = NULL;
    TAILQ_FOREACH(item, head, entry) {
        put(item->name);
    }
    if (!r || (err = r->type) != 0) return err;
    memcpy(dst, none, 0);
    memset(&none, 0, sizeof(none));
    return 0;
}
int g(struct item *q) {
    struct item *p = NULL;
    if (q != NULL) return q->type;
    return q->type + p->type;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "null-dereference", "a.c"),
        vec![20],
        "{found:?}"
    );
}
