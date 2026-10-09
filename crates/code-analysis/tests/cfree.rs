//! Memory used or freed again after `free` or `delete`. Each test pairs
//! code that must be reported with a safe variant that must not be.

use code_analysis::project::Project;
use code_analysis::Options;

fn scan(files: &[(&str, &str)]) -> Vec<(String, u32, String, String)> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    code_analysis::analyze_with(&project, Options::default())
        .findings
        .into_iter()
        .map(|f| (f.rule, f.line, f.file, f.message))
        .collect()
}

/// Lines of `file` reported for `rule`.
fn lines(found: &[(String, u32, String, String)], rule: &str, file: &str) -> Vec<u32> {
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
fn memory_used_or_freed_again_after_free_is_reported() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct node { int n; struct node *next; };
void f(const char *s, struct node *head) {
    char *a = malloc(10);
    free(a);
    a[0] = 0;
    char *b = malloc(10);
    free(b);
    free((void *)b);
    char *c = malloc(10);
    free(c);
    strcpy(c, s);
    char *d = malloc(10);
    free(d);
    printf("%d %s\n", 1, d);
    struct node *p;
    for (p = head; p != NULL; p = p->next) free(p);
    a[1] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "use-after-free", "a.c"),
        vec![8, 14, 17, 19],
        "{found:?}"
    );
    assert_eq!(lines(&found, "double-free", "a.c"), vec![11], "{found:?}");
    let msg = |line: u32| {
        found
            .iter()
            .find(|f| f.1 == line)
            .map(|f| f.3.clone())
            .unwrap_or_default()
    };
    assert!(msg(11).contains("строке 10"), "{found:?}");
    assert!(msg(14).contains("strcpy()"), "{found:?}");
}

#[test]
fn memory_set_again_or_not_freed_is_not_reported() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
struct node { int n; struct node *next; };
int f(struct node *head, int n) {
    char *a = malloc(10);
    free(a);
    a = malloc(10);
    a[0] = 0;
    free(a);
    a = NULL;
    free(a);
    if (a) a[0] = 1;
    struct node *p = head;
    while (p != NULL) {
        struct node *next = p->next;
        free(p);
        p = next;
    }
    char *b = malloc(10);
    if (n > 2) free(b);
    if (n <= 2) b[0] = 0;
    char *c = NULL;
    for (int i = 0; i < n; i++) {
        free(c);
        c = malloc(10);
    }
    free(c);
    return 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert!(
        found
            .iter()
            .all(|f| f.0 != "use-after-free" && f.0 != "double-free"),
        "{found:?}"
    );
}

/// Freed in one function and used in another: reported at the call that
/// hands the freed memory to the function that uses it.
#[test]
fn memory_freed_by_a_call_or_passed_to_one_is_reported_at_the_call() {
    let lib = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void show(const char *line) { if (line != NULL) printf("%s\n", line); }
void release(char *data) { free(data); }
void drop(char **pp) { free(*pp); }
void maybe_release(char *data, int last) { if (last) free(data); }
char *copy(const char *s) {
    char *r = malloc(8);
    strcpy(r, s);
    free(r);
    return r;
}
void sink(char *data) { show(data); }
"#;
    let src = r#"#include <stdlib.h>
void show(const char *line);
void release(char *data);
void drop(char **pp);
void maybe_release(char *data, int last);
char *copy(const char *s);
void sink(char *data);
void a(int n) {
    char *d = malloc(10);
    release(d);
    show(d);
    char *e = copy("x");
    show(e);
    char *g = malloc(10);
    maybe_release(g, n);
    show(g);
    char *h = malloc(10);
    show(h);
    sink(h);
    free(h);
    sink(h);
    char *k = malloc(10);
    drop(&k);
    k[0] = 0;
    char *m = malloc(10);
    release(m);
    free(m);
}
"#;
    let found = scan(&[("lib.c", lib), ("a.c", src)]);
    assert_eq!(
        lines(&found, "use-after-free", "a.c"),
        vec![11, 13, 21, 24],
        "{found:?}"
    );
    assert_eq!(lines(&found, "double-free", "a.c"), vec![27], "{found:?}");
    assert_eq!(lines(&found, "use-after-free", "lib.c"), Vec::<u32>::new());
    let msg = found
        .iter()
        .find(|f| f.1 == 11)
        .map(|f| f.3.clone())
        .unwrap_or_default();
    assert!(msg.contains("show()"), "{msg}");
}

/// A free in a branch taken on what a field holds is a guess: other code
/// may hold the object too (`if (--o->refs == 0) free(o);`).
#[test]
fn memory_freed_on_a_field_test_is_not_certain() {
    let src = r#"#include <stdlib.h>
struct obj { int refs; char *name; };
static void unref(struct obj *o) {
    o->refs--;
    if (o->refs == 0) free(o);
}
int use(void) {
    struct obj *o = malloc(sizeof(struct obj));
    if (!o) return 0;
    o->refs = 1;
    unref(o);
    return o->refs;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "use-after-free", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
}

#[test]
fn objects_used_or_deleted_again_after_delete_are_reported() {
    let src = r#"class Two {
public:
    int a;
};
int f() {
    Two *t = new Two;
    delete t;
    t->a = 1;
    char *c = new char[10];
    delete [] c;
    delete [] c;
    Two *u = new Two;
    u->a = 2;
    delete u;
    return 0;
}
"#;
    let found = scan(&[("a.cpp", src)]);
    assert_eq!(
        lines(&found, "use-after-free", "a.cpp"),
        vec![8],
        "{found:?}"
    );
    assert_eq!(lines(&found, "double-free", "a.cpp"), vec![11], "{found:?}");
}

/// A block declaring a variable again hides the outer one until it ends:
/// the inner loop's `i` leaves the outer loop's count alone, and findings
/// name the inner variable as written.
#[test]
fn variable_declared_again_in_a_block_hides_the_outer_one() {
    let src = r#"#include <stdlib.h>
void show(int x);
void f(char *q) {
    int i;
    int *data = NULL;
    for (i = 0; i < 1; i++) {
        data = malloc(10 * sizeof(int));
        if (data == NULL) exit(1);
        {
            size_t i;
            for (i = 0; i < 10; i++) data[i] = 0;
        }
        free(data);
    }
    show(data[0]);
    {
        char *q = malloc(4);
        if (q == NULL) exit(1);
        free(q);
        q[0] = 0;
    }
    q[0] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "use-after-free", "a.c"),
        vec![15, 20],
        "{found:?}"
    );
    let msg = found
        .iter()
        .find(|f| f.1 == 20)
        .map(|f| f.3.clone())
        .unwrap_or_default();
    assert!(msg.contains("Указатель q используется"), "{msg:?}");
}

/// `xasprintf(&p, ...)`, a function not followed, may give `p` new memory;
/// a function freeing an element frees the element, not its array.
#[test]
fn memory_set_by_a_call_or_freed_by_element_is_not_reported() {
    let src = r#"#include <stdlib.h>
int xasprintf(char **ret, const char *fmt, ...);
int load(const char *p);
static void release(void *ptr) { free(ptr); }
struct reader { void **task; int tasks; };
void f(const char *name) {
    char *cp = malloc(4);
    free(cp);
    xasprintf(&cp, "%s-cert", name);
    load(cp);
    free(cp);
    struct reader *r = calloc(1, sizeof(struct reader));
    if (r == NULL) return;
    r->task = calloc(2, sizeof(void *));
    if (r->task == NULL) return;
    for (int i = 0; i < 2; i++) release(r->task[i]);
    release(r->task);
    release(r);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert!(
        found
            .iter()
            .all(|f| f.0 != "use-after-free" && f.0 != "double-free"),
        "{found:?}"
    );
}
