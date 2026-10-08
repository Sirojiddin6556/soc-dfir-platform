//! Memory errors in C: writes and reads outside a buffer. Each test pairs
//! code that must be reported with a safe variant that must not be.

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
fn copies_and_indexes_past_a_fixed_array() {
    let src = r#"#include <string.h>
void f(void) {
    char small[8];
    char big[64];
    strcpy(small, "this string is too long");
    strcpy(big, "this string is too long");
    memset(small, 0, 9);
    memset(small, 0, 8);
    small[8] = 0;
    small[7] = 0;
    int i;
    for (i = 0; i <= 8; i++) big[i] = small[i];
    for (i = 0; i < 8; i++) big[i] = small[i];
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![5, 7, 9],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "buffer-overread", "a.c"),
        vec![12],
        "{found:?}"
    );
}

#[test]
fn postfix_increment_moves_after_the_store() {
    let src = r#"void f(void) {
    char b[4];
    int n = 0;
    b[n++] = 'a';
    b[n++] = 'b';
    b[n++] = 'c';
    b[n++] = 'd';
    b[n++] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![8],
        "{found:?}"
    );
}

#[test]
fn network_index_is_reported_unless_checked_or_the_program_exits() {
    let src = r#"#include <stdlib.h>
#include <sys/socket.h>
static int count(int c) {
    int n = 0;
    recv(c, &n, sizeof(n), 0);
    return n;
}
void unchecked(int c) {
    char b[16];
    int n = count(c);
    b[n] = 0;
}
void checked(int c) {
    char b[16];
    int n = count(c);
    if (n < 0 || n >= 16) {
        exit(1);
    }
    b[n] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![11],
        "{found:?}"
    );
}

/// A value that only may run past the end, on a path the analysis cannot
/// tell is taken, is not a finding; one every run of a loop reaches is.
#[test]
fn possible_end_is_reported_only_when_it_is_reached() {
    let src = r#"void maybe(int n) {
    char b[10];
    if (n < 20) {
        b[n] = 0;
    }
}
void always(void) {
    char b[10];
    int i;
    for (i = 0; i < 20; i++) {
        b[i] = 0;
    }
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![11],
        "{found:?}"
    );
}

/// The callee's copy of a pointer moves on its own; through `char **` it
/// moves the caller's.
#[test]
fn pointer_moved_by_callee_only_through_a_pointer_to_it() {
    let src = r#"static void skip(char *p) {
    p += 100;
    *p = 0;
}
static void skip_caller(char **pp) {
    *pp += 100;
}
void f(void) {
    char b[200];
    char c[8];
    skip(b);
    c[0] = b[0];
    char *q = c;
    skip_caller(&q);
    q[0] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![15],
        "{found:?}"
    );
}

/// `if (!p) return p;` returns NULL, so the struct the function fills
/// keeps its fields for the caller that checked for NULL.
#[test]
fn allocation_checked_for_null_keeps_its_fields() {
    let src = r#"#include <stdlib.h>
#include <string.h>
struct params { unsigned int size; };
struct ctx { const struct params *p; };
static const struct params LONG = { 100 };
static const struct params SHORT = { 16 };
static struct ctx *make(const struct params *p) {
    struct ctx *c = malloc(sizeof(*c));
    if (!c)
        return c;
    c->p = p;
    return c;
}
int use(void) {
    unsigned char out[16];
    struct ctx *a = make(&LONG);
    struct ctx *b = make(&SHORT);
    if (!a || !b)
        return 1;
    memset(out, 0, a->p->size);
    memset(out, 0, b->p->size);
    return out[0];
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![20],
        "{found:?}"
    );
}

/// A byte read through `u_char *` is 0 to 255 even from the network, and a
/// `char` may be negative.
#[test]
fn bytes_index_tables_by_their_range() {
    let src = r#"#include <sys/socket.h>
#include <unistd.h>
typedef unsigned char u_char;
static unsigned int table[8];
static unsigned int big[256];
int f(int c) {
    u_char ub[64];
    char sb[64];
    unsigned char len;
    char dst[100];
    char dst2[256];
    if (recv(c, ub, sizeof(ub), 0) <= 0) return 0;
    if (recv(c, sb, sizeof(sb), 0) <= 0) return 0;
    int n = table[ub[0] >> 5];
    n += big[ub[1]];
    n += table[ub[2]];
    n += big[sb[3]];
    u_char ch = sb[4];
    n += big[ch];
    if (recv(c, &len, 1, 0) != 1) return 0;
    recv(c, dst, len, 0);
    recv(c, dst2, len, 0);
    return n;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overread", "a.c"),
        vec![16, 17],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![21],
        "{found:?}"
    );
}

#[test]
fn finding_in_a_condition_points_at_the_condition() {
    let src = r#"#include <sys/socket.h>
static unsigned int table[8];
int f(int c) {
    unsigned int k = 0;
    int n = 0;
    recv(c, &k, sizeof(k), 0);
    while (n < 3) {
        n++;
        if (table[k])
            n++;
    }
    return n;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overread", "a.c"),
        vec![9],
        "{found:?}"
    );
}

/// `if (!(tp = realloc(...))) return -1; *dp = tp;`: the caller that
/// checked the result goes on with the new buffer.
#[test]
fn buffer_grown_through_pointers_to_pointers() {
    let src = r#"#include <stdlib.h>
static int grow(char **dst, char **dp, size_t sz, size_t tsz) {
    char *tp;
    if ((tp = malloc(tsz)) == NULL)
        return -1;
    *dp = tp + (*dp - *dst);
    *dst = tp;
    return 0;
}
int big(void) {
    char *dst, *dp;
    if ((dst = malloc(2)) == NULL)
        return -1;
    dp = dst;
    if (grow(&dst, &dp, 2, 16) == -1)
        return -1;
    dp[3] = 0;
    return 0;
}
int small(void) {
    char *dst, *dp;
    if ((dst = malloc(2)) == NULL)
        return -1;
    dp = dst;
    if (grow(&dst, &dp, 2, 3) == -1)
        return -1;
    dp[3] = 0;
    return 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![27],
        "{found:?}"
    );
}

/// A check on a struct field holds for the code after it, also when the
/// struct came through a pointer.
#[test]
fn field_checked_against_zero_stays_checked() {
    let src = r#"#include <stdint.h>
typedef struct { int *items; uint32_t count; } queue;
static int pop_checked(queue *q) {
    if (q->count == 0)
        return -1;
    q->count--;
    return q->items[q->count];
}
static int pop_unchecked(queue *q) {
    q->count--;
    return q->items[q->count];
}
int f(int n) {
    queue q;
    int arr[16];
    q.items = arr;
    q.count = n > 3 ? 1 : 0;
    return pop_checked(&q);
}
int g(int n) {
    queue q;
    int arr[16];
    q.items = arr;
    q.count = n > 3 ? 1 : 0;
    return pop_unchecked(&q);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overread", "a.c"),
        vec![11],
        "{found:?}"
    );
}

/// A call through a struct member whose function is not known runs every
/// function stored in members of that name, with arguments that may never
/// meet them: there only sizes the user chooses are reported.
#[test]
fn guessed_member_call_reports_user_sizes_only() {
    let src = r#"#include <string.h>
#include <sys/socket.h>
struct ops { void (*fill)(unsigned char *p, unsigned int n); };
static void zero(unsigned char *p, unsigned int n) {
    memset(p, 0, n);
}
static const struct ops OPS = { zero };
void fixed(const struct ops *o) {
    unsigned char b[16];
    o->fill(b, 64);
}
void chosen(const struct ops *o, int c) {
    unsigned char b[16];
    unsigned int n = 0;
    recv(c, &n, sizeof(n), 0);
    o->fill(b, n);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![5],
        "{found:?}"
    );
    let tainted = found.iter().filter(|f| f.0 == "buffer-overflow").count();
    assert_eq!(tainted, 1, "{found:?}");
}

/// `if (**pp != c) return 1; (*pp)++;` compares the character: the
/// caller's pointer stays a pointer, one further on.
#[test]
fn comparing_through_a_pointer_to_a_pointer_keeps_the_pointer() {
    let src = r#"static int skip(const char **pp, char c) {
    if (**pp != c)
        return 1;
    (*pp)++;
    return 0;
}
void f(void) {
    char b[8];
    char *p = b;
    if (skip((const char **)&p, 'a'))
        return;
    p[6] = 0;
    p[7] = 0;
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![13],
        "{found:?}"
    );
}

/// `expect_true(maxlen > 16)` expands to `__builtin_expect((maxlen > 16)
/// != 0, 1)`: the branch runs only when the comparison holds.
#[test]
fn branch_hint_macros_keep_their_test() {
    let callee = r#"#include <stddef.h>
#define expect_true(expr) __builtin_expect((expr) != 0, 1)
static int scan(const unsigned char *ip, size_t n) {
    unsigned int len = 2;
    size_t maxlen = n - len;
    if (expect_true(maxlen > 16)) {
        len++;
        if (ip[len + 8] != 0)
            return 1;
    }
    return 0;
}
"#;
    let short = format!(
        "{callee}int f(void) {{\n    unsigned char a[8] = \"abcdefg\";\n    return scan(a, 8);\n}}\n"
    );
    let found = scan(&[("a.c", &short)]);
    assert_eq!(
        lines(&found, "buffer-overread", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
    let long = format!(
        "{callee}int f(void) {{\n    unsigned char a[10] = \"abcdefghi\";\n    return scan(a, 40);\n}}\n"
    );
    let found = scan(&[("a.c", &long)]);
    assert_eq!(
        lines(&found, "buffer-overread", "a.c"),
        vec![8],
        "{found:?}"
    );
}

/// `snprintf` writes no more than the text its format makes: a number
/// fits in 64 bytes even one byte into the buffer. A size larger than the
/// buffer is still reported when the text may be that long.
#[test]
fn snprintf_writes_the_text_it_makes() {
    let src = r#"#include <stdio.h>
void f(long long n, const char *name) {
    char b[64];
    char *s = b;
    if (n < 0) { *s = '-'; s++; n = -n; }
    snprintf(s, sizeof(b), "%lldB", n);
    char c[8];
    snprintf(c, 16, "%s", name);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "buffer-overflow", "a.c"),
        vec![8],
        "{found:?}"
    );
}
