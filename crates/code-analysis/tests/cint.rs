//! Integer overflow and underflow in C arithmetic. Each test pairs code
//! that must be reported with a safe variant that must not be.

use code_analysis::project::Project;
use code_analysis::Options;

fn scan(files: &[(&str, &str)]) -> Vec<(String, u32, String, String)> {
    let project = Project::from_sources(
        files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    );
    let options = Options {
        external_sources: true,
        ..Options::default()
    };
    code_analysis::analyze_with(&project, options)
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

fn message(found: &[(String, u32, String, String)], line: u32) -> String {
    found
        .iter()
        .find(|f| f.1 == line)
        .map(|f| f.3.clone())
        .unwrap_or_default()
}

#[test]
fn unchecked_arithmetic_on_user_numbers_is_reported() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
void sink(long long x);
void f(void) {
    char buf[20];
    int data = 0;
    if (fgets(buf, sizeof(buf), stdin) != NULL) data = atoi(buf);
    int sum = data + 1;
    sink(sum);
    int diff = data - 1;
    sink(diff);
    if (data < INT_MAX) sink(data + 1);
    if (data > INT_MIN) sink(data - 1);
    if (data > 0 && data < 1000) sink(data * 1000);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "integer-overflow", "a.c"),
        vec![9],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "integer-underflow", "a.c"),
        vec![11],
        "{found:?}"
    );
    let msg = message(&found, 9);
    assert!(msg.contains("stdin"), "{msg}");
    assert!(msg.contains("максимум int (2147483647)"), "{msg}");
}

/// `char r = c * c;` is computed in int and cut to a char when stored;
/// `abs(c) <= sqrt(CHAR_MAX)` keeps the square in range.
#[test]
fn square_stored_in_a_small_type_is_checked_against_it() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>
void sink(long long x);
void f(void) {
    char c = ' ';
    fscanf(stdin, "%c", &c);
    char sq = c * c;
    sink(sq);
    if (abs((long)c) <= (long)sqrt((double)CHAR_MAX)) {
        char ok = c * c;
        sink(ok);
    }
    long long big = 0;
    fscanf(stdin, "%lld", &big);
    if (llabs(big) <= sqrtl(LLONG_MAX)) sink(big * big);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "integer-overflow", "a.c"),
        vec![9],
        "{found:?}"
    );
    assert!(message(&found, 9).contains("при записи в sq"), "{found:?}");
}

/// A signed constant out of range is a defect; unsigned arithmetic wraps
/// by definition and hashes, counters and `while (n--)` rely on it.
#[test]
fn signed_constants_are_reported_and_unsigned_wrapping_is_not() {
    let src = r#"#include <stdio.h>
#include <string.h>
#include <limits.h>
void sink(long long x);
void f(const char *s, size_t n) {
    int m = INT_MIN;
    sink(m * 2);
    int k;
    fscanf(stdin, "%d", &k);
    if (k < 0 && k > INT_MIN / 2) sink(k * 2);
    unsigned int h = 5381;
    while (*s) { h = h * 33 + *s; s++; }
    sink(h);
    unsigned int u = UINT_MAX;
    u++;
    sink(u);
    while (n--) sink(n);
    size_t len = strlen(s);
    if (len) sink(len - 1);
    long long big = 1LL << 40;
    sink(big * 4);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "integer-overflow", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "integer-underflow", "a.c"),
        vec![7],
        "{found:?}"
    );
    assert!(message(&found, 7).contains("-4294967296"), "{found:?}");
}

/// A number computed from the user's input (a loop count, a length, a
/// division) is not the user's number: only direct arithmetic on what the
/// user gave is reported.
#[test]
fn numbers_computed_from_input_are_not_reported() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
void sink(long long x);
void f(int argc, char **argv) {
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL) return;
    int n = atoi(buf);
    int half = n / 2;
    sink(half + 1);
    int count = 0;
    for (int i = 0; i < n; i++) count = count + 1;
    sink(count);
    size_t len = strlen(buf);
    sink(len + 1);
    unsigned short port;
    memcpy(&port, buf, sizeof(port));
    int p = ntohs(port);
    sink(p + 1);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert!(
        found
            .iter()
            .all(|f| f.0 != "integer-overflow" && f.0 != "integer-underflow"),
        "{found:?}"
    );
}

/// A value a `case` handles does not reach the code after the `switch`.
#[test]
fn values_handled_by_a_switch_case_are_left_out_after_it() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
void sink(long long x);
void f(void) {
    char buf[32];
    if (fgets(buf, sizeof(buf), stdin) == NULL) return;
    unsigned long len = strtoul(buf, NULL, 10);
    switch (len) {
    case 0:
        return;
    default:
        sink(len - 1);
    }
    sink(len - 1);
    unsigned long n = strtoul(buf, NULL, 16);
    switch (n) {
    case 1:
        return;
    }
    sink(n - 1);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "integer-underflow", "a.c"),
        vec![20],
        "{found:?}"
    );
}

/// Bounds the program sets up are kept: a loop's exit test, a 32-bit
/// number widened by a cast, and `len -= MIN(chunk, len)`.
#[test]
fn bounds_from_loops_casts_and_min_are_kept() {
    let src = r#"#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
void sink(long long x);
static time_t load_time(int fd) {
    int32_t t32;
    if (read(fd, &t32, 4) != 4) return -1;
    return (time_t)t32;
}
void f(int fd, size_t chunk, char *buf) {
    char line[32];
    if (fgets(line, sizeof(line), stdin) == NULL) return;
    uint64_t value = strtoull(line, NULL, 10);
    while (value >= 100) value /= 100;
    if (value >= 10) sink((uint32_t)value * 2);
    int n = atoi(line);
    while (n > 1000) n = n - 1000;
    sink(n * 1000);
    long long when = load_time(fd);
    when *= 1000;
    sink(when);
    uint32_t len;
    if (read(fd, &len, 4) != 4) return;
    while (len) {
        size_t step = (chunk && chunk < len) ? chunk : len;
        if (read(fd, buf, step) <= 0) return;
        len -= step;
    }
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "integer-overflow", "a.c"),
        Vec::<u32>::new(),
        "{found:?}"
    );
    // `n` may still be any negative number.
    assert_eq!(
        lines(&found, "integer-underflow", "a.c"),
        vec![20],
        "{found:?}"
    );
}

/// A struct read from a file or socket as it came holds numbers the user
/// gave; a struct the program filled in does not.
#[test]
fn fields_of_a_struct_read_from_input_are_user_numbers() {
    let src = r#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct image { char header[4]; int width; int height; };
struct buf { size_t len; size_t cap; };
void sink(long long x);
void load(const char *name, int fd, struct buf *b) {
    struct image img;
    FILE *fp = fopen(name, "r");
    if (fp == NULL) return;
    if (fread(&img, sizeof(img), 1, fp) != 1) return;
    int size = img.width * img.height;
    sink(size);
    struct image *p = malloc(sizeof(struct image));
    if (p == NULL || read(fd, p, sizeof(*p)) <= 0) return;
    sink(p->width - p->height);
    sink(b->len + 1);
}
"#;
    let found = scan(&[("a.c", src)]);
    assert_eq!(
        lines(&found, "integer-overflow", "a.c"),
        vec![12],
        "{found:?}"
    );
    assert_eq!(
        lines(&found, "integer-underflow", "a.c"),
        vec![16],
        "{found:?}"
    );
    assert!(
        message(&found, 12).contains("img.width * img.height"),
        "{found:?}"
    );
}
