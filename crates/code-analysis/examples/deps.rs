//! Lists the third-party packages a project names:
//! `cargo run --example deps -- <dir>` prints one TSV line per entry.

fn main() {
    let dir = std::env::args().nth(1).expect("usage: deps <dir>");
    for d in code_analysis::deps::collect(std::path::Path::new(&dir)) {
        println!(
            "{}\t{}\t{}\t{}\t{}:{}\t{:?}",
            d.ecosystem,
            d.name,
            d.version.as_deref().unwrap_or("-"),
            d.requirement,
            d.file,
            d.line,
            d.kind
        );
    }
}
