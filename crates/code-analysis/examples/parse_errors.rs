//! Lists files with syntax errors and the line of the first one:
//! `parse_errors DIR [PREFIX]`.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = std::path::Path::new(args.first().expect("directory"));
    let prefix = args.get(1).map(String::as_str).unwrap_or("");
    let project = code_analysis::project::Project::from_dir(root).expect("load");
    for m in &project.modules {
        if let Some(line) = m.first_error.filter(|_| m.path.starts_with(prefix)) {
            println!("{}:{}: {}", m.path, line, m.line_text(line));
        }
    }
}
