//! Prints the tree-sitter syntax tree of a file: `dump_tree <lang> <file>`.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let lang: tree_sitter::Language = match args[1].as_str() {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        other => panic!("unknown language {other}"),
    };
    let src = std::fs::read_to_string(&args[2]).unwrap();
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang).unwrap();
    let tree = parser.parse(&src, None).unwrap();
    print(tree.root_node(), &src, 0, None);
}

fn print(node: tree_sitter::Node, src: &str, depth: usize, field: Option<&str>) {
    let text = if node.child_count() == 0 {
        format!(" {:?}", &src[node.byte_range()])
    } else {
        String::new()
    };
    println!(
        "{}{}{}{}",
        "  ".repeat(depth),
        field.map(|f| format!("{f}: ")).unwrap_or_default(),
        node.kind(),
        text
    );
    let mut cursor = node.walk();
    for (i, child) in node.children(&mut cursor).enumerate() {
        let f = node.field_name_for_child(i as u32);
        print(child, src, depth + 1, f);
    }
}
