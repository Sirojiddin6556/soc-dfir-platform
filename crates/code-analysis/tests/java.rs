//! Behaviour of the Java analysis on small programs: each test pairs code
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

const SERVLET: &str = "package app;
import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
";

#[test]
fn concatenated_query_is_injection_and_bound_parameters_are_not() {
    let src = format!(
        "{SERVLET}
public class Users extends HttpServlet {{
  private Connection conn;
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String name = request.getParameter(\"name\");
    conn.createStatement().executeQuery(\"SELECT * FROM users WHERE name = '\" + name + \"'\");
    PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");
    ps.setString(1, name);
    ps.executeQuery();
  }}
}}
"
    );
    let found = scan(&[("app/Users.java", &src)]);
    assert_eq!(
        lines(&found, "sql-injection", "app/Users.java"),
        vec![10],
        "{found:?}"
    );
}

#[test]
fn spring_handler_parameters_are_user_data() {
    let src = "package app;
import org.springframework.web.bind.annotation.*;

@RestController
public class Ping {
  @GetMapping(\"/ping\")
  public String ping(@RequestParam String host) throws Exception {
    Runtime.getRuntime().exec(\"ping -c 1 \" + host);
    Runtime.getRuntime().exec(new String[] {\"ping\", \"-c\", \"1\", \"example.org\"});
    return \"ok\";
  }
}
";
    let found = scan(&[("app/Ping.java", src)]);
    assert_eq!(
        lines(&found, "command-injection", "app/Ping.java"),
        vec![8],
        "{found:?}"
    );
}

#[test]
fn injected_service_is_followed_through_its_interface() {
    let controller = "package app;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
  private final UserService users;

  public UserController(UserService users) {
    this.users = users;
  }

  @GetMapping(\"/user\")
  public String find(@RequestParam String name) {
    return users.find(name);
  }
}
";
    let service = "package app;
public interface UserService {
  String find(String name);
}
";
    let impl_ = "package app;
import org.springframework.jdbc.core.JdbcTemplate;

public class UserServiceImpl implements UserService {
  private JdbcTemplate jdbc;

  public String find(String name) {
    return jdbc.queryForObject(\"SELECT email FROM users WHERE name = '\" + name + \"'\", String.class);
  }
}
";
    let found = scan(&[
        ("app/UserController.java", controller),
        ("app/UserService.java", service),
        ("app/UserServiceImpl.java", impl_),
    ]);
    assert_eq!(
        lines(&found, "sql-injection", "app/UserServiceImpl.java"),
        vec![8],
        "{found:?}"
    );
}

#[test]
fn file_built_from_input_is_reported_unless_the_normalized_path_is_checked() {
    let src = format!(
        "{SERVLET}
public class Files extends HttpServlet {{
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String name = request.getParameter(\"f\");
    File plain = new File(\"/srv/files\", name);
    plain.delete();
    File checked = new File(\"/srv/files\", name);
    if (!checked.getCanonicalPath().startsWith(\"/srv/files/\")) {{
      return;
    }}
    checked.delete();
    File onlyNamed = new File(name);
    response.setHeader(\"X-Name\", onlyNamed.getName());
    java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(\"/srv\", name));
  }}
}}
"
    );
    let found = scan(&[("app/Files.java", &src)]);
    assert_eq!(
        lines(&found, "path-traversal", "app/Files.java"),
        vec![9, 18],
        "{found:?}"
    );
}

#[test]
fn xml_parser_needs_hardening_before_it_reads_input() {
    let src = format!(
        "{SERVLET}
import javax.xml.parsers.*;
public class Xml extends HttpServlet {{
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    DocumentBuilderFactory open = DocumentBuilderFactory.newInstance();
    open.newDocumentBuilder().parse(request.getInputStream());
    DocumentBuilderFactory hard = DocumentBuilderFactory.newInstance();
    hard.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);
    hard.newDocumentBuilder().parse(request.getInputStream());
  }}
}}
"
    );
    let found = scan(&[("app/Xml.java", &src)]);
    assert_eq!(lines(&found, "xxe", "app/Xml.java"), vec![10], "{found:?}");
}

#[test]
fn reflected_output_depends_on_content_type_and_encoding() {
    let src = format!(
        "{SERVLET}
public class Echo extends HttpServlet {{
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String q = request.getParameter(\"q\");
    response.getWriter().print(q);
    response.getWriter().print(org.owasp.esapi.ESAPI.encoder().encodeForHTML(q));
  }}
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    PrintWriter out = response.getWriter();
    response.setContentType(\"text/plain\");
    out.print(request.getParameter(\"q\"));
  }}
}}
"
    );
    let found = scan(&[("app/Echo.java", &src)]);
    assert_eq!(lines(&found, "xss", "app/Echo.java"), vec![9], "{found:?}");
}

#[test]
fn weak_random_matters_only_for_secrets() {
    let src = format!(
        "{SERVLET}
import java.util.Random;
public class Tokens extends HttpServlet {{
  private final Random random;
  public Tokens() {{
    this.random = new Random();
  }}
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String sessionToken = Integer.toHexString(random.nextInt());
    int delay = new Random().nextInt(100);
    Thread.sleep(delay);
    Cookie c = new Cookie(\"token\", sessionToken);
    c.setSecure(true);
    response.addCookie(c);
  }}
}}
"
    );
    let found = scan(&[("app/Tokens.java", &src)]);
    assert_eq!(
        lines(&found, "weak-random", "app/Tokens.java"),
        vec![13],
        "{found:?}"
    );
}

#[test]
fn reflected_origin_is_a_cors_flaw_and_other_headers_are_not_split() {
    let src = format!(
        "{SERVLET}
public class Cors extends HttpServlet {{
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    String origin = request.getHeader(\"Origin\");
    response.setHeader(\"Access-Control-Allow-Origin\", origin);
    response.setHeader(\"X-Request-Id\", request.getHeader(\"X-Request-Id\"));
    if (origin.equals(\"https://app.example.org\")) {{
      response.addHeader(\"Access-Control-Allow-Origin\", origin);
    }}
  }}
}}
"
    );
    let found = scan(&[("app/Cors.java", &src)]);
    assert_eq!(
        lines(&found, "cors-any-origin", "app/Cors.java"),
        vec![9],
        "{found:?}"
    );
    assert!(
        !found.iter().any(|f| f.0 == "header-injection"),
        "{found:?}"
    );
}

#[test]
fn test_code_is_skipped_unless_asked_for() {
    let src = format!(
        "{SERVLET}
public class EchoServletTest extends HttpServlet {{
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    response.getWriter().print(request.getParameter(\"q\"));
  }}
}}
"
    );
    let path = "src/test/java/app/EchoServletTest.java";
    assert!(scan(&[(path, &src)]).is_empty());
    let found = scan_with(
        &[(path, &src)],
        Options {
            include_tests: true,
            ..Options::default()
        },
    );
    assert_eq!(lines(&found, "xss", path), vec![8], "{found:?}");
}
