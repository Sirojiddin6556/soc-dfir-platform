//! Learning a site's endpoints from an OpenAPI / Swagger description.
//!
//! Many API frameworks publish a machine-readable description of every
//! endpoint — its path, method, query parameters and JSON request body. When
//! one is exposed (FastAPI serves `/openapi.json` by default), reading it tells
//! the scan exactly what to probe, including JSON bodies that no crawl could
//! ever discover. This module fetches the description from the usual
//! locations, parses it (JSON only), and turns each operation into an
//! [`InjectionPoint`].

use crate::http::Client;
use crate::{InjectionPoint, Method};
use serde_json::Value;
use url::Url;

/// Where API frameworks commonly expose the description.
const SPEC_PATHS: &[&str] = &[
    "openapi.json",
    "swagger.json",
    "api/openapi.json",
    "api/swagger.json",
    "swagger/v1/swagger.json",
    "v2/api-docs",
    "v3/api-docs",
    "api-docs",
    "openapi/openapi.json",
];

/// Caps the number of endpoints turned into checks, so a huge API stays bounded.
const MAX_POINTS: usize = 500;

/// Fetches and parses a description if the site exposes one, returning the
/// injection points it describes. On no description, returns nothing.
pub fn discover(client: &Client, base: &Url, notes: &mut Vec<String>) -> Vec<InjectionPoint> {
    let mut root = base.clone();
    root.set_path("/");
    root.set_query(None);
    root.set_fragment(None);

    for candidate in SPEC_PATHS {
        let Ok(url) = root.join(candidate) else {
            continue;
        };
        let Ok(resp) = client.get(&url) else { continue };
        if resp.status != 200 {
            continue;
        }
        let Ok(spec) = serde_json::from_str::<Value>(&resp.body) else {
            continue;
        };
        if !spec.get("paths").map(Value::is_object).unwrap_or(false) {
            continue;
        }
        let points = parse(&spec, &root);
        if !points.is_empty() {
            notes.push(format!(
                "OpenAPI найден ({}): эндпоинтов — {}",
                candidate,
                points.len()
            ));
        }
        return points;
    }
    Vec::new()
}

/// The path prefix that endpoints hang off, from OpenAPI 3 `servers` or
/// Swagger 2 `basePath`.
fn base_prefix(spec: &Value) -> String {
    if let Some(server) = spec
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|s| s.get("url"))
        .and_then(Value::as_str)
    {
        // A server URL may be absolute; keep only its path.
        if let Ok(u) = Url::parse(server) {
            return u.path().trim_end_matches('/').to_string();
        }
        return server.trim_end_matches('/').to_string();
    }
    if let Some(bp) = spec.get("basePath").and_then(Value::as_str) {
        return bp.trim_end_matches('/').to_string();
    }
    String::new()
}

fn parse(spec: &Value, root: &Url) -> Vec<InjectionPoint> {
    let prefix = base_prefix(spec);
    let components = spec.get("components").and_then(|c| c.get("schemas"));
    let definitions = spec.get("definitions"); // Swagger 2
    let mut points = Vec::new();

    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return points;
    };

    for (raw_path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        // Parameters declared once for every method on the path.
        let shared = item.get("parameters").and_then(Value::as_array);

        for (method_key, op) in item {
            let verb = match method_key.to_lowercase().as_str() {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "patch" => "PATCH",
                "delete" => "DELETE",
                _ => continue,
            };
            let Some(op) = op.as_object() else { continue };

            // Merge path-level and operation-level parameters.
            let mut query: Vec<(String, String)> = Vec::new();
            let mut path_values: Vec<(String, String)> = Vec::new();
            for list in [shared, op.get("parameters").and_then(Value::as_array)]
                .into_iter()
                .flatten()
            {
                for p in list {
                    let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                    if name.is_empty() {
                        continue;
                    }
                    let loc = p.get("in").and_then(Value::as_str).unwrap_or("");
                    let schema = p.get("schema").unwrap_or(p);
                    let value = sample(schema, components, definitions);
                    match loc {
                        "query" => query.push((name.to_string(), value)),
                        "path" => path_values.push((name.to_string(), value)),
                        _ => {}
                    }
                }
            }

            // Fill path placeholders like `/users/{id}`.
            let filled = fill_path(raw_path, &path_values);
            let full = format!("{prefix}{filled}");
            let Ok(url) = root.join(full.trim_start_matches('/')) else {
                continue;
            };

            // JSON request body properties (OpenAPI 3 requestBody or Swagger 2
            // body parameter) become the fields of a JSON injection point.
            let body_fields = request_body_fields(op, shared, components, definitions);

            if matches!(verb, "POST" | "PUT" | "PATCH") && !body_fields.is_empty() {
                points.push(InjectionPoint {
                    url: url.clone(),
                    method: Method::Json(verb.to_string()),
                    params: body_fields,
                    source: format!("OpenAPI {verb} {raw_path}"),
                });
            } else if matches!(verb, "GET" | "DELETE") && !query.is_empty() {
                points.push(InjectionPoint {
                    url,
                    method: Method::Get,
                    params: query,
                    source: format!("OpenAPI {verb} {raw_path}"),
                });
            }

            if points.len() >= MAX_POINTS {
                return points;
            }
        }
    }
    points
}

/// Replaces `{name}` placeholders in a path with sample values.
fn fill_path(path: &str, values: &[(String, String)]) -> String {
    let mut out = path.to_string();
    for (name, value) in values {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    // Any placeholder without a declared parameter gets a benign value.
    while let Some(start) = out.find('{') {
        if let Some(end) = out[start..].find('}') {
            out.replace_range(start..start + end + 1, "1");
        } else {
            break;
        }
    }
    out
}

/// The JSON body field names for an operation, resolving a `$ref` to a schema.
fn request_body_fields(
    op: &serde_json::Map<String, Value>,
    shared: Option<&Vec<Value>>,
    components: Option<&Value>,
    definitions: Option<&Value>,
) -> Vec<(String, String)> {
    // OpenAPI 3: requestBody.content["application/json"].schema
    if let Some(schema) = op
        .get("requestBody")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
    {
        return object_fields(schema, components, definitions);
    }
    // Swagger 2: a parameter with `in: body` carries a schema.
    for list in [op.get("parameters").and_then(Value::as_array), shared]
        .into_iter()
        .flatten()
    {
        for p in list {
            if p.get("in").and_then(Value::as_str) == Some("body") {
                if let Some(schema) = p.get("schema") {
                    return object_fields(schema, components, definitions);
                }
            }
        }
    }
    Vec::new()
}

/// The sampled (name, value) pairs for an object schema's properties.
fn object_fields(
    schema: &Value,
    components: Option<&Value>,
    definitions: Option<&Value>,
) -> Vec<(String, String)> {
    let resolved = resolve_ref(schema, components, definitions);
    let Some(props) = resolved.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    props
        .iter()
        .map(|(name, prop)| {
            let value = sample(prop, components, definitions);
            (name.clone(), value)
        })
        .collect()
}

/// Follows a `$ref` like `#/components/schemas/User` to the schema it names.
fn resolve_ref<'a>(
    schema: &'a Value,
    components: Option<&'a Value>,
    definitions: Option<&'a Value>,
) -> &'a Value {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().unwrap_or("");
        if let Some(found) = components.and_then(|c| c.get(name)) {
            return found;
        }
        if let Some(found) = definitions.and_then(|d| d.get(name)) {
            return found;
        }
    }
    schema
}

/// A benign sample value for a parameter or property schema, by its type.
fn sample(schema: &Value, components: Option<&Value>, definitions: Option<&Value>) -> String {
    let schema = resolve_ref(schema, components, definitions);
    // An explicit example or the first enum value is the safest sample.
    if let Some(example) = schema.get("example") {
        if let Some(s) = scalar_to_string(example) {
            return s;
        }
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        if let Some(s) = scalar_to_string(first) {
            return s;
        }
    }
    let ty = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string");
    let format = schema.get("format").and_then(Value::as_str).unwrap_or("");
    match ty {
        "integer" => "1".into(),
        "number" => "1".into(),
        "boolean" => "true".into(),
        "array" => "test".into(),
        _ => match format {
            "email" => "test@example.com".into(),
            "uuid" => "00000000-0000-0000-0000-000000000000".into(),
            "date" => "2020-01-01".into(),
            "date-time" => "2020-01-01T00:00:00Z".into(),
            _ => "test".into(),
        },
    }
}

fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openapi3_paths_into_points() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "servers": [{"url": "/api"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "schema": {"type": "integer"}},
                            {"name": "q", "in": "query", "schema": {"type": "string"}}
                        ]
                    }
                },
                "/login": {
                    "post": {
                        "requestBody": {
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}
                        }
                    }
                }
            },
            "components": {"schemas": {"Login": {
                "type": "object",
                "properties": {"email": {"type": "string"}, "password": {"type": "string"}}
            }}}
        });
        let root = Url::parse("http://h:3000/").unwrap();
        let points = parse(&spec, &root);

        // GET /api/users/1?q=... as a query point.
        let get = points
            .iter()
            .find(|p| p.method == Method::Get)
            .expect("a query point");
        assert_eq!(get.url.as_str(), "http://h:3000/api/users/1");
        assert_eq!(get.params, vec![("q".to_string(), "test".to_string())]);

        // POST /api/login with a JSON body of email + password.
        let post = points
            .iter()
            .find(|p| matches!(p.method, Method::Json(_)))
            .expect("a json point");
        assert_eq!(post.url.as_str(), "http://h:3000/api/login");
        let names: Vec<&str> = post.params.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"email") && names.contains(&"password"));
    }

    #[test]
    fn fills_unnamed_path_placeholders() {
        assert_eq!(
            fill_path("/a/{id}/b/{x}", &[("id".into(), "7".into())]),
            "/a/7/b/1"
        );
    }
}
