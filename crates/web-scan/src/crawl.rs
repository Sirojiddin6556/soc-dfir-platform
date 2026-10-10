//! Walking the site to collect the places a check can probe.
//!
//! A breadth-first crawl stays on the target's origin, follows `<a>` links and
//! reads `<form>`s. From what it sees it builds [`InjectionPoint`]s: the query
//! parameters of any URL it followed, and the fuzzable fields of every form.
//! Pages and requests are both capped so a large or looping site is bounded.

use crate::html;
use crate::http::Client;
use crate::{InjectionPoint, Method, Options};
use std::collections::{BTreeSet, HashSet, VecDeque};
use url::Url;

pub struct Crawl {
    pub pages: usize,
    pub forms: usize,
    pub points: Vec<InjectionPoint>,
}

/// A benign value for a form field with no default, so the request is well
/// formed before a check overwrites one field with a payload.
fn baseline(kind: &str) -> &'static str {
    match kind {
        "email" => "test@example.com",
        "number" | "range" => "1",
        "url" => "http://example.com",
        "tel" => "1000000",
        _ => "test",
    }
}

/// A key that collapses URLs pointing at the same page with the same set of
/// query keys, so `?id=1` and `?id=2` are crawled once.
fn page_key(url: &Url) -> String {
    let mut keys: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    keys.sort_unstable();
    keys.dedup();
    format!(
        "{}://{}{}?{}",
        url.scheme(),
        url.authority(),
        url.path(),
        keys.join("&")
    )
}

/// A key that identifies an injection point by where it sends and which
/// parameters it carries, so duplicates across pages are dropped.
fn point_key(method: &Method, url: &Url, params: &[(String, String)]) -> String {
    let names: BTreeSet<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
    let names: Vec<&str> = names.into_iter().collect();
    format!(
        "{} {}://{}{} [{}]",
        method.as_str(),
        url.scheme(),
        url.authority(),
        url.path(),
        names.join(",")
    )
}

/// Walks the site starting from `base` and any `seeds` from content discovery.
pub fn crawl(
    client: &Client,
    base: &Url,
    seeds: &[Url],
    options: &Options,
    notes: &mut Vec<String>,
) -> Crawl {
    let mut queue: VecDeque<Url> = VecDeque::new();
    let mut seen_pages: HashSet<String> = HashSet::new();
    let mut point_keys: HashSet<String> = HashSet::new();
    let mut points: Vec<InjectionPoint> = Vec::new();
    let mut pages = 0usize;
    let mut forms_found = 0usize;

    queue.push_back(base.clone());
    seen_pages.insert(page_key(base));
    for seed in seeds {
        if client.same_origin(seed) && seen_pages.insert(page_key(seed)) {
            queue.push_back(seed.clone());
        }
    }

    while let Some(url) = queue.pop_front() {
        if pages >= options.max_pages || client.remaining() == 0 {
            break;
        }
        let resp = match client.get(&url) {
            Ok(r) => r,
            Err(e) => {
                notes.push(format!("{url}: {e}"));
                continue;
            }
        };
        pages += 1;

        // Only parse HTML for links and forms.
        let is_html = resp
            .header("content-type")
            .map(|c| c.to_lowercase().contains("html"))
            .unwrap_or(true);
        if !is_html {
            continue;
        }

        // A followed URL that carries a query is itself a GET point.
        add_get_point(&url, &url, &mut points, &mut point_keys);

        for href in html::links(&resp.body) {
            let Ok(next) = url.join(&href) else { continue };
            if !client.same_origin(&next) {
                continue;
            }
            let mut next = next;
            next.set_fragment(None);
            add_get_point(&url, &next, &mut points, &mut point_keys);
            let key = page_key(&next);
            if seen_pages.insert(key) {
                queue.push_back(next);
            }
        }

        for form in html::forms(&resp.body) {
            let action = if form.action.trim().is_empty() {
                url.clone()
            } else {
                match url.join(&form.action) {
                    Ok(u) => u,
                    Err(_) => continue,
                }
            };
            if !client.same_origin(&action) {
                continue;
            }
            forms_found += 1;
            let method = if form.method == "POST" {
                Method::Post
            } else {
                Method::Get
            };
            let params: Vec<(String, String)> = form
                .fields
                .iter()
                .filter(|f| f.is_fuzzable())
                .map(|f| {
                    let v = if f.value.is_empty() {
                        baseline(&f.kind).to_string()
                    } else {
                        f.value.clone()
                    };
                    (f.name.clone(), v)
                })
                .collect();
            if params.is_empty() {
                continue;
            }
            let mut target = action.clone();
            if method == Method::Get {
                target.set_query(None);
            }
            let key = point_key(&method, &target, &params);
            if point_keys.insert(key) {
                points.push(InjectionPoint {
                    url: target,
                    method,
                    params,
                    source: url.to_string(),
                });
            }
        }
    }

    Crawl {
        pages,
        forms: forms_found,
        points,
    }
}

/// Adds a GET injection point for `url`'s query parameters, if it has any and
/// unless `submit_forms`-style POST already covered it.
fn add_get_point(
    source: &Url,
    url: &Url,
    points: &mut Vec<InjectionPoint>,
    point_keys: &mut HashSet<String>,
) {
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if params.is_empty() {
        return;
    }
    let mut bare = url.clone();
    bare.set_query(None);
    bare.set_fragment(None);
    let key = point_key(&Method::Get, &bare, &params);
    if point_keys.insert(key) {
        points.push(InjectionPoint {
            url: bare,
            method: Method::Get,
            params,
            source: source.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_key_collapses_differing_query_values() {
        let a = Url::parse("http://h/p?id=1&q=x").unwrap();
        let b = Url::parse("http://h/p?id=2&q=y").unwrap();
        assert_eq!(page_key(&a), page_key(&b));
        let c = Url::parse("http://h/p?id=1").unwrap();
        assert_ne!(page_key(&a), page_key(&c));
    }

    #[test]
    fn point_key_ignores_values_and_order() {
        let url = Url::parse("http://h/s").unwrap();
        let a = point_key(
            &Method::Get,
            &url,
            &[("b".into(), "1".into()), ("a".into(), "2".into())],
        );
        let b = point_key(
            &Method::Get,
            &url,
            &[("a".into(), "9".into()), ("b".into(), "8".into())],
        );
        assert_eq!(a, b);
    }
}
