//! Public Suffix List lookups (same algorithm as icp/psl.py; the list is compiled in).

use std::collections::HashSet;
use std::sync::OnceLock;

struct Rules { plain: HashSet<&'static str>, wild: HashSet<&'static str>, exc: HashSet<&'static str> }

static LIST: &str = include_str!("../../../icp/data/public_suffix_list.dat");

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| {
        let mut r = Rules { plain: HashSet::new(), wild: HashSet::new(), exc: HashSet::new() };
        for line in LIST.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") { continue; }
            if let Some(x) = line.strip_prefix('!') { r.exc.insert(x); }
            else if let Some(x) = line.strip_prefix("*.") { r.wild.insert(x); }
            else { r.plain.insert(line); }
        }
        r
    })
}

pub fn is_ip(host: &str) -> bool {
    if host.contains(':') { return true; }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

fn suffix_len(host: &str) -> usize {
    let r = rules();
    let host = host.to_lowercase();
    let labels: Vec<&str> = host.trim_matches('.').split('.').collect();
    let mut best = 1;
    for i in 0..labels.len() {
        let cand = labels[i..].join(".");
        let n = labels.len() - i;
        if r.exc.contains(cand.as_str()) { return n - 1; }
        if r.plain.contains(cand.as_str()) { best = best.max(n); }
        if i + 1 < labels.len() && r.wild.contains(labels[i + 1..].join(".").as_str()) { best = best.max(n); }
    }
    best
}

pub fn is_public_suffix(host: &str) -> bool {
    let h = host.to_lowercase();
    let h = h.trim_matches('.');
    !h.is_empty() && !is_ip(h) && suffix_len(h) >= h.split('.').count()
}

pub fn registrable_domain(host: &str) -> String {
    let h = host.to_lowercase();
    let h = h.trim_matches('.').to_string();
    if h.is_empty() || is_ip(&h) { return h; }
    let labels: Vec<&str> = h.split('.').collect();
    let n = suffix_len(&h);
    if n >= labels.len() { h.clone() } else { labels[labels.len() - (n + 1)..].join(".") }
}
