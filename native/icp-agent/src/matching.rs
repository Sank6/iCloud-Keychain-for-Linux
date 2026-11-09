//! Credential matching: a line-for-line port of the rules in icp/vault/host.py, icp/related.py and
//! icp/choices.py, so the Rust agent offers exactly the same logins as the Python one.

use std::collections::HashSet;
use std::fs;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{config_file, psl, totp};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Default, Clone)]
pub struct Credential {
    #[serde(default)] pub domain: String,
    #[serde(default)] pub username: String,
    #[serde(default)] pub password: String,
    #[serde(default)] pub title: String,
    #[serde(default)] pub mdat: f64,
    #[serde(default)] pub notes: String,
    #[serde(default)] pub last_used: f64,
    #[serde(default)] pub totp: String,
}

impl Credential {
    pub fn recency(&self) -> f64 { if self.last_used != 0.0 { self.last_used } else { self.mdat } }

    /// The extension's view: the otpauth URI is replaced by a code generated now.
    pub fn wire(&self) -> Value {
        let t = totp::generate(&self.totp, None);
        let mut m = Map::new();
        m.insert("domain".into(), json!(self.domain));
        m.insert("username".into(), json!(self.username));
        m.insert("password".into(), json!(self.password));
        m.insert("title".into(), json!(self.title));
        m.insert("mdat".into(), json!(self.mdat));
        m.insert("notes".into(), json!(self.notes));
        m.insert("last_used".into(), json!(self.last_used));
        m.insert("totp".into(), t);
        Value::Object(m)
    }
}

pub fn normalize_host(value: &str) -> String {
    let mut v = value.trim().to_lowercase();
    if let Some((_, rest)) = v.split_once("://") { v = rest.to_string(); }
    v = v.split('/').next().unwrap_or("").split('?').next().unwrap_or("").to_string();
    v = v.rsplit('@').next().unwrap_or("").to_string();
    v = v.split(':').next().unwrap_or("").to_string();
    if let Some(r) = v.strip_prefix("www.") { v = r.to_string(); }
    v
}

pub fn domains_match(page: &str, stored: &str) -> bool {
    let (p, s) = (normalize_host(page), normalize_host(stored));
    if p.is_empty() || s.is_empty() { return false; }
    if p == s { return true; }
    if psl::is_ip(&p) || psl::is_ip(&s) { return false; }
    let shorter = if p.ends_with(&format!(".{s}")) { Some(&s) }
                  else if s.ends_with(&format!(".{p}")) { Some(&p) } else { None };
    shorter.map_or(false, |sh| !psl::is_public_suffix(sh))
}

fn is_credential(domain: &str, title: &str) -> bool {
    for tag in [domain, title] {
        let t = tag.trim().to_lowercase();
        if t.starts_with("pcs ") || t.starts_with("pcs-") || t.starts_with("website metadata")
            || t.contains("com.apple.") { return false; }
    }
    true
}

const GENERIC: [&str; 9] = ["account", "accounts", "admin", "app", "dashboard", "login", "password",
                            "passwords", "signin"];

fn name_matches_host(page: &str, name: &str) -> bool {
    let host = normalize_host(page);
    let labels: HashSet<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() { return false; }
    let lower = name.to_lowercase();
    let generic: HashSet<&str> = GENERIC.iter().copied().chain(["sign", "web", "www"]).collect();
    // regex [a-z0-9]+ tokens
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() { cur.push(ch); }
        else if !cur.is_empty() { tokens.push(std::mem::take(&mut cur)); }
    }
    if !cur.is_empty() { tokens.push(cur); }
    tokens.iter().any(|t| t.len() >= 4 && !generic.contains(t.as_str()) && labels.contains(t.as_str()))
}

const GROUPS: &[&[&str]] = &[
    &["google.com", "youtube.com", "gmail.com", "googleusercontent.com", "blogger.com"],
    &["microsoft.com", "live.com", "office.com", "microsoftonline.com", "xbox.com", "bing.com",
      "outlook.com", "skype.com", "msn.com", "azure.com", "windows.com", "visualstudio.com"],
    &["apple.com", "icloud.com"],
    &["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.co.jp",
      "amazon.it", "amazon.es", "amazon.in", "amazon.com.au", "audible.com", "twitch.tv"],
    &["facebook.com", "messenger.com", "fb.com"],
    &["twitter.com", "x.com"],
    &["github.com", "githubusercontent.com"],
    &["adobe.com", "behance.net"],
    &["paypal.com", "paypal.me"],
    &["ebay.com", "ebay.co.uk", "ebay.de"],
    &["yahoo.com", "aol.com"],
    &["steampowered.com", "steamcommunity.com"],
    &["dropbox.com", "dropboxapi.com"],
    &["atlassian.com", "atlassian.net", "bitbucket.org"],
];

fn group_of(domain: &str) -> Option<usize> { GROUPS.iter().position(|g| g.contains(&domain)) }

fn related(a: &str, b: &str) -> bool {
    let (ra, rb) = (psl::registrable_domain(a), psl::registrable_domain(b));
    ra != rb && group_of(&ra).is_some() && group_of(&ra) == group_of(&rb)
}

fn tag(username: &str) -> String {
    let d = Sha256::digest(username.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect::<String>()[..12].to_string()
}

fn choices() -> Map<String, Value> {
    fs::read_to_string(config_file("choices.json")).ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

pub fn record_choice(host: &str, username: &str) {
    let mut c = choices();
    c.insert(psl::registrable_domain(host), json!(tag(username)));
    let f = config_file("choices.json");
    let tmp = f.with_extension("tmp");
    if fs::write(&tmp, serde_json::to_vec(&c).unwrap_or_default()).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        let _ = fs::rename(&tmp, &f);
    }
}

pub fn match_creds<'a>(creds: &'a [Credential], page: &str) -> Vec<&'a Credential> {
    let mut ranked: Vec<(u8, &Credential)> = Vec::new();
    for c in creds {
        if !is_credential(&c.domain, &c.title) { continue; }
        let rank = if domains_match(page, &c.domain) {
            Some(if normalize_host(page) == normalize_host(&c.domain) { 0 } else { 1 })
        } else {
            let stored = normalize_host(&c.domain);
            if related(page, &stored) { Some(2) }
            else if !stored.contains('.') && name_matches_host(page, if c.title.is_empty() { &c.domain } else { &c.title }) { Some(3) }
            else { None }
        };
        if let Some(r) = rank { ranked.push((r, c)); }
    }
    ranked.sort_by(|a, b| a.0.cmp(&b.0)
        .then(b.1.recency().partial_cmp(&a.1.recency()).unwrap_or(std::cmp::Ordering::Equal))
        .then(a.1.title.cmp(&b.1.title)).then(a.1.username.cmp(&b.1.username)));
    let mut out: Vec<&Credential> = ranked.into_iter().map(|(_, c)| c).collect();
    if let Some(t) = choices().get(&psl::registrable_domain(page)).and_then(Value::as_str) {
        out.sort_by_key(|c| if tag(&c.username) == t { 0 } else { 1 }); // stable
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cred(domain: &str, user: &str) -> Credential {
        let mut c = Credential::default();
        c.domain = domain.into();
        c.username = user.into();
        c.password = "pw".into();
        c
    }
    #[test]
    fn suffix_and_ip_rules() {
        assert!(domains_match("login.example.co.uk", "example.co.uk"));
        assert!(!domains_match("a.github.io", "github.io"));
        assert!(!domains_match("evil.co.uk", "co.uk"));
        assert!(!domains_match("10.0.0.1", "0.0.1"));
        assert!(!domains_match("notexample.com", "example.com"));
    }
    #[test]
    fn related_ranks_below_exact() {
        let v = vec![cred("google.com", "a"), cred("youtube.com", "b")];
        let m = match_creds(&v, "youtube.com");
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].username, "b");
    }
    #[test]
    fn non_logins_are_dropped() {
        assert!(!is_credential("PCS com.apple.foo", ""));
        assert!(is_credential("example.com", "Example"));
    }
}
