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
    #[serde(default)] pub group: String,   // empty for the user's own keychain
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
        m.insert("group".into(), json!(self.group));
        m.insert("totp".into(), t);
        Value::Object(m)
    }
}

/// Reduce a URL or host to a bare lowercase hostname, or "" when it cannot be trusted. This decides
/// whose passwords a page is offered, so it reads a URL exactly as a browser does: `\` is `/`, and
/// `/`, `?` and `#` all end the authority (`evil.com\@a.com` and `evil.com#@a.com` are
/// `evil.com`, never `a.com`). A trailing dot, a port, userinfo and a leading `www.` are dropped.
/// Anything but ASCII letters, digits, `.`, `-`, `_` (or a bracketed IPv6 literal) is refused, so a
/// look-alike name can never match (browsers send punycode, `xn--...`, for international names).
/// Mirrors `_normalize_host` in icp/vault/host.py.
pub fn normalize_host(value: &str) -> String {
    let lowered = value.trim().to_lowercase().replace('\\', "/");
    let rest = match lowered.split_once("://") {
        Some((_, r)) => r,
        None => lowered.strip_prefix("//").unwrap_or(&lowered),
    };
    let authority = rest.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let mut host = if hostport.starts_with('[') {
        match hostport.find(']') { Some(i) => hostport[..=i].to_string(), None => return String::new() }
    } else {
        hostport.split(':').next().unwrap_or("").trim_end_matches('.').to_string()
    };
    if let Some(r) = host.strip_prefix("www.") { host = r.to_string(); }
    let ok = if host.starts_with('[') {
        host.len() > 2 && host[1..host.len() - 1].bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !host.is_empty() && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'))
    };
    if ok { host } else { String::new() }
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

/// Wi-Fi network passwords sync as generic items whose service is "AirPort" and whose account and
/// label are the network's name: never the login of a website. Mirrors `is_wifi_password`.
fn is_wifi_password(domain: &str) -> bool { domain.trim().eq_ignore_ascii_case("airport") }

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

/// Fallback for entries that only have a saved label. Only the site's own name may match: the label
/// just left of the public suffix (`amazon` in `www.amazon.co.uk`). A label anywhere else in the host
/// is attacker-chosen (`amazon.evil.com`), so it never counts. Mirrors `_name_matches_host`.
fn name_matches_host(page: &str, name: &str) -> bool {
    let host = normalize_host(page);
    if host.is_empty() || psl::is_ip(&host) || psl::is_public_suffix(&host) || !host.contains('.') {
        return false;
    }
    let registrable = psl::registrable_domain(&host);
    let site = registrable.split('.').next().unwrap_or("");
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
    tokens.iter().any(|t| t.len() >= 4 && !generic.contains(t.as_str()) && t == site)
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

/// True for entries identified only by a name: no domain at all, or a bare one-word domain. An
/// unusable domain (non-ASCII, junk) is NOT label-only, or a name inside it would match any site.
fn label_only(raw_domain: &str, stored: &str) -> bool {
    raw_domain.trim().is_empty() || (!stored.is_empty() && !stored.contains('.'))
}

pub fn match_creds<'a>(creds: &'a [Credential], page: &str) -> Vec<&'a Credential> {
    let mut ranked: Vec<(u8, &Credential)> = Vec::new();
    for c in creds {
        if !is_credential(&c.domain, &c.title) { continue; }
        if is_wifi_password(&c.domain) { continue; }   // a name like "Office Guest" must not match office.com
        let rank = if domains_match(page, &c.domain) {
            Some(if normalize_host(page) == normalize_host(&c.domain) { 0 } else { 1 })
        } else {
            let stored = normalize_host(&c.domain);
            if related(page, &stored) { Some(2) }
            else if label_only(&c.domain, &stored) && name_matches_host(page, if c.title.is_empty() { &c.domain } else { &c.title }) { Some(3) }
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

    // ---- red team: the same table as tests/test_matching_security.py ------------------------
    fn offered(page: &str) -> Vec<String> {
        let mut named = cred("amazon", "me");
        named.title = "Amazon".into();
        let mut cf = cred("cloudflare", "me");
        cf.title = "Cloudflare".into();
        let mut shop = cred("b\u{fc}cher.example", "me");
        shop.title = "B\u{fc}cher Shop".into();
        let mut nameless = cred("", "me");
        nameless.title = "Cloudflare Dashboard".into();
        let v = vec![cred("example.com", "me"), cred("paypal.com", "me"), named, cred("localhost", "me"),
                     cf, cred("192.168.1.1", "me"), cred("xn--bcher-kva.example", "me"), shop, nameless];
        let mut out: Vec<String> = match_creds(&v, page).iter().map(|c| c.domain.clone()).collect();
        out.sort();
        out
    }

    #[test]
    fn phishing_pages_are_offered_nothing() {
        for page in [
            "example.com.evil.com", "evil-example.com", "evilexample.com", "example.com@evil.com",
            "paypal.com.evil.com", "paypa1.com", "xn--pypal-4ve.com", "\u{440}aypal.com",
            "amazon.evil.com", "amazon-login.com", "myamazon.com", "amazonaws.com",
            "cloudflare.evil.com", "cloudflare.example.org", "evil.localhost", "shop.evil.com",
            "buecher.example", "b\u{fc}cher.example",
            "192.168.1.10", "1.192.168.1.1", "evil.com.192.168.1.1",
            "https://evil.com\\@example.com/", "https://evil.com#@example.com/",
            "https://evil.com?@example.com", "https://user:pw@evil.com/example.com",
            "https://evil.com/https://example.com", "https://evil.com/?u=example.com",
            "//evil.com/@example.com", "https://example.com\0.evil.com", "https://exa mple.com",
            "javascript:alert(1)", "", "   ", ".", "..", "[",
        ] {
            assert_eq!(offered(page), Vec::<String>::new(), "page {page:?}");
        }
    }

    #[test]
    fn legitimate_pages_still_match() {
        for (page, want) in [
            ("example.com", "example.com"), ("EXAMPLE.COM", "example.com"),
            ("www.example.com", "example.com"), ("login.deep.example.com", "example.com"),
            ("example.com.", "example.com"), ("https://example.com:8443/a?b=c#d", "example.com"),
            ("https://user:pw@example.com/", "example.com"),
            ("amazon.com", "amazon"), ("www.amazon.co.uk", "amazon"),
            ("localhost", "localhost"),
            ("192.168.1.1", "192.168.1.1"),
        ] {
            assert_eq!(offered(page), vec![want.to_string()], "page {page:?}");
        }
    }

    #[test]
    fn a_name_only_entry_matches_its_own_site_and_nothing_else() {
        assert_eq!(offered("dash.cloudflare.com"), vec!["".to_string(), "cloudflare".to_string()]);
        assert_eq!(offered("xn--bcher-kva.example"), vec!["xn--bcher-kva.example".to_string()]);
    }

    #[test]
    fn wifi_passwords_never_match_a_page() {
        let wifi = |name: &str| { let mut c = cred("AirPort", name); c.title = name.into(); c };
        let v = vec![wifi("Home-WiFi"), wifi("Office Guest")];
        for page in ["wifi.example.com", "home.example.com", "guest.example.com", "office.com",
                     "airport", "airport.example.com"] {
            assert!(match_creds(&v, page).is_empty(), "page {page:?}");
        }
    }

    #[test]
    fn normalize_host_reads_urls_like_a_browser() {
        for (raw, host) in [
            ("https://evil.com\\@example.com/", "evil.com"), ("https://evil.com#@example.com/", "evil.com"),
            ("http://[::1]:8080/", "[::1]"), ("https://EXAMPLE.com:443/x", "example.com"),
            ("example.com\0", ""), ("exa mple.com", ""), ("", ""), ("b\u{fc}cher.example", ""),
        ] {
            assert_eq!(normalize_host(raw), host, "raw {raw:?}");
        }
    }
}
