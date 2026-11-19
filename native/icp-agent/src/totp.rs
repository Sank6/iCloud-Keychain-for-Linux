//! RFC 6238 one-time codes from an otpauth:// URI (same behaviour as icp/totp.py::generate).

use hmac::{Hmac, Mac};
use serde_json::{json, Value};

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(v) => { out.push(v); i += 3; }
                    Err(_) => { out.push(b'%'); i += 1; }
                }
            }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (pct_decode(k) == name).then(|| pct_decode(v))
    })
}

fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let (mut bits, mut acc, mut out) = (0u32, 0u64, Vec::new());
    for c in s.bytes() {
        let v = match c { b'A'..=b'Z' => c - b'A', b'2'..=b'7' => c - b'2' + 26, _ => return None };
        acc = (acc << 5) | v as u64;
        bits += 5;
        if bits >= 8 { bits -= 8; out.push((acc >> bits) as u8); acc &= (1 << bits) - 1; }
    }
    Some(out)
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <M as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// {"code","expires","period"}, or null when the URI is unusable.
pub fn generate(uri: &str, at: Option<f64>) -> Value {
    if uri.is_empty() { return Value::Null; }
    let query = uri.split_once('?').map(|x| x.1).unwrap_or("");
    let raw: String = param(query, "secret").unwrap_or_default().replace(' ', "").to_uppercase();
    let Some(key) = b32_decode(&raw) else { return Value::Null };
    if key.is_empty() { return Value::Null; }
    let algo = param(query, "algorithm").unwrap_or_else(|| "SHA1".into()).to_uppercase();
    let digits: u32 = param(query, "digits").and_then(|d| d.parse().ok()).unwrap_or(6).clamp(6, 10);
    let period: u64 = param(query, "period").and_then(|d| d.parse().ok()).unwrap_or(30).max(1);
    let counter = (at.unwrap_or_else(crate::now) as u64) / period;
    let msg = counter.to_be_bytes();
    let digest = match algo.as_str() {
        "SHA1" => mac::<Hmac<sha1::Sha1>>(&key, &msg),
        "SHA256" => mac::<Hmac<sha2::Sha256>>(&key, &msg),
        "SHA512" => mac::<Hmac<sha2::Sha512>>(&key, &msg),
        _ => return Value::Null,
    };
    let off = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([digest[off], digest[off + 1], digest[off + 2], digest[off + 3]]) & 0x7fff_ffff;
    let code = (bin as u64) % 10u64.pow(digits);
    json!({"code": format!("{:0width$}", code, width = digits as usize),
           "expires": (counter + 1) * period, "period": period})
}

#[cfg(test)]
mod tests {
    use super::*;
    // RFC 6238 appendix B: SHA1 secret "12345678901234567890", T=59 -> 94287082 (8 digits)
    #[test]
    fn rfc6238_sha1() {
        let v = generate("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30", Some(59.0));
        assert_eq!(v["code"], "94287082");
        assert_eq!(v["expires"], 60);
    }
    #[test]
    fn unusable_uris_are_null() {
        assert!(generate("", None).is_null());
        assert!(generate("otpauth://totp/x?secret=!!!", None).is_null());
        assert!(generate("otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5", None).is_null());
    }
}
