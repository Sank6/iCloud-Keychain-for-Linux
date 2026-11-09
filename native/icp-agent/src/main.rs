//! icp-agent (Rust): the same job as `icp/agent.py`, without Python.
//!
//! Reads `~/.config/icp/vault.enc` (libsodium secretbox, key from the login keyring), answers the
//! native-messaging shim over `$XDG_RUNTIME_DIR/icp/agent.sock` using the browser's framing
//! (4-byte LE length + JSON), and drops the vault from memory after 15 idle minutes. Secrets are
//! zeroized on drop and the process is non-dumpable. (No mlockall: MCL_FUTURE makes thread creation
//! fail under the default 8 MiB memlock limit, so swap protection is left to encrypted swap.)

mod matching;
mod psl;
mod totp;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use matching::Credential;

const MAX_FRAME: usize = 1 << 20;

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn config_dir() -> PathBuf {
    let base = env::var("XDG_CONFIG_HOME").ok().filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var("HOME").unwrap_or_default()).join(".config"));
    base.join("icp")
}
pub fn config_file(name: &str) -> PathBuf { config_dir().join(name) }

fn data_dir() -> PathBuf {
    env::var("XDG_DATA_HOME").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/share"))
        .join("icp")
}

fn socket_path() -> PathBuf {
    let base = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/tmp/icp-{}", unsafe { libc::getuid() }));
    PathBuf::from(base).join("icp").join("agent.sock")
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Default)]
struct Alias {
    #[serde(default)] address: String,
    #[serde(default)] label: String,
    #[serde(default)] domain: String,
}

// ---- keyring + vault -----------------------------------------------------------------------

fn decode_key(stored: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if stored.len() == 32 { return Some(Zeroizing::new(stored.to_vec())); }
    let trimmed: Vec<u8> = stored.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let key = base64::engine::general_purpose::STANDARD.decode(trimmed).ok()?;
    (key.len() == 32).then(|| Zeroizing::new(key))
}

fn master_key() -> Result<Zeroizing<Vec<u8>>, String> {
    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| format!("Secret Service unavailable: {e}"))?;
    let coll = ss.get_default_collection().map_err(|e| format!("no default keyring: {e}"))?;
    if coll.is_locked().unwrap_or(true) {
        coll.unlock().map_err(|e| format!("keyring unlock failed: {e}"))?;
        if coll.is_locked().unwrap_or(true) {
            return Err("the keyring is locked - unlock it (login keyring) and try again".into());
        }
    }
    let attrs: HashMap<&str, &str> = HashMap::from([("application", "icp"), ("type", "master-key")]);
    for item in coll.search_items(attrs).map_err(|e| e.to_string())? {
        let secret = Zeroizing::new(item.get_secret().map_err(|e| e.to_string())?);
        if let Some(k) = decode_key(&secret) { return Ok(k); }
    }
    Err("master key not found in the keyring (run `icp login`)".into())
}

fn open_box(key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() < 24 + 16 { return Err("vault file too short".into()); }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let (nonce, ct) = blob.split_at(24);
    cipher.decrypt(Nonce::from_slice(nonce), ct).map(Zeroizing::new)
        .map_err(|_| "cannot decrypt with the current master key".to_string())
}

#[derive(Deserialize)]
struct VaultFile { #[serde(default)] credentials: Vec<Credential> }
#[derive(Deserialize)]
struct AliasFile { #[serde(default)] aliases: Vec<Alias> }

struct Loaded { creds: Vec<Credential>, aliases: Vec<Alias>, vault_mtime: f64 }

fn mtime(p: &PathBuf) -> f64 {
    fs::metadata(p).and_then(|m| m.modified()).ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn load() -> Result<Loaded, String> {
    let key = master_key()?;
    let vf = config_file("vault.enc");
    let creds = match fs::read(&vf) {
        Ok(blob) => {
            let plain = open_box(&key, &blob)?;
            serde_json::from_slice::<VaultFile>(&plain).map_err(|e| format!("bad vault: {e}"))?.credentials
        }
        Err(_) => vec![],
    };
    // Hide My Email aliases are a best-effort extra: any problem just means no aliases.
    let aliases = fs::read(config_file("aliases.enc")).ok()
        .and_then(|b| open_box(&key, &b).ok())
        .and_then(|p| serde_json::from_slice::<AliasFile>(&p).ok())
        .map(|f| f.aliases).unwrap_or_default();
    Ok(Loaded { creds, aliases, vault_mtime: mtime(&vf) })
}

// ---- agent state & request handling ----------------------------------------------------------

struct State { data: Option<Loaded>, last_used: f64 }

fn handle(state: &Mutex<State>, req: &Value) -> Value {
    let cmd = req.get("cmd").and_then(Value::as_str).unwrap_or("");
    let mut st = state.lock().unwrap();
    st.last_used = now();
    match cmd {
        "lock" => { st.data = None; return json!({"ok": true, "locked": true}); }
        "unlock" => {
            if st.data.is_none() {
                match load() {
                    Ok(l) => st.data = Some(l),
                    Err(e) => return json!({"ok": false, "locked": true, "error": e}),
                }
            }
            return json!({"ok": true, "locked": false});
        }
        "ping" => return json!({"ok": true, "locked": st.data.is_none(),
                                "count": st.data.as_ref().map_or(0, |d| d.creds.len())}),
        "status" => {
            let sync = fs::read_to_string(config_file("sync-status.json")).ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!({}));
            return json!({"ok": true, "locked": st.data.is_none(), "sync": sync,
                          "signed_in": config_file("session.enc").exists(),
                          "count": st.data.as_ref().map_or(0, |d| d.creds.len())});
        }
        "open_app" => {
            spawn_from(&data_dir().join("gui-cmd"));
            return json!({"ok": true});
        }
        "login" => {
            spawn_login();
            return json!({"ok": true});
        }
        "chose" => {
            let d = req.get("domain").and_then(Value::as_str).unwrap_or("");
            let u = req.get("username").and_then(Value::as_str).unwrap_or("");
            if !d.is_empty() && !u.is_empty() { matching::record_choice(d, u); }
            return json!({"ok": true});
        }
        "match" | "search" | "totp" => {}
        other => return json!({"ok": false, "error": format!("unknown cmd '{}'", other)}),
    }
    // secret-bearing commands need an unlocked agent
    if st.data.is_none() { return json!({"ok": false, "locked": true, "error": "locked"}); }
    // pick up a vault rewritten by a sync
    let stale = st.data.as_ref().map_or(false, |d| mtime(&config_file("vault.enc")) != d.vault_mtime);
    if stale { if let Ok(l) = load() { st.data = Some(l); } }
    let data = st.data.as_ref().unwrap();

    match cmd {
        "match" => {
            let domain = req.get("domain").and_then(Value::as_str).unwrap_or("");
            if domain.is_empty() { return json!({"ok": false, "error": "missing domain"}); }
            let creds: Vec<Value> = matching::match_creds(&data.creds, domain).iter().map(|c| c.wire()).collect();
            let aliases: Vec<Value> = data.aliases.iter()
                .filter(|a| !a.domain.is_empty() && matching::domains_match(domain, &a.domain))
                .map(|a| json!({"address": a.address, "label": a.label, "domain": a.domain})).collect();
            json!({"ok": true, "credentials": creds, "aliases": aliases})
        }
        "search" => {
            let q = req.get("query").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
            if q.chars().count() < 2 { return json!({"ok": true, "credentials": []}); }
            let mut hits: Vec<&Credential> = data.creds.iter()
                .filter(|c| format!("{} {} {}", c.title, c.domain, c.username).to_lowercase().contains(&q)).collect();
            hits.sort_by(|a, b| b.recency().partial_cmp(&a.recency()).unwrap_or(std::cmp::Ordering::Equal));
            json!({"ok": true, "credentials": hits.iter().take(40).map(|c| c.wire()).collect::<Vec<_>>()})
        }
        _ => { // totp
            let domain = req.get("domain").and_then(Value::as_str).unwrap_or("");
            let user = req.get("username").and_then(Value::as_str).unwrap_or("");
            for c in matching::match_creds(&data.creds, domain) {
                if c.username == user && !c.totp.is_empty() {
                    return json!({"ok": true, "totp": totp::generate(&c.totp, None)});
                }
            }
            json!({"ok": false, "error": "no code for that login"})
        }
    }
}

fn spawn_from(file: &PathBuf) {
    let Ok(line) = fs::read_to_string(file) else { return };
    let mut parts = line.split_whitespace();
    let Some(prog) = parts.next() else { return };
    let _ = Command::new(prog).args(parts).stdin(Stdio::null()).stdout(Stdio::null())
        .stderr(Stdio::null()).spawn();
}

/// Argv for the sync command: the configured one, with `--background` ensured so an unattended
/// run can never sign in with the password or prompt for 2FA.
fn background_sync_cmd(line: &str) -> Vec<String> {
    let mut parts: Vec<String> = line.split_whitespace().map(String::from).collect();
    if !parts.is_empty() && !parts.iter().any(|p| p == "--background") { parts.push("--background".into()); }
    parts
}

/// Argv for the sign-in window: `login-cmd` if `icp setup` wrote one, else derived from `sync-cmd`
/// (everything before the `sync` word, then `login --gui`).
fn login_cmd(login_line: Option<&str>, sync_line: Option<&str>) -> Vec<String> {
    if let Some(l) = login_line {
        let v: Vec<String> = l.split_whitespace().map(String::from).collect();
        if !v.is_empty() { return v; }
    }
    let mut v: Vec<String> = Vec::new();
    for p in sync_line.unwrap_or("").split_whitespace() {
        if p == "sync" { v.push("login".into()); v.push("--gui".into()); return v; }
        v.push(p.to_string());
    }
    Vec::new()
}

fn spawn_login() {
    let argv = login_cmd(fs::read_to_string(data_dir().join("login-cmd")).ok().as_deref(),
                         fs::read_to_string(data_dir().join("sync-cmd")).ok().as_deref());
    if let Some((prog, rest)) = argv.split_first() {
        let _ = Command::new(prog).args(rest).stdin(Stdio::null()).stdout(Stdio::null())
            .stderr(Stdio::null()).spawn();
    }
}

/// Kick off a detached `icp sync` when the vault is old, with exponential back-off after failures
/// (same rules as the Python host). Disabled by ICP_SYNC_MAX_AGE=0.
fn maybe_trigger_sync() {
    let max_age: f64 = env::var("ICP_SYNC_MAX_AGE").ok().and_then(|s| s.parse().ok()).unwrap_or(6.0 * 3600.0);
    if max_age <= 0.0 { return; }
    let vault = config_file("vault.enc");
    if vault.exists() && now() - mtime(&vault) < max_age { return; }
    let attempt = config_file("sync.attempt");
    if attempt.exists() && now() - mtime(&attempt) < 300.0 { return; }
    if let Some(st) = fs::read_to_string(config_file("sync-status.json")).ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        // sign-in needed: nothing an unattended sync can fix (the UIs offer "Sign in")
        if st.get("needs_login").and_then(Value::as_bool).unwrap_or(false) { return; }
        let fails = st.get("failures").and_then(Value::as_i64).unwrap_or(0);
        let last = st.get("last_attempt").and_then(Value::as_f64).unwrap_or(0.0);
        if fails > 0 && now() - last < (900.0 * 2f64.powi((fails - 1).min(20) as i32)).min(86400.0) { return; }
    }
    let _ = fs::write(&attempt, b"");
    if let Ok(line) = fs::read_to_string(data_dir().join("sync-cmd")) {
        let argv = background_sync_cmd(&line);
        if let Some((prog, rest)) = argv.split_first() {
            let _ = Command::new(prog).args(rest).stdin(Stdio::null()).stdout(Stdio::null())
                .stderr(Stdio::null()).spawn();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_cmd_always_background() {
        assert_eq!(background_sync_cmd("python -m icp.cli.app sync"),
                   vec!["python", "-m", "icp.cli.app", "sync", "--background"]);
        assert_eq!(background_sync_cmd("x sync --background").len(), 3);
        assert!(background_sync_cmd("  ").is_empty());
    }

    #[test]
    fn login_cmd_from_file_or_derived_from_sync_cmd() {
        assert_eq!(login_cmd(Some("py -m icp.cli.app login --gui\n"), None),
                   vec!["py", "-m", "icp.cli.app", "login", "--gui"]);
        assert_eq!(login_cmd(None, Some("/v/bin/python -m icp.cli.app sync\n")),
                   vec!["/v/bin/python", "-m", "icp.cli.app", "login", "--gui"]);
        assert!(login_cmd(None, None).is_empty());
    }
}

// ---- framing & server ----------------------------------------------------------------------

fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head).ok()?;
    let n = u32::from_le_bytes(head) as usize;
    if n > MAX_FRAME { return None; }
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).ok()?;
    Some(body)
}

fn peer_is_me(s: &UnixStream) -> bool {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
                                       &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    rc == 0 && cred.uid == unsafe { libc::getuid() }
}

fn client(state: Arc<Mutex<State>>, mut s: UnixStream) {
    if !peer_is_me(&s) { return; }
    while let Some(body) = read_frame(&mut s) {
        let resp = match serde_json::from_slice::<Value>(&body) {
            Ok(req) => handle(&state, &req),
            Err(_) => json!({"ok": false, "error": "bad json"}),
        };
        let out = serde_json::to_vec(&resp).unwrap_or_default();
        if s.write_all(&(out.len() as u32).to_le_bytes()).is_err() || s.write_all(&out).is_err() { return; }
    }
}

fn main() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);          // no ptrace / core dumps of secrets
    }
    let idle_lock: f64 = env::var("ICP_IDLE_LOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(900.0);
    let state = Arc::new(Mutex::new(State { data: None, last_used: now() }));
    if let Ok(l) = load() { state.lock().unwrap().data = Some(l); } // else start locked

    let sp = socket_path();
    let dir = sp.parent().unwrap().to_path_buf();
    let _ = fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    if sp.exists() {
        if UnixStream::connect(&sp).is_ok() { return; } // a live agent already owns it
        let _ = fs::remove_file(&sp);
    }
    let old = unsafe { libc::umask(0o177) };
    let listener = match UnixListener::bind(&sp) { Ok(l) => l, Err(e) => { eprintln!("bind {}: {e}", sp.display()); return; } };
    unsafe { libc::umask(old); }
    let _ = fs::set_permissions(&sp, fs::Permissions::from_mode(0o600));

    maybe_trigger_sync();
    {
        let state = state.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(30));
            let mut st = state.lock().unwrap();
            if st.data.is_some() && idle_lock > 0.0 && now() - st.last_used > idle_lock { st.data = None; }
        });
        thread::spawn(|| loop { thread::sleep(Duration::from_secs(3600)); maybe_trigger_sync(); });
    }
    for conn in listener.incoming().flatten() {
        let state = state.clone();
        thread::spawn(move || client(state, conn));
    }
}
