//! icp-shim: the program the browser launches for native messaging.
//!
//! Chrome frames every message as a 4-byte little-endian length followed by JSON. The agent speaks
//! the same framing, so this is a plain forwarder: stdin -> agent socket -> stdout. If the agent is
//! not running it is started (the command comes from `~/.local/share/icp/agent-cmd`, written by
//! `icp setup`) and we wait briefly for its socket.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 1 << 20;

fn socket_path() -> PathBuf {
    let base = env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/tmp/icp-{}", unsafe_uid()));
    PathBuf::from(base).join("icp").join("agent.sock")
}

/// Real uid without a libc dependency: the owner of /proc/self.
fn unsafe_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0)
}

fn data_dir() -> PathBuf {
    match env::var("XDG_DATA_HOME") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/share"),
    }
}

fn start_agent() {
    let cmd_file = data_dir().join("icp").join("agent-cmd");
    let Ok(line) = fs::read_to_string(cmd_file) else { return };
    let mut parts = line.split_whitespace();
    let Some(prog) = parts.next() else { return };
    let _ = Command::new(prog)
        .args(parts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn(); // detached enough: the agent outlives us and reparents to init
}

fn connect() -> io::Result<UnixStream> {
    let path = socket_path();
    if let Ok(s) = UnixStream::connect(&path) {
        return Ok(s);
    }
    start_agent();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match UnixStream::connect(&path) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => sleep(Duration::from_millis(50)),
        }
    }
}

fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(head) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn error_frame(msg: &str) -> Vec<u8> {
    format!("{{\"ok\":false,\"error\":{:?}}}", msg).into_bytes()
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let (mut input, mut output) = (stdin.lock(), stdout.lock());
    let mut sock: Option<UnixStream> = None;

    loop {
        let req = match read_frame(&mut input) {
            Ok(Some(b)) => b,
            _ => return, // browser closed the pipe
        };
        if sock.is_none() {
            match connect() {
                Ok(s) => sock = Some(s),
                Err(e) => {
                    let _ = write_frame(&mut output, &error_frame(&format!("agent unavailable: {e}")));
                    continue;
                }
            }
        }
        let s = sock.as_mut().unwrap();
        let reply = write_frame(s, &req).and_then(|_| read_frame(s));
        match reply {
            Ok(Some(body)) => {
                if write_frame(&mut output, &body).is_err() {
                    return;
                }
            }
            _ => {
                sock = None; // agent went away; reconnect on the next request
                let _ = write_frame(&mut output, &error_frame("agent connection lost"));
            }
        }
    }
}
