"""`icp doctor`: a read-only checklist of everything that has to work for autofill to work.
Never prompts, never writes, never contacts Apple (it only pokes the local anisette server)."""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from . import config, hosts, keyring, paths, ratelimit, status
from .auth import session
from .const import ANISETTE_IMAGE, ANISETTE_PORT, EXTENSION_ID

OK, WARN, FAIL = "ok", "warn", "fail"
_MARK = {OK: "\033[32m✓\033[0m", WARN: "\033[33m!\033[0m", FAIL: "\033[31m✗\033[0m"}


def _age(ts: float) -> str:
    d = max(0, time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{int(d // n)}{unit} ago"
    return "just now"


def anisette_run_command(runner: str) -> list[str]:
    """Start the anisette server published on loopback only (never 0.0.0.0: it is unauthenticated
    and anyone on the LAN could use it)."""
    return [runner, "run", "-d", "--restart=always", "--name", "icp-anisette",
            "-p", f"127.0.0.1:{ANISETTE_PORT}:{ANISETTE_PORT}", ANISETTE_IMAGE]


def listening_exposed(port: int, proc_dir: str = "/proc/net") -> list[str]:
    """Non-loopback local addresses with a TCP listener on `port` (read from /proc, no network).
    `0.0.0.0` / `::` mean the service is reachable from the whole LAN."""
    out = []
    for name, v6 in (("tcp", False), ("tcp6", True)):
        try:
            lines = Path(proc_dir, name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 4 or f[3] != "0A":  # 0A = LISTEN
                continue
            addr_hex, port_hex = f[1].rsplit(":", 1)
            if int(port_hex, 16) != port:
                continue
            raw = bytes.fromhex(addr_hex)
            if v6:
                # 4 little-endian 32-bit words
                raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
                ip = ipaddress.IPv6Address(raw)
                ip = ip.ipv4_mapped or ip
            else:
                ip = ipaddress.IPv4Address(raw[::-1])
            if not ip.is_loopback:
                out.append("0.0.0.0" if ip == ipaddress.IPv4Address(0) else
                           "::" if ip == ipaddress.IPv6Address(0) else str(ip))
    return sorted(set(out))


def check_anisette(url: str | None):
    import requests
    url = config.anisette_url(url)
    port = urlparse(url).port or ANISETTE_PORT
    runner = shutil.which("docker") or shutil.which("podman")
    hint = (" ".join(anisette_run_command(os.path.basename(runner))) if runner
            else "install Docker or Podman (see packaging/anisette/README.md)")
    try:
        r = requests.get(url, timeout=3)
    except Exception as e:
        return FAIL, f"anisette server not reachable at {url} ({type(e).__name__})", hint
    if not r.ok:
        return FAIL, f"anisette server at {url} answered HTTP {r.status_code}", ""
    if not config.is_loopback(url):
        return WARN, f"anisette server {url} is not on this machine", \
            "a remote server sees your device identity; prefer a loopback-only local one"
    exposed = listening_exposed(port)
    if exposed:
        return WARN, (f"anisette server on port {port} is listening on {', '.join(exposed)} "
                      "- reachable from your network"), \
            ("re-create it bound to loopback: "
             f"{os.path.basename(runner) if runner else 'docker'} rm -f <name>; then "
             f"{hint if runner else 'see packaging/anisette/'}")
    return OK, f"anisette server reachable at {url} (loopback only)", ""


def check_keyring():
    """Read-only: never prompts, never creates the master key."""
    try:
        coll = keyring.open_collection(interactive=False)
    except keyring.KeyringLocked:
        return WARN, "keyring is locked (it will ask to unlock on first use)", \
            "unlock it with your login password, or `icp mirror`"
    except keyring.KeyringUnavailable as e:
        return WARN, f"{e}; the 0600 key file fallback is used", \
            "log in to a desktop session with gnome-keyring running"
    if keyring.find(coll, {"application": "icp", "type": "master-key"}):
        return OK, "keyring (Secret Service) is unlocked and holds the vault key", ""
    if session._encrypted_files():
        return FAIL, "keyring has no vault key but encrypted data exists (wrong collection?)", \
            "unlock the right keyring, or `icp logout --reset-keys` to start over"
    return OK, "keyring (Secret Service) is available (no vault key yet)", ""


def check_signin():
    st = ratelimit.load()
    if st.get("needs_login"):
        return FAIL, f"sign-in needed: {st.get('last_error') or 'Apple rejected the saved session'}", \
            "run `icp login --gui` (or use the button in the Passwords app)"
    circuit = ratelimit.circuit_status()
    if circuit:
        return WARN, f"unattended Apple calls paused: {circuit}", "an interactive `icp login` resets it"
    return OK, "no sign-in problem recorded", ""


def check_files():
    out = []
    cfg = paths.config_dir()
    for name, f, hint in (("device identity", paths.device_file(), "run `icp login`"),
                          ("session", paths.session_file(), "run `icp login`")):
        out.append((OK if f.exists() else FAIL,
                    f"{name} present" if f.exists() else f"{name} missing", "" if f.exists() else hint))
    v = paths.vault_file()
    if not v.exists():
        out.append((FAIL, "vault missing", "run `icp login` or `icp sync`"))
    else:
        age = time.time() - v.stat().st_mtime
        sev = OK if age < 24 * 3600 else WARN
        out.append((sev, f"vault last written {_age(v.stat().st_mtime)}",
                    "" if sev == OK else "run `icp sync`"))
    if (cfg / "master.key").exists():
        out.append((WARN, "plaintext master.key file in use (less safe than the keyring)", ""))
    return out


def check_sync_status():
    s = status.read()
    if not s:
        return WARN, "no sync has been recorded yet", "run `icp sync`"
    if s.get("failures"):
        msg = f"last sync failed ({s['failures']} in a row): {s.get('last_error', '')}"
        return FAIL, msg, s.get("hint", "")
    if not s.get("last_success"):
        return WARN, "no successful sync recorded yet", "run `icp sync`"
    return OK, f"last successful sync {_age(s['last_success'])}", ""


def check_hosts():
    found = hosts.detected()
    if not found:
        return [(WARN, "no supported browser profile found", "")]
    out = []
    for label, kind, nmh in found:
        problems = hosts.inspect(nmh, kind)
        out.append((OK, f"{label}: native host registered", "") if not problems else
                   (FAIL, f"{label}: {'; '.join(problems)}", "run `icp setup`"))
    out.append((OK, f"extension id (pinned): {EXTENSION_ID}", ""))
    return out


def check_timer():
    if not shutil.which("systemctl"):
        return WARN, "systemd not found; background sync relies on the browser trigger", ""
    r = subprocess.run(["systemctl", "--user", "is-enabled", "icp-sync.timer"],
                       capture_output=True, text=True)
    if r.stdout.strip() == "enabled":
        return OK, "systemd sync timer enabled", ""
    return WARN, "systemd sync timer not installed", "run `icp setup`"


def check_notify():
    return (OK, "desktop notifications available", "") if shutil.which("notify-send") else \
        (WARN, "notify-send not found; failures won't pop up", "sudo apt install libnotify-bin")


def run(anisette_url: str | None = None) -> int:
    results = [check_anisette(anisette_url), check_keyring(), check_signin(), *check_files(),
               check_sync_status(), *check_hosts(), check_timer(), check_notify()]
    for sev, msg, hint in results:
        print(f" {_MARK[sev]} {msg}")
        if hint:
            print(f"     -> {hint}")
    bad = sum(1 for s, _, _ in results if s == FAIL)
    warn = sum(1 for s, _, _ in results if s == WARN)
    print(f"\n{bad} problem(s), {warn} warning(s)")
    return 1 if bad else 0
