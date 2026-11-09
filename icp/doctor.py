"""`icp doctor`: a read-only checklist of everything that has to work for autofill to work.
Never prompts, never writes, never contacts Apple (it only pokes the local anisette server)."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from . import hosts, paths, status
from .const import DEFAULT_ANISETTE_URL, EXTENSION_ID

OK, WARN, FAIL = "ok", "warn", "fail"
_MARK = {OK: "\033[32m✓\033[0m", WARN: "\033[33m!\033[0m", FAIL: "\033[31m✗\033[0m"}


def _age(ts: float) -> str:
    d = max(0, time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{int(d // n)}{unit} ago"
    return "just now"


def check_anisette(url: str | None):
    import requests
    url = url or os.environ.get("ICP_ANISETTE_URL") or DEFAULT_ANISETTE_URL
    try:
        r = requests.get(url, timeout=3)
        if r.ok:
            return OK, f"anisette server reachable at {url}", ""
        return FAIL, f"anisette server at {url} answered HTTP {r.status_code}", ""
    except Exception as e:
        runner = shutil.which("docker") or shutil.which("podman")
        hint = (f"start it: {os.path.basename(runner)} run -d --restart=always -p 6969:6969 "
                "dadoum/anisette-v3-server:latest") if runner else "install Docker or Podman"
        return FAIL, f"anisette server not reachable at {url} ({type(e).__name__})", hint


def check_keyring():
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            return WARN, "keyring is locked (it will ask to unlock on first use)", ""
        return OK, "keyring (Secret Service) is available and unlocked", ""
    except Exception as e:
        return WARN, f"Secret Service unavailable ({e}); the 0600 key file fallback is used", \
            "log in to a desktop session with gnome-keyring running"


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
    results = [check_anisette(anisette_url), check_keyring(), *check_files(),
               check_sync_status(), *check_hosts(), check_timer(), check_notify()]
    for sev, msg, hint in results:
        print(f" {_MARK[sev]} {msg}")
        if hint:
            print(f"     -> {hint}")
    bad = sum(1 for s, _, _ in results if s == FAIL)
    warn = sum(1 for s, _, _ in results if s == WARN)
    print(f"\n{bad} problem(s), {warn} warning(s)")
    return 1 if bad else 0
