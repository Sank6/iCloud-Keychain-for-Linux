"""Setup checklist and system integration for the desktop app's Settings page. Qt-free so it
is testable: each check reports a state plus, where possible, an automatic fix (`action`) and
a command the user can copy and run themselves (`command`).

Everything here is local and read-only except the explicit actions (start/enable a systemd
user service, write or remove a .desktop file), which run only when the user clicks them."""

from __future__ import annotations

import dataclasses
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .. import paths, ratelimit

OK, WARN, FAIL = "ok", "warn", "fail"
DEFAULT_ANISETTE_URL = "http://127.0.0.1:6970"
STALE_AFTER = 24 * 3600
REPO = Path(__file__).resolve().parents[2]   # the source checkout, for host/ and desktop/
_ICLOUD_AUTH_TOKEN = "com.apple.gs.icloud.auth"

TERMINALS = (
    ("konsole", ["-e"]), ("gnome-terminal", ["--"]), ("kgx", ["--"]), ("kitty", []),
    ("alacritty", ["-e"]), ("wezterm", ["start", "--"]), ("foot", []), ("xfce4-terminal", ["-x"]),
    ("tilix", ["-e"]), ("x-terminal-emulator", ["-e"]), ("xterm", ["-e"]),
)


@dataclasses.dataclass
class Check:
    key: str
    title: str
    state: str                  # OK | WARN | FAIL
    detail: str = ""
    command: str = ""           # a command the user can copy and run to fix it
    action: str = ""            # an automatic fix the app can run (see MainWindow)
    action_label: str = ""


# --- small helpers -------------------------------------------------------------------------

def icp_bin() -> str:
    """The `icp` next to this interpreter (the venv), else whatever is on PATH."""
    local = Path(sys.executable).parent / "icp"
    return str(local) if local.exists() else (shutil.which("icp") or "icp")


def gui_bin() -> str:
    local = Path(sys.executable).parent / "icp-gui"
    return str(local) if local.exists() else (shutil.which("icp-gui") or "icp-gui")


def _run(*cmd: str, timeout: float = 10) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def systemctl(*args: str) -> tuple[bool, str]:
    if not shutil.which("systemctl"):
        return False, "systemctl not found"
    return _run("systemctl", "--user", *args)


def anisette_services() -> list[str]:
    """systemd user units that look like an anisette server (anisette-rs, omnisette, ...)."""
    ok, out = systemctl("list-unit-files", "--no-legend", "--plain", "--type=service")
    if not ok:
        return []
    units = [line.split()[0] for line in out.splitlines() if line.strip()]
    return [u for u in units if "anisette" in u.lower()]


def service_state(unit: str) -> tuple[bool, bool]:
    """-> (enabled at login, running now)."""
    return systemctl("is-enabled", unit)[0], systemctl("is-active", unit)[0]


def probe_anisette(url: str, timeout: float = 3) -> tuple[bool, str]:
    """Ask the server for its client info, which `icp` needs (no Apple traffic involved)."""
    import requests

    if not url:
        return False, "no URL set"
    try:
        r = requests.get(url.rstrip("/") + "/v3/client_info", timeout=timeout)
        r.raise_for_status()
        info = r.json()
    except requests.RequestException as e:
        reason = getattr(e, "__class__", type(e)).__name__
        return False, f"not reachable ({reason})"
    except ValueError:
        return False, "answered, but not with anisette JSON"
    if not isinstance(info, dict) or "client_info" not in info:
        return False, "answered, but without client_info"
    return True, "responding"


def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or "~/.local/share").expanduser()


def _config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser()


def launcher_file() -> Path:
    return _data_home() / "applications" / "icp-gui.desktop"


def autostart_file() -> Path:
    return _config_home() / "autostart" / "icp-gui.desktop"


def desktop_entry(anisette_url: str = "", hidden_on_start: bool = False) -> str:
    exec_line = shlex.quote(gui_bin())
    if anisette_url:
        exec_line = f"env ICP_ANISETTE_URL={shlex.quote(anisette_url)} {exec_line}"
    if hidden_on_start:
        exec_line += " --minimized"
    return ("[Desktop Entry]\nType=Application\nName=iCloud Passwords\n"
            "GenericName=Password Manager\n"
            "Comment=Browse your iCloud Keychain passwords and verification codes\n"
            f"Exec={exec_line}\nIcon=dialog-password\nTerminal=false\n"
            "Categories=Utility;Security;Qt;\nStartupWMClass=icp-gui\n")


def install_launcher(anisette_url: str) -> tuple[bool, str]:
    f = launcher_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(desktop_entry(anisette_url))
    return True, f"Added {f}"


def gui_autostart_enabled() -> bool:
    return autostart_file().exists()


def set_gui_autostart(on: bool, anisette_url: str) -> tuple[bool, str]:
    f = autostart_file()
    if on:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(desktop_entry(anisette_url, hidden_on_start=True))
        return True, "iCloud Passwords will open at login"
    f.unlink(missing_ok=True)
    return True, "iCloud Passwords won't open at login"


def terminal_argv(command: list[str]) -> list[str] | None:
    """argv that opens `command` in the first available terminal, or None."""
    for term, flag in TERMINALS:
        if shutil.which(term):
            return [term, *flag, *command]
    return None


def login_command(anisette_url: str) -> list[str]:
    cmd = [icp_bin(), "login"]
    return (["env", f"ICP_ANISETTE_URL={anisette_url}", *cmd] if anisette_url else cmd)


def account_info() -> list[tuple[str, str]]:
    """(label, value) rows about the signed-in account; no secrets."""
    from ..auth import session
    from ..octagon import client as octagon

    try:
        s = session.load()
    except Exception as e:  # noqa: BLE001 - keyring locked or key mismatch
        return [("Account", f"unavailable ({e})")]
    if not s:
        return [("Account", "not signed in")]
    rows = [("Apple ID", str(s.get("username") or "")),
            ("Signed in", time.strftime("%-d %B %Y", time.localtime(s.get("logged_in_at", 0)))),
            ("Keychain", "joined" if octagon.is_joined(s) or (s.get("octagon") or {}).get("peer_id")
             else "not joined")]
    token = (s.get("app_tokens") or {}).get(_ICLOUD_AUTH_TOKEN) or {}
    if token.get("expiry"):
        exp = token["expiry"] / 1000
        state = "valid until" if exp > time.time() else "expired on"
        rows.append(("iCloud sign-in", f"{state} {time.strftime('%-d %B %Y', time.localtime(exp))}"))
    return rows


# --- the checklist -------------------------------------------------------------------------

def run_checks(anisette_url: str, now: float | None = None) -> list[Check]:
    now = time.time() if now is None else now
    checks: list[Check] = []
    url = (anisette_url or "").strip()

    # 1-3. Anisette server: configured, reachable, starts at login.
    if not url:
        checks.append(Check("anisette_url", "Anisette server address", FAIL,
                            "No server address is set. Enter it under Anisette server above.",
                            command=f"set -Ux ICP_ANISETTE_URL {DEFAULT_ANISETTE_URL}"))
    services = anisette_services()
    unit = services[0] if services else ""
    enabled, active = service_state(unit) if unit else (False, False)
    if url:
        ok, why = probe_anisette(url)
        if ok:
            checks.append(Check("anisette_up", "Anisette server is running", OK, f"{url} - {why}"))
        elif unit and not active:
            checks.append(Check("anisette_up", "Anisette server is stopped", FAIL,
                                f"{url} is {why}. The {unit} service isn't running.",
                                command=f"systemctl --user start {unit}",
                                action="start_service", action_label="Start"))
        else:
            checks.append(Check("anisette_up", "Anisette server isn't answering", FAIL,
                                f"{url} is {why}. Check the address, or start your server.",
                                command=(f"systemctl --user restart {unit}" if unit else ""),
                                action="restart_service" if unit else "",
                                action_label="Restart" if unit else ""))
    if unit:
        checks.append(Check("anisette_boot", "Anisette server starts at login",
                            OK if enabled else WARN,
                            f"systemd user service {unit}" + ("" if enabled else " is not enabled"),
                            command="" if enabled else f"systemctl --user enable --now {unit}",
                            action="" if enabled else "enable_service",
                            action_label="" if enabled else "Enable"))
    else:
        checks.append(Check("anisette_boot", "Anisette server starts at login", WARN,
                            "No systemd user service found for an anisette server, so it has "
                            "to be started by hand. See the README for running one as a service."))

    # 4-6. Signed in, joined, sign-in still valid.
    login = shlex.join(login_command(url))
    signed_in = paths.session_file().exists()
    if not signed_in:
        checks.append(Check("signed_in", "Signed in to iCloud", FAIL,
                            "Sign in once in a terminal: Apple ID, password, 2FA code and a "
                            "device passcode.", command=login, action="login",
                            action_label="Open terminal"))
    else:
        joined = None
        try:
            from ..auth import session
            from ..octagon import client as octagon
            s = session.load() or {}
            joined = octagon.is_joined(s) or bool((s.get("octagon") or {}).get("peer_id"))
        except Exception as e:  # noqa: BLE001
            checks.append(Check("signed_in", "Signed in to iCloud", FAIL,
                                f"The saved sign-in can't be opened: {e}", command=login,
                                action="login", action_label="Open terminal"))
        if joined is not None:
            checks.append(Check("signed_in", "Signed in to iCloud", OK if joined else FAIL,
                                "Joined to your iCloud Keychain" if joined else
                                "Signed in, but this device hasn't joined your keychain yet.",
                                command="" if joined else login,
                                action="" if joined else "login",
                                action_label="" if joined else "Open terminal"))

    state = ratelimit.load()
    if signed_in and state.get("needs_login"):
        checks.append(Check("login_valid", "Sign-in is current", FAIL,
                            "Apple needs you to sign in again; syncing is paused until then.",
                            command=login, action="login", action_label="Open terminal"))

    # 7-8. Vault freshness and the last sync.
    vault = paths.vault_file()
    if signed_in:
        if not vault.exists():
            checks.append(Check("vault", "Passwords downloaded", FAIL, "Nothing synced yet.",
                                command=f"{shlex.quote(icp_bin())} sync", action="sync",
                                action_label="Sync now"))
        else:
            age = now - (state.get("last_success") or vault.stat().st_mtime)
            stale = age > STALE_AFTER
            checks.append(Check("vault", "Passwords are up to date", WARN if stale else OK,
                                f"Last synced {int(age // 3600)} hours ago" if stale
                                else "Synced within the last day",
                                command=f"{shlex.quote(icp_bin())} sync" if stale else "",
                                action="sync" if stale else "",
                                action_label="Sync now" if stale else ""))
        if state.get("failures") and state.get("last_error"):
            checks.append(Check("last_sync", "Last sync failed", WARN, state["last_error"],
                                command=f"{shlex.quote(icp_bin())} sync --force",
                                action="sync", action_label="Try again"))

    # 9. Secrets kept in the login keyring rather than a key file.
    if paths.fallback_key_file().exists():
        checks.append(Check("keyring", "Secrets stored in your login keyring", WARN,
                            "The login keyring wasn't available, so the encryption key is in "
                            f"{paths.fallback_key_file()} instead. Make sure a Secret Service "
                            "(KWallet or GNOME Keyring) is running."))
    else:
        checks.append(Check("keyring", "Secrets stored in your login keyring", OK,
                            "The vault key is kept in the Secret Service"))

    # 10. Browser extension: added and connected in at least one browser.
    from . import browsers
    ready, found = browsers.any_connected()
    if ready:
        detail = f"Set up in {ready} of {found} browser{'s' if found != 1 else ''}"
    elif found:
        detail = f"Found {found} browser{'s' if found != 1 else ''}, but autofill isn't set up yet"
    else:
        detail = "No supported browser found"
    checks.append(Check("browser", "Browser autofill", OK if ready else WARN, detail,
                        action="" if ready else "open_extension",
                        action_label="" if ready else "Set up"))

    # 11. App menu entry.
    has_launcher = launcher_file().exists()
    checks.append(Check("launcher", "In your application menu", OK if has_launcher else WARN,
                        str(launcher_file()) if has_launcher else
                        "Add iCloud Passwords to your desktop's app launcher.",
                        command="" if has_launcher else
                        f"{shlex.quote(str(REPO / 'desktop' / 'install.sh'))}",
                        action="" if has_launcher else "install_launcher",
                        action_label="" if has_launcher else "Add"))
    return checks


def summary(checks: list[Check]) -> tuple[int, int]:
    """-> (problems, warnings)."""
    return (sum(c.state == FAIL for c in checks), sum(c.state == WARN for c in checks))
