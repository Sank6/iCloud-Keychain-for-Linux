"""Qt-free logic behind the desktop app (`icp-gui`): which credentials a sidebar section and a
search show, how they are labelled, and the one-line sync status. Kept separate from `app.py` so
it is testable without a display or PySide6 installed."""

from __future__ import annotations

import time

from .. import paths, ratelimit
from ..vault.host import Credential, is_wifi_password

# Sidebar sections: (key, label). "all" is every login except Wi-Fi networks, as in the
# Passwords app; Wi-Fi has its own section.
SECTIONS = (
    ("all", "All Passwords"),
    ("codes", "Verification Codes"),
    ("shared", "Shared Groups"),
    ("wifi", "Wi-Fi"),
    ("hme", "Hide My Email"),
)


def title(c: Credential) -> str:
    return c.title or c.domain or c.username or "(untitled)"


def subtitle(c: Credential) -> str:
    """Second line of a list row: the account, or the site when the title already is the
    account (Wi-Fi networks are titled and named by their SSID)."""
    if is_wifi_password(c.domain):
        return "Wi-Fi network"
    return c.username or c.domain


def website(c: Credential) -> str:
    return "" if is_wifi_password(c.domain) else c.domain


def in_section(c: Credential, section: str) -> bool:
    wifi = is_wifi_password(c.domain)
    if section == "wifi":
        return wifi
    if wifi:
        return False
    if section == "codes":
        return bool(c.totp)
    if section == "shared":
        return bool(c.group)
    return section == "all"


def matches(c: Credential, query: str) -> bool:
    """Case-insensitive substring match over the fields a person would search by."""
    q = query.strip().lower()
    return not q or any(q in (f or "").lower()
                        for f in (c.title, c.domain, c.username, c.group, c.notes))


def credentials_for(creds: list[Credential], section: str, query: str = "") -> list[Credential]:
    shown = [c for c in creds if in_section(c, section) and matches(c, query)]
    shown.sort(key=lambda c: (title(c).lower(), c.username.lower()))
    return shown


def alias_matches(a, query: str) -> bool:
    q = query.strip().lower()
    return not q or any(q in (f or "").lower()
                        for f in (a.label, a.address, a.note, a.forward_to, a.domain))


def aliases_for(aliases: list, query: str = "") -> list:
    shown = [a for a in aliases if alias_matches(a, query)]
    shown.sort(key=lambda a: (not a.is_active, (a.label or a.address).lower()))
    return shown


def section_counts(creds: list[Credential], aliases: list) -> dict[str, int]:
    counts = {key: sum(in_section(c, key) for c in creds) for key, _ in SECTIONS if key != "hme"}
    counts["hme"] = len(aliases)
    return counts


def relative_time(ts: float | None, now: float | None = None) -> str:
    if not ts:
        return "never"
    delta = max(0, (time.time() if now is None else now) - ts)
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)} min ago"
    if delta < 86400:
        return f"{int(delta // 3600)} h ago"
    days = int(delta // 86400)
    return f"{days} day{'s' if days != 1 else ''} ago"


def sync_status(state: dict | None = None, now: float | None = None) -> tuple[str, bool]:
    """-> (one-line status, is_problem) from the sync pacing state (no network, no secrets)."""
    state = ratelimit.load() if state is None else state
    if not paths.session_file().exists():
        return "Not signed in - run `icp login` in a terminal", True
    if state.get("needs_login"):
        return "Sign-in expired - run `icp login` in a terminal", True
    vault = paths.vault_file()
    last = state.get("last_success") or (vault.stat().st_mtime if vault.exists() else None)
    text = f"Synced {relative_time(last, now)}"
    if state.get("failures") and state.get("last_error"):
        return f"{text} - last sync failed: {state['last_error']}", True
    return text, False
