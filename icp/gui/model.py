"""Display logic of the Passwords window that needs no toolkit (so it can be unit-tested):
search/sort of logins, "how long ago" text, and the sync / sign-in state shown in the window,
the browser popup and the status files."""

from __future__ import annotations

import time
from dataclasses import dataclass


def ago(ts: float, now: float | None = None) -> str:
    d = max(0, (time.time() if now is None else now) - ts)
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if d >= n:
            v = int(d // n)
            return f"{v} {unit}{'' if v == 1 else 's'} ago"
    return "just now"


def matches(cred, query: str) -> bool:
    """Every whitespace-separated word of `query` must appear (case-insensitive) in the title,
    website or username. Notes and passwords are deliberately not searched."""
    words = query.lower().split()
    if not words:
        return True
    hay = f"{cred.title} {cred.domain} {cred.username}".lower()
    return all(w in hay for w in words)


def sort_key(cred) -> tuple:
    return ((cred.title or cred.domain).lower(), cred.username.lower())


def visible(creds, query: str) -> list:
    return sorted((c for c in creds if matches(c, query)), key=sort_key)


@dataclass
class SyncState:
    kind: str          # "ok" | "stale" | "failing" | "signin" | "never"
    text: str          # one line for the sidebar footer
    banner: str = ""   # non-empty: show the banner with this title
    action: str = ""   # "login" | "sync" | "" - what the banner button does


STALE_AFTER = 3 * 86400


def sync_state(status: dict, n: int, *, signed_in: bool, now: float | None = None) -> SyncState:
    """Summarise ~/.config/icp/sync-status.json (plus whether a session exists)."""
    now = time.time() if now is None else now
    hint = status.get("hint") or ""
    if not signed_in or status.get("needs_login"):
        why = status.get("last_error") or "you are not signed in to iCloud"
        return SyncState("signin", f"{n} logins · sign-in needed",
                         banner=f"Sign-in needed: {why}"[:160], action="login")
    if status.get("failures"):
        return SyncState("failing", f"{n} logins · sync failing" + (f": {hint}" if hint else ""),
                         banner=f"Sync is failing. {hint}".strip(), action="sync")
    last = status.get("last_success")
    if not last:
        return SyncState("never", f"{n} logins · not synced yet")
    if now - last > STALE_AFTER:
        return SyncState("stale", f"{n} logins · last synced {ago(last, now)}",
                         banner=f"Logins are {ago(last, now).replace(' ago', '')} old.",
                         action="sync")
    return SyncState("ok", f"{n} logins · synced {ago(last, now)}")
