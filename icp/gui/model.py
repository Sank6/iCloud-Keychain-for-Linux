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


def autofill_summary(st: dict) -> tuple[str, str]:
    """Heading and body for the "Browser autofill" panel, from applehost_install.status()."""
    if not st["hosts"]:
        return ("No supported browser found",
                "Install a Chromium-based browser (Chrome, Chromium, Helium, Brave, Edge...), "
                "open it once, then run `icp setup`.")
    broken = [f"{label}: {problem}" for label, ok, problem in st["hosts"] if not ok]
    if broken:
        return "Browser integration needs repair", "\n".join(broken) + "\n\nRun `icp setup`."
    names = ", ".join(label for label, _ok, _p in st["hosts"])
    mode = st["mode"]
    if not st["installed"] and mode != "unpacked":
        return ("Install Apple's extension",
                f"Install \"iCloud Passwords\" from the Chrome Web Store in {names}. It is "
                "patched for Linux automatically as soon as it appears.")
    if mode == "inplace" and st["disabled"]:
        return ("Your browser disabled the patched extension",
                "Run `icp setup --apple-extension unpacked`, then load that copy with Developer "
                "mode -> Load unpacked.")
    if mode == "inplace" and st.get("stale_cache"):
        return ("Reload the extension to finish",
                "The extension is patched, but your browser is still running its original, "
                "unpatched script, so it shows a blank window. Open the extensions page and "
                "reload iCloud Passwords (restarting the browser does not refresh it).")
    if mode == "inplace":
        return ("Apple's extension is ready",
                f"{names}: Apple's iCloud Passwords extension is patched for Linux and re-patched "
                "after every update. Click its icon and type the 6-digit pairing code shown in a "
                "notification (once per browser start). If it was installed just now, reload it "
                "on the extensions page first.")
    if mode == "unpacked":
        return ("Apple's extension is ready (separate copy)",
                f"{names}: load the copy once (extensions page, Developer mode, Load unpacked) and "
                "turn the store version off. Re-run `icp setup --apple-extension unpacked` after "
                "Apple updates the extension.")
    return ("Apple's extension is not patched yet",
            "Run `icp setup`: it patches the installed extension and keeps it patched.")


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
