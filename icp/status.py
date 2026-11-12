"""Sync status for displays (doctor, the native host/agent, the browser popup, the GTK app).

The data lives in `ratelimit`'s state.json, which publishes the display fields to sync-status.json
on every save; this module only reads that projection, turns error text into a next step and
sends the desktop notification. No secrets in either file."""

from __future__ import annotations

import json
import shutil
import subprocess

from . import paths

NOTIFY_AFTER = 3  # consecutive failures before a desktop notification


def status_file():
    return paths.config_dir() / "sync-status.json"


def read() -> dict:
    try:
        data = json.loads(status_file().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def explain(message: str) -> str:
    """A plain-language next step for common failures. Hints are best-effort guesses about the
    cause, not Apple's own wording."""
    m = (message or "").lower()
    if "not signed in" in m or "not joined" in m:
        return "Sign in: run `icp login --gui`."
    if "blocked by apple" in m or "http 403" in m:
        return ("Apple is refusing the request (HTTP 403). Retrying makes blocks last longer: "
                "check `icp doctor` (anisette), wait, then sign in again.")
    if "anisette" in m or "connection refused" in m or "6969" in m:
        return "The anisette server looks unreachable. Start it (see `icp doctor`)."
    if "cannot reach" in m or "network" in m:
        return "No network connection to Apple. It will retry on its own."
    if "-80045" in m or "sign-in" in m or "re-authenticating" in m or "token" in m or "login needed" in m:
        return ("Apple refused the saved sign-in. Sign in again (`icp login --gui`); if it keeps "
                "failing, check that the anisette server is running.")
    if "2fa" in m:
        return "Apple wants a 2FA code. Run `icp login --gui`."
    if "cannot decrypt" in m or "master key" in m:
        return "The keyring entry changed. Run `icp logout --reset-keys` then `icp login`."
    return ""


def maybe_notify(state: dict) -> None:
    """Desktop notification when a sign-in is needed or sync keeps failing (once per threshold)."""
    n = int(state.get("failures", 0))
    if state.get("needs_login") and n in (1, NOTIFY_AFTER):
        notify("iCloud Passwords: sign-in needed", state.get("hint") or state.get("last_error", ""))
    elif n == NOTIFY_AFTER:
        notify("iCloud Passwords sync is failing", state.get("hint") or state.get("last_error", ""))


def notify(title: str, body: str) -> None:
    exe = shutil.which("notify-send")
    if not exe:
        return
    try:
        subprocess.run([exe, "-a", "iCloud Passwords", "-i", "dialog-password", title, body],
                       timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
