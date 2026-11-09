"""Sync status, written by `icp sync` and read by the doctor, the native host and the popup.

A small JSON file (no secrets): when the last sync was tried, when it last worked, the last error
and how many failures in a row. A desktop notification fires after repeated failures so a broken
sync is never silent."""

from __future__ import annotations

import json
import shutil
import subprocess
import time

from . import paths

NOTIFY_AFTER = 3  # consecutive failures before a desktop notification


def _file():
    return paths.config_dir() / "sync-status.json"


def read() -> dict:
    try:
        return json.loads(_file().read_text())
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    f = _file()
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(f)


def record_success() -> None:
    now = time.time()
    _write({**read(), "last_attempt": now, "last_success": now, "last_error": "",
            "failures": 0, "hint": ""})


def record_failure(message: str) -> dict:
    cur = read()
    data = {**cur, "last_attempt": time.time(), "last_error": message,
            "failures": int(cur.get("failures", 0)) + 1, "hint": explain(message)}
    _write(data)
    if data["failures"] == NOTIFY_AFTER:
        notify("iCloud Passwords sync is failing",
               data["hint"] or message)
    return data


def explain(message: str) -> str:
    """A plain-language next step for common failures. Hints are best-effort guesses about the
    cause, not Apple's own wording."""
    m = (message or "").lower()
    if "not signed in" in m or "not joined" in m:
        return "Run `icp login`."
    if "anisette" in m or "connection refused" in m or "6969" in m:
        return "The anisette server looks unreachable. Start it (see `icp doctor`)."
    if "-80045" in m or "sign-in" in m or "re-authenticating" in m or "token" in m:
        return ("Apple refused the saved sign-in. Run `icp login` again; if it keeps failing, "
                "check that the anisette server is running.")
    if "2fa" in m:
        return "Apple wants a 2FA code. Run `icp login` in a terminal."
    if "cannot decrypt" in m or "master key" in m:
        return "The keyring entry changed. Run `icp logout` then `icp login`."
    return ""


def notify(title: str, body: str) -> None:
    exe = shutil.which("notify-send")
    if not exe:
        return
    try:
        subprocess.run([exe, "-a", "iCloud Passwords", "-i", "dialog-password", title, body],
                       timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
