"""Sync pacing: minimum interval, exponential backoff and a "needs login" stop.

Unattended syncs (timers, the browser host, a desktop shell) must never hammer Apple: every sync
re-mints a CloudKit token and fetches ~20 zones, and a failing auth path can mean repeated
password sign-ins - which risks rate limits, 2FA pushes to the user's devices or an account lock.

State lives in ~/.config/icp/state.json (0600, no secrets):
  last_attempt / last_success  unix seconds
  failures                     consecutive failed syncs (reset on success)
  next_allowed                 unix seconds before which a sync is refused (unless forced)
  needs_login                  auth is gone; background syncs stop until `icp login`
  last_error                   short message for status displays (never contains secrets)
"""

from __future__ import annotations

import json
import os
import time

from . import paths

MIN_INTERVAL = int(os.environ.get("ICP_MIN_SYNC_INTERVAL", "300"))   # 5 min
BACKOFF_BASE = 300                                                    # first failure: 5 min
BACKOFF_MAX = 6 * 3600                                                # cap: 6 h
HME_INTERVAL = 24 * 3600            # Hide My Email web sign-in at most once a day from `sync`


def _file():
    return paths.config_dir() / "state.json"


def load() -> dict:
    try:
        data = json.loads(_file().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(state: dict) -> None:
    f = _file()
    tmp = f.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, f)


def may_sync(state: dict, *, force: bool, background: bool, now: float | None = None
             ) -> tuple[bool, str]:
    """(allowed, reason). `force` skips the interval/backoff but never the login stop for
    background runs - only an interactive run may try to repair auth."""
    now = time.time() if now is None else now
    if state.get("needs_login") and background:
        return False, "iCloud login needed - run `icp login`"
    if force:
        return True, ""
    wait_until = max(state.get("next_allowed", 0), state.get("last_attempt", 0) + MIN_INTERVAL)
    if now < wait_until:
        return False, f"too early - next sync allowed in {int(wait_until - now)} s"
    return True, ""


def record_attempt(state: dict, now: float | None = None) -> None:
    state["last_attempt"] = time.time() if now is None else now
    save(state)


def record_success(state: dict, now: float | None = None) -> None:
    now = time.time() if now is None else now
    state.update(last_success=now, failures=0, next_allowed=now + MIN_INTERVAL,
                 needs_login=False, last_error="")
    save(state)


def record_failure(state: dict, message: str, *, auth: bool = False,
                   retry_after: float | None = None, now: float | None = None) -> None:
    """Exponential backoff (5 min, 10, 20 ... 6 h), at least Apple's Retry-After."""
    now = time.time() if now is None else now
    failures = int(state.get("failures", 0)) + 1
    delay = min(BACKOFF_BASE * 2 ** (failures - 1), BACKOFF_MAX)
    if retry_after:
        delay = max(delay, min(float(retry_after), BACKOFF_MAX))
    state.update(failures=failures, next_allowed=now + delay, last_error=message[:200])
    if auth:
        state["needs_login"] = True
    save(state)


def clear_login_block() -> None:
    """After a successful interactive `icp login`."""
    state = load()
    state.update(needs_login=False, failures=0, next_allowed=0, last_error="")
    save(state)


def hme_due(state: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return now - state.get("hme_attempt", 0) >= HME_INTERVAL


def mark_hme(state: dict, now: float | None = None) -> None:
    state["hme_attempt"] = time.time() if now is None else now
    save(state)


def retry_after_seconds(resp) -> float | None:
    """Retry-After as seconds (numeric form only; the HTTP-date form is rare for Apple)."""
    value = getattr(resp, "headers", {}).get("Retry-After") if resp is not None else None
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None
