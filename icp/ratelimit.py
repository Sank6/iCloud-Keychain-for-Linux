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
  hint                         plain-language next step for last_error
  circuit                      per-host HTTP circuit breaker (see circuit_* below)

Every save also publishes the display subset to sync-status.json, which the Rust agent, the native
host and the browser popup read - that file is derived, never written anywhere else.
"""

from __future__ import annotations

import json
import os
import random
import time

from . import paths

MIN_INTERVAL = int(os.environ.get("ICP_MIN_SYNC_INTERVAL", "300"))   # 5 min
BACKOFF_BASE = 300                                                    # first failure: 5 min
BACKOFF_MAX = 6 * 3600                                                # cap: 6 h
STOP_AFTER = 5       # consecutive failures after which unattended syncs stop until `icp login`
CIRCUIT_AFTER = 3    # consecutive 403/4xx/5xx from one host before unattended calls to it pause
CIRCUIT_BASE = 1800  # first pause: 30 min, doubling per re-trip, capped at BACKOFF_MAX
_PUBLISHED = ("last_attempt", "last_success", "failures", "last_error", "hint", "needs_login")
HME_INTERVAL = 24 * 3600            # Hide My Email web sign-in at most once a day from `sync`


def _file():
    return paths.config_dir() / "state.json"


def load() -> dict:
    try:
        data = json.loads(_file().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def save(state: dict) -> None:
    """Persist pacing state. The circuit breaker is owned by the circuit_* functions (other
    processes may have tripped it since `state` was loaded), so it is carried over, not overwritten."""
    if "circuit" in (cur := load()):
        state["circuit"] = cur["circuit"]
    _write(_file(), state)
    from . import status
    _write(status.status_file(), {k: state.get(k, "" if k in ("last_error", "hint") else 0)
                                  for k in _PUBLISHED})


def backoff(attempt: int, base: float, cap: float, *, retry_after: float | None = None,
            jitter: float = 0.0) -> float:
    """Exponential delay for the `attempt`-th retry (0-based): base * 2**attempt up to `cap`,
    never shorter than the server's Retry-After, plus up to +jitter (a fraction) of random spread
    so unattended clients don't synchronise."""
    delay = min(base * 2 ** min(attempt, 30), cap)
    if retry_after:
        delay = max(delay, min(float(retry_after), cap))
    return delay * (1 + jitter * random.random())


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
    state.update(last_success=now, last_attempt=now, failures=0, next_allowed=now + MIN_INTERVAL,
                 needs_login=False, last_error="", hint="")
    save(state)


def record_failure(state: dict, message: str, *, auth: bool = False, transient: bool = False,
                   retry_after: float | None = None, now: float | None = None,
                   jitter: float = 0.0) -> None:
    """Exponential backoff (5 min, 10, 20 ... 6 h), at least Apple's Retry-After.
    `transient` (we are offline, or a circuit is open) only delays the next try: it does not
    count toward the stop-after-N-failures rule, so a laptop on a plane never demands a sign-in."""
    from . import status
    now = time.time() if now is None else now
    if transient:
        state.update(next_allowed=now + max(BACKOFF_BASE, retry_after or 0), last_attempt=now,
                     last_error=message[:200], hint=status.explain(message))
        save(state)
        return
    failures = int(state.get("failures", 0)) + 1
    delay = backoff(failures - 1, BACKOFF_BASE, BACKOFF_MAX, retry_after=retry_after, jitter=jitter)
    state.update(failures=failures, next_allowed=now + delay, last_error=message[:200],
                 last_attempt=now, hint=status.explain(message))
    if auth or failures >= STOP_AFTER:
        state["needs_login"] = True
    save(state)


def clear_login_block() -> None:
    """After a successful interactive `icp login`."""
    state = load()
    state.update(needs_login=False, failures=0, next_allowed=0, last_error="", hint="",
                 circuit={})
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


# ---- per-host circuit breaker (used by icp/net.py) --------------------------------------------

def _circuit_update(host: str, fn) -> None:
    state = load()
    circuit = state.setdefault("circuit", {})
    before = dict(circuit.get(host) or {})
    entry = dict(before or {"fails": 0, "trips": 0, "open_until": 0, "last": ""})
    fn(entry)
    if entry["fails"] == 0 and entry["open_until"] == 0 and entry["trips"] == 0:
        circuit.pop(host, None)
    else:
        circuit[host] = entry
    if circuit.get(host, {}) != before:
        _write(_file(), state)


def circuit_remaining(host: str, now: float | None = None) -> float:
    """Seconds an unattended call to `host` must still wait (0 = closed)."""
    now = time.time() if now is None else now
    entry = (load().get("circuit") or {}).get(host) or {}
    return max(0.0, float(entry.get("open_until", 0)) - now)


def circuit_record(host: str, ok: bool, detail: str = "", now: float | None = None) -> None:
    """A success closes the breaker; CIRCUIT_AFTER consecutive failures open it for
    CIRCUIT_BASE * 2**trips seconds (the pause doubles each time it re-trips)."""
    now = time.time() if now is None else now

    def upd(e):
        if ok:
            e.update(fails=0, trips=0, open_until=0, last="")
            return
        e["fails"] += 1
        e["last"] = detail[:80]
        if e["fails"] >= CIRCUIT_AFTER:
            e["open_until"] = now + backoff(e["trips"], CIRCUIT_BASE, BACKOFF_MAX)
            e["trips"] += 1
            e["fails"] = 0
    _circuit_update(host, upd)


def circuit_status(now: float | None = None) -> str:
    """Human summary of open breakers ("" when all closed)."""
    now = time.time() if now is None else now
    parts = [f"{h} ({e.get('last') or 'errors'}, {int((e['open_until'] - now) / 60) + 1} min left)"
             for h, e in (load().get("circuit") or {}).items() if e.get("open_until", 0) > now]
    return "; ".join(parts)
