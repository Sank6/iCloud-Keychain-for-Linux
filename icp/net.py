"""The one HTTP layer for every call to Apple (and its Hide-My-Email/idmsa web hosts).

What it adds on top of `requests`:
  - timeouts everywhere (connect, read), so nothing hangs a sync or the GUI
  - a minimum gap between requests to the same host (per process)
  - bounded retries with exponential backoff + jitter for transport errors, 429 and 5xx, honouring
    Retry-After (a long Retry-After is not slept on: it is raised so the caller schedules it)
  - NO retries for 401/403 or any other 4xx: auth problems are not transient and repeating them
    risks locking the account
  - a per-host circuit breaker (icp.ratelimit) that stops *unattended* calls after repeated
    403/4xx/5xx; interactive runs bypass it and a success closes it
  - typed errors, and logs that carry only method, host+path, status and size (never headers,
    query strings or bodies)

Call `request()` instead of `requests.get/post`; `set_background(True)` marks unattended runs."""

from __future__ import annotations

import logging
import os
import time
from urllib.parse import urlparse

import requests

from . import ratelimit
from .errors import AppleError

logger = logging.getLogger(__name__)

TIMEOUT = (5, 30)                   # connect, read (seconds)
MIN_GAP = float(os.environ.get("ICP_HTTP_MIN_GAP", "0.25"))  # seconds between calls per host
RETRY_BASE, RETRY_CAP = 1.0, 30.0   # inline retry delays; a longer Retry-After is raised instead

_background = False
_last: dict[str, float] = {}


class AppleNetError(AppleError):
    """Base for HTTP-layer failures. `kind` is stable for programs; the message is for people."""
    kind = "error"

    def __init__(self, message: str, *, status: int | None = None,
                 retry_after: float | None = None, host: str = ""):
        super().__init__(message)
        self.status, self.retry_after, self.host = status, retry_after, host


class NetworkDown(AppleNetError):
    """Could not reach the host at all (offline, DNS, TLS, timeout). Not Apple's fault."""
    kind = "network"


class AuthRejected(AppleNetError):
    """HTTP 401: the token/credentials are no longer accepted. Never retried."""
    kind = "auth"


class BlockedByApple(AppleNetError):
    """HTTP 403: Apple refused the request itself. Never retried."""
    kind = "blocked"


class Throttled(AppleNetError):
    """HTTP 429, or a Retry-After too long to wait inline."""
    kind = "throttled"


class ServerError(AppleNetError):
    """HTTP 5xx after the allowed retries."""
    kind = "server"


class CircuitOpen(AppleNetError):
    """Unattended call refused: this host kept answering errors, so calls are paused."""
    kind = "circuit"


def set_background(flag: bool) -> None:
    global _background
    _background = flag


def safe_url(url: str) -> str:
    """host + path only: no scheme credentials, query string or fragment."""
    u = urlparse(url)
    return f"{u.hostname or '?'}{u.path}"


def blocked_message(what: str, status: int = 403) -> str:
    return (f"Apple refused {what} (HTTP {status}) before looking at any password. That points at "
            "how the request looks (anisette data or device identity) or a temporary block, not "
            "at your credentials. Check `icp doctor`, wait before trying again (repeating makes "
            "blocks last longer), and avoid retrying from scripts.")


def _pace(host: str) -> None:
    gap = _last.get(host, 0.0) + MIN_GAP - time.monotonic()
    if gap > 0:
        time.sleep(gap)
    _last[host] = time.monotonic()


def _retry_after(resp) -> float | None:
    return ratelimit.retry_after_seconds(resp)


def request(method: str, url: str, *, session=None, retries: int = 0, timeout=TIMEOUT,
            sleep=time.sleep, **kwargs) -> requests.Response:
    """Perform one logical HTTP call. Returns the response for every status the caller should
    interpret itself (2xx, 3xx, 401, 403, other 4xx); raises for transport failure, a tripped
    breaker, and 429/5xx once retries are used up. `session` is a requests.Session (cookies)."""
    host = urlparse(url).hostname or ""
    if _background:
        wait = ratelimit.circuit_remaining(host)
        if wait:
            raise CircuitOpen(
                f"{host} kept answering errors; unattended calls are paused for another "
                f"{int(wait / 60) + 1} min (an interactive `icp login` or `icp sync` retries now)",
                host=host, retry_after=wait)
    send = getattr(session if session is not None else requests, method.lower())
    for attempt in range(retries + 1):
        last = attempt == retries
        _pace(host)
        started = time.monotonic()
        try:
            resp = send(url, timeout=timeout, **kwargs)
        except requests.RequestException as e:
            logger.info("HTTP %s %s failed: %s", method.upper(), safe_url(url), type(e).__name__)
            if last:
                raise NetworkDown(f"cannot reach {host} ({type(e).__name__}); check your "
                                  "connection", host=host) from None
            sleep(ratelimit.backoff(attempt, RETRY_BASE, RETRY_CAP, jitter=0.5))
            continue
        status = resp.status_code
        logger.info("HTTP %s %s -> %s (%d bytes, %.2fs)", method.upper(), safe_url(url), status,
                    len(getattr(resp, "content", b"") or b""), time.monotonic() - started)
        _count(host, status)
        if status != 429 and status < 500:
            return resp
        wait = _retry_after(resp)
        if last or (wait and wait > RETRY_CAP):
            cls = Throttled if status == 429 or wait else ServerError
            raise cls(f"{host} answered HTTP {status} ({'throttled' if cls is Throttled else 'unavailable'})",
                      status=status, retry_after=wait, host=host)
        sleep(ratelimit.backoff(attempt, RETRY_BASE, RETRY_CAP, retry_after=wait, jitter=0.5))
    raise AssertionError("unreachable")  # pragma: no cover


def _count(host: str, status: int) -> None:
    """Feed the breaker: 401 is an expired token (handled by login), everything else >= 400
    counts toward pausing unattended calls."""
    try:
        if status < 400:
            ratelimit.circuit_record(host, True)
        elif status != 401:
            ratelimit.circuit_record(host, False, f"HTTP {status}")
    except OSError:  # a read-only config dir must never break the request itself
        pass


def auth_error(resp, what: str) -> AppleNetError | None:
    """The typed error for the statuses `request()` hands back for the caller to interpret
    (401 -> AuthRejected, 403 -> BlockedByApple), else None. Callers raise their own error type
    carrying `.kind`, so messages are consistent across GSA, iCloud, CloudKit and the web hosts."""
    host = urlparse(getattr(resp, "url", "") or "").hostname or ""
    if resp.status_code == 401:
        return AuthRejected(f"{what}: Apple no longer accepts the saved sign-in (HTTP 401)",
                            status=401, host=host)
    if resp.status_code == 403:
        return BlockedByApple(blocked_message(what), status=403, host=host)
    return None
