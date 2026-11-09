"""Remember which login the user picked on each site, so it is offered first next time.
Stored as site -> short hash of the username (no usernames on disk in the clear)."""

from __future__ import annotations

import hashlib
import json

from . import paths, psl


def _file():
    return paths.config_dir() / "choices.json"


def _site(host: str) -> str:
    return psl.registrable_domain(host)


def _tag(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()[:12]


def _load() -> dict:
    try:
        return json.loads(_file().read_text())
    except (OSError, ValueError):
        return {}


def record(host: str, username: str) -> None:
    data = _load()
    data[_site(host)] = _tag(username)
    f = _file()
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.chmod(0o600)
    tmp.replace(f)


def preferred_first(host: str, creds: list) -> list:
    """Stable reorder: the remembered login (if present) moves to the front."""
    tag = _load().get(_site(host))
    if not tag:
        return creds
    return sorted(creds, key=lambda c: 0 if _tag(c.username) == tag else 1)
