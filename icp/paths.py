"""Filesystem locations. Everything lives under $XDG_CONFIG_HOME/icp."""

import os
from pathlib import Path


def private_dir(path) -> Path:
    """Create `path` (and parents) readable by this user only."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def write_private(path, text: str, *, executable: bool = False) -> Path:
    """Write `text` to `path` atomically with owner-only permissions (0600, or 0700 for a
    program). Launchers and command files live here and are executed by the browser or the
    app, so another local user must never be able to replace them."""
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700 if executable else 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o700 if executable else 0o600)
    os.replace(tmp, p)
    return p


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = Path(base) / "icp"
    d.mkdir(parents=True, exist_ok=True)
    # Tokens and identity are sensitive; keep the directory private.
    os.chmod(d, 0o700)
    return d


def device_file() -> Path:
    return config_dir() / "device.json"


def session_file() -> Path:
    return config_dir() / "session.enc"


def fallback_key_file() -> Path:
    return config_dir() / "master.key"


def vault_file() -> Path:
    return config_dir() / "vault.enc"


def aliases_file() -> Path:
    return config_dir() / "aliases.enc"


def sync_lock_file() -> Path:
    return config_dir() / "sync.lock"


def open_sync_lock():
    """The sync lock file, opened for flock() and readable by this user only."""
    f = open(sync_lock_file(), "w")
    os.chmod(sync_lock_file(), 0o600)
    return f


def sync_attempt_file() -> Path:
    return config_dir() / "sync.attempt"
