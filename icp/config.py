"""User configuration: `$XDG_CONFIG_HOME/icp/config.toml` plus environment overrides.

Recognised keys (all optional):
  anisette_url         where the anisette server listens (env ICP_ANISETTE_URL, CLI --anisette)
  mirror_collection    Secret Service collection (label) for the logins mirror (ICP_MIRROR_COLLECTION)

Precedence for every value: explicit argument > environment > config file > built-in default."""

from __future__ import annotations

import ipaddress
import logging
import os
import tomllib
from urllib.parse import urlparse

from . import paths
from .const import DEFAULT_ANISETTE_URL

logger = logging.getLogger(__name__)


def load() -> dict:
    f = paths.config_dir() / "config.toml"
    try:
        with open(f, "rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as e:
        logger.warning("ignoring unreadable %s: %s", f, e)
        return {}


def get(key: str, *, env: str | None = None, explicit: str | None = None,
        default: str | None = None) -> str | None:
    if explicit:
        return explicit
    if env and os.environ.get(env):
        return os.environ[env]
    value = load().get(key)
    return str(value) if value else default


def anisette_url(explicit: str | None = None) -> str:
    return get("anisette_url", env="ICP_ANISETTE_URL", explicit=explicit,
               default=DEFAULT_ANISETTE_URL).rstrip("/")


def is_loopback(url: str) -> bool:
    """True when `url` points at this machine only (localhost / 127.0.0.0/8 / ::1)."""
    host = urlparse(url if "//" in url else f"//{url}").hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
