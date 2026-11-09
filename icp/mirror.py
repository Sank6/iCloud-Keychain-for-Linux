"""One-way mirror of the vault's logins into the Secret Service (gnome-keyring / KWallet), so they
appear in Seahorse ("Passwords and Keys") and are visible to libsecret apps.

iCloud stays the source of truth: every sync adds, updates and removes mirrored items to match.
Only items this module created (application=icp, type=login) are ever touched. Passwords go in the
secret; TOTP seeds and notes are deliberately NOT mirrored. Disable with ICP_NO_MIRROR=1."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass

from . import config, keyring, paths

logger = logging.getLogger(__name__)

OWN = {"application": "icp", "type": "login"}  # attributes marking items we manage


@dataclass
class Result:
    added: int = 0
    updated: int = 0
    removed: int = 0
    skipped: str = ""  # why nothing happened ("" = ran)

    def __str__(self) -> str:
        if self.skipped:
            return f"mirror skipped: {self.skipped}"
        return f"mirror: {self.added} added, {self.updated} updated, {self.removed} removed"


def item_id(domain: str, username: str) -> str:
    return hashlib.sha256(f"{domain.lower()}\0{username}".encode()).hexdigest()[:24]


def _label(c) -> str:
    name = c.title or c.domain
    return f"{name} ({c.username})" if c.username else name


def _desired(credentials) -> dict[str, tuple[str, dict, bytes]]:
    """id -> (label, attributes, secret). Duplicates (same site+user) keep the most recent."""
    out: dict[str, tuple[float, str, dict, bytes]] = {}
    for c in credentials:
        if not c.domain or not c.password:
            continue
        key = item_id(c.domain, c.username)
        if key in out and out[key][0] >= c.recency:
            continue
        attrs = {**OWN, "icp-id": key, "xdg:schema": "org.gnome.keyring.NetworkPassword",
                 "server": c.domain.lower(), "protocol": "https"}
        if c.username:
            attrs["user"] = c.username
        out[key] = (c.recency, _label(c), attrs, c.password.encode())
    return {k: v[1:] for k, v in out.items()}


def reconcile(collection, credentials) -> Result:
    """Make the managed items in `collection` match `credentials`. An empty `credentials` never
    wipes existing items (an empty list usually means the vault failed to load, not that every
    login was deleted); use `remove_all` for that."""
    want = _desired(credentials)
    res = Result()
    items = list(collection.search_items(OWN))
    if not want and items:
        return Result(skipped="vault has no logins; kept the existing mirrored items")
    seen = set()
    for item in items:
        key = item.get_attributes().get("icp-id")
        if key not in want or key in seen:
            item.delete()  # gone from iCloud, or a duplicate
            res.removed += 1
            continue
        seen.add(key)
        label, attrs, secret = want[key]
        changed = False
        if item.get_label() != label:
            item.set_label(label)
            changed = True
        if item.get_secret() != secret:
            item.set_secret(secret)
            changed = True
        if changed:
            res.updated += 1
    for key, (label, attrs, secret) in want.items():
        if key not in seen:
            collection.create_item(label, attrs, secret, replace=False)
            res.added += 1
    return res


def fingerprint(credentials) -> str:
    """Digest of what the mirror should contain (ids, labels, secrets) - not reversible."""
    h = hashlib.sha256()
    for key, (label, _, secret) in sorted(_desired(credentials).items()):
        h.update(f"{key}\0{label}\0".encode() + hashlib.sha256(secret).digest())
    return h.hexdigest()


def _state_file():
    return paths.config_dir() / "mirror.json"


def _last_fingerprint() -> str:
    try:
        return json.loads(_state_file().read_text()).get("fingerprint", "")
    except (OSError, ValueError):
        return ""


def _remember(fp: str) -> None:
    f = _state_file()
    f.write_text(json.dumps({"fingerprint": fp}))
    f.chmod(0o600)


def collection_name() -> str | None:
    return config.get("mirror_collection", env="ICP_MIRROR_COLLECTION")


def sync_to_keyring(credentials, *, interactive: bool, force: bool = True) -> Result:
    """Mirror into the configured (default: the default) collection. A locked keyring is only
    unlocked when `interactive` (a prompt can't be answered from a background sync). With
    force=False (the automatic run after a sync) nothing is touched while the vault is unchanged
    since the last successful mirror."""
    if os.environ.get("ICP_NO_MIRROR"):
        return Result(skipped="disabled by ICP_NO_MIRROR")
    fp = fingerprint(credentials)
    if not force and fp and fp == _last_fingerprint():
        return Result(skipped="unchanged since the last mirror")
    try:
        res = reconcile(keyring.open_collection(collection_name(), interactive=interactive),
                        credentials)
    except keyring.KeyringLocked as e:
        return Result(skipped=f"{e} (run `icp mirror` to unlock it)")
    except keyring.KeyringUnavailable as e:
        return Result(skipped=str(e))
    except Exception as e:  # noqa: BLE001 - a half-failed mirror must not break the sync
        logger.warning("mirror failed: %s", e)
        return Result(skipped=f"keyring error ({type(e).__name__}: {e})")
    if not res.skipped:
        _remember(fp)
    return res


def remove_all(*, interactive: bool = True) -> int:
    """Delete every item this module created (used by `icp logout`). Foreign items are never
    touched. Returns the count; a missing/locked keyring means there is nothing to remove."""
    try:
        coll = keyring.open_collection(collection_name(), interactive=interactive)
    except keyring.KeyringError:
        return 0
    n = 0
    for item in list(coll.search_items(OWN)):
        item.delete()
        n += 1
    try:
        _state_file().unlink()
    except OSError:
        pass
    return n
