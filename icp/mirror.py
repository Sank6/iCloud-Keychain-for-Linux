"""One-way mirror of the vault's logins into the Secret Service (gnome-keyring / KWallet), so they
appear in Seahorse ("Passwords and Keys") and are visible to libsecret apps.

iCloud stays the source of truth: every sync adds, updates and removes mirrored items to match.
Only items this module created (application=icp, type=login) are ever touched. Passwords go in the
secret; TOTP seeds and notes are deliberately NOT mirrored. Disable with ICP_NO_MIRROR=1."""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

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
    """Make the managed items in `collection` match `credentials`."""
    want = _desired(credentials)
    res = Result()
    seen = set()
    for item in list(collection.search_items(OWN)):
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


def sync_to_keyring(credentials, *, interactive: bool) -> Result:
    """Mirror into the default collection. A locked keyring is only unlocked when `interactive`
    (a prompt can't be answered from a background sync)."""
    if os.environ.get("ICP_NO_MIRROR"):
        return Result(skipped="disabled by ICP_NO_MIRROR")
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            if not interactive:
                return Result(skipped="keyring is locked (run `icp mirror` to unlock it)")
            if coll.unlock():  # True = the prompt was dismissed
                return Result(skipped="keyring unlock was dismissed")
        return reconcile(coll, credentials)
    except Exception as e:
        logger.warning("mirror failed: %s", e)
        return Result(skipped=f"Secret Service unavailable ({e})")
