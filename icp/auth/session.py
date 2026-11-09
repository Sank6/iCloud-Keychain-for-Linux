"""Encrypted session store: persistent auth artifacts encrypted with a libsodium secret box,
the master key held in the GNOME login keyring (Secret Service), or a 0600 key file if absent."""

import base64
import binascii
import json
import logging
import os

import nacl.exceptions
import nacl.secret
import nacl.utils

from .. import paths
from ..errors import AppleError

logger = logging.getLogger(__name__)

_ATTRS = {"application": "icp", "type": "master-key"}
_LABEL = "ApplePasswords-Linux master key"
_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE


class SessionError(AppleError):
    """The stored session exists but cannot be read with the current master key."""


class KeyringLocked(SessionError):
    """The keyring is locked and the unlock prompt was dismissed. Deliberately NOT a reason to fall
    back to a key file: that would mint a new key and make every stored file undecryptable."""


def _decode_key(stored: bytes | str | None) -> bytes | None:
    if stored is None:
        return None
    raw = stored.encode() if isinstance(stored, str) else bytes(stored)
    if len(raw) == _KEY_SIZE:
        return raw
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return key if len(key) == _KEY_SIZE else None


def _key_from_secret_service() -> bytes | None:
    try:
        import secretstorage
    except Exception:
        return None
    try:
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked() and coll.unlock():  # secretstorage: True means the prompt was dismissed
            raise KeyringLocked("the keyring is locked - unlock it (login keyring) and try again")
        unusable = 0
        for item in coll.search_items(_ATTRS):
            key = _decode_key(item.get_secret())
            if key is not None:
                return key
            unusable += 1
        if unusable:
            logger.warning("keyring holds %d unusable master-key item(s); replacing them", unusable)
        key = nacl.utils.random(_KEY_SIZE)
        coll.create_item(_LABEL, _ATTRS, base64.b64encode(key), replace=True)
        return key
    except KeyringLocked:
        raise
    except Exception as e:  # dbus not running, no keyring, etc.
        logger.warning("Secret Service unavailable (%s); using key file fallback", e)
        return None


def _key_from_file() -> bytes:
    f = paths.fallback_key_file()
    if f.exists():
        key = _decode_key(f.read_bytes())
        if key is not None:
            return key
        logger.warning("master key file %s is unusable; writing a fresh key", f)
    key = nacl.utils.random(_KEY_SIZE)
    _write_private(f, base64.b64encode(key))
    logger.warning("Stored master key at %s (0600) - less safe than the keyring", f)
    return key


def _master_key() -> bytes:
    key = _key_from_secret_service()
    return key if key is not None else _key_from_file()


def _write_private(f, data: bytes) -> None:
    """Write 0600 from creation - secrets must never exist world-readable, even briefly."""
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(f, 0o600)


def save(data: dict) -> None:
    box = nacl.secret.SecretBox(_master_key())
    _write_private(paths.session_file(), box.encrypt(json.dumps(data).encode()))


def load() -> dict | None:
    f = paths.session_file()
    if not f.exists():
        return None
    box = nacl.secret.SecretBox(_master_key())
    try:
        return json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError as e:
        raise SessionError(
            f"cannot decrypt {f} - the master key no longer matches it (the keyring entry was "
            "lost or replaced). Run `icp logout`, then `icp login` to sign in again.") from e


def clear() -> None:
    f = paths.session_file()
    if f.exists():
        f.unlink()
