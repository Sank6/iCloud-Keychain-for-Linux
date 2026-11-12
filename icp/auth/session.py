"""Encrypted session store: persistent auth artifacts encrypted with a libsodium secret box,
the master key held in the GNOME login keyring (Secret Service), or a 0600 key file if absent."""

import base64
import binascii
import json
import logging
import os
import time

import nacl.exceptions
import nacl.secret
import nacl.utils

from .. import account, keyring, paths
from ..errors import SessionError
from ..keyring import KeyringLocked, KeyringUnavailable  # noqa: F401 - re-exported

logger = logging.getLogger(__name__)

_ATTRS = {"application": "icp", "type": "master-key"}
_LABEL = "ApplePasswords-Linux master key"
_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE


class KeyLost(SessionError):
    """Encrypted data exists but its key is missing or unusable. We refuse to mint a new key
    (that would silently orphan the vault); `icp logout --reset-keys` starts over explicitly."""


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


def _encrypted_files() -> list:
    return [f for f in (paths.session_file(), paths.vault_file(), paths.aliases_file())
            if f.exists() and f.stat().st_size > 0]


def _refuse_new_key(where: str) -> None:
    if _encrypted_files():
        raise KeyLost(
            f"the master key is missing from {where} but encrypted data exists "
            f"({', '.join(f.name for f in _encrypted_files())}). Not creating a new key, because "
            "that would make the vault unreadable. Restore the keyring entry (is the right "
            "keyring unlocked?) or run `icp logout --reset-keys` to start over.")


def _file_key() -> bytes | None:
    f = paths.fallback_key_file()
    return _decode_key(f.read_bytes()) if f.exists() else None


def _key_from_secret_service() -> bytes | None:
    """The keyring's key; None when there is no Secret Service at all. Raises KeyringLocked when
    locked/dismissed and KeyLost when the entry is gone but data exists."""
    try:
        coll = keyring.open_collection()
    except KeyringUnavailable as e:
        logger.warning("%s; using key file fallback", e)
        return None
    items = keyring.find(coll, _ATTRS)
    for item in items:
        key = _decode_key(item.get_secret())
        if key is not None:
            return key
    if items:
        logger.warning("keyring holds %d unusable master-key item(s)", len(items))
    # A key from the 0600 file (an earlier run without a keyring) moves into the keyring as-is.
    key = _file_key()
    migrating = key is not None
    if not migrating:
        _refuse_new_key("the keyring")
        key = nacl.utils.random(_KEY_SIZE)
    coll.create_item(_LABEL, _ATTRS, base64.b64encode(key), replace=True)
    if migrating and any(_decode_key(i.get_secret()) == key for i in keyring.find(coll, _ATTRS)):
        paths.fallback_key_file().unlink()   # read back OK: drop the less-safe plaintext copy
        logger.warning("moved the master key from master.key into the keyring")
    return key


def _key_from_file() -> bytes:
    f = paths.fallback_key_file()
    key = _file_key()
    if key is not None:
        return key
    _refuse_new_key(f"the key file {f.name} (and there is no Secret Service)")
    key = nacl.utils.random(_KEY_SIZE)
    _write_private(f, base64.b64encode(key))
    logger.warning("Stored master key at %s (0600) - less safe than the keyring", f)
    return key


def _master_key() -> bytes:
    key = _key_from_secret_service()
    return key if key is not None else _key_from_file()


def reset_keys() -> list[str]:
    """Explicit start-over: set aside (never delete) the encrypted files and forget the key.
    Returns what was done, for display."""
    done = []
    stamp = int(time.time())
    for f in _encrypted_files():
        f.rename(f.with_name(f"{f.name}.lost-{stamp}"))
        done.append(f"moved {f.name} -> {f.name}.lost-{stamp}")
    try:
        coll = keyring.open_collection()
        for item in keyring.find(coll, _ATTRS):
            item.delete()
            done.append("removed master key from the keyring")
    except keyring.KeyringError as e:
        done.append(f"keyring not touched: {e}")
    kf = paths.fallback_key_file()
    if kf.exists():
        kf.unlink()
        done.append("removed master.key")
    return done


def _write_private(f, data: bytes) -> None:
    """Write 0600 from creation (secrets never exist world-readable) and atomically, so a crash or
    a closed window mid-write can never leave a truncated session behind."""
    tmp = f.with_name(f.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, f)


def save(data: dict) -> None:
    """Encrypt and store the session. The Apple ID password goes to the keyring (icp.account)
    when that works and is then left out of the blob; otherwise it stays in the blob."""
    data = dict(data)
    user = data.get("username")
    if user:
        try:
            account.save(user, data.get("password"))
            data.pop("password", None)
        except keyring.KeyringError as e:
            logger.info("Apple ID not stored in the keyring (%s); password stays in session.enc", e)
    box = nacl.secret.SecretBox(_master_key())
    _write_private(paths.session_file(), box.encrypt(json.dumps(data).encode()))


def load() -> dict | None:
    f = paths.session_file()
    if not f.exists():
        return None
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError as e:
        raise SessionError(
            f"cannot decrypt {f} - the master key no longer matches it (the keyring entry was "
            "lost or replaced). Run `icp logout --reset-keys`, then `icp login`.") from e
    if data.get("username") and not data.get("password"):
        user, pw = account.load(interactive=False)
        if pw and user == data["username"]:
            data["password"] = pw
    return data


def clear() -> None:
    """Forget the session: the encrypted blob and the saved Apple ID/password in the keyring."""
    f = paths.session_file()
    if f.exists():
        f.unlink()
    try:
        account.forget()
    except keyring.KeyringError:
        pass
