"""Encrypted session store: persistent auth artifacts encrypted with a libsodium secret box.

The master key is held in the desktop login keyring when available:
  - GNOME / other Secret Service providers (via keyring or secretstorage)
  - KDE Plasma (KWallet, via the keyring library)
falling back to a 0600 key file under $XDG_CONFIG_HOME/icp/ when no keyring is reachable.
"""

from __future__ import annotations

import base64
import json
import logging

import nacl.secret
import nacl.utils

from .. import paths

logger = logging.getLogger(__name__)

# keyring service / username (string API; binary key is base64-encoded)
_KEYRING_SERVICE = "icp-linux"
_KEYRING_USERNAME = "master-key"

# Legacy Secret Service attributes (GNOME keyring items created by older icp builds)
_SS_ATTRS = {"application": "icp", "type": "master-key"}
_SS_LABEL = "ApplePasswords-Linux master key"


def _b64(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def _from_b64(s: str) -> bytes | None:
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if len(raw) != nacl.secret.SecretBox.KEY_SIZE:
        return None
    return raw


def _key_from_keyring() -> bytes | None:
    """Cross-desktop keyring: GNOME Secret Service, KDE KWallet, macOS Keychain, etc."""
    try:
        import keyring
        from keyring.errors import KeyringError
    except Exception:
        return None
    try:
        stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        if stored:
            key = _from_b64(stored)
            if key is not None:
                return key
            logger.warning("keyring entry for %s is not a valid master key; ignoring",
                           _KEYRING_SERVICE)
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, _b64(key))
        # Confirm the backend actually persisted it (some fail backends silently no-op).
        check = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        if check != _b64(key):
            logger.warning("keyring backend did not persist the master key; trying next store")
            return None
        return key
    except Exception as e:  # KeyringError, dbus failures, locked wallet, etc.
        logger.warning("Desktop keyring unavailable (%s); trying legacy Secret Service", e)
        return None

def _key_from_secret_service() -> bytes | None:
    """Legacy path: direct org.freedesktop.secrets (GNOME keyring / older icp installs).

    Kept so existing GNOME users keep their vault without re-login after upgrading.
    New installs prefer the keyring library above (which also covers KWallet on KDE).
    """
    try:
        import secretstorage
    except Exception:
        return None
    try:
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            coll.unlock()
        for item in coll.search_items(_SS_ATTRS):
            return item.get_secret()
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        coll.create_item(_SS_LABEL, _SS_ATTRS, key, replace=True)
        return key
    except Exception as e:  # dbus not running, no keyring, etc.
        logger.warning("Secret Service unavailable (%s); using key file fallback", e)
        return None


def _migrate_ss_key_to_keyring(key: bytes) -> None:
    """Best-effort: copy a legacy Secret Service key into the cross-desktop keyring."""
    try:
        import keyring
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, _b64(key))
    except Exception:
        pass

def _master_key() -> bytes:
    key = _key_from_keyring()
    if key is not None:
        return key

    # Existing GNOME install: recover the key from Secret Service and migrate it.
    key = _key_from_secret_service()
    if key is not None:
        _migrate_ss_key_to_keyring(key)
        return key

    f = paths.fallback_key_file()
    if f.exists():
        return f.read_bytes()
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    f.write_bytes(key)
    f.chmod(0o600)
    logger.warning("Stored master key at %s (0600) - less safe than the desktop keyring", f)
    return key


def save(data: dict) -> None:
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps(data).encode())
    f = paths.session_file()
    f.write_bytes(blob)
    f.chmod(0o600)


def load() -> dict | None:
    f = paths.session_file()
    if not f.exists():
        return None
    box = nacl.secret.SecretBox(_master_key())
    return json.loads(box.decrypt(f.read_bytes()).decode())


def clear() -> None:
    f = paths.session_file()
    if f.exists():
        f.unlink()
