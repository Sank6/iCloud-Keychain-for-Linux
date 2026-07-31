"""Encrypted session store backed by a libsodium secret box.

The random SecretBox master key is stored in ``pass`` (password-store), so the
application is not coupled to GNOME Secret Service or any desktop environment.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess

import nacl.secret
import nacl.utils

from .. import paths

_PASS_ENTRY_DEFAULT = "icloud-keychain-for-linux/master-key"


class PassStoreError(RuntimeError):
    """Raised when the password-store backend cannot read or write the master key."""


def _pass_command() -> str:
    command = os.environ.get("ICP_PASS_COMMAND", "pass")
    resolved = shutil.which(command)
    if resolved is None:
        raise PassStoreError(
            f"{command!r} was not found. Install password-store and run 'pass init <gpg-id>'."
        )
    return resolved


def _pass_entry() -> str:
    return os.environ.get("ICP_PASS_ENTRY", _PASS_ENTRY_DEFAULT)


def _run_pass(args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Never let pass invoke an interactive editor from the native-messaging host.
    env.setdefault("PASSWORD_STORE_ENABLE_EXTENSIONS", "false")
    try:
        return subprocess.run(
            [_pass_command(), *args],
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
    except OSError as exc:
        raise PassStoreError(f"could not execute pass: {exc}") from exc


def _decode_key(value: str) -> bytes:
    first_line = value.splitlines()[0].strip() if value else ""
    try:
        key = base64.b64decode(first_line, validate=True)
    except Exception as exc:
        raise PassStoreError(f"pass entry {_pass_entry()!r} does not contain a valid base64 key") from exc
    if len(key) != nacl.secret.SecretBox.KEY_SIZE:
        raise PassStoreError(
            f"pass entry {_pass_entry()!r} contains {len(key)} key bytes; "
            f"expected {nacl.secret.SecretBox.KEY_SIZE}"
        )
    return key


def _store_key(key: bytes) -> None:
    encoded = base64.b64encode(key).decode("ascii") + "\n"
    result = _run_pass(["insert", "--multiline", _pass_entry()], input_text=encoded)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise PassStoreError(
            f"could not store the iCloud Keychain master key in pass entry {_pass_entry()!r}: "
            f"{detail}. Ensure 'pass init <gpg-id>' has been run."
        )


def _master_key() -> bytes:
    result = _run_pass(["show", _pass_entry()])
    if result.returncode == 0:
        return _decode_key(result.stdout)

    # Preserve installations that previously used the key-file fallback: import that exact key
    # into pass once so existing encrypted session/vault files remain readable.
    legacy = paths.fallback_key_file()
    if legacy.exists():
        key = legacy.read_bytes()
        if len(key) != nacl.secret.SecretBox.KEY_SIZE:
            raise PassStoreError(f"legacy master key {legacy} has an invalid length")
        _store_key(key)
        return key

    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    _store_key(key)
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
