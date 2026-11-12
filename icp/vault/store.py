"""Encrypted local vault of decrypted credentials (read by the native host). Persisted with the
same libsodium secret box + keyring master key as the auth session, file mode 0600."""

from __future__ import annotations

import json

import nacl.exceptions
import nacl.secret

from .. import paths
from .host import Credential, CredentialStore
from ..auth.session import _master_key, _write_private
from ..errors import SessionError


def save_vault(store: CredentialStore) -> None:
    creds = [c.public_dict() for c in store.all()]
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps({"credentials": creds}).encode())
    _write_private(paths.vault_file(), blob)


def load_vault() -> CredentialStore:
    f = paths.vault_file()
    if not f.exists():
        return CredentialStore([])
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError as e:
        # Never delete: the file is fine, the key is what changed. Deleting would turn a
        # recoverable keyring problem into data loss (and sync may be unable to rebuild it).
        raise SessionError(
            f"cannot decrypt {f.name} - the master key no longer matches it. The file was left "
            "untouched; restore the keyring entry, or `icp logout --reset-keys` to start over.") from e
    creds = [Credential(domain=c.get("domain", ""), username=c.get("username", ""),
                        password=c.get("password", ""), title=c.get("title", ""),
                        mdat=c.get("mdat", 0.0),
                        notes=c.get("notes", ""), last_used=c.get("last_used", 0.0),
                        totp=c.get("totp", ""), group=c.get("group", ""))
             for c in data.get("credentials", [])]
    return CredentialStore(creds)
