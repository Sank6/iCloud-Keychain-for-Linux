"""Encrypted local vault of decrypted credentials (read by the native host). Persisted with the
same libsodium secret box + keyring master key as the auth session, file mode 0600."""

from __future__ import annotations

import json
import logging

import nacl.exceptions
import nacl.secret

from .. import paths
from .host import Credential, CredentialStore
from ..auth.session import _master_key


def save_vault(store: CredentialStore) -> None:
    creds = [c.public_dict() for c in store.all()]
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps({"credentials": creds}).encode())
    f = paths.vault_file()
    f.write_bytes(blob)
    f.chmod(0o600)


def load_vault() -> CredentialStore:
    f = paths.vault_file()
    if not f.exists():
        return CredentialStore([])
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError:
        logging.getLogger(__name__).warning("cannot decrypt %s with the current master key; "
                                            "discarding it - run `icp sync` to rebuild", f)
        f.unlink()
        return CredentialStore([])
    creds = [Credential(domain=c.get("domain", ""), username=c.get("username", ""),
                        password=c.get("password", ""), title=c.get("title", ""),
                        mdat=c.get("mdat", 0.0),
                        notes=c.get("notes", ""), last_used=c.get("last_used", 0.0),
                        totp=c.get("totp", ""), group=c.get("group", ""),
                        sites=tuple(c.get("sites") or ()), uuid=c.get("uuid", ""))
             for c in data.get("credentials", [])]
    return CredentialStore(creds)
