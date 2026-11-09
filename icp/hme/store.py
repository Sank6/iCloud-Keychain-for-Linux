"""Encrypted local cache of Hide My Email aliases (read by the native host). Same encryption as
`vault/store.py`; refreshed by `icp show`/`icp sync` so the host serves a snapshot, never live."""

from __future__ import annotations

import dataclasses
import json
import logging

import nacl.exceptions
import nacl.secret

from .. import paths
from ..auth.session import _master_key, _write_private
from .client import HmeAlias


def save_aliases(aliases: list[HmeAlias]) -> None:
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps({"aliases": [dataclasses.asdict(a) for a in aliases]}).encode())
    _write_private(paths.aliases_file(), blob)


def load_aliases() -> list[HmeAlias]:
    f = paths.aliases_file()
    if not f.exists():
        return []
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError:
        logging.getLogger(__name__).warning("cannot decrypt %s with the current master key; "
                                            "ignoring it (file kept)", f)
        return []
    return [HmeAlias(**a) for a in data.get("aliases", [])]
