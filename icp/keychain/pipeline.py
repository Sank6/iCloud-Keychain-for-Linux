"""Decryption pipeline: composes the primitives into the unwrap chain
tlkshare -> TLK -> class key -> item key -> item plist -> credential. See RESEARCH.md."""

from __future__ import annotations

import base64
import plistlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec

from ..proto.codec import decode_fields, first, first_str
from ..transport import ckks
from . import crypto as kc, nska
from ..vault.host import CredentialStore

# item-record fields that are NOT part of the per-item authenticated data (everything else is)
_AAD_EXCLUDED = {"gen", "pcspublickey", "UUID", "data", "pcsservice", "pcspublicidentity",
                 "parentkeyref", "uploadver", "wrappedkey", "encver"}


def _le8(n: int) -> bytes:
    """64-bit two's-complement little-endian (Rust i64/u64 `.to_le_bytes`). Masks to 64 bits so
    proto int64 negatives (which arrive as large unsigned varints) don't raise OverflowError."""
    return (int(n) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def authenticated_data_v2(uuid: str, fields: dict, *, encver: int, gen: int,
                          parent_key_id: str) -> list[bytes]:
    """Build the AES-SIV associated-data values for an `item` record (encver 2): the item's
    authenticated metadata as a by-key-sorted map, values in key order (after the leading IV)."""
    aad = {
        "UUID": uuid.encode(),
        "encver": _le8(encver),
        "gen": _le8(gen),
        "wrappedkey": parent_key_id.encode(),  # the parent class key's id, not the wrappedkey field
    }
    # PCS fields are authenticated when present, with specific encodings, so are handled here
    # rather than in the generic loop below.
    if fields.get("pcsservice") is not None:
        aad["pcsservice"] = _le8(fields["pcsservice"])
    for _pcs in ("pcspublicidentity", "pcspublickey"):
        v = fields.get(_pcs)
        if isinstance(v, (bytes, bytearray)):
            aad[_pcs] = bytes(v)
    for name, val in fields.items():
        if name in _AAD_EXCLUDED or name.startswith("server_"):
            continue
        if isinstance(val, str):
            aad[name] = val.encode()
        elif isinstance(val, (bytes, bytearray)):
            aad[name] = bytes(val)
        elif isinstance(val, ckks.CKDate):               # RFC3339 seconds, 'Z' suffix
            dt = datetime.fromtimestamp(int(val.time), tz=timezone.utc)
            aad[name] = dt.strftime("%Y-%m-%dT%H:%M:%SZ").encode()
        elif isinstance(val, bool):                      # before int - bool is an int subclass
            aad[name] = _le8(1 if val else 0)
        elif isinstance(val, float):                     # (value as u64).to_le_bytes()
            aad[name] = (int(val) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        elif isinstance(val, int):                       # signedValue: i64 little-endian
            aad[name] = _le8(val)
    return [aad[k] for k in sorted(aad)]


def unwrap_tlkshares(tlkshares, our_peer_id: str,
                     our_encryption_key: ec.EllipticCurvePrivateKey) -> dict:
    """Return {tlkUuid: TLK key bytes} for every TLKShare addressed to us that we can decrypt.

    A TLKShare's `wrappedkey` ECIES-decrypts (with our peer encryption key) to a
    `CuttlefishSerializedKey` protobuf {uuid(1), zoneName(2), keyclass(3), key(4)} - NOT raw
    TLK bytes - so the TLK uuid comes from field 1 and the key material from field 4."""
    tlks: dict[str, bytes] = {}
    for share in tlkshares:
        if share.get_str("receiver") != our_peer_id:
            continue
        wrapped = share.get_str("wrappedkey")
        if not wrapped:
            continue
        try:
            ies = nska.expand(base64.b64decode(wrapped))
            serialized = kc.ecies_decrypt_sf(our_encryption_key, ies)
        except Exception:
            continue                           # skip a poisoned/foreign share, keep the rest
        f = decode_fields(serialized)
        key_id, tlk = first_str(f, 1), first(f, 4)
        if key_id and tlk:
            tlks[key_id] = tlk
    return tlks


def unwrap_class_keys(synckeys, tlks: dict) -> dict:
    """Return {keyId: class-key (64B SIV)} by unwrapping each synckey with its parent TLK."""
    keys: dict[str, bytes] = {}
    for sk in synckeys:
        parent = sk.get_str("parentkeyref")
        tlk = tlks.get(parent)
        if tlk is None:
            continue
        wrapped = sk.get_str("wrappedkey")
        if not wrapped:
            continue
        key = kc.siv_unwrap(tlk, base64.b64decode(wrapped))
        keys[sk.record_name] = key
    return keys


def decrypt_items(items, class_keys: dict) -> list[dict]:
    """Decrypt each `item` record whose parent class key we hold -> the item plist dict."""
    out = []
    for it in items:
        parent = it.get_str("parentkeyref")
        ck = class_keys.get(parent)
        data = it.get_bytes("data")
        wrapped = it.get_str("wrappedkey")
        if ck is None or data is None or not wrapped:
            continue
        item_key = kc.siv_unwrap(ck, base64.b64decode(wrapped))
        encver = it.fields.get("encver", 2)
        gen = it.fields.get("gen", 0)
        aad = authenticated_data_v2(it.record_name, it.fields, encver=encver, gen=gen,
                                    parent_key_id=parent)
        try:
            plaintext = kc.decrypt_item(item_key, data, aad)
            out.append(plistlib.loads(plaintext))
        except Exception:
            continue  # skip an item we can't decrypt, keep the rest
    return out


def build_credential_store(records_by_type: dict, our_peer_id: str,
                           our_encryption_key: ec.EllipticCurvePrivateKey,
                           tlks: dict | None = None) -> CredentialStore:
    """Full pipeline: grouped CKKS records -> decrypted CredentialStore.

    TLKs come from two UNIONed sources: `tlks` supplied pre-computed (from
    `fetchRecoverableTLKShares`, the only source for user-controllable views like Passwords) and the
    plain `tlkshare` records in the fetched zones (always-on views like WiFi)."""
    return CredentialStore.from_items(
        decrypt_all(records_by_type, our_peer_id, our_encryption_key, tlks))


def decrypt_all(records_by_type: dict, our_peer_id: str,
                our_encryption_key: ec.EllipticCurvePrivateKey, tlks: dict | None = None) -> list[dict]:
    """Grouped CKKS records -> every decrypted keychain item (plist dicts), all access groups.
    Same TLK union as build_credential_store; also feeds the shared-group service keys."""
    plain_tlks = unwrap_tlkshares(records_by_type.get("tlkshare", []), our_peer_id,
                                  our_encryption_key)
    merged_tlks = {**plain_tlks, **tlks} if tlks else plain_tlks
    class_keys = unwrap_class_keys(records_by_type.get("synckey", []), merged_tlks)
    return decrypt_items(records_by_type.get("item", []), class_keys)
