"""Shared password groups ("Shared Groups" in the Passwords app) - fetch + decrypt, read-only.

Groups live in their own CloudKit container (`com.apple.security.shared.keychain`), one zone per
group named `group-<uuid>`, in the owner's PRIVATE database (groups shared *with* us sit in the
SHARED database and need the participant path - not implemented). Per zone:

  zone/retrieve      -> zone.protectionInfo (PCS, wrapped to our Manatee service key)
                        zone.recordProtectionInfo (PCS, wrapped to the zone's identity keys)
  record/sync        -> `item` records (encrypted `payload` = SharingItem protobuf) and one
                        `cloudkit.share` record (encrypted `displayName` = the group's name)

Only fetch operations are used - never zone/record save, share accept or any other write.
"""

from __future__ import annotations

import logging
import struct
import time

from ..proto.codec import Writer, decode_fields, first, first_str
from ..transport import ckks, cloudkit
from . import pcs

log = logging.getLogger(__name__)

OP_TYPE_ZONE_RETRIEVE = 201
FIELD_ZONE_RETRIEVE = 201
CKDATABASE_ZONE_RETRIEVE_URL = "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve"

FIELD_TYPE_ENCRYPTED_BYTES = 20


def _fetch_zone(transport, zone_raw: bytes) -> dict:
    """zone/retrieve -> {protection, record_protection} (raw PCS blobs, may be None)."""
    result = transport._perform(
        CKDATABASE_ZONE_RETRIEVE_URL, OP_TYPE_ZONE_RETRIEVE, FIELD_ZONE_RETRIEVE,
        Writer().bytes(1, zone_raw).finish(), bundle=cloudkit.KCSHARING_BUNDLE)
    resp = result.field(FIELD_ZONE_RETRIEVE) or b""
    summary = first(decode_fields(resp), 1)
    zone = first(decode_fields(summary), 1) if summary else None
    zf = decode_fields(zone) if zone else {}

    def blob(n):
        info = first(zf, n)
        return first(decode_fields(info), 1) if info else None
    return {"protection": blob(3), "record_protection": blob(6)}


def _parse_record(raw: bytes) -> dict:
    """Record -> {name, type, fields: {name: (type, bytesValue)}, protection}. Keeps the raw
    encrypted bytes (ckks.parse_record drops the protection info this needs)."""
    f = decode_fields(raw)
    rid = first(f, 2)
    name = ""
    if rid is not None:
        idval = first(decode_fields(rid), 1)
        name = first_str(decode_fields(idval), 1, "") if idval is not None else ""
    tblob = first(f, 3)
    rtype = first_str(decode_fields(tblob), 1, "") if tblob is not None else ""
    fields = {}
    for fld in f.get(7, []):
        ff = decode_fields(fld)
        ident, val = first(ff, 1), first(ff, 2)
        if ident is None or val is None:
            continue
        vf = decode_fields(val)
        fields[first_str(decode_fields(ident), 1, "")] = (first(vf, 1, 0), first(vf, 2))
    prot = first(f, 13)
    return {"name": name, "type": rtype, "fields": fields,
            "protection": first(decode_fields(prot), 1) if prot else None}


def _fetch_records(transport, zone_raw: bytes) -> list[dict]:
    out, continuation = [], None
    for _ in range(50):                              # page cap
        raw = transport.fetch_records(ckks.build_retrieve_changes_request(zone_raw, continuation),
                                      bundle=cloudkit.KCSHARING_BUNDLE)
        f = decode_fields(raw)
        for change in f.get(1, []):
            rec = first(decode_fields(change), 5)
            if rec is not None:
                out.append(_parse_record(rec))
        continuation = first(f, 2)
        if first(f, 4) != 1 or not continuation:
            break
    return out


def _double(v) -> float:
    return struct.unpack("<d", v.to_bytes(8, "little"))[0] if isinstance(v, int) else 0.0


def sharing_item_to_keychain(payload: bytes) -> dict | None:
    """SharingItem{3: SharingInternetPassword} -> a keychain-style item dict, so the normal
    CredentialStore.from_items classification (logins, metadata sidecars, ...) applies as-is."""
    ip = first(decode_fields(payload), 3)
    if ip is None:
        return None                                  # privateKey items (passkeys) - skipped
    f = decode_fields(ip)
    item = {
        "agrp": first_str(f, 1, ""),
        "mdat": _double(first(f, 2)),
        "cdat": _double(first(f, 3)),
        "acct": first_str(f, 4, ""),
        "srvr": first_str(f, 6, ""),
        "v_Data": first(f, 9, b""),
        "labl": first_str(f, 12, ""),
        "desc": first_str(f, 24, ""),
    }
    if first(f, 10):
        item["path"] = first_str(f, 10, "")
    return item


def _open_zone(transport, zone: dict, keychain_keys: dict[bytes, bytes]):
    """-> (zone identity keys, default record keys)."""
    z = _fetch_zone(transport, zone["raw"])
    if not z["protection"]:
        raise pcs.PCSError("zone has no protection info")
    prot = pcs.ShareProtection.parse(z["protection"])
    privs = [pcs.private_key_from_der(keychain_keys[x]) for x in prot.public_keys()
             if x in keychain_keys]
    if not privs:
        raise pcs.PCSError("no service key in the keychain for this group")
    _, idents = prot.open(privs)
    record_keys = []
    if z["record_protection"]:
        record_keys, _ = pcs.ShareProtection.parse(z["record_protection"]).open(idents)
    return idents, record_keys


def _record_keys(rec: dict, idents, default_keys) -> list[pcs.PCSKey]:
    if rec["protection"]:
        keys, _ = pcs.ShareProtection.parse(rec["protection"]).open(idents)
        return keys
    return default_keys


def _decrypt_field(rec: dict, zone_name: str, fname: str, keys) -> bytes | None:
    ftype, data = rec["fields"].get(fname, (0, None))
    if not data:
        return None
    return pcs.decrypt_with_any(keys, data, f"{zone_name}-{rec['name']}-{fname}".encode())


def fetch_groups(record: dict, device, anisette, keychain_items: list[dict]) -> list[dict]:
    """Every shared group we own -> [{id, name, items: [keychain-style dicts]}]. A group that
    fails to open is logged and skipped; the caller's own keychain is never affected."""
    mme = record.get("mme") or {}
    tokens = mme.get("tokens") or {}
    ck_token, mme_token = tokens.get("cloudKitToken"), mme.get("mmeAuthToken")
    dsid = str(mme.get("dsid") or record.get("dsid_numeric") or "")
    if not ck_token or not mme_token:
        raise pcs.PCSError("no CloudKit token in session")

    # per-container user id, cached in the session like the keychain container's
    user_id = mme.get("kcsharingUserId")
    if not user_id:
        user_id = cloudkit.ck_app_init(cloudkit.KCSHARING_CONTAINER, cloudkit.KCSHARING_BUNDLE,
                                       dsid, mme_token, anisette)
        mme["kcsharingUserId"] = user_id
        record["mme"] = mme
    dev = cloudkit.DeviceConfig(device_uuid=getattr(device, "device_id", ""),
                                serial=getattr(device, "serial", "") or "0000000000",
                                name=getattr(device, "name", "") or "Mac")
    transport = cloudkit.CloudKitTransport(ck_token, user_id, dev, anisette,
                                           container=cloudkit.KCSHARING_CONTAINER)

    zones, continuation = [], None
    for _ in range(25):
        page = ckks.parse_zone_changes_response(
            transport.fetch_zone_changes(continuation, bundle=cloudkit.KCSHARING_BUNDLE))
        zones.extend(page["zones"])
        continuation = page.get("continuation_token")
        if page.get("status") == 2 or not continuation:
            break
    deleted = {z["name"] for z in zones if z.get("change_type") == 2}
    live = {z["name"]: z for z in zones
            if z["name"].startswith("group-") and z["name"] not in deleted}

    keychain_keys = pcs.keychain_key_index(keychain_items)
    groups = []
    for name, zone in live.items():
        time.sleep(0.2)
        try:
            idents, default_keys = _open_zone(transport, zone, keychain_keys)
            records = _fetch_records(transport, zone["raw"])
        except (pcs.PCSError, cloudkit.CloudKitError, ValueError, IndexError, StopIteration) as e:
            log.warning("shared group %s: cannot open (%s)", name, type(e).__name__)
            continue
        group = {"id": name.removeprefix("group-"), "name": "", "items": []}
        for rec in records:
            try:
                keys = _record_keys(rec, idents, default_keys)
                if rec["type"] == "cloudkit.share":
                    raw = _decrypt_field(rec, name, "displayName", keys)
                    if raw:
                        group["name"] = first_str(decode_fields(raw), 6, "") or ""
                elif rec["type"] == "item":
                    payload = _decrypt_field(rec, name, "payload", keys)
                    item = sharing_item_to_keychain(payload) if payload else None
                    if item:
                        group["items"].append(item)
            except (pcs.PCSError, ValueError, IndexError, StopIteration) as e:
                log.warning("shared group %s: skipped a record (%s)", name, type(e).__name__)
        groups.append(group)
    return groups
