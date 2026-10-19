"""CKKS record fetch: pull the iCloud Keychain zone records (tlkshare / synckey / item /
currentitem) via a CloudKit RecordRetrieveChanges op per zone. See RESEARCH.md "transport/ckks.py"."""

from __future__ import annotations

import dataclasses
import struct

from ..proto.codec import Writer, decode_fields, first, first_str


@dataclasses.dataclass
class CKDate:
    """A CloudKit Date value - kept distinct from a plain double so the item AAD encodes it
    as RFC3339 rather than as a number."""
    time: float   # seconds (UNIX)


# Keychain CKKS zones (private DB). "Passwords" + "Manatee" hold web credentials.
KEYCHAIN_ZONES = (
    "Passwords", "Manatee", "Engram", "SecureObjectSync", "ProtectedCloudStorage",
    "CreditCards", "ApplePay", "WiFi", "Home", "Groups", "Contacts", "Mail",
    "LimitedPeersAllowed", "SE-PTC", "Photos",
)

ID_TYPE_RECORD_ZONE = 6
ID_TYPE_USER = 7

OP_TYPE_RECORD_RETRIEVE_CHANGES = 213
FIELD_RETRIEVE_CHANGES = 213


def _identifier(name: str, type_: int) -> bytes:
    return Writer().string(1, name).uint64(2, type_).finish()


def record_zone_identifier(zone: str, user_id: str) -> bytes:
    return (Writer()
            .message(1, _identifier(zone, ID_TYPE_RECORD_ZONE))
            .message(2, _identifier(user_id, ID_TYPE_USER))
            .finish())


def build_retrieve_changes_request(zone_identifier: bytes,
                                   continuation_token: bytes | None = None,
                                   max_changes: int = 500) -> bytes:
    return (Writer()
            .bytes(1, continuation_token)
            .message(2, zone_identifier)
            .uint64(4, max_changes)
            .finish())


def _parse_zone_identifier(raw: bytes) -> dict:
    """RecordZoneIdentifier{value=1 Identifier, ownerIdentifier=2 Identifier} -> {name, owner,
    raw}. `raw` is kept so a record fetch can address the same zone verbatim."""
    f = decode_fields(raw)
    value = first(f, 1)
    owner = first(f, 2)
    return {
        "name": first_str(decode_fields(value), 1) if value is not None else "",
        "owner": first_str(decode_fields(owner), 1) if owner is not None else "",
        "raw": raw,
    }


def parse_zone_changes_response(raw: bytes) -> dict:
    """RetrieveZoneChangesResponse -> {zones, continuation_token, status}. status 2 = done.
    Each zone: {name, owner, change_type, raw} (raw = the RecordZoneIdentifier message)."""
    f = decode_fields(raw)
    zones = []
    for change in f.get(1, []):
        cf = decode_fields(change)
        zid = first(cf, 1)
        if zid is None:
            continue
        info = _parse_zone_identifier(zid)
        info["change_type"] = first(cf, 2, 0)   # 2 = deleted
        zones.append(info)
    return {"zones": zones, "continuation_token": first(f, 2), "status": first(f, 3)}


@dataclasses.dataclass
class CloudKitRecord:
    record_name: str        # identifier value name (usually a UUID)
    type: str               # "item" / "synckey" / "tlkshare" / "currentitem" / ...
    fields: dict            # {field_name: python value}

    def get_bytes(self, name: str) -> bytes | None:
        v = self.fields.get(name)
        return v if isinstance(v, (bytes, bytearray)) else None

    def get_str(self, name: str) -> str | None:
        v = self.fields.get(name)
        return v if isinstance(v, str) else None


def _parse_value(raw: bytes):
    """Record.Field.Value -> python value. Types are preserved so the item AAD encodes each
    correctly: str, bytes, int, float, CKDate."""
    v = decode_fields(raw)
    if 2 in v:
        return first(v, 2)                     # bytesValue
    if 7 in v:
        return first_str(v, 7)                 # stringValue
    if 4 in v:
        return first(v, 4)                     # signedValue (int64)
    if 5 in v:                                 # doubleValue (fixed64, IEEE-754)
        return struct.unpack("<d", first(v, 5).to_bytes(8, "little"))[0]
    if 6 in v:                                 # dateValue: Date{ time(1): double }
        d = decode_fields(first(v, 6))
        if 1 in d:
            return CKDate(struct.unpack("<d", first(d, 1).to_bytes(8, "little"))[0])
    if 9 in v:                                 # referenceValue -> the target record's name,
        ref = decode_fields(first(v, 9))       # e.g. parentkeyref linking synckey->TLK / item->classkey
        rid = first(ref, 2)
        if rid is not None:
            idval = first(decode_fields(rid), 1)
            if idval is not None:
                return first_str(decode_fields(idval), 1)
    return None


def parse_record(raw: bytes) -> CloudKitRecord:
    f = decode_fields(raw)
    rec_id = first(f, 2)
    name = ""
    if rec_id is not None:
        idval = first(decode_fields(rec_id), 1)
        if idval is not None:
            name = first_str(decode_fields(idval), 1) or ""
    type_blob = first(f, 3)
    rtype = first_str(decode_fields(type_blob), 1) if type_blob is not None else ""
    fields = {}
    for fld in f.get(7, []):
        ff = decode_fields(fld)
        ident = first(ff, 1)
        fname = first_str(decode_fields(ident), 1) if ident is not None else None
        val = first(ff, 2)
        if fname is not None and val is not None:
            fields[fname] = _parse_value(val)
    return CloudKitRecord(record_name=name, type=rtype or "", fields=fields)


def parse_retrieve_changes_response(raw: bytes) -> dict:
    """Returns {records, continuation_token, status}. status 1 means another page is available;
    status 3 is the final state token for the zone."""
    f = decode_fields(raw)
    records = []
    for change in f.get(1, []):
        cf = decode_fields(change)
        rec = first(cf, 5)
        if rec is not None:
            records.append(parse_record(rec))
    return {"records": records, "continuation_token": first(f, 2), "status": first(f, 4)}
