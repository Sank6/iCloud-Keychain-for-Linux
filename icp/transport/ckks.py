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
    etag: str = ""          # server change tag - the conflict guard for a save
    # Wire bytes as received, so a save re-sends identifier, zone and untouched fields verbatim
    # instead of re-encoding them: {"id": RecordIdentifier, "type": Record.Type,
    # "fields": [(name, Record.Field bytes), ...] in received order}.
    raw: dict = dataclasses.field(default_factory=dict, repr=False)

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
    fields, raw_fields = {}, []
    for fld in f.get(7, []):
        ff = decode_fields(fld)
        ident = first(ff, 1)
        fname = first_str(decode_fields(ident), 1) if ident is not None else None
        val = first(ff, 2)
        if fname is not None and val is not None:
            fields[fname] = _parse_value(val)
            raw_fields.append((fname, fld))
    return CloudKitRecord(record_name=name, type=rtype or "", fields=fields,
                          etag=first_str(f, 1) or "",
                          raw={"id": rec_id, "type": type_blob, "fields": raw_fields})


# --- writing (RecordSave, op 210) -----------------------------------------------------------
# Layout from Laky-64/appleservices (MIT, cloudkit/recordsave.go + ckks/encode.go) and the
# CloudKit proto in OpenBubbles/rustpush (facts only, SSPL): RecordSaveRequest{record=1, etag=4,
# saveSemantics=6}; saveSemantics 2 = insert, 3 = update (with the etag as the conflict guard).
OP_TYPE_RECORD_SAVE = 210
FIELD_RECORD_SAVE = 210
SAVE_SEMANTICS_INSERT = 2
SAVE_SEMANTICS_UPDATE = 3
# RecordDeleteRequest{recordIdentifier=1, etag=2} at /record/delete (op 214).
OP_TYPE_RECORD_DELETE = 214
FIELD_RECORD_DELETE = 214
VALUE_TYPE_BYTES = 1
VALUE_TYPE_STRING = 3
VALUE_TYPE_INT64 = 7


def encode_int_value(value: int) -> bytes:
    return Writer().uint64(1, VALUE_TYPE_INT64).uint64(4, value).finish()


def encode_bytes_value(value: bytes) -> bytes:
    return Writer().uint64(1, VALUE_TYPE_BYTES).bytes(2, value).finish()


def encode_string_value(value: str) -> bytes:
    return Writer().uint64(1, VALUE_TYPE_STRING).string(7, value).finish()


def _field(name: str, value: bytes) -> bytes:
    return Writer().message(1, Writer().string(1, name).finish()).message(2, value).finish()


def build_update_record(record: CloudKitRecord, replace: dict) -> bytes:
    """Record bytes for saving `record` with the field values in `replace` ({name: encoded
    Value}) swapped in. Everything else - identifier with its zone, type and every other field -
    goes back byte for byte as fetched. Only replaces fields the record already has."""
    if not record.raw.get("id") or not record.raw.get("type"):
        raise ValueError("record was not fetched with its wire bytes")
    unknown = set(replace) - {n for n, _ in record.raw["fields"]}
    if unknown:
        raise ValueError(f"record has no field(s) {sorted(unknown)}")
    w = Writer().message(2, record.raw["id"]).message(3, record.raw["type"])
    for name, fld in record.raw["fields"]:
        w.message(7, _field(name, replace[name]) if name in replace else fld)
    return w.finish()


def _renamed_id(raw_id: bytes, new_name: str) -> bytes:
    """RecordIdentifier with a new record name, zone identifier kept byte for byte."""
    f = decode_fields(raw_id)
    w = Writer().message(1, Writer().string(1, new_name).uint64(2, 1).finish())  # type RECORD
    for zid in f.get(2, []):
        w.message(2, zid)
    return w.finish()


def build_insert_record(template: CloudKitRecord, new_name: str, replace: dict) -> bytes:
    """A new record next to `template` (same zone, type and field layout) under `new_name`.
    `replace` must carry the new `data`/`wrappedkey`; server-managed `server_*` fields start
    at 0 like a fresh upload (appleservices does the same)."""
    if not template.raw.get("id") or not template.raw.get("type"):
        raise ValueError("template was not fetched with its wire bytes")
    if not {"data", "wrappedkey"} <= set(replace):
        raise ValueError("an insert needs new data + wrappedkey")
    w = (Writer().message(2, _renamed_id(template.raw["id"], new_name))
         .message(3, template.raw["type"]))
    for name, fld in template.raw["fields"]:
        if name in replace:
            w.message(7, _field(name, replace[name]))
        elif name.startswith("server_"):
            w.message(7, _field(name, encode_int_value(0)))
        else:
            w.message(7, fld)
    return w.finish()


def build_insert_request(record_bytes: bytes) -> bytes:
    """RecordSaveRequest for a new record (no etag: the server refuses if the name exists)."""
    return Writer().message(1, record_bytes).uint64(6, SAVE_SEMANTICS_INSERT).finish()


def build_delete_request(record: CloudKitRecord) -> bytes:
    """RecordDeleteRequest for `record` as fetched. The etag is mandatory: a newer version from
    another device makes the delete fail instead of removing it."""
    if not record.etag or not record.raw.get("id"):
        raise ValueError("refusing to delete without etag / identifier")
    return Writer().message(1, record.raw["id"]).string(2, record.etag).finish()


def build_save_request(record_bytes: bytes, etag: str) -> bytes:
    """RecordSaveRequest for an update. An etag is mandatory: without it the server would
    overwrite a newer version from another device."""
    if not etag:
        raise ValueError("refusing to save without an etag")
    return (Writer().message(1, record_bytes).string(4, etag)
            .uint64(6, SAVE_SEMANTICS_UPDATE).finish())


def parse_save_response(raw: bytes) -> str:
    """RecordSaveResponse -> the record's new etag ("" if the server sent none). The proto names
    serverFields(4) = Record{etag=1}; appleservices reads a bare string at 2 - accept both."""
    f = decode_fields(raw)
    server_fields = first(f, 4)
    if server_fields is not None:
        etag = first_str(decode_fields(server_fields), 1)
        if etag:
            return etag
    return first_str(f, 2) or ""


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
