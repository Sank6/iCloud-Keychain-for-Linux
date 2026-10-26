"""Write path: edit an existing Passwords login (website, username, password, title, notes,
extra websites, 2FA code) or create a new one, and save it to iCloud Keychain, so the change
reaches the user's other devices.

Website (`srvr`) and username (`acct`) are part of an item's primary key. Devices reconcile an
incoming modify by primary key only (CKKSIncomingQueueOperation -> SecDbItemInsertOrReplace),
so changing them in place leaves the old row next to the new one (seen on iOS 27). Such a
change is therefore a *rekey*: insert login + metadata under new UUIDs, read them back, and
only then delete the old versions. A failed delete leaves a duplicate, never a
loss.

Safety model (every rule is enforced here, not by callers):
  * never touch zones, keys or TLKs; delete only the old version of a rekeyed login, after its
    replacement was read back from the server;
  * every update/delete carries the etag of a record fetched moments before (a newer version
    from another device makes it fail instead of being overwritten);
  * a rekey refuses a target website/username that another login already uses (CKKS would
    keep only one of two items with the same primary key);
  * the record's class key must be the current one for its class;
  * the re-encrypted record is decrypted again locally and compared before it is sent;
  * the record as fetched is backed up (encrypted) before it is updated or deleted, so
    `restore` can put the old ciphertext back unchanged - it stays valid because the AAD does
    not change;
  * writes are paced (WRITE_MIN_GAP / WRITE_MAX_PER_HOUR) and any failure blocks further writes
    until cleared by hand (`icp write-state --clear`).

Formats: CKKS item encryption is the inverse of pipeline.decrypt_record. The Passwords-app
sidecar (`agrp com.apple.password-manager`, plist in `v_Data` with title/notes/`s_as` extra
websites) follows Laky-64/appleservices (MIT) `keychain/webpassword*.go`.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import json
import os
import plistlib
import re
import time
import uuid as uuid_mod

import nacl.secret

from .. import paths
from ..auth.session import _master_key
from ..errors import AppleError
from ..proto.codec import decode_fields, first, first_str
from ..transport import ckks
from . import pipeline

# Web-password zones (Passwords holds the logins, Manatee the rest of the user views).
WRITE_ZONES = ("Passwords", "Manatee")
AGRP_LOGIN = "com.apple.cfnetwork"
AGRP_SIDECAR = "com.apple.password-manager"
SIDECAR_LABEL = "Password Manager Metadata: "

WRITE_MIN_GAP = 10.0         # seconds between two edits
WRITE_MAX_PER_HOUR = 30      # single writes (an edit is 1-4 of them)
OP_GAP = 2.0                 # seconds between the writes of one edit


class WriteError(AppleError):
    pass


# --- record helpers --------------------------------------------------------------------------

def record_zone(record: ckks.CloudKitRecord) -> str:
    """Zone name from the record's own identifier (RecordIdentifier.zoneIdentifier.value.name)."""
    rid = record.raw.get("id")
    if not rid:
        return ""
    zid = first(decode_fields(rid), 2)
    value = first(decode_fields(zid), 1) if zid is not None else None
    return (first_str(decode_fields(value), 1) or "") if value is not None else ""


def _is_tomb(item: dict) -> bool:
    return bool(item.get("tomb"))


def _norm(s) -> str:
    return str(s or "").strip().lower()


@dataclasses.dataclass
class Keyring:
    """What a write needs from one fetch: the class keys, which class each key belongs to, and
    the current key per (zone, class)."""
    class_keys: dict            # {key uuid: 64-byte key}
    key_class: dict             # {key uuid: "classA" / "classC"}
    key_zone: dict              # {key uuid: zone}
    current: dict               # {(zone, class): key uuid}

    def check_current(self, record: ckks.CloudKitRecord) -> bytes:
        """The class key of `record`, if it is the current key of its class - else WriteError."""
        parent = record.get_str("parentkeyref") or ""
        key = self.class_keys.get(parent)
        if key is None:
            raise WriteError("class key of this entry is not available")
        cls = self.key_class.get(parent)
        cur = self.current.get((record_zone(record), cls))
        if not cls or not cur:
            raise WriteError("current class key unknown (no currentkey record fetched)")
        if cur != parent:
            raise WriteError(f"entry is encrypted with an old {cls} key (rotated) - not supported")
        return key


def build_keyring(records_by_type: dict, tlks: dict) -> Keyring:
    synckeys = records_by_type.get("synckey", [])
    class_keys = pipeline.unwrap_class_keys(synckeys, tlks)
    key_class = {sk.record_name: sk.get_str("class") or "" for sk in synckeys}
    key_zone = {sk.record_name: record_zone(sk) for sk in synckeys}
    current = {}
    for ck in records_by_type.get("currentkey", []):
        target = ck.get_str("parentkeyref")
        if target:
            current[(record_zone(ck), ck.record_name)] = target
    return Keyring(class_keys, key_class, key_zone, current)


# --- the logins ------------------------------------------------------------------------------

@dataclasses.dataclass
class Entry:
    login_record: ckks.CloudKitRecord
    login: dict
    sidecar_record: ckks.CloudKitRecord | None = None
    sidecar: dict | None = None
    sidecar_count: int = 0      # >1: ambiguous metadata, nothing that touches it is allowed
    # other logins with the same website + username (they differ in protocol, port or path): the
    # metadata, joined on (website, username), belongs to them too - a rekey or delete leaves it
    siblings: int = 0

    @property
    def domain(self) -> str:
        return str(self.login.get("srvr") or "")

    @property
    def username(self) -> str:
        return str(self.login.get("acct") or "")


def _sidecar_payload(item: dict) -> dict:
    raw = item.get("v_Data")
    if isinstance(raw, (bytes, bytearray)) and bytes(raw).startswith(b"bplist00"):
        try:
            d = plistlib.loads(bytes(raw))
            return d if isinstance(d, dict) else {}
        except Exception:  # noqa: BLE001 - a broken sidecar just has no payload
            return {}
    return {}


def find_entries(items_records: list) -> list[Entry]:
    """[(record, plist)] -> logins with their sidecar. Only own (non-shared) web logins."""
    logins, sidecars = [], {}
    for rec, it in items_records:
        if _is_tomb(it):
            continue
        agrp = str(it.get("agrp") or "")
        key = (_norm(it.get("srvr")), _norm(it.get("acct")))
        if agrp == AGRP_LOGIN and it.get("class") in (None, "inet"):
            logins.append((key, rec, it))
        elif agrp == AGRP_SIDECAR and str(it.get("labl") or "").startswith(SIDECAR_LABEL):
            sidecars.setdefault(key, []).append((rec, it))
    per_key = {}
    for key, _rec, _it in logins:
        per_key[key] = per_key.get(key, 0) + 1
    out = []
    for key, rec, it in logins:
        side = sidecars.get(key, [])
        e = Entry(rec, it, sidecar_count=len(side), siblings=per_key[key] - 1)
        if len(side) == 1:
            e.sidecar_record, e.sidecar = side[0]
        out.append(e)
    return out


def select_entry(entries: list[Entry], domain: str, username: str,
                 uuid: str | None = None) -> Entry:
    """The login to edit. `uuid` (the record name, e.g. from the vault) is exact; website +
    username alone can match several logins that differ in protocol, port or path."""
    if uuid:
        hits = [e for e in entries if e.login_record.record_name == uuid]
        if not hits:
            raise WriteError(f"no login with id {uuid} (synced since?)")
        return hits[0]
    hits = [e for e in entries
            if _norm(e.domain) == _norm(domain) and _norm(e.username) == _norm(username)]
    if not hits:
        raise WriteError(f"no login for {domain} / {username!r}")
    if len(hits) > 1:
        raise WriteError(f"{len(hits)} logins for {domain} / {username!r} - pass its id "
                         "(--uuid) to pick one")
    return hits[0]


# --- shape probe (read-only, no values) --------------------------------------------------------

def _shape(value, depth: int = 0):
    if isinstance(value, dict) and depth < 3:
        return {k: _shape(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list) and depth < 3:
        return [_shape(value[0], depth + 1)] if value else []
    return type(value).__name__


def probe(records_by_type: dict, tlks: dict) -> dict:
    """Structure report for the write path: record fields, etags, key pointers and the
    attribute/payload shapes of logins and sidecars. Names and types only - no values."""
    keyring = build_keyring(records_by_type, tlks)
    items = records_by_type.get("item", [])
    pairs = _decrypted(records_by_type, keyring)
    entries = find_entries(pairs)
    login_keys, side_keys, payload_shape, sites_count = {}, {}, {}, 0
    for e in entries:
        for k, v in e.login.items():
            login_keys[k] = type(v).__name__
        if e.sidecar:
            for k, v in e.sidecar.items():
                side_keys[k] = type(v).__name__
            for k, v in _shape(_sidecar_payload(e.sidecar)).items():
                if v or k not in payload_shape:   # keep the first non-empty list's element shape
                    payload_shape[k] = v
            sites = _sidecar_payload(e.sidecar).get("s_as") or []
            sites_count = max(sites_count, len(sites))
    record_fields = sorted({n for r in items for n in r.fields})
    stale = 0
    for e in entries:
        try:
            keyring.check_current(e.login_record)
        except WriteError:
            stale += 1
    return {
        "zones": sorted({record_zone(r) for r in items}),
        "items": len(items), "decrypted": len(pairs),
        "items_with_etag": sum(1 for r in items if r.etag),
        "items_with_raw": sum(1 for r in items if r.raw.get("fields")),
        "record_fields": record_fields,
        "currentkeys": sorted(f"{z}/{c}" for z, c in keyring.current),
        "logins": len(entries),
        "logins_with_sidecar": sum(1 for e in entries if e.sidecar),
        "logins_ambiguous_sidecar": sum(1 for e in entries if e.sidecar_count > 1),
        "logins_old_class_key": stale,
        "login_attrs": dict(sorted(login_keys.items())),
        "sidecar_attrs": dict(sorted(side_keys.items())),
        "sidecar_payload": payload_shape,
        "max_extra_sites": sites_count,
        "uuid_attr_is_record_name": all(str(e.login.get("UUID", e.login_record.record_name))
                                        == e.login_record.record_name for e in entries),
    }


# --- edits -----------------------------------------------------------------------------------

@dataclasses.dataclass
class Changes:
    site: str | None = None              # new primary website (login `srvr`) -> rekey
    username: str | None = None          # new username (`acct`) -> rekey
    add_sites: tuple = ()                # extra websites (sidecar `s_as`)
    remove_sites: tuple = ()
    password: str | None = None
    title: str | None = None
    notes: str | None = None
    totp: str | None = None              # otpauth:// URI or base32 key; "" removes the code
    trash: bool = False                  # move to Recently Deleted (alone, no other change)

    def touches_sidecar(self) -> bool:
        return bool(self.add_sites or self.remove_sites or self.title is not None
                    or self.notes is not None or self.totp is not None)

    def empty(self) -> bool:
        return not (self.site or self.username is not None or self.password is not None
                    or self.touches_sidecar() or self.trash)


@dataclasses.dataclass
class Edit:
    """Result of apply_changes: the new plists (None = unchanged) and whether the primary key
    moved (rekey: both become new records, the old ones are deleted afterwards)."""
    login: dict | None
    sidecar: dict | None
    diff: list
    rekey: bool = False


def _now() -> datetime.datetime:
    # plistlib writes naive datetimes as UTC
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)


def _like(old, new: str):
    """Keep a sidecar text field's type (the Passwords app stores some as bytes)."""
    return new.encode() if isinstance(old, (bytes, bytearray)) else new


def _site_host(site: str) -> str:
    s = site.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].lower()
    if not s or any(c in s for c in " :@"):   # no ports or credentials: `srvr` is a bare host
        raise WriteError(f"not a website: {site!r}")
    return s


RECENTLY_DELETED = "-recently-deleted"   # agrp suffix of the Passwords app's Recently Deleted


def trash_entry(entry: Entry) -> Edit:
    """Delete the way the Passwords app does: login and metadata move to their
    `<agrp>-recently-deleted` access group (a rekey - new records, then the originals are
    deleted), so the entry can still be recovered from Recently Deleted on any device.
    Format from Laky-64/appleservices (MIT) ckks/vault.go MoveRecordIn."""
    if entry.sidecar_count > 1:
        raise WriteError(f"this login has {entry.sidecar_count} Passwords metadata records - "
                         "ambiguous, not deleting")
    stamp = _now()
    moved = []
    # metadata shared with a sibling login stays where it is (it still describes that one)
    for item in (entry.login, None if entry.siblings else entry.sidecar):
        if item is None:
            moved.append(None)
            continue
        copy = {**item, "agrp": str(item.get("agrp") or "") + RECENTLY_DELETED, "mdat": stamp}
        copy.pop("sha1", None)
        moved.append(copy)
    return Edit(moved[0], moved[1], ["moved to Recently Deleted"], rekey=True)


def apply_changes(entry: Entry, ch: Changes, others: list | None = None) -> Edit:
    """The edit as new plists plus a diff without secrets. Pure: no network. `others` = all
    logins, for the duplicate check of a rekey."""
    if ch.empty():
        raise WriteError("nothing to change")
    if ch.trash:
        if dataclasses.replace(ch, trash=False) != Changes():
            raise WriteError("delete cannot be combined with other changes")
        return trash_entry(entry)
    login = dict(entry.login)
    diff: list[str] = []
    old_key = (entry.domain, entry.username)
    new_srvr = _site_host(ch.site) if ch.site else entry.domain
    new_acct = ch.username if ch.username is not None else entry.username
    rekey = (_norm(new_srvr), new_acct) != (_norm(entry.domain), entry.username)
    if rekey:
        clash = [e for e in (others or []) if e is not entry
                 and _norm(e.domain) == _norm(new_srvr) and _norm(e.username) == _norm(new_acct)]
        if clash:
            raise WriteError(f"another login already uses {new_srvr} / {new_acct!r}")
        if new_srvr != entry.domain:
            diff.append(f"website: {entry.domain} -> {new_srvr}")
        if new_acct != entry.username:
            diff.append(f"username: {entry.username!r} -> {new_acct!r}")
        login["srvr"], login["acct"] = new_srvr, new_acct
        if str(login.get("labl") or "") == f"{old_key[0]} ({old_key[1]})":
            login["labl"] = f"{new_srvr} ({new_acct})"
    if ch.password is not None:
        if not ch.password:
            raise WriteError("empty password")
        old_pw = login.get("v_Data")
        if bytes(old_pw or b"") != ch.password.encode():
            login["v_Data"] = ch.password if isinstance(old_pw, str) else ch.password.encode()
            diff.append("password: changed")

    if entry.sidecar_count > 1 and (rekey or ch.touches_sidecar()):
        raise WriteError(f"this login has {entry.sidecar_count} Passwords metadata records - "
                         "ambiguous, not editing website, username, title, notes or 2FA")
    sidecar = None
    if ch.touches_sidecar() or (rekey and entry.sidecar is not None):
        if entry.sidecar is None:
            raise WriteError("this login has no Passwords metadata yet - add a note in the "
                             "Passwords app once (title, notes, websites and 2FA need it)")
        sidecar = dict(entry.sidecar)
        payload = _sidecar_payload(entry.sidecar)
        new_payload = dict(payload)
        if ch.title is not None and ch.title != _text(payload.get("title")):
            new_payload["title"] = _like(payload.get("title", b""), ch.title)
            diff.append(f"title: {_text(payload.get('title'))!r} -> {ch.title!r}")
        if ch.notes is not None and ch.notes != _text(payload.get("notes")):
            new_payload["notes"] = _like(payload.get("notes", b""), ch.notes)
            diff.append("notes: changed")
        if ch.totp is not None:
            if not ch.totp.strip():
                if new_payload.pop("totp", None) is not None:
                    diff.append("2FA code: removed")
            else:
                from .. import totp as totp_codes
                try:
                    block = totp_codes.sidecar_from_input(ch.totp)
                except ValueError as e:
                    raise WriteError(str(e)) from None
                old = payload.get("totp") if isinstance(payload.get("totp"), dict) else {}
                same = all(old.get(k) == block[k]
                           for k in ("secret", "algorithm", "digits", "period"))
                if not same:
                    new_payload["totp"] = block
                    diff.append("2FA code: changed" if old else "2FA code: added")
        if ch.add_sites or ch.remove_sites:
            sites = [dict(s) for s in payload.get("s_as") or [] if isinstance(s, dict)]
            have = [_norm(s.get("s")) for s in sites]
            for raw in ch.remove_sites:
                host = _site_host(raw)
                if host not in have:
                    raise WriteError(f"{host} is not an extra website of this login")
                sites = [s for s in sites if _norm(s.get("s")) != host]
                have = [_norm(s.get("s")) for s in sites]
                diff.append(f"extra website removed: {host}")
            for raw in ch.add_sites:
                host = _site_host(raw)
                if host in have or host == _norm(new_srvr):
                    continue
                sites.append({"s": host})
                have.append(host)
                diff.append(f"extra website added: {host}")
            new_payload["s_as"] = sites
        if new_payload != payload:
            sidecar["v_Data"] = plistlib.dumps(new_payload, fmt=plistlib.FMT_BINARY)
        if rekey:
            sidecar["srvr"], sidecar["acct"] = new_srvr, new_acct
            sidecar["labl"] = f"{SIDECAR_LABEL}{new_srvr} ({new_acct})"
        if sidecar == entry.sidecar:
            sidecar = None
    if login == entry.login:
        login = None
    if login is None and sidecar is None:
        raise WriteError("nothing to change (values already set)")
    stamp = _now()
    for item in (login, sidecar):
        if item is not None:
            item["mdat"] = stamp
            item.pop("sha1", None)   # receivers recompute it; a stale one would mismatch
    return Edit(login, sidecar, diff, rekey)


def _text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value) if value else ""


# --- encryption + self-check -------------------------------------------------------------------

def _plist_equal(a: dict, b: dict) -> bool:
    """Compare as the plist codec sees them (dates lose sub-second precision on the way)."""
    def canon(d):
        return plistlib.loads(plistlib.dumps(d, fmt=plistlib.FMT_BINARY))
    return canon(a) == canon(b)


def build_save(record: ckks.CloudKitRecord, item: dict, keyring: Keyring) -> bytes:
    """Re-encrypt `item` for `record`, verify by decrypting the result, -> RecordSaveRequest."""
    class_key = keyring.check_current(record)
    if record.fields.get("encver", 2) != 2:
        raise WriteError(f"unsupported encver {record.fields.get('encver')}")
    if not record.etag:
        raise WriteError("record has no etag - cannot save safely")
    new = pipeline.encrypt_record_payload(record, class_key, item)
    record_bytes = ckks.build_update_record(record, {
        "data": ckks.encode_bytes_value(new["data"]),
        "wrappedkey": ckks.encode_string_value(new["wrappedkey"]),
    })
    check = ckks.parse_record(record_bytes)
    if (check.record_name != record.record_name
            or pipeline.record_aad(check) != pipeline.record_aad(record)):
        raise WriteError("self-check failed: record metadata changed")
    back = pipeline.decrypt_record(check, keyring.class_keys)
    if back is None or not _plist_equal(back, item):
        raise WriteError("self-check failed: re-encrypted item does not decrypt to the edit")
    return ckks.build_save_request(record_bytes, record.etag)


def build_insert(template: ckks.CloudKitRecord, item: dict,
                 keyring: Keyring, *, fresh: bool = False) -> tuple[str, bytes, dict]:
    """`item` as a NEW record next to `template` (same zone + class key) under a fresh UUID,
    verified by decrypting the result. -> (new uuid, RecordSaveRequest, item as stored - its
    `UUID` attribute follows the record name). `fresh`: a brand-new item, not a moved one -
    its generation count starts at 0 (CKKS counts up from 0 on each modify of an item)."""
    class_key = keyring.check_current(template)
    if template.fields.get("encver", 2) != 2:
        raise WriteError(f"unsupported encver {template.fields.get('encver')}")
    new_uuid = str(uuid_mod.uuid4()).upper()
    item = {**item, "UUID": new_uuid} if "UUID" in item else item
    stub = dataclasses.replace(template, record_name=new_uuid)
    replace = {}
    if fresh and "gen" in template.fields:
        stub.fields = {**template.fields, "gen": 0}   # gen is part of the AAD
        replace["gen"] = ckks.encode_int_value(0)
    new = pipeline.encrypt_record_payload(stub, class_key, item)
    record_bytes = ckks.build_insert_record(template, new_uuid, {
        **replace,
        "data": ckks.encode_bytes_value(new["data"]),
        "wrappedkey": ckks.encode_string_value(new["wrappedkey"]),
    })
    check = ckks.parse_record(record_bytes)
    if check.record_name != new_uuid or record_zone(check) != record_zone(template):
        raise WriteError("self-check failed: new record identifier")
    back = pipeline.decrypt_record(check, keyring.class_keys)
    if back is None or not _plist_equal(back, item):
        raise WriteError("self-check failed: new record does not decrypt to the edit")
    return new_uuid, ckks.build_insert_request(record_bytes), item


# --- backup ----------------------------------------------------------------------------------

def _backup_dir():
    return paths.config_dir() / "backup"


def backup_record(record: ckks.CloudKitRecord) -> str:
    """Store the record as fetched (encrypted with the vault key). Returns the file name."""
    d = _backup_dir()
    d.mkdir(mode=0o700, exist_ok=True)
    blob = json.dumps({
        "uuid": record.record_name, "zone": record_zone(record), "etag": record.etag,
        "saved": time.time(),
        "record": base64.b64encode(ckks.build_update_record(record, {})).decode(),
    }).encode()
    f = d / f"{record.record_name}-{time.time_ns()}.bak"
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(nacl.secret.SecretBox(_master_key()).encrypt(blob))
    return f.name


def _backup_stamp(f) -> int:
    try:
        return int(f.stem.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return 0


def load_backup(uuid: str) -> ckks.CloudKitRecord:
    """The oldest backup of `uuid` (= the state before the first edit)."""
    if not re.fullmatch(r"[A-Za-z0-9-]+", uuid or ""):
        raise WriteError(f"not a record uuid: {uuid!r}")
    d = _backup_dir()
    files = sorted(d.glob(f"{uuid}-*.bak"), key=_backup_stamp) if d.exists() else []
    if not files:
        raise WriteError(f"no backup for {uuid}")
    data = json.loads(nacl.secret.SecretBox(_master_key()).decrypt(files[0].read_bytes()))
    return ckks.parse_record(base64.b64decode(data["record"]))


# --- pacing ----------------------------------------------------------------------------------

def _state_file():
    return paths.config_dir() / "write-state.json"


def load_state() -> dict:
    try:
        return json.loads(_state_file().read_text())
    except (OSError, ValueError):
        return {"writes": [], "blocked": None}


def save_state(state: dict) -> None:
    """Atomic, created 0600 (like ratelimit.save)."""
    f = _state_file()
    tmp = f.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, f)


def may_write(state: dict, now: float | None = None, n: int = 1) -> tuple[bool, str]:
    """May an edit with `n` writes start now? The gap applies between edits; the writes of one
    edit follow each other at OP_GAP."""
    now = time.time() if now is None else now
    if state.get("blocked"):
        return False, f"writes blocked after an error: {state['blocked']} (icp write-state --clear)"
    recent = [t for t in state.get("writes", []) if now - t < 3600]
    if recent and now - max(recent) < WRITE_MIN_GAP:
        return False, f"wait {WRITE_MIN_GAP - (now - max(recent)):.0f}s between saves"
    if len(recent) + n > WRITE_MAX_PER_HOUR:
        return False, f"{WRITE_MAX_PER_HOUR} saves in the last hour - try later"
    return True, ""


def record_write(state: dict, now: float | None = None) -> None:
    now = time.time() if now is None else now
    state["writes"] = [t for t in state.get("writes", []) if now - t < 3600] + [now]
    save_state(state)


def block(state: dict, reason: str) -> None:
    state["blocked"] = reason
    save_state(state)


# --- live flow (network) -----------------------------------------------------------------------

def fetch(client) -> tuple[dict, dict]:
    """LIVE, read-only: TLKs (recoverable shares, ours + sponsor's, plus plain shares to us) and
    the write zones' records. `client` is an OctagonClient."""
    from ..octagon.client import load_peer_keys
    tlks, view_synckeys = client.fetch_recoverable_tlks()
    records = client.sync_keychain(zones=WRITE_ZONES)
    records.setdefault("synckey", []).extend(view_synckeys)
    oct_state = client.record["octagon"]
    plain = pipeline.unwrap_tlkshares(records.get("tlkshare", []), oct_state["peer_id"],
                                      load_peer_keys(oct_state).encryption.private_key)
    return records, {**plain, **tlks}


def _decrypted(records: dict, keyring: Keyring) -> list:
    """[(record, plist)] for every `item` record we can decrypt."""
    return [(r, d) for r in records.get("item", [])
            if (d := pipeline.decrypt_record(r, keyring.class_keys))]


def _find_record(records: dict, uuid: str) -> ckks.CloudKitRecord | None:
    return next((r for r in records.get("item", []) if r.record_name == uuid), None)


def _send(client, state: dict, op: str, what: str, rec, req: bytes, result: dict) -> None:
    """One write. Any failure blocks further writes and says what already went through."""
    done = result["saved"]
    if done:
        time.sleep(OP_GAP)
    if op != "insert":
        backup_record(rec)
        result["backups"].append(rec.record_name)
    try:
        if op == "delete":
            client.transport.delete_record(req)
        else:
            client.transport.save_record(req)
    except Exception as e:
        block(state, f"{op} {what} {getattr(rec, 'record_name', '')} failed: "
                     f"{type(e).__name__}: {e}")
        raise WriteError(f"{op} of the {what} failed: {e}"
                         + (" - already done: " + ", ".join(done) if done else "")) from e
    record_write(state)
    done.append(f"{op} {what}")


def _read_back(client, state: dict, writes: list, result: dict, then: str) -> None:
    """Fetch again and check that every saved record decrypts to exactly what was sent. Any
    failure blocks further writes."""
    try:
        records2, tlks2 = fetch(client)
    except Exception as e:
        block(state, f"read-back after {', '.join(result['saved'])} failed: "
                     f"{type(e).__name__}: {e}")
        raise WriteError(f"saved ({', '.join(result['saved'])}), but the read-back failed: {e} - "
                         f"{then}") from e
    keyring2 = build_keyring(records2, tlks2)
    for _op, what, _rec, item, _req, uuid in writes:
        fresh = _find_record(records2, uuid)
        back = pipeline.decrypt_record(fresh, keyring2.class_keys) if fresh else None
        if back is None or not _plist_equal(back, item):
            block(state, f"read-back of {uuid} ({what}) does not match")
            raise WriteError(f"saved, but the read-back of the {what} does not match - {then}; "
                             "check the entry on an Apple device")


def edit(client, domain: str, username: str, changes: Changes, *, apply: bool,
         uuid: str | None = None) -> dict:
    """Edit one login (`uuid` picks it exactly, see select_entry). Dry run (apply=False) does
    everything up to and including the encryption self-check, but sends nothing. Returns
    {ok, diff, saved, backups, uuid, rekey, login, sidecar}; `backups` are the record names
    `restore` accepts."""
    records, tlks = fetch(client)
    keyring = build_keyring(records, tlks)
    entries = find_entries(_decrypted(records, keyring))
    entry = select_entry(entries, domain, username, uuid)
    ed = apply_changes(entry, changes, entries)

    # (op, what, record, item, request): updates in place, or a rekey = inserts, then deletes
    writes, deletes = [], []
    if ed.rekey:
        new_login_uuid, req, login = build_insert(entry.login_record, ed.login, keyring)
        writes.append(("insert", "login", None, login, req, new_login_uuid))
        sidecar = ed.sidecar
        if ed.sidecar is not None:
            new_side_uuid, req, sidecar = build_insert(entry.sidecar_record, ed.sidecar, keyring)
            writes.append(("insert", "metadata", None, sidecar, req, new_side_uuid))
        if entry.sidecar_record is not None and not entry.siblings:   # else still theirs
            deletes.append(("delete", "old metadata", entry.sidecar_record,
                            ckks.build_delete_request(entry.sidecar_record)))
        deletes.append(("delete", "old login", entry.login_record,
                        ckks.build_delete_request(entry.login_record)))
    else:
        login, sidecar = ed.login, ed.sidecar
        if login is not None:
            writes.append(("update", "login", entry.login_record, login,
                           build_save(entry.login_record, login, keyring),
                           entry.login_record.record_name))
        if sidecar is not None:
            writes.append(("update", "metadata", entry.sidecar_record, sidecar,
                           build_save(entry.sidecar_record, sidecar, keyring),
                           entry.sidecar_record.record_name))
    login_uuid = next((w[5] for w in writes if w[1] == "login"),
                      entry.login_record.record_name)
    result = {"ok": True, "diff": ed.diff, "saved": [], "backups": [], "dry_run": not apply,
              "uuid": login_uuid, "old_uuid": entry.login_record.record_name, "rekey": ed.rekey,
              "trashed": changes.trash}
    if not apply:
        return result

    state = load_state()
    allowed, why = may_write(state, n=len(writes) + len(deletes))
    if not allowed:
        raise WriteError(why)
    for op, what, rec, _item, req, _uuid in writes:
        _send(client, state, op, what, rec, req, result)

    # read back: the server must now hold exactly the edit - before anything old is deleted
    _read_back(client, state, writes, result, "nothing old was deleted, writes are blocked")

    for op, what, rec, req in deletes:
        try:
            _send(client, state, op, what, rec, req, result)
        except WriteError as e:
            raise WriteError(f"{e} - the new version is saved; the old one is still there "
                             "(duplicate), delete it on an Apple device") from e
    result["login"] = login if login is not None else entry.login
    result["sidecar"] = sidecar if sidecar is not None else entry.sidecar
    return result


# --- create ----------------------------------------------------------------------------------
#
# A new login is modelled on a real one of the same account: its record (zone, class key, record
# fields) is the insert template, and its attribute set decides which attributes the new item
# carries, so the item looks like one the user's own devices wrote. Identity and value
# attributes are set from the input; structural ones are copied; per-item content starts empty;
# anything else is left out and listed in the report.

CREATE_ZONE = "Passwords"
# copied from the template: protection class (must match the template's class key), auth type,
# multi-user / view hints
_COPY_ATTRS = frozenset({"pdmn", "atyp", "musr", "vwht"})
# per-item content: the template's attribute, with the empty value of its type
_EMPTY_ATTRS = frozenset({"path", "sdmn", "port", "desc", "icmt", "alis", "crtr", "type", "cusi",
                          "invi", "nega", "scrp"})


class ExistsError(WriteError):
    """A login with this website + username exists already: CKKS keeps one item per primary key,
    so a second one would replace it on a device. Change it with `edit` instead."""


def _empty_like(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    if isinstance(value, str):
        return ""
    if isinstance(value, (bytes, bytearray)):
        return b""
    return None


def _new_item(template: dict, fixed: dict) -> tuple[dict, list]:
    """(new item, names of template attributes left out). `fixed` wins over the template."""
    item, skipped = {}, []
    for name, value in template.items():
        if name in fixed or name == "sha1":    # receivers compute sha1 themselves
            continue
        if name in _COPY_ATTRS:
            item[name] = value
        elif name in _EMPTY_ATTRS and _empty_like(value) is not None:
            item[name] = _empty_like(value)
        else:
            skipped.append(name)
    if "pdmn" not in item:
        raise WriteError("template login has no protection class (pdmn) - not creating")
    item.update(fixed)
    return item, sorted(skipped)


def _stamp(value) -> float:
    if isinstance(value, datetime.datetime):
        return value.replace(tzinfo=datetime.timezone.utc).timestamp()
    return 0.0


def pick_template(pairs: list, keyring: Keyring, agrp: str, zones: tuple):
    """The (record, item) to model a new login or sidecar on: an own item of `agrp` under the
    current class key, in the first of `zones` that has one, without per-item PCS identity
    fields (those must never be copied). Prefers https and then the newest - closest to what
    the user's devices write today. None if there is none."""
    for zone in zones:
        cands = []
        for rec, it in pairs:
            if (_is_tomb(it) or str(it.get("agrp") or "") != agrp
                    or it.get("class") not in (None, "inet") or record_zone(rec) != zone
                    or any(n.startswith("pcs") for n in rec.fields)
                    or rec.fields.get("encver", 2) != 2):
                continue
            if agrp == AGRP_SIDECAR and not str(it.get("labl") or "").startswith(SIDECAR_LABEL):
                continue
            try:
                keyring.check_current(rec)
            except WriteError:
                continue
            cands.append((rec, it))
        if cands:
            return max(cands, key=lambda c: (c[1].get("ptcl") == "htps", _stamp(c[1].get("cdat"))))
    return None


def new_login(template: dict, srvr: str, acct: str, password: str, ptcl: str,
              stamp: datetime.datetime) -> tuple[dict, list]:
    return _new_item(template, {
        "class": "inet", "agrp": AGRP_LOGIN, "srvr": srvr, "acct": acct, "ptcl": ptcl,
        "labl": f"{srvr} ({acct})", "v_Data": password.encode(), "cdat": stamp, "mdat": stamp,
        "tomb": 0, "sync": True, "UUID": "",       # UUID follows the record name (build_insert)
    })


def new_sidecar(template: dict, srvr: str, acct: str, ptcl: str, stamp: datetime.datetime, *,
                title: str | None, notes: str | None, totp_block: dict | None) -> tuple[dict, list]:
    """Passwords-app metadata for a new login. Title and notes are stored as bytes, like the
    Passwords app does; the title defaults to the website."""
    payload = {"title": (title or srvr).encode(), "notes": (notes or "").encode(), "s_as": []}
    if totp_block:
        payload["totp"] = totp_block
    return _new_item(template, {
        "class": "inet", "agrp": AGRP_SIDECAR, "srvr": srvr, "acct": acct, "ptcl": ptcl,
        "labl": f"{SIDECAR_LABEL}{srvr} ({acct})",
        "v_Data": plistlib.dumps(payload, fmt=plistlib.FMT_BINARY),
        "cdat": stamp, "mdat": stamp, "tomb": 0, "sync": True, "UUID": "",
    })


def _shape_of(item: dict | None) -> dict:
    return {k: type(v).__name__ for k, v in sorted((item or {}).items())}


def create(client, site: str, username: str, password: str, *, title: str | None = None,
           notes: str | None = None, totp: str | None = None, apply: bool) -> dict:
    """Create a new login (+ Passwords metadata when title, notes or a 2FA code are given).
    Dry run (apply=False) builds and self-checks the records but sends nothing. Never deletes.
    Returns {ok, dry_run, uuid, site, user, sidecar, zone, diff, warnings, login_attrs,
    sidecar_attrs, skipped_attrs, saved, backups} - names and types only - plus the items as
    `login_item` / `sidecar_item` for the local vault (secrets: never print those)."""
    srvr = _site_host(site or "")
    if not username:
        raise WriteError("username is required")
    if not password:
        raise WriteError("password is required")
    ptcl = "http" if site.strip().lower().startswith("http://") else "htps"
    totp_block = None
    if totp and totp.strip():
        from .. import totp as totp_codes
        try:
            totp_block = totp_codes.sidecar_from_input(totp)
        except ValueError as e:
            raise WriteError(str(e)) from None
    want_sidecar = bool(title or notes or totp_block)

    records, tlks = fetch(client)
    keyring = build_keyring(records, tlks)
    pairs = _decrypted(records, keyring)
    key = (_norm(srvr), _norm(username))
    if any((_norm(e.domain), _norm(e.username)) == key for e in find_entries(pairs)):
        raise ExistsError(f"a login for {srvr} / {username!r} exists already - "
                          "change it with `icp edit` instead")
    if any(not _is_tomb(it) and str(it.get("agrp") or "") == AGRP_SIDECAR
           and (_norm(it.get("srvr")), _norm(it.get("acct"))) == key for _r, it in pairs):
        raise WriteError(f"Passwords metadata for {srvr} / {username!r} exists without a login - "
                         "check it on an Apple device first")

    tpl = pick_template(pairs, keyring, AGRP_LOGIN, (CREATE_ZONE,))
    if tpl is None:
        raise WriteError(f"no login under the current class key in {CREATE_ZONE} to model the "
                         "new one on - create one in the Passwords app first")
    stamp = _now()
    login, skipped = new_login(tpl[1], srvr, username, password, ptcl, stamp)
    new_uuid, req, login = build_insert(tpl[0], login, keyring, fresh=True)
    writes = [("insert", "login", None, login, req, new_uuid)]
    zone = record_zone(tpl[0])

    sidecar, side_skipped, warnings = None, [], []
    if want_sidecar:
        stpl = pick_template(pairs, keyring, AGRP_SIDECAR,
                             (zone,) + tuple(z for z in WRITE_ZONES if z != zone))
        if stpl is None:
            warnings.append("no Passwords metadata to model on - title, notes and 2FA code were "
                            "not saved; add them in the Passwords app")
        else:
            sidecar, side_skipped = new_sidecar(stpl[1], srvr, username, ptcl, stamp, title=title,
                                                notes=notes, totp_block=totp_block)
            side_uuid, req, sidecar = build_insert(stpl[0], sidecar, keyring, fresh=True)
            writes.append(("insert", "metadata", None, sidecar, req, side_uuid))

    diff = [f"new login: {srvr} / {username!r} ({ptcl}, zone {zone})"]
    if sidecar is not None:
        parts = [n for n, v in (("title", title), ("notes", notes), ("2FA code", totp_block)) if v]
        diff.append("metadata: " + ", ".join(parts))
    result = {"ok": True, "dry_run": not apply, "uuid": new_uuid, "site": srvr,
              "user": username, "sidecar": sidecar is not None, "zone": zone, "diff": diff,
              "warnings": warnings, "login_attrs": _shape_of(login),
              "sidecar_attrs": _shape_of(sidecar),
              "skipped_attrs": sorted(set(skipped) | set(side_skipped)),
              "saved": [], "backups": []}
    if not apply:
        return result

    state = load_state()
    allowed, why = may_write(state, n=len(writes))
    if not allowed:
        raise WriteError(why)
    for op, what, rec, _item, req, _uuid in writes:
        _send(client, state, op, what, rec, req, result)
    _read_back(client, state, writes, result, "writes are blocked")
    result["login_item"], result["sidecar_item"] = login, sidecar
    return result


def restore(client, uuid: str, *, apply: bool) -> dict:
    """Put the backed-up (pre-edit) version of record `uuid` back, with the current etag."""
    old = load_backup(uuid)
    records, tlks = fetch(client)
    keyring = build_keyring(records, tlks)
    current = _find_record(records, uuid)
    if pipeline.decrypt_record(old, keyring.class_keys) is None:
        raise WriteError("backup no longer decrypts (class key gone) - cannot restore")
    keyring.check_current(old)   # same rule as an edit: never write under a rotated class key
    replace = {name: first(decode_fields(fld), 2) for name, fld in old.raw["fields"]
               if name in ("data", "wrappedkey")}
    if current is None:
        # deleted by a rekey: put it back as it was, under its old UUID
        record_bytes = ckks.build_insert_record(old, uuid, replace)
        req = ckks.build_insert_request(record_bytes)
    else:
        record_bytes = ckks.build_update_record(current, replace)
        req = ckks.build_save_request(record_bytes, current.etag)
    if pipeline.decrypt_record(ckks.parse_record(record_bytes), keyring.class_keys) is None:
        raise WriteError("self-check failed: backup does not decrypt under the current record")
    what = "deleted record" if current is None else "record"
    if not apply:
        return {"ok": True, "dry_run": True, "uuid": uuid, "diff": [f"restore {what} {uuid}"]}
    state = load_state()
    # a restore is the remedy for a blocked state, so only the pacing applies to it
    allowed, why = may_write({**state, "blocked": None})
    if not allowed:
        raise WriteError(why)
    if current is not None:
        backup_record(current)
    try:
        client.transport.save_record(req)
    except Exception as e:
        block(state, f"restore of {uuid} failed: {type(e).__name__}: {e}")
        raise WriteError(f"restore failed: {e}") from e
    record_write(state)
    return {"ok": True, "dry_run": False, "uuid": uuid, "saved": [f"restore {what}"],
            "backups": [uuid] if current is not None else []}
