"""Diagnostic logging for the token flow. `login --debug` writes a redacted transcript to
~/.config/icp/debug-<ts>.log - secret values are replaced with their length, safe to share."""

import json
import logging
import time
from pathlib import Path

from . import paths

# Keys whose string values must never be written verbatim.
_SECRET_HINTS = (
    "token", "pet", "sk", "spd", "m1", "m2", "secret", "password", "pwd",
    "cookie", "auth", "prk", "et", "key", "salt", "challenge",
)


def redact(value, key: str = ""):
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes:{len(value)}>"
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        low = key.lower()
        if any(h in low for h in _SECRET_HINTS) and len(value) > 8:
            return f"<redacted:{len(value)}>"
        if len(value) > 80:
            return f"<str:{len(value)}>"
        return value
    return value


def start() -> Path:
    """Attach a DEBUG file handler; return the log path."""
    path = paths.config_dir() / f"debug-{int(time.time())}.log"
    handler = logging.FileHandler(path)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger = logging.getLogger("icp")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    path.chmod(0o600)
    return path


def dump(logger: logging.Logger, label: str, obj) -> None:
    logger.debug("%s (redacted):\n%s", label, json.dumps(redact(obj), indent=2, default=str))


def dump_token_dict(logger: logging.Logger, spd: dict) -> None:
    """Log the available app tokens by name + expiry - the most useful single artifact."""
    t = spd.get("t") or {}
    logger.debug("spd contains %d app token(s):", len(t))
    for name, entry in t.items():
        if isinstance(entry, dict):
            logger.debug("  token %r -> fields=%s expiry=%s",
                         name, list(entry.keys()), entry.get("expiry"))
        else:
            logger.debug("  token %r -> %s", name, type(entry).__name__)
    logger.debug("spd top-level keys: %s", list(spd.keys()))
    logger.debug("ids present: adsid=%s DsPrsId=%s GsIdmsToken=%s",
                 bool(spd.get("adsid")), bool(spd.get("DsPrsId")), bool(spd.get("GsIdmsToken")))


# Extra zone names probed by `icp diag zones` (read-only fetch; an unknown zone just errors out).
# Guesses for where shared password groups might live - Apple's KCSharing code is closed source.
_PROBE_ZONES = ("KCSharing", "SharedPasswords", "PasswordsSharing", "Sharing", "SharedGroups")


def zone_report(client, out) -> None:
    """`icp diag zones`: which keychain zones this peer sees and what they hold - counts and
    access groups (`agrp`) only. Never prints a domain, username, label or secret value.

    Answers "why is a login missing": a zone we can't fetch, items we can't decrypt (no TLK for
    that view), or items decrypted but dropped by `classify_item` (e.g. an unknown agrp)."""
    from collections import Counter
    from .transport import ckks, cloudkit
    from .keychain import pipeline
    from .octagon.client import load_peer_keys
    from .vault.host import classify_item

    tlks, view_synckeys = client.fetch_recoverable_tlks()
    out(f"TLKs via fetchRecoverableTLKShares: {len(tlks)}")

    per_zone: dict[str, dict] = {}
    all_records: dict[str, list] = {"synckey": list(view_synckeys)}
    for zone in ckks.KEYCHAIN_ZONES + _PROBE_ZONES:
        zid = ckks.record_zone_identifier(zone, client.user_id)
        types: Counter = Counter()
        items, continuation, err = [], None, ""
        try:
            while True:
                page = ckks.parse_retrieve_changes_response(client.transport.fetch_records(
                    ckks.build_retrieve_changes_request(zid, continuation)))
                for r in page["records"]:
                    types[r.type] += 1
                    all_records.setdefault(r.type, []).append(r)
                    if r.type == "item":
                        items.append(r)
                continuation = page.get("continuation_token")
                if page.get("status") != 1 or not continuation:
                    break
        except cloudkit.CloudKitError as e:
            err = f"error {getattr(e, 'code', '')}".strip()
        per_zone[zone] = {"types": types, "items": items, "err": err}

    keys = load_peer_keys(client.record["octagon"])
    plain = pipeline.unwrap_tlkshares(all_records.get("tlkshare", []),
                                      client.record["octagon"]["peer_id"],
                                      keys.encryption.private_key)
    class_keys = pipeline.unwrap_class_keys(all_records.get("synckey", []), {**plain, **tlks})

    out("")
    out(f"{'zone':<24} {'records':>8} {'items':>6} {'decrypted':>9}  types / status")
    agrps: Counter = Counter()
    kinds: dict[str, Counter] = {}
    for zone, z in per_zone.items():
        dec = pipeline.decrypt_items(z["items"], class_keys)
        for it in dec:
            g = str(it.get("agrp") or "?")
            agrps[(zone, g)] += 1
            kind = classify_item(it)[0]
            kinds.setdefault(f"{zone} {g}", Counter())[kind] += 1
            # Form only (does it look like a login?), never the values themselves.
            shape = kinds[f"{zone} {g}"]
            shape["+srvr"] += bool(it.get("srvr"))
            shape["+acct"] += bool(it.get("acct"))
            raw = it.get("v_Data") or b""
            if isinstance(raw, (bytes, bytearray)) and raw[:6] == b"bplist":
                shape["+v_plist"] += 1
                try:
                    import plistlib
                    pl = plistlib.loads(bytes(raw))
                    if isinstance(pl, dict):
                        for k in pl:             # key NAMES only, never values
                            shape[f"key:{k}"] += 1
                except Exception:
                    pass
            elif raw:
                shape["+v_other"] += 1
        status = z["err"] or ", ".join(f"{t}={n}" for t, n in sorted(z["types"].items())) or "empty"
        out(f"{zone:<24} {sum(z['types'].values()):>8} {len(z['items']):>6} {len(dec):>9}  {status}")

    out("")
    out("decrypted items by zone + access group (kind as icp classifies it):")
    for (zone, g), n in sorted(agrps.items()):
        k = ", ".join(f"{kd}={c}" for kd, c in kinds[f"{zone} {g}"].most_common())
        out(f"  {zone:<14} {g:<55} {n:>5}  {k}")


# --- Shared-passwords ("Shared Groups") container probe --------------------------------------
# A sharing group the user OWNS lives not in the keychain CKKS container but in container
# `com.apple.security.shared.keychain` (bundle `com.apple.security.kcsharing`): one CloudKit zone
# per group, named `group-<uuid>`, in the owner's PRIVATE DB (groups shared WITH the user sit in
# the SHARED DB). Provenance: rustpush src/passwords.rs. This probe is strictly read-only - it
# only enumerates zones (RetrieveZoneChanges) and counts records (RecordRetrieveChanges); it never
# decrypts, accepts a share, or writes anything, and it prints only zone/record-type NAMES and
# counts (group zone names are UUIDs, owner is an opaque per-container id - no personal data).

def _probe_scope(transport, bundle, scope, dbnum, out) -> None:
    from collections import Counter
    from .transport import ckks, cloudkit

    out("")
    out(f"  [{scope} DB] enumerating zones (RetrieveZoneChanges)...")
    zones, continuation = [], None
    try:
        for _ in range(25):                       # page cap: keep request volume modest
            page = ckks.parse_zone_changes_response(transport.fetch_zone_changes(
                continuation, bundle=bundle, database_scope=scope, database=dbnum))
            zones.extend(page["zones"])
            continuation = page.get("continuation_token")
            if page.get("status") == 2 or not continuation:
                break
            time.sleep(0.3)
    except cloudkit.CloudKitError as e:
        out(f"    zone list FAILED code={getattr(e, 'code', '')} "
            f"http={getattr(e, 'http_status', '')}: {e}")
        return
    except Exception as e:                         # noqa: BLE001 - never crash a probe; class only
        out(f"    zone list error: {type(e).__name__}")
        return

    live = [z for z in zones if z.get("change_type") != 2]
    out(f"    zones returned: {len(zones)} ({len(live)} live, rest deleted)")
    for z in live:
        out(f"      zone {z['name']!r}  owner={z['owner']!r}  changeType={z['change_type']}")

    group_zones = [z for z in live if str(z["name"]).startswith("group-")]
    for z in group_zones:
        time.sleep(0.3)
        types: Counter = Counter()
        continuation = None
        try:
            for _ in range(10):
                raw = transport.fetch_records(
                    ckks.build_retrieve_changes_request(z["raw"], continuation),
                    bundle=bundle, database_scope=scope, database=dbnum)
                page = ckks.parse_retrieve_changes_response(raw)
                for r in page["records"]:
                    types[r.type] += 1
                continuation = page.get("continuation_token")
                if page.get("status") != 1 or not continuation:
                    break
            summary = ", ".join(f"{t}={n}" for t, n in sorted(types.items())) or "empty"
            out(f"      records in {z['name']!r}: {sum(types.values())}  ({summary})")
        except cloudkit.CloudKitError as e:
            out(f"      records in {z['name']!r}: FAILED code={getattr(e, 'code', '')}: {e}")
        except Exception as e:                     # noqa: BLE001
            out(f"      records in {z['name']!r}: error {type(e).__name__}")


def sharing_report(record: dict, device, anisette, out, *,
                   container: str | None = None, bundle: str | None = None) -> None:
    """`icp diag sharing` / `icp diag container <id>`: read-only probe of a CloudKit container's
    private + shared DBs for shared-password group zones. Reuses the session's existing tokens
    (no re-auth); if they are missing, reports and stops rather than prompting."""
    from .transport import cloudkit

    container = container or cloudkit.KCSHARING_CONTAINER
    bundle = bundle or cloudkit.KCSHARING_BUNDLE

    mme = record.get("mme") or {}
    tokens = mme.get("tokens") or {}
    ck_token = tokens.get("cloudKitToken")
    mme_dsid = str(mme.get("dsid") or record.get("dsid_numeric") or "")
    mme_token = mme.get("mmeAuthToken")
    if not ck_token or not mme_token:
        out("no cloudKitToken/mmeAuthToken in session - run `icp sync` once, then retry")
        return

    out(f"container {container}  (bundle {bundle})")
    try:
        user_id = cloudkit.ck_app_init(container, bundle, mme_dsid, mme_token, anisette)
    except cloudkit.CloudKitError as e:
        out(f"  ckAppInit FAILED (http={getattr(e, 'http_status', '')}): {e}")
        out("  -> this account/token cannot open the container (or it does not exist).")
        return
    out("  ckAppInit ok - per-container cloudKitUserId resolved (container is reachable)")

    dev = cloudkit.DeviceConfig(
        device_uuid=getattr(device, "device_id", ""),
        serial=getattr(device, "serial", "") or "0000000000",
        name=getattr(device, "name", "") or "Mac")
    transport = cloudkit.CloudKitTransport(ck_token, user_id, dev, anisette, container=container)

    for scope, dbnum in (("Private", cloudkit.DB_PRIVATE), ("Shared", cloudkit.DB_SHARED)):
        _probe_scope(transport, bundle, scope, dbnum, out)


def groups_report(client, out) -> None:
    """`icp diag groups`: open every shared password group we own and report what decrypts -
    group name, item count and how icp classifies the items. Never prints a login's values."""
    from collections import Counter
    from .keychain import pipeline
    from .octagon.client import load_peer_keys
    from .sharing import groups as sharing
    from .vault.host import CredentialStore, classify_item

    tlks, view_synckeys = client.fetch_recoverable_tlks()
    records = client.sync_keychain()
    records.setdefault("synckey", []).extend(view_synckeys)
    keys = load_peer_keys(client.record["octagon"])
    items = pipeline.decrypt_all(records, client.record["octagon"]["peer_id"],
                                 keys.encryption.private_key, tlks)
    groups = sharing.fetch_groups(client.record, client.device, client.anisette, items)
    out(f"shared groups opened: {len(groups)}")
    for g in groups:
        kinds = Counter(classify_item(it)[0] for it in g["items"])
        agrps = Counter(str(it.get("agrp") or "?") for it in g["items"])
        logins = len(CredentialStore.from_items(g["items"]))
        out(f"  {g['name'] or '(no name)'!r:<24} items={len(g['items']):>3}  logins={logins:>3}  "
            + ", ".join(f"{k}={n}" for k, n in kinds.most_common()))
        for a, n in agrps.most_common():
            out(f"      {a:<50} {n:>3}")
