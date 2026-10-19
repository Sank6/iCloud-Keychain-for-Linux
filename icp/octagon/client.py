"""Octagon join + keychain sync orchestration: ensure_peer_identity -> fetch_changes ->
join(voucher) -> sync_keychain -> decrypt_to_vault. See RESEARCH.md (Stages 4-5)."""

from __future__ import annotations

import dataclasses
import logging
import time

from . import keys as ok
from ..vault import store as vault
from ..escrow import bottle as escrow, srp as escrow_srp
from ..transport import ckks, cloudkit
from ..keychain import pipeline
from ..proto import cuttlefish as cf
from ..proto.codec import decode_fields, first, first_str
from ..errors import AppleError
from ..sharing import groups as sharing
from ..vault.host import CredentialStore

log = logging.getLogger(__name__)


# Prevailing builtin Octagon policy version<->hash, declared in our stableInfo; Cuttlefish validates
# them. If Apple bumps the version, refresh via fetchPolicyDocuments.
FROZEN_POLICY_VERSION = 5
FROZEN_POLICY_HASH = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
FLEXIBLE_POLICY_VERSION = 20
FLEXIBLE_POLICY_HASH = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="

PEER_MODEL_ID = "MacBookPro18,3"
PEER_OS_VERSION = "macOS 13.4.1 (22F8)"


def is_joined(record: dict) -> bool:
    oct_state = record.get("octagon") or {}
    return bool(oct_state.get("joined") or oct_state.get("sponsor"))


def ensure_peer_identity(record: dict, device, *, clock: int = 1) -> dict:
    """Generate (once) and persist the Octagon self-peer into the session `record`.

    Stores the two P-384 private keys + the signed permanent/stable/dynamic blobs and the
    peerID, so a later sync reuses the same identity. Returns record['octagon'].

    The stored stableInfo/dynamicInfo here are an initial form (prevailing policy constants,
    clock=1, trusts only self); the live join REGENERATES + re-signs both from the fetchChanges
    trust state (`build_join_peer`), as the real client does.
    """
    oct_state = record.get("octagon")
    if oct_state and oct_state.get("peer_id"):
        return oct_state

    keys = ok.PeerKeySet.generate()
    machine_id = getattr(device, "device_id", "") or record.get("dsid_numeric", "")
    serial = getattr(device, "serial", "") or "0000000000"
    model = PEER_MODEL_ID

    perm = ok.build_permanent_info(keys, machine_id=str(machine_id), model_id=model,
                                   epoch=1, creation_time=int(time.time()))
    stable = ok.build_stable_info(
        keys, clock=clock,
        frozen_policy_version=FROZEN_POLICY_VERSION, frozen_policy_hash=FROZEN_POLICY_HASH,
        flexible_policy_version=FLEXIBLE_POLICY_VERSION, flexible_policy_hash=FLEXIBLE_POLICY_HASH,
        device_name="", serial_number=str(serial), os_version=PEER_OS_VERSION,
        user_controllable_views=ok.UCV_FOLLOWING)
    dynamic = ok.build_dynamic_info(keys, clock=clock, included_peer_ids=[perm.peer_id])

    oct_state = {
        "peer_id": perm.peer_id,
        "keys": keys.to_storage(),
        "permanent": {"data": perm.data.hex(), "sig": perm.sig.hex()},
        "stable": stable.to_storage(),
        "dynamic": dynamic.to_storage(),
        "created_at": int(time.time()),
    }
    record["octagon"] = oct_state
    return oct_state


def load_peer_keys(oct_state: dict) -> ok.PeerKeySet:
    return ok.PeerKeySet.from_storage(oct_state["keys"])


def trust_from_changes(changes: dict, sponsor_peer_id: str) -> tuple[list[str], int, int]:
    """From a fetchChanges result, derive (sponsor's included peerIDs, next stable clock,
    next dynamic clock) for building our joining peer."""
    stable_clocks = [0]
    sponsor_includeds: list[str] = []
    sponsor_dyn_clock = 0
    for p in changes.get("peers", []):
        si = p.get("stable_info")
        if si is not None:
            stable_clocks.append(ok.parse_stable_info_data(si.info).get("clock", 0))
        if p.get("hash") == sponsor_peer_id and p.get("dynamic_info") is not None:
            di = ok.parse_dynamic_info_data(p["dynamic_info"].info)
            sponsor_includeds = di.get("included", [])
            sponsor_dyn_clock = di.get("clock", 0)
    return sponsor_includeds, max(stable_clocks) + 1, sponsor_dyn_clock + 1


def build_join_peer(oct_state: dict, keys: ok.PeerKeySet, voucher: cf.SignedBlob,
                    included_peer_ids: list[str], stable_clock: int, dynamic_clock: int,
                    serial: str) -> bytes:
    """Regenerate + re-sign stableInfo (prevailing policy) and dynamicInfo (sponsor's trusted
    peers + self), then encode the CuttlefishPeer for joinWithVoucher. The permanentInfo is the
    fixed identity; the other two are fresh at join time, as the real client does."""
    our_peer_id = oct_state["peer_id"]
    stable = ok.build_stable_info(
        keys, clock=stable_clock,
        frozen_policy_version=FROZEN_POLICY_VERSION, frozen_policy_hash=FROZEN_POLICY_HASH,
        flexible_policy_version=FLEXIBLE_POLICY_VERSION, flexible_policy_hash=FLEXIBLE_POLICY_HASH,
        device_name="", serial_number=str(serial), os_version=PEER_OS_VERSION,
        user_controllable_views=ok.UCV_FOLLOWING)
    includeds = list(dict.fromkeys(list(included_peer_ids) + [our_peer_id]))  # +self, dedup, order
    dynamic = ok.build_dynamic_info(keys, clock=dynamic_clock, included_peer_ids=includeds)
    return cf.encode_cuttlefish_peer(
        our_peer_id,
        cf.SignedBlob(bytes.fromhex(oct_state["permanent"]["data"]),
                      bytes.fromhex(oct_state["permanent"]["sig"])),
        cf.SignedBlob(stable.data, stable.sig),
        cf.SignedBlob(dynamic.data, dynamic.sig),
        voucher=voucher)


def decrypt_to_vault(records_by_type: dict, oct_state: dict, tlks: dict | None = None,
                     shared=None) -> int:
    """Decrypt fetched CKKS records into the encrypted vault. Returns credential count. `tlks` are
    the pre-fetched per-view TLKs (from fetchRecoverableTLKShares), UNIONed with the plain tlkshare
    records addressed to us. `shared(items)` -> [group dicts] adds the shared password groups;
    it is best-effort: if it fails, the own keychain is still saved."""
    keys = load_peer_keys(oct_state)
    items = pipeline.decrypt_all(records_by_type, oct_state["peer_id"],
                                 keys.encryption.private_key, tlks)
    creds = CredentialStore.from_items(items).all()
    if shared is not None:
        try:
            groups = shared(items)
        except (AppleError, ValueError, IndexError) as e:
            log.warning("shared password groups skipped: %s", type(e).__name__)
            groups = []
        for g in groups:
            creds += [dataclasses.replace(c, group=g["name"] or g["id"])
                      for c in CredentialStore.from_items(g["items"]).all()]
    store = CredentialStore(creds)
    vault.save_vault(store)
    return len(store)


class OctagonError(AppleError):
    pass


def parse_viable_bottles(raw: bytes) -> list[dict]:
    """-> [{id, otbottle bytes}]."""
    out = []
    for ed in decode_fields(raw).get(1, []):
        edf = decode_fields(ed)
        bottle_msg = first(edf, 2)
        otbottle = first(decode_fields(bottle_msg), 2) if bottle_msg is not None else None
        out.append({"id": first_str(edf, 1), "otbottle": otbottle})
    return out


class OctagonClient:
    """Drives the live join + sync from a logged-in session. Each method makes live CloudKit
    calls and raises `cloudkit.CloudKitError`/`OctagonError` on failure."""

    def __init__(self, record: dict, device, anisette):
        self.record = record
        self.device = device
        self.anisette = anisette
        mme = record.get("mme") or {}
        tokens = mme.get("tokens") or {}
        self.ck_token = tokens.get("cloudKitToken")
        self.mme_dsid = str(mme.get("dsid") or record.get("dsid_numeric") or "")
        self.mme_token = mme.get("mmeAuthToken")
        self.adsid = record.get("dsid") or ""   # the GUID adsid (escrow key derivation)
        if not self.ck_token:
            raise OctagonError("no cloudKitToken in session - run `icp login` first")
        # x-cloudkit-userid = per-container cloudKitUserId from ckAppInit (NOT the dsid -> 401). Cached.
        self.user_id = mme.get("cloudKitUserId")
        if not self.user_id:
            if not self.mme_token:
                raise OctagonError("no mmeAuthToken in session - run `icp login`")
            self.user_id = cloudkit.ck_app_init(
                cloudkit.CUTTLEFISH_CONTAINER, cloudkit.CUTTLEFISH_BUNDLE,
                self.mme_dsid, self.mme_token, anisette)
            mme["cloudKitUserId"] = self.user_id
            record["mme"] = mme   # persisted by the caller's next session.save
        dev = cloudkit.DeviceConfig(
            device_uuid=getattr(device, "device_id", ""),
            serial=getattr(device, "serial", "") or "0000000000",
            name=getattr(device, "name", "") or "Mac")
        self.transport = cloudkit.CloudKitTransport(self.ck_token, self.user_id, dev, anisette)

    def fetch_changes(self, sync_token: str | None = None) -> dict:
        result = self.transport.invoke("fetchChanges", cf.encode_fetch_changes_request(sync_token))
        return cf.parse_fetch_changes_response(result.serialized_result)

    def fetch_viable_bottles(self) -> list[dict]:
        result = self.transport.invoke(
            "fetchViableBottles", escrow_srp.encode_fetch_viable_bottles_request())
        return parse_viable_bottles(result.serialized_result)

    def list_recoverable_bottles(self, escrow_host: str, email: str, pet: str,
                                 *, warn=None) -> list[dict]:
        """Correlate the viable bottles (those carrying a decryptable OTBottle)
        with escrowproxy GETRECORDS metadata that names each backed-up device."""
        bottles = [b for b in self.fetch_viable_bottles() if b.get("otbottle")]
        meta_by_label: dict[str, dict] = {}
        try:
            recovery = escrow_srp.EscrowRecovery(escrow_host, email, pet, self.anisette)
            for rec in recovery.list_records():
                meta_by_label[rec["label"]] = rec.get("meta") or {}
        except Exception as e:               # noqa: BLE001 - metadata is best-effort, don't gate a join on it
            if warn:
                warn(f"GETRECORDS device metadata unavailable: {e}")
        out = [{"id": b["id"], "otbottle": b["otbottle"], "meta": meta_by_label.get(b["id"], {})}
               for b in bottles]
        return out

    def sync_keychain(self, zones=ckks.KEYCHAIN_ZONES) -> dict:
        """Fetch every keychain zone's records (live) and group them by CKKS type. A missing or
        empty zone is skipped rather than failing the whole sync."""
        grouped: dict[str, list] = {}
        for zone in zones:
            zid = ckks.record_zone_identifier(zone, self.user_id)
            continuation = None
            try:
                while True:
                    raw = self.transport.fetch_records(
                        ckks.build_retrieve_changes_request(zid, continuation))
                    page = ckks.parse_retrieve_changes_response(raw)
                    for r in page["records"]:
                        grouped.setdefault(r.type, []).append(r)
                    continuation = page.get("continuation_token")
                    if page.get("status") != 1 or not continuation:
                        break
            except cloudkit.CloudKitError:
                continue
        return grouped

    def _recover_sponsor(self, escrow_host: str, email: str, pet: str, passcode: bytes,
                         chosen: dict | None = None, *, confirm_irreversible: bool):
        """Recover the chosen escrow bottle (IRREVERSIBLE) and persist the recovered sponsor
        identity's peerID + encryption key into `octagon['sponsor']`. Returns the
        `RecoveredIdentity`. `chosen` is a `{id, otbottle}` dict picked by the caller (e.g. from
        `list_recoverable_bottles`); when None, falls back to the first viable bottle. The sponsor
        key is what lets a later sync fetch the user-controllable views' TLKs (Passwords/Manatee)
        - a freshly-joined peer isn't entitled to them, but the sponsor is, so
        `fetchRecoverableTLKShares(forPeer=sponsor)` returns them (see `fetch_recoverable_tlks`).
        `confirm_irreversible` MUST be True (set only after the user's typed confirmation), and
        each call spends one of the ~10 escrow attempts."""
        if chosen is None:
            bottles = self.fetch_viable_bottles()
            chosen = next((b for b in bottles if b.get("otbottle")), None)
        if not chosen or not chosen.get("otbottle"):
            raise OctagonError("no viable escrow bottle found for this account")

        recovery = escrow_srp.EscrowRecovery(escrow_host, email, pet, self.anisette)
        entropy = recovery.try_recover_escrow(
            chosen["id"], passcode, confirm_irreversible=confirm_irreversible)

        otbottle = escrow.OTBottle.parse(chosen["otbottle"])
        identity = escrow.recover_identity(otbottle, entropy, self.adsid)
        self.record["octagon"]["sponsor"] = {
            "peer_id": identity.peer_id,
            "encryption_priv_x963": identity.encryption_key.private_x963().hex(),
        }
        return identity

    def join_via_escrow(self, escrow_host: str, email: str, pet: str, passcode: bytes,
                        chosen: dict | None = None, *, confirm_irreversible: bool = False) -> str:
        """Full escrow-recovery join: recover the chosen bottle -> vouch -> join.
        `chosen` is the `{id, otbottle}` bottle the caller selected (from
        `list_recoverable_bottles`); None falls back to the first viable bottle. Returns the
        recovered sponsor peerID. `confirm_irreversible` is forwarded to the escrow SRP and MUST
        be True (set only after the user's typed confirmation)."""
        identity = self._recover_sponsor(escrow_host, email, pet, passcode, chosen,
                                         confirm_irreversible=confirm_irreversible)

        oct_state = self.record["octagon"]
        voucher = identity.make_voucher(oct_state["peer_id"])

        # Rebuild stableInfo + dynamicInfo from the live trust state (prevailing policy, current
        # clock, and the sponsor's trusted peers + self), then join.
        changes = self.fetch_changes()
        includeds, stable_clock, dyn_clock = trust_from_changes(changes, identity.peer_id)
        if not includeds:                       # sponsor not in the page - trust at least it + self
            includeds = [identity.peer_id]
        serial = getattr(self.device, "serial", "") or "0000000000"
        peer = build_join_peer(oct_state, load_peer_keys(oct_state), voucher,
                               includeds, stable_clock, dyn_clock, serial)
        req = cf.encode_join_with_voucher_request(peer, restore_point=changes.get("sync_token"))
        self.transport.invoke("joinWithVoucher", req)   # raises on failure
        self.record["octagon"]["joined"] = True
        return identity.peer_id

    def _fetch_recoverable_for(self, for_peer_id, enc_private_key):
        """fetchRecoverableTLKShares(forPeer=for_peer_id), unwrapped with `enc_private_key`
        (which must be that peer's encryption key). Returns ({tlkUuid: key}, [synckey records])."""
        result = self.transport.invoke(
            "fetchRecoverableTLKShares", cf.encode_fetch_recoverable_tlkshares_request(for_peer_id))
        parsed = cf.parse_recoverable_tlkshares_response(result.serialized_result)
        share_records = [ckks.parse_record(r) for r in parsed["share_records"]]
        view_synckeys = [ckks.parse_record(r) for r in parsed["synckey_records"]]
        tlks = pipeline.unwrap_tlkshares(share_records, for_peer_id, enc_private_key)
        return tlks, view_synckeys

    def fetch_recoverable_tlks(self) -> tuple[dict, list]:
        """Obtain every view's TLK via fetchRecoverableTLKShares, from BOTH our own peer and the
        escrow-recovered sponsor.

        A freshly-joined peer is only entitled to the always-on views (WiFi, Home, ...), so
        `forPeer=us` never returns the user-controllable views (Passwords/Manatee). The sponsor
        identity IS entitled to them, so we also ask `forPeer=sponsor` and unwrap those shares with
        the sponsor's encryption key (persisted at join by `_recover_sponsor`). Both sets are
        UNIONed."""
        oct_state = self.record["octagon"]
        keys = load_peer_keys(oct_state)
        tlks, view_synckeys = self._fetch_recoverable_for(
            oct_state["peer_id"], keys.encryption.private_key)

        sponsor = oct_state.get("sponsor")
        if sponsor:
            sp_key = ok.load_peer_key_x963(bytes.fromhex(sponsor["encryption_priv_x963"]))
            sp_tlks, sp_synckeys = self._fetch_recoverable_for(
                sponsor["peer_id"], sp_key.private_key)
            tlks = {**tlks, **sp_tlks}                 # sponsor adds the user-controllable views
            view_synckeys = view_synckeys + sp_synckeys
        return tlks, view_synckeys

    def sync_and_decrypt(self) -> int:
        """Fetch every view's TLK (via fetchRecoverableTLKShares), then fetch the keychain zones
        and decrypt them into the vault. Returns credential count."""
        tlks, view_synckeys = self.fetch_recoverable_tlks()
        records = self.sync_keychain()
        records.setdefault("synckey", []).extend(view_synckeys)
        return decrypt_to_vault(records, self.record["octagon"], tlks, shared=lambda items:
                                sharing.fetch_groups(self.record, self.device, self.anisette, items))
