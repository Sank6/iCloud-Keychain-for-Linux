"""Offline tests for the orchestration's non-network parts: identity persistence + join assembly."""

import unittest

from icp.octagon import client as octagon, keys as ok
from icp.proto import cuttlefish as cf


class _Device:
    device_id = "DEVICE-UUID-1"
    serial = "C02SERIAL"
    name = "Sank's Mac"


class SyncSourcesTlksFromRpcTests(unittest.TestCase):
    def test_sync_keychain_follows_zone_continuation_tokens(self):
        client = octagon.OctagonClient.__new__(octagon.OctagonClient)  # bypass __init__/network
        client.user_id = "CKUSER"

        class _Transport:
            def __init__(self):
                self.requests = []

            def fetch_records(self, request):
                self.requests.append(request)
                return b"page%d" % len(self.requests)

        client.transport = _Transport()
        orig_build = octagon.ckks.build_retrieve_changes_request
        orig_parse = octagon.ckks.parse_retrieve_changes_response
        requests = []

        def fake_build(zid, continuation_token=None):
            requests.append(continuation_token)
            return b"request"

        def fake_parse(raw):
            if raw == b"page1":
                return {"records": [_Record("item")], "continuation_token": b"next", "status": 1}
            return {"records": [_Record("synckey")], "continuation_token": b"done", "status": 3}

        octagon.ckks.build_retrieve_changes_request = fake_build
        octagon.ckks.parse_retrieve_changes_response = fake_parse
        try:
            grouped = client.sync_keychain(zones=("Passwords",))
        finally:
            octagon.ckks.build_retrieve_changes_request = orig_build
            octagon.ckks.parse_retrieve_changes_response = orig_parse

        self.assertEqual(requests, [None, b"next"])
        self.assertEqual([r.type for r in grouped["item"]], ["item"])
        self.assertEqual([r.type for r in grouped["synckey"]], ["synckey"])

    def test_sync_and_decrypt_threads_recoverable_tlks_and_view_synckeys(self):
        # The Passwords view's TLK is NOT in plain-zone tlkshare records addressed to a fresh peer:
        # `sync` obtains TLKs via fetchRecoverableTLKShares and merges its viewkey synckeys before
        # decrypting.
        client = octagon.OctagonClient.__new__(octagon.OctagonClient)  # bypass __init__/network
        client.record = {"octagon": {"peer_id": "SHA256:me"}}
        client.fetch_recoverable_tlks = lambda: ({"TLK-PW": b"k" * 64}, ["VIEW-SYNCKEY"])
        client.sync_keychain = lambda: {"synckey": ["ZONE-SYNCKEY"], "item": []}
        captured = {}
        orig = octagon.decrypt_to_vault
        octagon.decrypt_to_vault = (
            lambda recs, oct_state, tlks=None, shared=None: captured.update(recs=recs, tlks=tlks) or 7)
        try:
            n = client.sync_and_decrypt()
        finally:
            octagon.decrypt_to_vault = orig
        self.assertEqual(n, 7)
        self.assertEqual(captured["tlks"], {"TLK-PW": b"k" * 64})           # TLKs from the RPC
        self.assertEqual(captured["recs"]["synckey"], ["ZONE-SYNCKEY", "VIEW-SYNCKEY"])  # merged


class FetchRecoverableUnionTests(unittest.TestCase):
    def _client_with(self, octagon_state):
        client = octagon.OctagonClient.__new__(octagon.OctagonClient)  # bypass __init__/network
        client.record = {"octagon": octagon_state}
        return client

    def test_unions_self_and_sponsor_recoverable_tlks(self):
        # The sponsor fetch is what supplies the user-controllable views (Passwords/Manatee)
        # that our own peer is not entitled to; both fetches must be UNIONed.
        sp_key_hex = ok.generate_peer_key().private_x963().hex()
        client = self._client_with({
            "peer_id": "SHA256:me",
            "keys": ok.PeerKeySet.generate().to_storage(),
            "sponsor": {"peer_id": "SHA256:sponsor", "encryption_priv_x963": sp_key_hex},
        })
        calls = []

        def fake_fetch(for_peer_id, enc_private_key):
            calls.append(for_peer_id)
            if for_peer_id == "SHA256:me":
                return {"TLK-WIFI": b"w" * 64}, ["SK-sys"]
            return {"TLK-PW": b"p" * 64}, ["SK-pw"]

        client._fetch_recoverable_for = fake_fetch
        tlks, synckeys = client.fetch_recoverable_tlks()
        self.assertEqual(tlks, {"TLK-WIFI": b"w" * 64, "TLK-PW": b"p" * 64})
        self.assertEqual(synckeys, ["SK-sys", "SK-pw"])
        self.assertEqual(calls, ["SHA256:me", "SHA256:sponsor"])

    def test_without_sponsor_only_self_is_fetched(self):
        client = self._client_with({
            "peer_id": "SHA256:me",
            "keys": ok.PeerKeySet.generate().to_storage(),
        })
        calls = []
        client._fetch_recoverable_for = (
            lambda p, k: (calls.append(p), ({"T": b"x" * 64}, []))[1])
        tlks, _ = client.fetch_recoverable_tlks()
        self.assertEqual(calls, ["SHA256:me"])
        self.assertEqual(tlks, {"T": b"x" * 64})


class _Record:
    def __init__(self, type_):
        self.type = type_


class EnsureIdentityTests(unittest.TestCase):
    def test_generates_and_persists(self):
        record = {}
        st = octagon.ensure_peer_identity(record, _Device())
        self.assertTrue(st["peer_id"].startswith("SHA256:"))
        self.assertIn("octagon", record)
        self.assertIn("signing_priv_x963", st["keys"])

    def test_idempotent_reuse(self):
        record = {}
        a = octagon.ensure_peer_identity(record, _Device())
        b = octagon.ensure_peer_identity(record, _Device())
        self.assertEqual(a["peer_id"], b["peer_id"])  # same identity reused, not regenerated

    def test_keys_reload(self):
        record = {}
        st = octagon.ensure_peer_identity(record, _Device())
        keys = octagon.load_peer_keys(st)
        self.assertEqual(len(keys.signing.public_spki()) > 0, True)


class JoinPeerAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.record = {}
        self.st = octagon.ensure_peer_identity(self.record, _Device())
        self.keys = octagon.load_peer_keys(self.st)

    def test_stable_info_uses_prevailing_policy(self):
        p = ok.parse_stable_info_data(bytes.fromhex(self.st["stable"]["data"]))
        self.assertEqual(p["frozen_policy_version"], octagon.FROZEN_POLICY_VERSION)
        self.assertEqual(p["frozen_policy_hash"], octagon.FROZEN_POLICY_HASH)
        self.assertEqual(p["flexible_policy_version"], octagon.FLEXIBLE_POLICY_VERSION)
        self.assertEqual(p["flexible_policy_hash"], octagon.FLEXIBLE_POLICY_HASH)
        self.assertEqual(p["user_controllable_views"], ok.UCV_FOLLOWING)

    def _changes(self, sponsor_id, sponsor_includes, sponsor_dyn_clock, stable_clock):
        sponsor_keys = ok.PeerKeySet.generate()
        si = ok.build_stable_info(sponsor_keys, clock=stable_clock, frozen_policy_version=5,
                                  frozen_policy_hash="SHA256:x", flexible_policy_version=20,
                                  flexible_policy_hash="SHA256:y", device_name="d",
                                  serial_number="s", os_version="o")
        di = ok.build_dynamic_info(sponsor_keys, clock=sponsor_dyn_clock,
                                   included_peer_ids=sponsor_includes)
        return {"sync_token": "tok", "peers": [{
            "hash": sponsor_id,
            "stable_info": cf.SignedBlob(si.data, si.sig),
            "dynamic_info": cf.SignedBlob(di.data, di.sig),
        }]}

    def test_trust_from_changes(self):
        sponsor = "SHA256:sponsor"
        changes = self._changes(sponsor, [sponsor, "SHA256:other"], 7, 9)
        includeds, stable_clock, dyn_clock = octagon.trust_from_changes(changes, sponsor)
        self.assertEqual(includeds, [sponsor, "SHA256:other"])
        self.assertEqual(stable_clock, 10)   # max stable (9) + 1
        self.assertEqual(dyn_clock, 8)        # sponsor dynamic (7) + 1

    def test_build_join_peer_includes_self_and_sponsor(self):
        voucher = cf.SignedBlob(b"vinfo", b"vsig")
        peer_bytes = octagon.build_join_peer(
            self.st, self.keys, voucher, ["SHA256:sponsor"], stable_clock=10,
            dynamic_clock=8, serial="C02")
        peer = cf.parse_cuttlefish_peer(peer_bytes)
        self.assertEqual(peer["hash"], self.st["peer_id"])
        self.assertEqual(peer["voucher"].info, b"vinfo")
        # dynamicInfo includes the sponsor AND our own peerID
        dyn = ok.parse_dynamic_info_data(peer["dynamic_info"].info)
        self.assertIn("SHA256:sponsor", dyn["included"])
        self.assertIn(self.st["peer_id"], dyn["included"])
        self.assertEqual(dyn["clock"], 8)
        # stableInfo carries the prevailing policy at the new clock
        st = ok.parse_stable_info_data(peer["stable_info"].info)
        self.assertEqual(st["clock"], 10)
        self.assertEqual(st["flexible_policy_version"], 20)


class ViableBottlesParseTests(unittest.TestCase):
    def test_parse_viable_bottles(self):
        from icp.proto.codec import Writer
        otbottle = b"OTBOTTLE-BYTES"
        bottle = Writer().bytes(2, otbottle).finish()                  # Bottle{ bottle(2) }
        escrow_data = Writer().string(1, "escrow-id-1").message(2, bottle).finish()
        resp = Writer().message(1, escrow_data).finish()               # response{ valid(1) }
        out = octagon.parse_viable_bottles(resp)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "escrow-id-1")
        self.assertEqual(out[0]["otbottle"], otbottle)

    def test_parse_empty(self):
        self.assertEqual(octagon.parse_viable_bottles(b""), [])


class IsJoinedTests(unittest.TestCase):
    def test_bare_peer_id_is_not_joined(self):
        self.assertFalse(octagon.is_joined({"octagon": {"peer_id": "SHA256:abc"}}))

    def test_joined_flag_or_sponsor_counts_as_joined(self):
        self.assertTrue(octagon.is_joined({"octagon": {"peer_id": "p", "joined": True}}))
        self.assertTrue(octagon.is_joined({"octagon": {"peer_id": "p", "sponsor": {"peer_id": "s"}}}))

    def test_no_octagon_state_is_not_joined(self):
        self.assertFalse(octagon.is_joined({}))
        self.assertFalse(octagon.is_joined({"octagon": {}}))


class ListRecoverableBottlesTests(unittest.TestCase):
    def _client(self, viable):
        client = octagon.OctagonClient.__new__(octagon.OctagonClient)  # bypass __init__/network
        client.anisette = object()
        client.fetch_viable_bottles = lambda: viable
        return client

    def test_correlates_getrecords_metadata_and_drops_bottleless(self):
        client = self._client([
            {"id": "b1", "otbottle": b"OT1"},
            {"id": "b2", "otbottle": None},        # no OTBottle -> not recoverable, dropped
            {"id": "b3", "otbottle": b"OT3"},
        ])

        class FakeRecovery:
            def __init__(self, *a, **k):
                pass

            def list_records(self):
                return [{"label": "b1", "meta": {"serial": "S1"}},
                        {"label": "b3", "meta": {"serial": "S3"}}]

        orig = octagon.escrow_srp.EscrowRecovery
        octagon.escrow_srp.EscrowRecovery = FakeRecovery
        try:
            out = client.list_recoverable_bottles("https://h", "e", "pet")
        finally:
            octagon.escrow_srp.EscrowRecovery = orig
        self.assertEqual(out, [
            {"id": "b1", "otbottle": b"OT1", "meta": {"serial": "S1"}},
            {"id": "b3", "otbottle": b"OT3", "meta": {"serial": "S3"}},
        ])

    def test_metadata_failure_is_best_effort(self):
        # GETRECORDS erroring must not block the join - bottles still returned with empty meta.
        client = self._client([{"id": "b1", "otbottle": b"OT1"}])

        class BoomRecovery:
            def __init__(self, *a, **k):
                pass

            def list_records(self):
                raise RuntimeError("escrowproxy down")

        orig = octagon.escrow_srp.EscrowRecovery
        octagon.escrow_srp.EscrowRecovery = BoomRecovery
        try:
            out = client.list_recoverable_bottles("https://h", "e", "pet")
        finally:
            octagon.escrow_srp.EscrowRecovery = orig
        self.assertEqual(out, [{"id": "b1", "otbottle": b"OT1", "meta": {}}])


if __name__ == "__main__":
    unittest.main()
