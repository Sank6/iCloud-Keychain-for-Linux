"""Offline tests for the native-messaging host: framing, domain matching, dispatch.

Run: .venv/bin/python -m unittest tests.test_host
"""

import datetime
import io
import json
import plistlib
import struct
import unittest

from icp.hme.client import HmeAlias
from icp.vault import host
from icp.vault.host import Credential, CredentialStore


class DomainMatchTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(host.domains_match("example.com", "example.com"))

    def test_www_normalized(self):
        self.assertTrue(host.domains_match("www.example.com", "example.com"))

    def test_subdomain_either_way(self):
        self.assertTrue(host.domains_match("login.example.com", "example.com"))
        self.assertTrue(host.domains_match("example.com", "accounts.example.com"))

    def test_url_input_normalized(self):
        self.assertTrue(host.domains_match("https://login.example.com/path?x=1", "example.com"))

    def test_no_false_suffix(self):
        self.assertFalse(host.domains_match("notexample.com", "example.com"))
        self.assertFalse(host.domains_match("example.com.evil.com", "example.com"))

    def test_empty(self):
        self.assertFalse(host.domains_match("", "example.com"))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore([
            Credential("example.com", "alice", "pw1", "Example"),
            Credential("login.example.com", "bob", "pw2", "Example Login"),
            Credential("other.org", "carol", "pw3", "Other"),
        ])

    def test_match_returns_relevant(self):
        hits = self.store.match("www.example.com")
        self.assertEqual({c.username for c in hits}, {"alice", "bob"})

    def test_exact_host_first(self):
        hits = self.store.match("example.com")
        self.assertEqual(hits[0].username, "alice")  # exact host sorts before subdomain

    def test_no_match(self):
        self.assertEqual(self.store.match("nowhere.test"), [])

    def test_label_only_item_matches_hostname_label(self):
        store = CredentialStore([Credential("", "me@example.com", "pw", "Cloudflare")])
        hits = store.match("dash.cloudflare.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].username, "me@example.com")

    def test_generic_label_only_item_does_not_match(self):
        store = CredentialStore([Credential("", "me@example.com", "pw", "Login")])
        self.assertEqual(store.match("login.example.com"), [])


def _alias(domain, address="quiet-otter@icloud.com", label="Claude"):
    return HmeAlias(anonymous_id="a1", address=address, label=label, note="",
                    forward_to="me@example.com", is_active=True, domain=domain,
                    created_at=0.0)


class MatchAliasesTests(unittest.TestCase):
    def test_matches_same_domains_match_rule_as_credentials(self):
        aliases = [_alias("claude.ai"), _alias("other.org", address="x@icloud.com")]
        hits = host.match_aliases("www.claude.ai", aliases)
        self.assertEqual([a.address for a in hits], ["quiet-otter@icloud.com"])

    def test_no_domain_never_matches(self):
        aliases = [_alias("")]
        self.assertEqual(host.match_aliases("claude.ai", aliases), [])

    def test_no_match(self):
        self.assertEqual(host.match_aliases("nowhere.test", [_alias("claude.ai")]), [])

    def test_service_field_can_act_as_label_only_domain(self):
        store = CredentialStore.from_items([
            {"svce": "Cloudflare", "acct": "me@example.com", "v_Data": b"pw",
             "labl": "Cloudflare"},
        ])
        self.assertEqual(store.match("dash.cloudflare.com")[0].password, "pw")

    def test_from_items_drops_internal_records(self):
        # PCS service blobs and per-site "Website Metadata" sync alongside real logins but are
        # not credentials.
        store = CredentialStore.from_items([
            {"srvr": "idmsa.apple.com", "acct": "me@gmail.com", "v_Data": b"pw",
             "labl": "idmsa.apple.com", "class": "inet"},
            {"acct": "0Z825FXfO144", "labl": "PCS com.apple.Accessibility - 0Z825FXf",
             "svce": "com.apple.Accessibility"},
            {"srvr": "apple.com", "labl": "Website Metadata for apple.com"},  # no user/pw
        ])
        self.assertEqual(len(store), 1)  # only the real login survives ingest
        self.assertEqual(store.match("idmsa.apple.com")[0].username, "me@gmail.com")
        # the page still matches just the one real login - no PCS/metadata noise
        self.assertEqual([c.username for c in store.match("apple.com")], ["me@gmail.com"])

    def test_match_sorts_recent_first_within_tier(self):
        store = CredentialStore([
            Credential("example.com", "old", "p", "Example", mdat=1000),
            Credential("example.com", "new", "p", "Example", mdat=2000),
        ])
        self.assertEqual([c.username for c in store.match("example.com")], ["new", "old"])

    def test_from_items_carries_mdat(self):
        import datetime
        when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        store = CredentialStore.from_items([
            {"srvr": "ex.com", "acct": "a", "v_Data": b"p", "mdat": when},
        ])
        self.assertEqual(store.all()[0].mdat, when.timestamp())

    def test_from_items_apple_fields(self):
        store = CredentialStore.from_items([
            # the real iCloud web-login shape: an `inet` item uses `srvr`, not `server`.
            {"srvr": "accounts.google.com", "acct": "me@gmail.com", "v_Data": b"hunter2",
             "labl": "Google", "class": "inet", "agrp": "com.apple.cfnetwork"},
            {"server": "apple.com", "acct": "me@icloud.com", "v_Data": b"secret", "labl": "Apple"},
            {"domain": "git.example", "username": "dev", "password": "hunter2"},
            {"acct": "noserver"},  # kept (has username)
            {},                    # dropped (no domain/username)
        ])
        self.assertEqual(len(store), 4)
        g = store.match("accounts.google.com")[0]
        self.assertEqual((g.domain, g.username, g.password),
                         ("accounts.google.com", "me@gmail.com", "hunter2"))
        apple = store.match("apple.com")[0]
        self.assertEqual(apple.username, "me@icloud.com")
        self.assertEqual(apple.password, "secret")


class FramingTests(unittest.TestCase):
    def _encode(self, obj):
        data = json.dumps(obj).encode()
        return struct.pack("<I", len(data)) + data

    def test_read_write_round_trip(self):
        buf_in = io.BytesIO(self._encode({"cmd": "ping"}))
        self.assertEqual(host.read_message(buf_in), {"cmd": "ping"})
        buf_out = io.BytesIO()
        host.write_message({"ok": True, "count": 2}, buf_out)
        buf_out.seek(0)
        self.assertEqual(host.read_message(buf_out), {"ok": True, "count": 2})

    def test_read_eof_returns_none(self):
        self.assertIsNone(host.read_message(io.BytesIO(b"")))

    def test_partial_length_returns_none(self):
        self.assertIsNone(host.read_message(io.BytesIO(b"\x01\x02")))


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore([Credential("example.com", "alice", "pw1")])

    def test_ping(self):
        self.assertEqual(host.handle({"cmd": "ping"}, self.store), {"ok": True, "count": 1})

    def test_match(self):
        r = host.handle({"cmd": "match", "domain": "example.com"}, self.store)
        self.assertTrue(r["ok"])
        self.assertEqual(r["credentials"][0]["password"], "pw1")

    def test_match_with_no_aliases_arg_returns_empty_alias_list(self):
        r = host.handle({"cmd": "match", "domain": "example.com"}, self.store)
        self.assertEqual(r["aliases"], [])

    def test_match_includes_matching_aliases(self):
        r = host.handle({"cmd": "match", "domain": "claude.ai"}, self.store,
                        [_alias("claude.ai")])
        self.assertEqual(r["aliases"], [{"address": "quiet-otter@icloud.com",
                                        "label": "Claude", "domain": "claude.ai"}])

    def test_match_excludes_non_matching_aliases(self):
        r = host.handle({"cmd": "match", "domain": "other.org"}, self.store,
                        [_alias("claude.ai")])
        self.assertEqual(r["aliases"], [])

    def test_match_missing_domain(self):
        self.assertFalse(host.handle({"cmd": "match"}, self.store)["ok"])

    def test_unknown_cmd(self):
        self.assertFalse(host.handle({"cmd": "frobnicate"}, self.store)["ok"])

    def test_serve_loop_processes_until_eof(self):
        msgs = self._stream([{"cmd": "ping"}, {"cmd": "match", "domain": "example.com"}])
        out = io.BytesIO()
        host.serve(self.store, instream=msgs, outstream=out)
        out.seek(0)
        r1 = host.read_message(out)
        r2 = host.read_message(out)
        self.assertEqual(r1["count"], 1)
        self.assertEqual(r2["credentials"][0]["username"], "alice")
        self.assertIsNone(host.read_message(out))  # nothing more

    def _stream(self, objs):
        b = io.BytesIO()
        for o in objs:
            host.write_message(o, b)
        b.seek(0)
        return b


def _bplist(obj) -> bytes:
    return plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)


class RecordClassificationTests(unittest.TestCase):
    """Several record types share the keychain item schema; only some are logins."""

    def test_agrp_routes_each_record_type(self):
        card = _bplist({"CardNumber": "4111111111111111"})
        cases = [
            ("com.apple.cfnetwork", b"hunter2", "password"),
            ("apple", b"wifi-pw", "password"),
            ("com.apple.password-manager", _bplist({"notes": "n"}), "sidecar"),
            ("com.apple.password-manager.website-metadata", _bplist({}), "sidecar"),
            ("com.apple.safari.credit-cards", card, "card"),
            # A card record's v_Data can be plain text; the group still decides.
            ("com.apple.safari.credit-cards", b"1234", "card"),
            ("com.apple.webkit.webauthn", b"\x04key", "passkey"),
            ("com.apple.ProtectedCloudStorage", b"blob", "subsystem"),
            ("com.apple.hap.pairing", b"text", "subsystem"),
            ("com.thirdparty.app", b"hunter2", "password"),  # unknown group -> payload fallback
            ("", b"hunter2", "password"),
        ]
        for agrp, data, expected in cases:
            with self.subTest(agrp=agrp):
                self.assertEqual(host.classify_item({"agrp": agrp, "v_Data": data})[0], expected)

    def test_non_text_payload_is_never_decoded_lossily(self):
        # Key material is not UTF-8; some protobufs are, but carry C0 control bytes.
        for blob in (b"\x04\xd0\x9f\xff\xfe key \x80\x81", b"\x08\x01\x12n\x1a\x02GB"):
            self.assertEqual(host.classify_payload(blob), ("binary", None))
        self.assertEqual(host.classify_payload(b"line1\nline2"), ("password", "line1\nline2"))

    def test_only_logins_reach_the_vault(self):
        cred_id = "AAAAAAAAAAAAAAAAAAAAAA=="
        items = [
            {"agrp": "com.apple.cfnetwork", "srvr": "ex.com", "acct": "a", "v_Data": b"real"},
            {"agrp": "com.apple.webkit.webauthn", "srvr": "ex.com", "acct": cred_id,
             "v_Data": b"\x04key"},
            {"agrp": "com.apple.safari.credit-cards", "srvr": "cards", "acct": "u",
             "v_Data": _bplist({"CardNumber": "4111111111111111"})},
            {"agrp": "com.apple.ProtectedCloudStorage", "srvr": "pcs", "acct": "k",
             "v_Data": b"\x80\x81"},
            # An orphan sidecar (a passkey's) must not appear as an entry of its own.
            {"agrp": "com.apple.password-manager", "srvr": "other.test", "acct": cred_id,
             "v_Data": _bplist({"ctxt": {"": {"lUsed": 780_000_000.0}}})},
        ]
        self.assertEqual([c.password for c in CredentialStore.from_items(items).all()], ["real"])
        self.assertEqual(host.decode_payment_cards(items)[0]["CardNumber"], "4111111111111111")


class SidecarMergeTests(unittest.TestCase):
    """A login and its sidecar are two items joined on (srvr, acct); the sidecar must fold into
    the login, never become an entry of its own."""

    def _items(self, sidecar):
        return [
            {"agrp": "com.apple.cfnetwork", "srvr": "ex.com", "acct": "a@b.c",
             "v_Data": b"hunter2", "labl": "ex.com (a@b.c)", "mdat": 1_600_000_000.0},
            {"agrp": "com.apple.password-manager", "srvr": "ex.com", "acct": "a@b.c",
             "v_Data": _bplist(sidecar)},
        ]

    def test_sidecar_folds_into_the_login(self):
        # lUsed is nested under ctxt, keyed by browser profile, in Apple absolute time.
        store = CredentialStore.from_items(self._items(
            {"notes": b"my note", "title": b"My Bank",
             "ctxt": {"": {"lUsed": 700_000_000.0},
                      "Profile2": {"lUsed": 750_000_000.0}}}))
        self.assertEqual(len(store), 1)
        c = store.all()[0]
        self.assertEqual((c.password, c.notes, c.title), ("hunter2", "my note", "My Bank"))
        self.assertEqual(c.last_used, 750_000_000.0 + 978307200)

    def test_only_allowlisted_sidecar_keys_are_kept(self):
        # s_hi is password history: {d, p, id, t} where `p` is a previous password in cleartext.
        store = CredentialStore.from_items(self._items({
            "notes": "keep",
            "s_hi": [{"d": datetime.datetime(2025, 12, 27), "p": "old-password-1",
                      "id": "00000000-0000-0000-0000-000000000000", "t": "pwcr"}],
            "notPrompted": True, "s_as": [], "wn_dm": datetime.datetime(2025, 6, 18),
            "supportsPasskey": True, "enrollPasskeyURL": "https://x/enroll",
        }))
        blob = json.dumps(store.all()[0].public_dict())
        self.assertIn("keep", blob)
        for dropped in ("old-password-1", "s_hi", "notPrompted", "s_as", "wn_dm",
                        "supportsPasskey", "enrollPasskeyURL"):
            self.assertNotIn(dropped, blob)

    def test_recently_deleted_never_reaches_the_vault(self):
        login, side = self._items({"notes": b"old note", "title": b"Deleted"})
        gone = [{**login, "agrp": "com.apple.cfnetwork-recently-deleted"},
                {**side, "agrp": "com.apple.password-manager-recently-deleted",
                 "labl": "Password Manager Metadata: ex.com (a@b.c)"}]
        self.assertEqual(len(CredentialStore.from_items(gone)), 0)
        # a live login with the same key must not pick up the deleted metadata
        c = CredentialStore.from_items([login] + gone[1:]).all()[0]
        self.assertEqual((c.notes, c.title), ("", "ex.com (a@b.c)"))

    def test_extra_websites_are_kept_and_matched(self):
        # s_as = the entry's other websites in the Passwords app: [{"s": "<host>"}]
        store = CredentialStore.from_items(self._items(
            {"s_as": [{"s": "shop.example.org"}, {"s": b"login.ex.net"}, {"x": 1}, "junk"]}))
        c = store.all()[0]
        self.assertEqual(c.sites, ("shop.example.org", "login.ex.net"))
        self.assertEqual(store.match("https://shop.example.org/cart"), [c])
        self.assertEqual(store.match("ex.com"), [c])
        self.assertEqual(store.match("other.org"), [])

    def test_last_used_drives_ordering(self):
        # mdat is unix seconds; the sidecar's lUsed is Apple absolute time (+978307200), so
        # 780_000_000 resolves later than stale's mdat.
        store = CredentialStore.from_items([
            {"agrp": "com.apple.cfnetwork", "srvr": "ex.com", "acct": "stale",
             "v_Data": b"p", "mdat": 1_500_000_000.0},
            {"agrp": "com.apple.cfnetwork", "srvr": "ex.com", "acct": "fresh",
             "v_Data": b"p", "mdat": 1_000_000_000.0},
            {"agrp": "com.apple.password-manager", "srvr": "ex.com", "acct": "fresh",
             "v_Data": _bplist({"ctxt": {"": {"lUsed": 780_000_000.0}}})},
        ])
        self.assertEqual([c.username for c in store.match("ex.com")], ["fresh", "stale"])


if __name__ == "__main__":
    unittest.main()
