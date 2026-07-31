"""Offline tests for the native-messaging host: framing, domain matching, dispatch.

Run: .venv/bin/python -m unittest tests.test_host
"""

import io
import json
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


    def test_apple_wrapper_with_inner_shared_login_is_kept(self):
        import plistlib
        wrapped = plistlib.dumps({
            "website": "shared.example.com",
            "username": "shared-user",
            "password": "shared-secret",
            "title": "Shared Example",
        }, fmt=plistlib.FMT_BINARY)
        store = CredentialStore.from_items([
            {"srvr": "com.apple.password-manager", "labl": "Website Metadata",
             "v_Data": wrapped},
        ])
        self.assertEqual(len(store), 1)
        cred = store.all()[0]
        self.assertEqual(cred.domain, "shared.example.com")
        self.assertEqual(cred.username, "shared-user")
        self.assertEqual(cred.password, "shared-secret")

    def test_same_password_on_different_sites_is_not_deduplicated(self):
        store = CredentialStore.from_items([
            {"srvr": "one.example", "acct": "alice", "v_Data": b"reused"},
            {"srvr": "two.example", "acct": "alice", "v_Data": b"reused"},
        ])
        self.assertEqual(len(store), 2)

if __name__ == "__main__":
    unittest.main()

class AppleMetadataTests(unittest.TestCase):
    def test_binary_plist_totp_is_merged_not_shown_as_password(self):
        import plistlib
        otp = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        metadata = plistlib.dumps({"txt": "personal note", "otp": otp},
                                  fmt=plistlib.FMT_BINARY)
        store = CredentialStore.from_items([
            {"srvr": "example.com", "acct": "alice", "v_Data": b"hunter2",
             "labl": "Example", "mdat": 100},
            {"srvr": "example.com", "acct": "alice", "v_Data": metadata,
             "labl": "Example", "mdat": 200},
        ])
        self.assertEqual(len(store), 1)
        cred = store.all()[0]
        self.assertEqual(cred.password, "hunter2")
        self.assertEqual(cred.notes, "personal note")
        self.assertEqual(cred.otp_uri, otp)
        self.assertNotIn("bplist", cred.password)

    def test_rfc6238_sha1_vector(self):
        # RFC 6238 Appendix B: ASCII secret "12345678901234567890", T=59 -> 94287082.
        uri = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"
        self.assertEqual(host.current_totp(uri, now=59)["code"], "94287082")

    def test_public_dict_contains_code_not_secret_uri(self):
        uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"
        public = Credential("example.com", "alice", "pw", otp_uri=uri).public_dict()
        self.assertIn("code", public["totp"])
        self.assertNotIn("otp_uri", public)
        self.assertNotIn("secret", str(public).lower())


class SharedAndDedupTests(unittest.TestCase):
    def test_shared_password_fields_inside_binary_plist(self):
        import plistlib
        shared = plistlib.dumps({
            "website": "https://shared.example.com/login",
            "username": "shared-user",
            "secretValue": "shared-password",
            "title": "Shared Example",
            "sharedGroupName": "Family",
        }, fmt=plistlib.FMT_BINARY)
        store = CredentialStore.from_items([{
            "class": "genp", "labl": "Shared Example", "v_Data": shared,
        }])
        self.assertEqual(len(store), 1)
        cred = store.all()[0]
        self.assertEqual(cred.domain, "https://shared.example.com/login")
        self.assertEqual(cred.username, "shared-user")
        self.assertEqual(cred.password, "shared-password")

    def test_parent_and_login_subdomain_duplicates_collapse(self):
        store = CredentialStore.from_items([
            {"srvr": "example.com", "acct": "alice", "v_Data": b"pw", "labl": "Example"},
            {"srvr": "login.example.com", "acct": "alice", "v_Data": b"pw", "labl": "Example Login"},
        ])
        self.assertEqual(len(store), 1)

    def test_auxiliary_record_without_username_merges(self):
        import plistlib
        otp = plistlib.dumps({
            "url": "https://example.com",
            "token": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
        }, fmt=plistlib.FMT_BINARY)
        store = CredentialStore.from_items([
            {"srvr": "example.com", "acct": "alice", "v_Data": b"pw", "labl": "Example"},
            {"labl": "Example", "v_Data": otp},
        ])
        self.assertEqual(len(store), 1)
        self.assertTrue(store.all()[0].otp_uri.startswith("otpauth://totp/"))

class PasswordSecurityMetadataTests(unittest.TestCase):
    def test_warning_value_does_not_replace_real_password(self):
        import plistlib
        wrapped = plistlib.dumps({
            "password": "actual-password",
            "securityRecommendation": {"value": "weak", "compromised": True},
        }, fmt=plistlib.FMT_BINARY)
        store = CredentialStore.from_items([
            {"srvr": "example.com", "acct": "alice", "v_Data": wrapped,
             "labl": "Example"},
        ])
        self.assertEqual(store.all()[0].password, "actual-password")

    def test_nskeyedarchive_password_with_warning_is_decoded(self):
        import plistlib
        objects = [
            "$null",
            {"NS.keys": plistlib.UID(2), "NS.objects": plistlib.UID(3),
             "$class": plistlib.UID(6)},
            {"NS.objects": [plistlib.UID(4), plistlib.UID(5)], "$class": plistlib.UID(7)},
            {"NS.objects": [plistlib.UID(8), plistlib.UID(9)], "$class": plistlib.UID(7)},
            "password", "securityRecommendation",
            {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]},
            {"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]},
            "archived-password", {"value": "compromised"},
        ]
        archived = plistlib.dumps({
            "$version": 100000, "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)}, "$objects": objects,
        }, fmt=plistlib.FMT_BINARY)
        store = CredentialStore.from_items([
            {"srvr": "example.org", "acct": "bob", "v_Data": archived,
             "labl": "Example"},
        ])
        self.assertEqual(store.all()[0].password, "archived-password")
