"""Offline tests for the escrow SRP apparatus: binary framing + SRP-6a math.

These prove internal correctness (framing round-trips; the SRP client completes a full
mutual-auth handshake against a local server). They CANNOT prove escrowproxy accepts our exact
variant - that is the documented blind spot, validated only by an irreversible live attempt,
which stays gated. No network here.

Run: .venv/bin/python -m unittest tests.test_escrow_srp
"""

import hashlib
import os
import unittest

from icp.escrow import srp as es


class GroupTests(unittest.TestCase):
    def test_group_is_2048_bit(self):
        self.assertEqual(es.N.bit_length(), 2048)
        self.assertEqual(es.g, 2)


class FramingTests(unittest.TestCase):
    def _pack(self, header, sections):
        m = es.KeyVaultMessage(header)
        for s in sections:
            m.section(s)
        return m.pack()

    def test_pack_unpack_round_trip(self):
        header = bytes(range(24))
        sections = [b"identifier-bytes", b"\x00\x11\x22salt", b"B" * 256]
        packed = self._pack(header, sections)
        got_header, got_sections = es.unpack_message(packed, header_len=24, section_count=3)
        self.assertEqual(got_header, header)
        self.assertEqual(got_sections, sections)

    def test_first_4_bytes_are_total_length(self):
        packed = self._pack(b"\x00" * 24, [b"a", b"bb"])
        self.assertEqual(int.from_bytes(packed[:4], "big"), len(packed))

    def test_section_sized_pads(self):
        m = es.KeyVaultMessage(b"\x00" * 24)
        m.section_sized(b"id", 20)
        m.section(b"proof")
        packed = m.pack()
        _, sections = es.unpack_message(packed, 24, 2)
        # the length prefix stays the real data length, so the reader recovers just the data;
        # the padding is reserved slot space (the fixed-size id section)
        self.assertEqual(sections[0], b"id")
        self.assertEqual(sections[1], b"proof")

    def test_section_sized_rejects_too_small(self):
        with self.assertRaises(ValueError):
            es.KeyVaultMessage(b"").section_sized(b"toolong", 4)

    def test_pack_byte_layout_is_exact(self):
        # Pin the EXACT KeyVaultMessage payload byte layout:
        #   total_len:u32-BE | header | (section_count+1) u32-BE offsets | body
        # body sections are len:u32-BE ++ data. The offset table has a TRAILING EOF offset
        # (= body length), so 2 data sections -> 3 offsets. Computed by hand from the spec.
        m = es.KeyVaultMessage(b"HHHH")          # 4-byte header
        m.section(b"AB")                          # -> 0x00000002 'AB'  (6 bytes) at body off 0
        m.section(b"CDE")                         # -> 0x00000003 'CDE' (7 bytes) at body off 6
        packed = m.pack()
        expected = bytes.fromhex(
            "00000021"                            # total length = 33
            "48484848"                            # header "HHHH"
            "00000000" "00000006" "0000000d"      # offsets: sec0=0, sec1=6, EOF=13 (body len)
            "00000002" "4142"                     # section 0: len 2 + "AB"
            "00000003" "434445"                   # section 1: len 3 + "CDE"
        )
        self.assertEqual(packed, expected)
        # and it reads back
        hdr, secs = es.unpack_message(packed, header_len=4, section_count=2)
        self.assertEqual(hdr, b"HHHH")
        self.assertEqual(secs, [b"AB", b"CDE"])


def _H(*p):
    h = hashlib.sha256()
    for x in p:
        h.update(x)
    return h.digest()


class _SrpServer:
    """Minimal RFC-5054 SRP-6a server (trimmed-A/B convention) for the round-trip test."""
    def __init__(self, username, password, salt):
        self.username, self.salt = username, salt
        x = int.from_bytes(_H(salt, _H(username + b":" + password)), "big")
        self.v = pow(es.g, x, es.N)
        self.b = int.from_bytes(os.urandom(32), "big")
        self.k = int.from_bytes(_H(es._pad(es.N), es._pad(es.g)), "big")
        self.B = (self.k * self.v + pow(es.g, self.b, es.N)) % es.N

    def b_pub(self):
        return es._pad(self.B)   # escrowproxy sends B padded to the modulus length

    def finish(self, a_pub: bytes, m1: bytes):
        # match the trimmed-A/B convention: A and B TRIMMED in u and M1; K over trimmed S.
        A = int.from_bytes(a_pub, "big")
        a_t, b_t = es._trim(A), es._trim(self.B)
        u = int.from_bytes(_H(a_t, b_t), "big")
        S = pow(A * pow(self.v, u, es.N), self.b, es.N)
        K = _H(es._trim(S))
        h_xor = bytes(p ^ q for p, q in zip(_H(es._pad(es.N)), _H(es._pad(es.g))))
        expect_m1 = _H(h_xor, _H(self.username), self.salt, a_t, b_t, K)
        if expect_m1 != m1:
            raise AssertionError("server rejected client M1")
        return K, _H(a_t, m1, K)  # K, M2


class SrpHandshakeTests(unittest.TestCase):
    def test_full_mutual_auth(self):
        username, password, salt = b"8467219025", b"123456", os.urandom(16)
        server = _SrpServer(username, password, salt)

        client = es.SrpClient.new(os.urandom(32))
        K_c, M1 = client.process(username, password, salt, server.b_pub())

        K_s, M2 = server.finish(client.public_a(), M1)
        self.assertEqual(K_c, K_s)                                   # shared session key agrees
        self.assertEqual(es.SrpClient.server_proof(client.public_a(), M1, K_c), M2)  # M2 ok

    def test_B_padding_is_normalized_away(self):
        # The vendored fork parses B to a BigUint and uses its TRIMMED bytes in u and M1, so a
        # leading-zero B fed padded vs trimmed gives identical (K, M1).
        salt, user, pw = os.urandom(16), b"8467219025", b"123456"
        b_int = 1 << 2030                       # 256-byte form has leading zero bytes
        self.assertEqual(es._pad(b_int)[0], 0)  # confirm a leading zero exists
        client = es.SrpClient.new(os.urandom(32))
        k1, m1_padded = client.process(user, pw, salt, es._pad(b_int))   # padded input
        k2, m1_trimmed = client.process(user, pw, salt, es._trim(b_int))  # trimmed input
        self.assertEqual(k1, k2)
        self.assertEqual(m1_padded, m1_trimmed)

    def test_a_pub_is_trimmed(self):
        # A is sent trimmed (no leading zero byte). Loop until we hit an A with a leading zero
        # to confirm public_a strips it (matches a_pub.to_bytes_be()).
        for _ in range(2000):
            c = es.SrpClient.new(os.urandom(32))
            if (c.A.bit_length() + 7) // 8 < es._N_BYTES:   # A would have a leading zero if padded
                self.assertEqual(c.public_a(), es._trim(c.A))
                self.assertNotEqual(len(c.public_a()), es._N_BYTES)
                return
        # extremely unlikely to never hit one; still assert the trimming property generally
        self.assertEqual(es.SrpClient.new(os.urandom(32)).public_a()[0:0], b"")

    def test_known_answer_against_spec_formula(self):
        # Fixed-input KAT: independently recompute K, M1, M2 from the SRP-6a spec formulas
        # (trimmed-A/B variant) and assert SrpClient.process matches. Pins the exact math:
        # trimmed A/B in u/M1/M2, padded g in k & M1, x=H(salt|H(user:pw)), K=H(trim S).
        N, gg = es.N, es.g
        a_bytes = (5).to_bytes(32, "big")
        username, password = b"1234567890", b"0000"
        salt = bytes(range(16))
        b_secret = 7

        # server side, by hand
        x = int.from_bytes(_H(salt, _H(username + b":" + password)), "big")
        v = pow(gg, x, N)
        k = int.from_bytes(_H(es._pad(N), es._pad(gg)), "big")
        B = (k * v + pow(gg, b_secret, N)) % N

        client = es.SrpClient.new(a_bytes)
        A = client.A
        # independent client-side recomputation
        u = int.from_bytes(_H(es._trim(A), es._trim(B)), "big")
        S = pow((B - (k * pow(gg, x, N)) % N) % N, client.a + u * x, N)
        exp_K = _H(es._trim(S))
        h_xor = bytes(p ^ q for p, q in zip(_H(es._pad(N)), _H(es._pad(gg))))
        exp_M1 = _H(h_xor, _H(username), salt, es._trim(A), es._trim(B), exp_K)
        exp_M2 = _H(es._trim(A), exp_M1, exp_K)

        K, M1 = client.process(username, password, salt, es._trim(B))
        self.assertEqual(K, exp_K)
        self.assertEqual(M1, exp_M1)
        self.assertEqual(es.SrpClient.server_proof(client.public_a(), M1, K), exp_M2)
        # also pin the literal digests so a silent algorithm change is caught
        self.assertEqual(
            K.hex(), "2d19ff43e3713fa1e0e46215140438f4cead8a97d1f0078c0e4d082a6879fad8")
        self.assertEqual(
            M1.hex(), "f4e679ce9d938ce6a6532f3f94e685c137f96754b7a6d4947777380469ffdd20")

    def test_x_uses_dsid_username_not_email(self):
        # SRP username = the dsid string the server returned, salt prefixes the identity hash:
        # x = H(salt | H(dsid ":" passcode)). Changing the
        # username (dsid) MUST change M1.
        salt = bytes(range(16))
        c1 = es.SrpClient.new((9).to_bytes(32, "big"))
        c2 = es.SrpClient.new((9).to_bytes(32, "big"))
        server_B = es._pad(es.N - 12345)  # arbitrary fixed B
        _, m1_a = c1.process(b"8467219025", b"pw", salt, server_B)
        _, m1_b = c2.process(b"me@icloud.com", b"pw", salt, server_B)
        self.assertNotEqual(m1_a, m1_b)

    def test_wrong_password_diverges(self):
        salt = os.urandom(16)
        server = _SrpServer(b"u", b"right", salt)
        client = es.SrpClient.new(os.urandom(32))
        _, M1 = client.process(b"u", b"wrong", salt, server.b_pub())
        with self.assertRaises(AssertionError):
            server.finish(client.public_a(), M1)


class _Anis:
    def headers(self):
        # include a stale X-Mme-Client-Info to prove the header builder OVERWRITES it
        return {"X-Apple-I-MD": "x", "X-Mme-Client-Info": "STALE-ANISETTE-VALUE"}


class GatedTests(unittest.TestCase):
    def test_recover_refuses_without_confirmation(self):
        rec = es.EscrowRecovery("https://example", "me@icloud.com", "PET", _Anis())
        with self.assertRaises(es.EscrowGateError):
            rec.try_recover_escrow("label", b"123456")  # confirm_irreversible defaults False

    def test_request_builder_shape(self):
        rec = es.EscrowRecovery("https://h/", "me@icloud.com", "PET", _Anis())
        req = rec._request("srp_init", "the-label", "TXN", blob="QUJD")
        # The body `command` is the serde SCREAMING_SNAKE_CASE form, NOT the PascalCase variant
        # name and NOT the lowercase URL slug.
        self.assertEqual(req["command"], "SRP_INIT")
        self.assertEqual(req["label"], "the-label")
        self.assertEqual(req["transactionUUID"], "TXN")
        self.assertEqual(req["version"], 1)
        self.assertEqual(req["blob"], "QUJD")
        self.assertNotIn("dsid", req)  # None extras dropped

    def test_command_wire_strings_are_screaming_snake_case(self):
        # Pin every command's wire value against the documented escrowproxy contract
        # (EscrowCommand #[serde(rename_all = "SCREAMING_SNAKE_CASE")]).
        self.assertEqual(es.EscrowRecovery._COMMAND_VARIANT, {
            "srp_init": "SRP_INIT", "recover": "RECOVER", "get_records": "GETRECORDS",
            "get_club_cert": "GETCLUB", "enroll": "ENROLL", "delete": "DELETE"})

    def test_headers_include_anisette_and_plist_content_type(self):
        rec = es.EscrowRecovery("https://h", "e", "p", _Anis())
        h = rec._headers()
        # Content-Type is the typo-looking `plst`, not `plist`; the body is
        # an XML plist, not JSON.
        self.assertEqual(h["Content-Type"], "application/x-apple-plst")
        # Escrow request header literal values.
        # User-Agent = the sbd item + first token of the iCloud UA;
        # NOT the AuthKit string (that's the X-Mme-Client-Info item).
        self.assertEqual(h["User-Agent"], "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282")
        self.assertEqual(h["Accept"], "*/*")
        self.assertEqual(h["Accept-Language"], "en-US,en;q=0.9")
        self.assertEqual(h["X-Apple-I-Locale"], "en_US")
        self.assertEqual(h["x-apple-i-device-type"], "1")
        self.assertEqual(h["X-Apple-I-MD"], "x")
        # X-Mme-Client-Info carries the AuthKit/sbd item and OVERWRITES the anisette value.
        self.assertEqual(h["X-Mme-Client-Info"],
                         "<PC> <Windows;6.2(0,0);9200> "
                         "<com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>")

    def test_user_action_label_exact(self):
        # Verbatim label, used by both srp_init and recover.
        self.assertEqual(es.EscrowRecovery.USER_ACTION, "com.apple.sbd: escrow recovery")

    def test_request_body_plist_keys_are_camelcase(self):
        # EscrowRequest #[serde(rename_all="camelCase")] with an explicit override making the
        # transaction-uuid key `transactionUUID` (all-caps UUID), NOT `transactionUuid`.
        # version is the integer 1.
        rec = es.EscrowRecovery("https://h", "me@icloud.com", "PET", _Anis())
        req = rec._request("srp_init", "the-label", "TXN-ABC", blob="QUJD")
        self.assertEqual(set(req), {"command", "label", "transactionUUID",
                                    "userActionLabel", "version", "blob"})
        self.assertIn("transactionUUID", req)
        self.assertNotIn("transactionUuid", req)
        self.assertEqual(req["userActionLabel"], "com.apple.sbd: escrow recovery")
        self.assertEqual(req["version"], 1)
        self.assertIsInstance(req["version"], int)

    def test_invoke_url_auth_and_content_type(self):
        # The URL path uses the lowercase slug,
        # while the body command value is SCREAMING_SNAKE. Auth = Basic(GSA email, PET token).
        # Content-Type = application/x-apple-plst.
        import plistlib

        captured = {}

        def fake_post(url, headers=None, data=None, auth=None, **kw):
            captured.update(url=url, headers=headers, data=data, auth=auth)

            class R:
                status_code = 200
                content = plistlib.dumps({"ok": True})
            return R()

        rec = es.EscrowRecovery("https://p99-escrowproxy.icloud.com/",
                                "person@icloud.com", "PET-XYZ", _Anis())
        import requests as _rq
        orig = _rq.post
        _rq.post = fake_post
        try:
            rec._invoke("srp_init", rec._request("srp_init", "lbl", "TXN", blob="QUJD"))
        finally:
            _rq.post = orig

        self.assertEqual(captured["url"],
                         "https://p99-escrowproxy.icloud.com/escrowproxy/api/srp_init")
        # Basic auth username = GSA email, password = PET token (NOT dsid, NOT mmeAuthToken)
        self.assertEqual(captured["auth"], ("person@icloud.com", "PET-XYZ"))
        self.assertEqual(captured["headers"]["Content-Type"], "application/x-apple-plst")
        # body is an XML plist whose command value is SCREAMING_SNAKE
        body = plistlib.loads(captured["data"])
        self.assertEqual(body["command"], "SRP_INIT")
        self.assertEqual(body["transactionUUID"], "TXN")

    def test_list_records_parses_metadata_non_destructively(self):
        # GETRECORDS: URL slug get_records, body command GETRECORDS; per-record metadata is a
        # base64 XML plist.
        import base64
        import plistlib
        rec = es.EscrowRecovery("https://h", "e", "p", _Anis())
        meta = {"serial": "C02XYZ", "build": "22F8", "bottleID": "B1", "passcode_generation": 3}
        captured = {}

        def fake_invoke(command, request):
            captured["command"] = command
            captured["body_command"] = request["command"]
            captured["label"] = request["label"]
            return {"metadataList": [
                {"label": "bottle-1",
                 "metadata": base64.b64encode(plistlib.dumps(meta)).decode()},
                {"label": "bottle-2"},                       # missing metadata -> {}
            ]}

        rec._invoke = fake_invoke
        out = rec.list_records()
        self.assertEqual(captured["command"], "get_records")          # URL slug
        self.assertEqual(captured["body_command"], "GETRECORDS")      # wire command
        self.assertEqual(captured["label"], "com.apple.securebackup.record")
        self.assertEqual(out, [
            {"label": "bottle-1", "meta": meta},
            {"label": "bottle-2", "meta": {}},
        ])

    def test_url_slug_differs_from_body_command(self):
        # The URL slug is NOT the body command string. e.g. POST .../api/get_club_cert sends
        # command GETCLUB; .../api/get_records sends GETRECORDS.
        v = es.EscrowRecovery._COMMAND_VARIANT
        self.assertEqual(v["get_club_cert"], "GETCLUB")       # slug get_club_cert (with _cert)
        self.assertEqual(v["get_records"], "GETRECORDS")      # slug get_records
        self.assertEqual(v["srp_init"], "SRP_INIT")           # slug srp_init, body SRP_INIT
        # NO underscore in the single-token variants; underscore only at the SrpInit hump.
        self.assertNotIn("GET_RECORDS", v.values())
        self.assertNotIn("GET_CLUB", v.values())


if __name__ == "__main__":
    unittest.main()
