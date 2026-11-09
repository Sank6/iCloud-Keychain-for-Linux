"""Offline tests for the CloudKit CKCode transport framing/assembly (no network).

The live POST (`CloudKitTransport.invoke`) is intentionally not exercised here - only the
request building and response parsing, which are byte-deterministic.

Run: .venv/bin/python -m unittest tests.test_cloudkit
"""

import unittest

from icp.transport import cloudkit as ck
from icp.proto import codec as _proto, cuttlefish as cf


class DelimitTests(unittest.TestCase):
    def test_round_trip(self):
        msgs = [b"", b"a", b"x" * 200, bytes(range(50))]
        stream = b"".join(ck.delimit(m) for m in msgs)
        self.assertEqual(ck.undelimit(stream), msgs)


class GunzipDecisionTests(unittest.TestCase):
    """`requests` already gunzips a Content-Encoding:gzip response, so a manual pass keys on the
    gzip MAGIC BYTES, not the header."""

    def test_real_gzip_is_decompressed(self):
        import gzip
        original = b"\x0a\x05hello-protobuf-body"
        self.assertEqual(ck.maybe_gunzip(gzip.compress(original)), original)

    def test_already_plain_body_is_untouched(self):
        # the shape `requests` hands us after auto-gunzip: a plain protobuf NOT starting with 1f 8b
        for plain in (b"\x9eK\x01\x02\x03", b"\x0a\x02hi", b"", b"\x1f"):
            self.assertEqual(ck.maybe_gunzip(plain), plain)


class RequestBuildTests(unittest.TestCase):
    def setUp(self):
        self.dev = ck.DeviceConfig(device_uuid="UUID-DEV", serial="C02ABC")

    def test_header_fields(self):
        f = _proto.decode_fields(ck.build_header(self.dev))
        self.assertEqual(_proto.first_str(f, 2), ck.CUTTLEFISH_CONTAINER)
        self.assertEqual(_proto.first_str(f, 3), ck.CUTTLEFISH_BUNDLE)
        self.assertEqual(_proto.first(f, 19), ck.ENV_PRODUCTION)
        self.assertEqual(_proto.first(f, 23), ck.DB_PRIVATE)
        self.assertEqual(_proto.first_str(f, 33), "C02ABC")
        # device identifier sub-message
        ident = _proto.decode_fields(_proto.first(f, 7))
        self.assertEqual(_proto.first_str(ident, 1), "UUID-DEV")
        self.assertEqual(_proto.first(ident, 2), ck.IDENTIFIER_TYPE_DEVICE)

    def test_request_operation_structure(self):
        header = ck.build_header(self.dev)
        fir = cf.encode_function_invoke_request("Cuttlefish", "fetchChanges", b"PARAMS")
        raw = ck.build_request_operation_generic(header, ck.OP_TYPE_FUNCTION_INVOKE, 1101,
                                                 fir, op_uuid="OP-1")
        f = _proto.decode_fields(raw)
        self.assertEqual(_proto.first(f, 1), header)            # header
        self.assertEqual(_proto.first(f, 1101), fir)            # functionInvokeRequest
        op = _proto.decode_fields(_proto.first(f, 2))           # Operation
        self.assertEqual(_proto.first_str(op, 1), "OP-1")
        self.assertEqual(_proto.first(op, 2), ck.OP_TYPE_FUNCTION_INVOKE)
        self.assertEqual(_proto.first(op, 4), 1)                # last=true

    def test_full_body_is_gzipped_delimited(self):
        # the request body _perform builds: gzip(delimit(RequestOperation{functionInvoke}))
        import gzip
        fir = cf.encode_function_invoke_request("Cuttlefish", "fetchChanges",
                                                cf.encode_fetch_changes_request(None))
        header = ck.build_header(self.dev)
        req = ck.build_request_operation_generic(header, ck.OP_TYPE_FUNCTION_INVOKE, 1101, fir)
        body = gzip.compress(ck.delimit(req))
        inner = ck.undelimit(gzip.decompress(body))
        self.assertEqual(len(inner), 1)
        f = _proto.decode_fields(inner[0])
        fir2 = _proto.decode_fields(_proto.first(f, 1101))
        self.assertEqual(_proto.first_str(fir2, 1), "Cuttlefish")
        self.assertEqual(_proto.first_str(fir2, 2), "fetchChanges")

    def test_headers_carry_auth(self):
        class _Anis:
            platform = "<TestDevice> <testOS;1.0>"

            def headers(self):
                return {"X-Apple-I-MD-M": "machine"}

        t = ck.CloudKitTransport("CKTOKEN", "USERID", self.dev, _Anis())
        h = t._headers(ck.CUTTLEFISH_BUNDLE, routing_hint="Cuttlefish/joinWithVoucher")
        self.assertEqual(h["x-cloudkit-authtoken"], "CKTOKEN")
        self.assertEqual(h["x-cloudkit-userid"], "USERID")
        self.assertEqual(h["x-cloudkit-functionroutinghint"], "Cuttlefish/joinWithVoucher")
        self.assertEqual(h["x-cloudkit-bundleid"], ck.CUTTLEFISH_BUNDLE)
        self.assertEqual(h["x-cloudkit-containerid"], ck.CUTTLEFISH_CONTAINER)
        self.assertEqual(
            h["x-mme-client-info"],
            "<TestDevice> <testOS;1.0> "
            "<com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>",
        )
        self.assertEqual(h["X-Apple-I-MD-M"], "machine")  # anisette merged in
        # record-fetch uses the securityd bundle + no routing hint
        h2 = t._headers(ck.SECURITYD_BUNDLE)
        self.assertEqual(h2["x-cloudkit-bundleid"], ck.SECURITYD_BUNDLE)
        self.assertNotIn("x-cloudkit-functionroutinghint", h2)


class ContainerHeaderTests(unittest.TestCase):
    """Pin the literal CloudKit container header wire values. These are the exact strings the
    CloudKit client sends; the expected values are hardcoded, not echoed from the code under
    test."""

    EXPECTED_CONTENT_TYPE = ('application/x-protobuf; desc="https://gateway.icloud.com:443'
                             '/static/protobuf/CloudDB/CloudDBClient.desc"; '
                             'messageType=RequestOperation; delimited=true')

    def test_container_headers_match_upstream(self):
        h = ck._container_headers(
            bundle=ck.CUTTLEFISH_BUNDLE,
            container=ck.CUTTLEFISH_CONTAINER,
            mme_client_info="info",
        )
        # accept is x-protobuf (NOT application/json) - the whole block is reused by ckAppInit
        # even though that response body is JSON.
        self.assertEqual(h["accept"], "application/x-protobuf")
        self.assertEqual(h["accept-encoding"], "gzip")
        self.assertEqual(h["accept-language"], "en-US,en;q=0.9")
        self.assertEqual(h["cache-control"], "no-transform")
        self.assertEqual(h["content-encoding"], "gzip")
        self.assertEqual(h["content-type"], self.EXPECTED_CONTENT_TYPE)
        self.assertEqual(h["user-agent"], "CloudKit/1970 (19H384)")
        self.assertEqual(h["x-apple-c2-metric-triggers"], "0")
        self.assertEqual(h["x-cloudkit-databasescope"], "Private")
        self.assertEqual(h["x-cloudkit-duetpreclearedmode"], "None")
        self.assertEqual(h["x-cloudkit-environment"], "Production")
        self.assertEqual(h["x-cloudkit-bundleid"], ck.CUTTLEFISH_BUNDLE)
        self.assertEqual(h["x-cloudkit-containerid"], ck.CUTTLEFISH_CONTAINER)

    def test_operation_id_headers_present_and_hex_upper(self):
        # x-apple-operation-{group-}id = uppercase hex of 8 random bytes: 16 uppercase hex chars.
        h = ck._container_headers(
            bundle=ck.CUTTLEFISH_BUNDLE,
            container=ck.CUTTLEFISH_CONTAINER,
            mme_client_info="info",
        )
        for key in ("x-apple-operation-group-id", "x-apple-operation-id"):
            val = h[key]
            self.assertEqual(len(val), 16)
            self.assertEqual(val, val.upper())
            int(val, 16)  # valid hex
        self.assertNotEqual(h["x-apple-operation-group-id"], h["x-apple-operation-id"])

    def test_request_uuid_is_uppercase(self):
        h = ck._container_headers(
            bundle=ck.CUTTLEFISH_BUNDLE,
            container=ck.CUTTLEFISH_CONTAINER,
            mme_client_info="info",
        )
        u = h["x-apple-request-uuid"]
        self.assertEqual(u, u.upper())

    def test_ck_app_init_headers_use_protobuf_accept_and_basic_dsid_mme(self):
        # Capture the request ck_app_init builds without hitting the network. Auth MUST be
        # Basic(dsid, mmeAuthToken) and accept MUST be x-protobuf.
        import base64

        class _Anis:
            platform = "<TestDevice> <testOS;1.0>"

            def headers(self):
                return {"X-Apple-I-MD": "md"}

        captured = {}

        def fake_post(url, params=None, headers=None, data=None, **kw):
            captured["url"], captured["params"] = url, params
            captured["headers"], captured["data"] = headers, data

            class R:
                status_code = 200

                def json(self):
                    return {"cloudKitUserId": "_ckuser123"}
            return R()

        orig = ck.requests.post
        ck.requests.post = fake_post
        try:
            uid = ck.ck_app_init(ck.CUTTLEFISH_CONTAINER, ck.CUTTLEFISH_BUNDLE,
                                 "16300000000", "MME-AUTH-TOKEN", _Anis())
        finally:
            ck.requests.post = orig

        self.assertEqual(uid, "_ckuser123")
        self.assertEqual(captured["url"], ck.CK_APP_INIT_URL)
        self.assertEqual(captured["params"], {"container": ck.CUTTLEFISH_CONTAINER})
        self.assertEqual(captured["data"], "")  # empty POST body
        hh = captured["headers"]
        self.assertEqual(hh["accept"], "application/x-protobuf")  # NOT application/json
        self.assertEqual(hh["content-type"], self.EXPECTED_CONTENT_TYPE)
        self.assertIn("x-apple-operation-group-id", hh)
        self.assertIn("x-apple-operation-id", hh)
        self.assertEqual(hh["X-Apple-I-MD"], "md")  # anisette merged
        # Basic(dsid : mmeAuthToken) - dsid is the username, mmeAuthToken the password
        self.assertEqual(hh["Authorization"],
                         "Basic " + base64.b64encode(b"16300000000:MME-AUTH-TOKEN").decode())

    def test_ckcode_invoke_headers_carry_userid_authtoken(self):
        # The CKCode header block adds x-cloudkit-userid (cloudKitUserId) + x-cloudkit-authtoken
        # (cloudKitToken) on top of the container block.
        class _Anis:
            platform = "<TestDevice> <testOS;1.0>"

            def headers(self):
                return {}

        dev = ck.DeviceConfig(device_uuid="d", serial="s")
        t = ck.CloudKitTransport("CK-CLOUDKIT-TOKEN", "CKUSER", dev, _Anis())
        h = t._headers(ck.CUTTLEFISH_BUNDLE, routing_hint="Cuttlefish/fetchViableBottles")
        self.assertEqual(h["x-cloudkit-authtoken"], "CK-CLOUDKIT-TOKEN")
        self.assertEqual(h["x-cloudkit-userid"], "CKUSER")
        self.assertEqual(h["x-cloudkit-functionroutinghint"], "Cuttlefish/fetchViableBottles")
        self.assertEqual(h["accept"], "application/x-protobuf")
        self.assertIn("x-apple-operation-id", h)  # was missing before the header refactor


class ResponseParseTests(unittest.TestCase):
    def test_success_with_result(self):
        result = _proto.Writer().uint64(1, ck.RESULT_SUCCESS).finish()
        fir = _proto.Writer().bytes(1, b"cuttlefish-response").finish()
        resp = _proto.Writer().message(3, result).message(1101, fir).finish()
        out = ck.parse_response_operation(resp)
        self.assertTrue(out.ok)
        self.assertEqual(out.serialized_result, b"cuttlefish-response")

    def test_error_surfaced(self):
        err = _proto.Writer().string(4, ".changeTokenExpired").finish()
        result = _proto.Writer().uint64(1, 3).message(2, err).finish()  # code=FAILURE
        resp = _proto.Writer().message(3, result).finish()
        out = ck.parse_response_operation(resp)
        self.assertFalse(out.ok)
        self.assertEqual(out.error_description, ".changeTokenExpired")

    def test_response_feeds_function_invoke_parser(self):
        # the serializedResult is itself a Cuttlefish proto (here a FetchChangesResponse)
        peer = cf.encode_cuttlefish_peer("SHA256:p", cf.SignedBlob(b"i", b"s"),
                                         cf.SignedBlob(b"i", b"s"), cf.SignedBlob(b"i", b"s"))
        change = _proto.Writer().message(3, peer).finish()
        changes = _proto.Writer().string(1, "tok").message(2, change).finish()
        cf_resp = _proto.Writer().message(1, changes).finish()

        result = _proto.Writer().uint64(1, ck.RESULT_SUCCESS).finish()
        fir = _proto.Writer().bytes(1, cf_resp).finish()
        resp = _proto.Writer().message(3, result).message(1101, fir).finish()

        out = ck.parse_response_operation(resp)
        parsed = cf.parse_fetch_changes_response(out.serialized_result)
        self.assertEqual(parsed["sync_token"], "tok")
        self.assertEqual(parsed["peers"][0]["hash"], "SHA256:p")


if __name__ == "__main__":
    unittest.main()
