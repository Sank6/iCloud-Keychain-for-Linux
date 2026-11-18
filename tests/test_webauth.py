"""Offline tests for the idmsa web-session auth (icp.auth.webauth).

No network: `WebAuthSession.http` is a real `requests.Session`, but its `get`/`post`
methods are monkeypatched per-test with fakes returning canned responses. `signin()`
itself is exercised via its private steps (`_auth_start`/`_federate`/`_srp_init`) mocked
out, since a full run needs a real SRP server on the other end.

Run: .venv/bin/python -m unittest tests.test_webauth
"""

import base64
import unittest
from unittest import mock

from icp.auth import webauth
from icp.auth.webauth import WebAuthError, WebAuthSession, _derive_password_key


class _FakeResponse:
    def __init__(self, status_code=200, json_body=None, headers=None, ok=None):
        self.status_code = status_code
        self._json = json_body
        self.headers = headers or {}
        self.ok = ok if ok is not None else 200 <= status_code < 300
        self.reason = "error" if not self.ok else "OK"
        self.text = ""

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


def _session(**kw) -> WebAuthSession:
    return WebAuthSession("auth-test-frame", **kw)


class TlsTests(unittest.TestCase):
    def test_session_verifies_certificates(self):
        # The session carries the Apple ID's SRP exchange, 2FA codes and session tokens.
        self.assertIs(WebAuthSession("auth-test-frame").http.verify, True)


class DerivePasswordKeyTests(unittest.TestCase):
    """Must match gsa.py's `_encrypt_password` exactly - same KDF, different transport."""

    def test_matches_gsa_encrypt_password(self):
        from icp.auth.gsa import _encrypt_password
        salt, iterations = b"some-salt", 20000
        for protocol in ("s2k", "s2k_fo"):
            self.assertEqual(
                _derive_password_key("hunter2", salt, iterations, protocol),
                _encrypt_password("hunter2", salt, iterations, protocol))

    def test_unknown_protocol_falls_back_to_s2k(self):
        """No protocol validation, deliberately - matches gsa.py's `_encrypt_password`,
        which treats anything other than "s2k_fo" as plain "s2k"."""
        from icp.auth.gsa import _encrypt_password
        self.assertEqual(_derive_password_key("hunter2", b"salt", 1000, "bogus"),
                         _encrypt_password("hunter2", b"salt", 1000, "bogus"))


class AuthStartTests(unittest.TestCase):
    def test_failure_raises(self):
        sess = _session()
        sess.http.get = lambda *a, **k: _FakeResponse(503, json_body=None)
        with self.assertRaises(WebAuthError):
            sess._auth_start()

    def test_success_captures_cookies_no_raise(self):
        sess = _session()
        sess.http.get = lambda *a, **k: _FakeResponse(200, json_body=None)
        sess._auth_start()  # must not raise


class FederateTests(unittest.TestCase):
    def test_failure_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(400, json_body=None)
        with self.assertRaises(WebAuthError):
            sess._federate("user@example.com")


class SrpInitTests(unittest.TestCase):
    def test_success_returns_parsed_body(self):
        sess = _session()
        body = {"iteration": 20000, "salt": base64.b64encode(b"salt").decode(),
                "protocol": "s2k", "b": base64.b64encode(b"B" * 32).decode(), "c": "chal-1"}
        sess.http.post = lambda *a, **k: _FakeResponse(200, json_body=body)
        self.assertEqual(sess._srp_init("user@example.com", b"A"), body)

    def test_error_body_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(
            200, json_body={"errorMessage": "Invalid ID or password."})
        with self.assertRaisesRegex(WebAuthError, "Invalid ID or password"):
            sess._srp_init("user@example.com", b"A")


class SigninTests(unittest.TestCase):
    """The multi-step signin() orchestration, with the network steps mocked out."""

    def _patched(self, sess, *, complete_status):
        init_resp = {"iteration": 1000, "salt": base64.b64encode(b"some-salt").decode(),
                    "protocol": "s2k", "b": base64.b64encode((7).to_bytes(256, "big")).decode(),
                    "c": "chal-1"}
        patches = [
            mock.patch.object(sess, "_auth_start"),
            mock.patch.object(sess, "_federate"),
            mock.patch.object(sess, "_srp_init", return_value=init_resp),
            mock.patch.object(sess, "_post",
                              return_value=_FakeResponse(complete_status, json_body={})),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_success_clears_needs_2fa(self):
        sess = _session()
        self._patched(sess, complete_status=200)
        sess.signin("user@example.com", "hunter2")
        self.assertFalse(sess.needs_2fa)

    def test_409_sets_needs_2fa_without_raising(self):
        sess = _session()
        self._patched(sess, complete_status=409)
        sess.signin("user@example.com", "hunter2")
        self.assertTrue(sess.needs_2fa)

    def test_other_failure_raises(self):
        sess = _session()
        self._patched(sess, complete_status=403)
        with self.assertRaises(WebAuthError):
            sess.signin("user@example.com", "wrongpassword")

    def test_username_is_lowercased_for_the_srp_proof(self):
        sess = _session()
        seen = {}

        def fake_federate(username):
            seen["username"] = username

        init_resp = {"iteration": 1000, "salt": base64.b64encode(b"some-salt").decode(),
                    "protocol": "s2k", "b": base64.b64encode((7).to_bytes(256, "big")).decode(),
                    "c": "chal-1"}
        with mock.patch.object(sess, "_auth_start"), \
             mock.patch.object(sess, "_federate", side_effect=fake_federate), \
             mock.patch.object(sess, "_srp_init", return_value=init_resp), \
             mock.patch.object(sess, "_post", return_value=_FakeResponse(200, json_body={})):
            sess.signin("User@Example.COM", "hunter2")
        self.assertEqual(seen["username"], "user@example.com")


class RequestPushNotificationTests(unittest.TestCase):
    def test_success(self):
        sess = _session()
        calls = []

        def fake_put(url, **k):
            calls.append(url)
            return _FakeResponse(200, json_body=None)

        sess.http.put = fake_put
        sess.request_push_notification()  # must not raise
        self.assertTrue(calls[0].endswith("/verify/trusteddevice/securitycode"))

    def test_failure_raises(self):
        sess = _session()
        sess.http.put = lambda *a, **k: _FakeResponse(500, json_body=None)
        with self.assertRaises(WebAuthError):
            sess.request_push_notification()


class TwoFactorTests(unittest.TestCase):
    def test_submit_2fa_then_trusts_session(self):
        sess = _session(session_data={"session_id": "sid-1", "scnt": "scnt-1"})
        calls = []

        def fake_post(url, **k):
            calls.append(("post", url))
            return _FakeResponse(204, json_body=None)

        def fake_get(url, **k):
            calls.append(("get", url))
            return _FakeResponse(200, json_body={},
                                 headers={"X-Apple-TwoSV-Trust-Token": "trust-1"})

        sess.http.post = fake_post
        sess.http.get = fake_get
        sess.needs_2fa = True
        sess.submit_2fa("123456")
        self.assertEqual(sess.session_data["trust_token"], "trust-1")
        self.assertFalse(sess.needs_2fa)
        self.assertTrue(calls[0][1].endswith("/verify/trusteddevice/securitycode"))
        self.assertTrue(calls[1][1].endswith("/2sv/trust"))

    def test_wrong_code_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(
            400, json_body={"errorMessage": "Incorrect verification code."})
        with self.assertRaisesRegex(WebAuthError, "Incorrect verification code"):
            sess.submit_2fa("000000")

    def test_trust_call_failure_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(204, json_body=None)
        sess.http.get = lambda *a, **k: _FakeResponse(500, json_body=None)
        with self.assertRaises(WebAuthError):
            sess.submit_2fa("123456")


class AccountLoginTests(unittest.TestCase):
    def test_returns_parsed_data(self):
        sess = _session(session_data={"session_token": "tok-1"})
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": True, "webservices": {}}
        sess.http.post = lambda *a, **k: _FakeResponse(200, json_body=data)
        self.assertEqual(sess.account_login(), data)

    def test_non_json_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(200, json_body=None)
        with self.assertRaises(WebAuthError):
            sess.account_login()

    def test_error_body_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(
            200, json_body={"errorMessage": "Authentication required for Account."})
        with self.assertRaises(WebAuthError):
            sess.account_login()


class HsaChallengeTests(unittest.TestCase):
    def test_hsa1_never_challenges(self):
        self.assertFalse(webauth.hsa_challenge_required({"dsInfo": {"hsaVersion": 1}}))

    def test_trusted_browser_no_challenge(self):
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": True}
        self.assertFalse(webauth.hsa_challenge_required(data))

    def test_untrusted_browser_challenges(self):
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": False}
        self.assertTrue(webauth.hsa_challenge_required(data))

    def test_explicit_challenge_flag_wins(self):
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": True,
                "hsaChallengeRequired": True}
        self.assertTrue(webauth.hsa_challenge_required(data))


class ExtractWebservicesTests(unittest.TestCase):
    def test_flattens_url_and_drops_off_services(self):
        data = {"webservices": {
            "premiummailsettings": {"url": "https://p1-maildomainws.icloud.com", "status": "active"},
            "drivews": {"url": "https://p1-drivews.icloud.com", "status": "off"},
            "noturl": {"status": "active"},
        }}
        self.assertEqual(webauth.extract_webservices(data),
                         {"premiummailsettings": "https://p1-maildomainws.icloud.com"})


class ExportTests(unittest.TestCase):
    def test_export_round_trips_frame_tag_and_session_data(self):
        sess = _session(session_data={"session_token": "tok-1"})
        exported = sess.export()
        self.assertEqual(exported["frame_tag"], "auth-test-frame")
        self.assertEqual(exported["session_data"]["session_token"], "tok-1")
        self.assertIn("cookies", exported)

        restored = WebAuthSession(exported["frame_tag"], session_data=exported["session_data"],
                                  cookies=exported["cookies"])
        self.assertEqual(restored.session_data["session_token"], "tok-1")


if __name__ == "__main__":
    unittest.main()
