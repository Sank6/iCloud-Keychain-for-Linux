"""Offline regression tests for GrandSlam request identities and protocol responses."""

import plistlib

import pytest

from icp import const
from icp.auth import gsa
from icp.auth.gsa import GSAClient, GSAError, GSAServiceError

CLIENT_INFO = "<TestDevice> <testOS;1.0> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
USER_AGENT = "test-authkit/1.0"


class _Device:
    def meta_headers(self):
        return {"X-Mme-Device-Id": "device-id"}


class _Anisette:
    client_info = CLIENT_INFO
    user_agent = USER_AGENT

    def headers(self):
        return {
            "X-Apple-I-MD": "otp",
            "X-Apple-I-MD-M": "machine",
        }


class _Response:
    def __init__(self, content, *, status=200, content_type="text/x-xml-plist"):
        self.content = content
        self.status_code = status
        self.ok = 200 <= status < 300
        self.headers = {"Content-Type": content_type}


@pytest.fixture
def client():
    return GSAClient(_Device(), _Anisette())


def _plist_response(response=None, *, status=200):
    body = {"Response": response if response is not None else {"Status": {"ec": 0}}}
    return _Response(plistlib.dumps(body), status=status)


def test_srp_request_uses_one_coherent_identity(monkeypatch, client):
    captured = {}

    def fake_post(method, url, **kwargs):
        captured.update({"method": method, "url": url, **kwargs})
        return _plist_response()

    monkeypatch.setattr(gsa.net, "request", fake_post)

    client._request(
        {"u": "nobody@example.invalid", "o": "init"},
        anisette_headers=client.anisette.headers(),
    )

    assert captured["url"] == const.GSA_ENDPOINT
    assert captured["method"].upper() == "POST"
    assert captured["headers"]["Content-Type"] == "text/xml"
    assert captured["headers"]["Connection"] == "close"
    request = plistlib.loads(captured["data"])["Request"]
    client_info = captured["headers"]["X-MMe-Client-Info"]
    assert client_info == CLIENT_INFO
    assert request["cpd"]["X-Mme-Client-Info"] == client_info


def test_twofa_headers_use_anisette_identity_with_xcode_application_context(client):
    headers = client._twofa_headers("123", "token")

    assert headers["X-Mme-Client-Info"] == CLIENT_INFO
    assert headers["User-Agent"] == USER_AGENT
    assert headers["X-Apple-App-Info"] == "com.apple.gs.xcode.auth"
    assert headers["X-Xcode-Version"] == const.XCODE_VERSION


def test_request_returns_response_dictionary(monkeypatch, client):
    expected = {"Status": {"ec": 0}, "sp": "s2k"}
    monkeypatch.setattr(gsa.net, "request", lambda *a, **k: _plist_response(expected))

    assert client._request({"o": "init"}, anisette_headers=client.anisette.headers()) == expected


def test_non_success_plist_preserves_apple_status(monkeypatch, client):
    response = {"Status": {"ec": -20101, "em": "bad account"}}
    monkeypatch.setattr(
        gsa.net, "request", lambda *a, **k: _plist_response(response, status=401),
    )

    with pytest.raises(GSAError) as exc_info:
        client._request({"o": "init"}, anisette_headers=client.anisette.headers())

    message = str(exc_info.value)
    assert "HTTP 401" in message
    assert "ec=-20101" in message
    assert "bad account" in message


def test_requests_use_the_anisette_sources_client_identity():
    """Apple rejects anisette whose claimed client differs from its source (Oct 2026)."""
    mac = "<MacBookPro17,1> <macOS;14.5;23F79> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    anis = _Anisette()
    anis.client_info = mac
    client = GSAClient(_Device(), anis)
    assert client._twofa_headers("1", "tok")["X-Mme-Client-Info"] == mac


def test_grandslam_requests_use_the_content_type_apples_firewall_accepts(monkeypatch):
    client = GSAClient(_Device(), _Anisette())
    assert client._twofa_headers("1", "tok")["Content-Type"] == "text/xml"
    assert const.GSA_CONTENT_TYPE == "text/xml"


def test_html_503_is_reported_without_retry(monkeypatch, client):
    calls = []

    def fail_once(*args, **kwargs):
        calls.append((args, kwargs))
        return _Response(b"<html>unavailable</html>", status=503, content_type="text/html")

    monkeypatch.setattr(
        gsa.net,
        "request",
        fail_once,
    )

    with pytest.raises(GSAServiceError, match="HTTP 503"):
        client._request({"o": "init"}, anisette_headers=client.anisette.headers())
    assert len(calls) == 1


def test_plist_503_is_reported_as_service_failure(monkeypatch, client):
    response = {"Status": {"ec": -1, "em": "unavailable"}}
    monkeypatch.setattr(
        gsa.net, "request", lambda *a, **k: _plist_response(response, status=503),
    )

    with pytest.raises(GSAServiceError, match="HTTP 503"):
        client._request({"o": "init"}, anisette_headers=client.anisette.headers())


class _ChangingAnisette(_Anisette):
    def __init__(self):
        self.calls = 0

    def headers(self):
        self.calls += 1
        return {"X-Apple-I-MD": f"otp-{self.calls}",
                "X-Apple-I-MD-M": "machine", "X-Apple-I-Client-Time": f"tick-{self.calls}"}


def _authentication_transport(monkeypatch):
    class User:
        def start_authentication(self):
            return "nobody@example.invalid", b"public-A"

        def process_challenge(self, salt, public_b):
            return b"client-proof"

        def verify_session(self, proof):
            assert proof == b"server-proof"

        def authenticated(self):
            return True

        def get_session_key(self):
            return b"synthetic-session-key"

    monkeypatch.setattr(gsa.srp, "User", lambda *a, **k: User())
    monkeypatch.setattr(gsa, "_decrypt_cbc", lambda *a: plistlib.dumps({"test": True}))
    requests = []

    def request(method, url, **kwargs):
        payload = plistlib.loads(kwargs["data"])["Request"]
        requests.append(payload)
        if payload["o"] == "init":
            return _plist_response({"Status": {"ec": 0}, "sp": "s2k", "s": b"salt",
                                    "i": 1, "B": b"public-B", "c": "challenge"})
        return _plist_response({"Status": {"ec": 0}, "M2": b"server-proof", "spd": b"encrypted"})

    monkeypatch.setattr(gsa.net, "request", request)
    return requests


def test_srp_legs_share_machine_validation_and_client_time(monkeypatch):
    requests = _authentication_transport(monkeypatch)
    anisette = _ChangingAnisette()
    client = GSAClient(_Device(), anisette)
    client.authenticate("nobody@example.invalid", "synthetic-password", "test")
    assert anisette.calls == 1
    assert len(requests) == 2
    assert requests[0]["cpd"] == requests[1]["cpd"]


def test_separate_srp_transactions_fetch_fresh_machine_validation(monkeypatch):
    requests = _authentication_transport(monkeypatch)
    anisette = _ChangingAnisette()
    client = GSAClient(_Device(), anisette)
    for _ in range(2):
        client.authenticate("nobody@example.invalid", "synthetic-password", "test")
    assert anisette.calls == 2
    assert requests[0]["cpd"] == requests[1]["cpd"]
    assert requests[2]["cpd"] == requests[3]["cpd"]
    assert requests[0]["cpd"] != requests[2]["cpd"]
