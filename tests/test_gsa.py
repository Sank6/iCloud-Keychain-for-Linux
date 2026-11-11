"""Offline regression tests for GrandSlam request identities and protocol responses."""

import plistlib

import pytest

from icp import const
from icp.auth import gsa
from icp.auth.gsa import GSAClient, GSAError


class _Device:
    def meta_headers(self):
        return {"X-Mme-Device-Id": "device-id"}


class _Anisette:
    client_info = None
    user_agent = None

    def headers(self):
        return {
            "X-Apple-I-MD": "otp",
            "X-Apple-I-MD-M": "machine",
        }


class _Response:
    def __init__(self, content, *, status=200):
        self.content = content
        self.status_code = status
        self.ok = 200 <= status < 300


@pytest.fixture
def client():
    return GSAClient(_Device(), _Anisette())


def _plist_response(response=None, *, status=200):
    body = {"Response": response if response is not None else {"Status": {"ec": 0}}}
    return _Response(plistlib.dumps(body), status=status)


def test_srp_request_uses_akd_identity(monkeypatch, client):
    captured = {}

    def fake_post(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return _plist_response()

    monkeypatch.setattr(gsa.requests, "post", fake_post)

    client._request({"u": "nobody@example.invalid", "o": "init"})

    assert captured["url"] == const.GSA_ENDPOINT
    assert captured["headers"]["Content-Type"] == "text/xml"
    client_info = captured["headers"]["X-MMe-Client-Info"]
    assert client_info == const.GSA_CLIENT_INFO
    assert "com.apple.akd/1.0" in client_info
    assert "com.apple.dt.Xcode" not in client_info


def test_twofa_headers_use_akd_with_xcode_application_context(client):
    headers = client._twofa_headers("123", "token")

    assert headers["X-Mme-Client-Info"] == const.GSA_CLIENT_INFO
    assert "com.apple.akd/1.0" in headers["X-Mme-Client-Info"]
    assert "com.apple.dt.Xcode" not in headers["X-Mme-Client-Info"]
    assert headers["User-Agent"] == "Xcode"
    assert headers["X-Apple-App-Info"] == "com.apple.gs.xcode.auth"
    assert headers["X-Xcode-Version"] == "11.2 (11B41)"


def test_request_returns_response_dictionary(monkeypatch, client):
    expected = {"Status": {"ec": 0}, "sp": "s2k"}
    monkeypatch.setattr(gsa.requests, "post", lambda *a, **k: _plist_response(expected))

    assert client._request({"o": "init"}) == expected


def test_non_success_plist_preserves_apple_status(monkeypatch, client):
    response = {"Status": {"ec": -20101, "em": "bad account"}}
    monkeypatch.setattr(
        gsa.requests, "post", lambda *a, **k: _plist_response(response, status=401),
    )

    with pytest.raises(GSAError) as exc_info:
        client._request({"o": "init"})

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


def test_grandslam_requests_use_the_content_type_apples_firewall_accepts():
    client = GSAClient(_Device(), _Anisette())
    assert client._twofa_headers("1", "tok")["Content-Type"] == "text/xml"
    assert const.GSA_CONTENT_TYPE == "text/xml"
