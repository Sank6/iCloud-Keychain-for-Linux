"""Offline regression tests for GrandSlam request identities and error handling."""

import plistlib

import pytest
import requests

from icp import const
from icp.auth import gsa
from icp.auth.gsa import GSAClient, GSAError


class _Device:
    def meta_headers(self):
        return {"X-Mme-Device-Id": "device-id"}


class _Anisette:
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


def test_srp_request_uses_akd_identity(monkeypatch, client):
    captured = {}

    def fake_post(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return _plist_response()

    monkeypatch.setattr(gsa.requests, "post", fake_post)

    client._request({"u": "nobody@example.invalid", "o": "init"})

    assert captured["url"] == const.GSA_ENDPOINT
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


def test_html_503_becomes_actionable_gsa_error(monkeypatch, client):
    html = b"<html><title>503 Service Temporarily Unavailable</title></html>"
    monkeypatch.setattr(
        gsa.requests, "post",
        lambda *a, **k: _Response(html, status=503, content_type="text/html"),
    )

    with pytest.raises(GSAError) as exc_info:
        client._request({"o": "init"})

    message = str(exc_info.value)
    assert "GSA init returned HTTP 503" in message
    assert "expected a plist" in message
    assert "text/html" in message
    assert f"{len(html)} bytes" in message


def test_non_plist_200_becomes_gsa_error(monkeypatch, client):
    monkeypatch.setattr(
        gsa.requests, "post",
        lambda *a, **k: _Response(b"not a plist", content_type="text/plain"),
    )

    with pytest.raises(GSAError, match="GSA complete returned HTTP 200"):
        client._request({"o": "complete"})


def test_transport_error_becomes_gsa_error(monkeypatch, client):
    def timeout(*args, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(gsa.requests, "post", timeout)

    with pytest.raises(GSAError, match="GSA init request failed: timed out"):
        client._request({"o": "init"})


def test_missing_response_dictionary_becomes_gsa_error(monkeypatch, client):
    response = _Response(plistlib.dumps({"Status": {"ec": 0}}))
    monkeypatch.setattr(gsa.requests, "post", lambda *a, **k: response)

    with pytest.raises(GSAError, match="without a Response dictionary"):
        client._request({"o": "init"})


def test_non_dictionary_plist_becomes_gsa_error(monkeypatch, client):
    response = _Response(plistlib.dumps(["unexpected"]))
    monkeypatch.setattr(gsa.requests, "post", lambda *a, **k: response)

    with pytest.raises(GSAError, match="without a Response dictionary"):
        client._request({"o": "init"})


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
