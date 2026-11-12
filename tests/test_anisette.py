import pytest
import requests

from icp.auth.anisette import Anisette, AnisetteError


SERVER_URL = "https://anisette.example.invalid"


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def test_server_url_is_required(monkeypatch):
    monkeypatch.delenv("ICP_ANISETTE_URL", raising=False)

    with pytest.raises(AnisetteError, match="no anisette server URL configured"):
        Anisette()


@pytest.mark.parametrize("url", ["localhost:6969", "ftp://localhost/service"])
def test_server_url_is_validated(url):
    with pytest.raises(AnisetteError, match="invalid anisette server URL"):
        Anisette(url)


def test_headers_are_filtered(monkeypatch):
    response = {
        "X-Apple-I-MD": "otp",
        "X-Apple-I-MD-M": "machine",
        "X-Mme-Device-Id": "device",
        "ignored": "value",
    }
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: _Response(response))

    assert Anisette(SERVER_URL).headers() == {
        "X-Apple-I-MD": "otp",
        "X-Apple-I-MD-M": "machine",
        "X-Mme-Device-Id": "device",
    }


@pytest.mark.parametrize(("client_info", "platform"), [
    (
        "<PC> <Windows;6.2(0,0);9200> "
        "<com.apple.AuthKitWin/7.3 (com.apple.iCloud/15.10.0.39)>",
        "<PC> <Windows;6.2(0,0);9200>",
    ),
    (
        "<MacBookPro13,2> <macOS;13.1;22C65> "
        "<com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        "<MacBookPro13,2> <macOS;13.1;22C65>",
    ),
])
def test_client_identity_is_cached(monkeypatch, client_info, platform):
    calls = []
    response = {
        "client_info": client_info,
        "user_agent": "test-authkit/1.0",
    }

    def get(url, **kwargs):
        calls.append(url)
        return _Response(response)

    monkeypatch.setattr(requests, "get", get)
    anisette = Anisette(SERVER_URL)

    assert anisette.client_info == response["client_info"]
    assert anisette.user_agent == response["user_agent"]
    assert anisette.platform == platform
    assert calls == [f"{SERVER_URL}/v3/client_info"]


def test_client_identity_is_required(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: _Response({}))

    with pytest.raises(AnisetteError, match="invalid client info"):
        _ = Anisette(SERVER_URL).client_info


def test_machine_data_is_required(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: _Response({}))

    with pytest.raises(AnisetteError, match="did not return"):
        Anisette(SERVER_URL).headers()


def test_query_string_is_kept(monkeypatch):
    """Servers can pick a backend with a query parameter, it has to survive."""
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return _Response({"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine"})

    monkeypatch.setattr(requests, "get", get)
    anisette = Anisette(f"{SERVER_URL}/?backend=macos")

    anisette.headers()
    assert calls == [f"{SERVER_URL}/?backend=macos"]

    calls.clear()

    def get_identity(url, **kwargs):
        calls.append(url)
        return _Response({
            "client_info": "<Mac> <macOS;15.0> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
            "user_agent": "akd/1.0",
        })

    monkeypatch.setattr(requests, "get", get_identity)
    _ = anisette.client_info
    assert calls == [f"{SERVER_URL}/v3/client_info?backend=macos"]
