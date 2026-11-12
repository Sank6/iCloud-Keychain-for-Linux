"""Which client identity sign-in claims: it must match where the anisette data came from."""

from icp import const
from icp.auth import anisette as anisette_mod
from icp.auth.anisette import Anisette

MAC = "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
DATA = {"X-Apple-I-MD": "a", "X-Apple-I-MD-M": "b", "X-MMe-Client-Info": MAC}


class _Resp:
    def __init__(self, data):
        self._d = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


def _serve(monkeypatch):
    def fake_get(url, **kw):
        if url.endswith("/v3/client_info"):
            return _Resp({"client_info": MAC, "user_agent": "akd/1.0 CFNetwork/811.5.4"})
        return _Resp(DATA)
    monkeypatch.setattr(anisette_mod.requests, "get", fake_get)


def test_loopback_server_claims_android(monkeypatch):
    monkeypatch.delenv("ICP_CLIENT_INFO", raising=False)
    _serve(monkeypatch)
    a = Anisette("http://127.0.0.1:6969")
    a.headers()
    assert a.client_info == const.ANDROID_CLIENT_INFO
    assert a.user_agent == "akd/1.0 CFNetwork/811.5.4"


def test_remote_server_claims_what_it_reports(monkeypatch):
    monkeypatch.delenv("ICP_CLIENT_INFO", raising=False)
    _serve(monkeypatch)
    a = Anisette("https://mac-ani.example.org")
    a.headers()
    assert a.client_info == MAC


def test_config_override_wins(monkeypatch):
    monkeypatch.setenv("ICP_CLIENT_INFO", "<X> <Y> <Z>")
    _serve(monkeypatch)
    a = Anisette("http://127.0.0.1:6969")
    a.headers()
    assert a.client_info == "<X> <Y> <Z>"


def test_service_identities_claim_the_anisettes_device():
    mac = const.MAC_CLIENT_INFO
    assert const.with_device("<PC> <Windows;6.2(0,0);9200> <com.apple.AOSKit/282 (com.apple.accountsd/113)>", mac) \
        == "<Mac15,7> <macOS;14.5;23F79> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
    # nothing known about the anisette's device: leave the service's identity alone
    plain = "<PC> <Windows;6.2(0,0);9200> <x/1 (y/2)>"
    assert const.with_device(plain, None) == plain
