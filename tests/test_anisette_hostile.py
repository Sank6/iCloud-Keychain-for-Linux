"""Red-team tests: the anisette server and the network are untrusted. Whatever they send, the
client either returns valid headers or raises AnisetteError. It never crashes, never forwards a
header value containing CR/LF, and never sends our identity to an address that is not Apple's."""

import base64
import json

import pytest

from icp import const
from icp.auth import anisette_v3 as v3
from icp.auth.anisette import Anisette, AnisetteError

CLIENT = {"client_info": "<M> <m;1> <com.apple.AuthKit/1 (x/1)>", "user_agent": "ua/1"}
HEADERS = {"result": "Headers", "X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine",
           "X-Apple-I-MD-RINFO": 1234}
SERVER = "https://v3.example.org"


class Reply:
    def __init__(self, data, status=200):
        self.data, self.status_code, self.ok = data, status, status < 400
        self.content = data if isinstance(data, bytes) else json.dumps(data).encode()

    def json(self):
        if isinstance(self.data, bytes):
            raise ValueError("not json")
        return self.data

    def raise_for_status(self):
        pass

    def iter_content(self, n):
        for i in range(0, len(self.content), n):
            yield self.content[i:i + n]

    def close(self):
        pass


def make(monkeypatch, tmp_path, client, headers):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(v3.requests, "get", lambda url, **k: Reply(client))
    monkeypatch.setattr(v3.requests, "post", lambda url, **k: Reply(headers))
    a = v3.AnisetteV3(SERVER)
    a.state.adi_pb, a.state.claim = b"ADI", const.MAC_CLIENT_INFO
    return a


BAD_CLIENT = [[], None, "x", 5, {}, {"client_info": 1, "user_agent": 2},
              {"client_info": "", "user_agent": "u"}, {"client_info": "a\r\nX-Evil: 1", "user_agent": "u"},
              {"client_info": "<M> <m> <c>", "user_agent": "u\nv"}, {"client_info": "x" * 100_000, "user_agent": "u"},
              {"client_info": "a\x00b", "user_agent": "u"}, b"<html>not json</html>", b"\xff\xfe"]
BAD_HEADERS = [[], None, "x", 5, {}, {"result": "Headers"}, {**HEADERS, "X-Apple-I-MD": 5.5},
               {**HEADERS, "X-Apple-I-MD": "a\r\nEvil: 1"}, {**HEADERS, "X-Apple-I-MD": "a" * 10_000_000},
               {**HEADERS, "X-Apple-I-MD-M": None}, {**HEADERS, "X-Apple-I-MD-RINFO": {"a": 1}},
               {"result": "GetHeadersError"}, {"result": "GetHeadersError", "message": 5},
               b"garbage"]


@pytest.mark.parametrize("client", BAD_CLIENT, ids=lambda c: repr(c)[:40])
def test_a_hostile_client_info_reply_is_refused(monkeypatch, tmp_path, client):
    with pytest.raises(AnisetteError):
        make(monkeypatch, tmp_path, client, HEADERS).headers()


@pytest.mark.parametrize("headers", BAD_HEADERS, ids=lambda c: repr(c)[:40])
def test_a_hostile_headers_reply_is_refused(monkeypatch, tmp_path, headers):
    with pytest.raises(AnisetteError):
        make(monkeypatch, tmp_path, CLIENT, headers).headers()


def test_a_good_reply_still_works_and_numbers_become_strings(monkeypatch, tmp_path):
    out = make(monkeypatch, tmp_path, CLIENT, HEADERS).headers()
    assert out["X-Apple-I-MD-RINFO"] == "1234" and out["X-Apple-I-MD"] == "otp"
    assert all(isinstance(v, str) and "\r" not in v and "\n" not in v for v in out.values())


def test_an_oversized_reply_is_refused_without_reading_it_all(monkeypatch, tmp_path):
    class Endless(Reply):
        def iter_content(self, n):
            for _ in range(10_000):
                yield b"x" * n
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(v3.requests, "get", lambda url, **k: Endless({}))
    with pytest.raises(AnisetteError, match="too large"):
        v3.AnisetteV3(SERVER).headers()


def test_a_v1_server_cannot_inject_headers_either(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("requests.get", lambda url, **k: Reply(
        {"X-Apple-I-MD": "a\r\nX-Evil: 1", "X-Apple-I-MD-M": "m"}))
    with pytest.raises(AnisetteError):
        Anisette("http://127.0.0.1:6969").headers()


# ---- provisioning -------------------------------------------------------------------------
class WS:
    def __init__(self, script):
        self.script, self.sent = list(script), []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def recv(self, timeout=None):
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item if isinstance(item, (str, bytes)) else json.dumps(item)

    def send(self, m):
        self.sent.append(json.loads(m))


GOOD_URLS = {"urls": {"midStartProvisioning": "https://gsa.apple.com/start",
                      "midFinishProvisioning": "https://gsa.apple.com/finish"}}


def provisioning(monkeypatch, tmp_path, script, urls=GOOD_URLS, apple_reply=None):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(v3.requests, "get", lambda url, **k: Reply(CLIENT))
    sent_to = []

    def apple(method, url, **kw):
        sent_to.append(url)
        if url.endswith("/lookup"):
            return Reply(urls)
        body = apple_reply if apple_reply is not None else {"Response": {"spim": "S", "ptm": "P", "tk": "T"}}
        r = Reply(body)
        r.content = json.dumps(body).encode()
        return r
    monkeypatch.setattr(v3.net, "request", apple)
    monkeypatch.setattr(v3, "_plist_loads", None, raising=False)
    a = v3.AnisetteV3(SERVER)
    return a, WS(script), sent_to


def run(a, ws):
    a.provision(connect=lambda *args, **kw: ws)


@pytest.mark.parametrize("urls", [
    {"urls": {"midStartProvisioning": "https://evil.example/x", "midFinishProvisioning": "https://gsa.apple.com/f"}},
    {"urls": {"midStartProvisioning": "http://gsa.apple.com/x", "midFinishProvisioning": "https://gsa.apple.com/f"}},
    {"urls": {"midStartProvisioning": "https://apple.com.evil.example/x", "midFinishProvisioning": "https://gsa.apple.com/f"}},
    {"urls": {"midStartProvisioning": "https://evil.example/@gsa.apple.com", "midFinishProvisioning": "https://gsa.apple.com/f"}},
    {"urls": {"midStartProvisioning": 5, "midFinishProvisioning": None}},
    {"urls": {}}, {"urls": []}, {},
])
def test_provisioning_never_sends_our_identity_to_a_non_apple_address(monkeypatch, tmp_path, urls):
    a, ws, sent_to = provisioning(monkeypatch, tmp_path, [{"result": "GiveIdentifier"}], urls=urls)
    with pytest.raises(AnisetteError):
        run(a, ws)
    assert all(u.endswith("/lookup") for u in sent_to) and ws.sent == []


@pytest.mark.parametrize("script", [
    ["not json"], [b"\xff"], [[1, 2]], [None], [{"result": "Mystery"}],
    [{"result": "GiveIdentifier"}, {"result": "GiveEndProvisioningData"}],          # no cpim
    [{"result": "ProvisioningSuccess"}],                                            # no blob
    [{"result": "ProvisioningSuccess", "adi_pb": "!!!not base64"}],
    [{"result": "ProvisioningSuccess", "adi_pb": ""}],
    [{"result": "ProvisioningSuccess", "adi_pb": 5}],
    [{"result": "ProvisioningSuccess", "adi_pb": base64.b64encode(b"x" * (2 << 20)).decode()}],
    [{"result": "Error", "message": "x" * 100_000}],
    [ConnectionResetError("boom")], [TimeoutError("slow")],
])
def test_a_hostile_provisioning_stream_ends_in_anisette_error(monkeypatch, tmp_path, script):
    a, ws, _ = provisioning(monkeypatch, tmp_path, script)
    with pytest.raises(AnisetteError):
        run(a, ws)
    assert a.state.adi_pb is None


def test_a_malformed_apple_reply_is_an_anisette_error(monkeypatch, tmp_path):
    a, ws, _ = provisioning(monkeypatch, tmp_path, [{"result": "GiveStartProvisioningData"}],
                            apple_reply={"Response": "not a dict"})
    with pytest.raises(AnisetteError):
        run(a, ws)


def test_error_messages_from_the_server_are_truncated(monkeypatch, tmp_path):
    a, ws, _ = provisioning(monkeypatch, tmp_path, [{"result": "Error", "message": "x" * 100_000}])
    with pytest.raises(AnisetteError) as e:
        run(a, ws)
    assert len(str(e.value)) < 500
