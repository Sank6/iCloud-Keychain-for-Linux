"""Anisette v3: our own identity, provisioned through a (fake) server and a (fake) Apple."""

import base64
import json
import plistlib

import pytest

from icp.auth import anisette as anisette_mod
from icp.auth import anisette_v3 as v3
from icp.auth.anisette import AnisetteError

CLIENT = "<MacBookPro17,1> <macOS;14.5;23F79> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
UA = "akd/1.0 CFNetwork/1494.0.7 Darwin/23.5.0"
SERVER = "https://v3.example.org"
URLS = {"urls": {"midStartProvisioning": "https://gsd.apple.com/start",
                 "midFinishProvisioning": "https://gsd.apple.com/finish"}}


class _Http:
    def __init__(self, data, status=200):
        self._d, self.status_code, self.ok = data, status, status < 400
        self.content = plistlib.dumps(data) if isinstance(data, dict) else b""
        self.url = ""

    def json(self):
        return self._d

    def raise_for_status(self):
        pass


class FakeWS:
    """Plays the server side of the provisioning session and records what the client sent."""
    def __init__(self, script):
        self.script, self.sent = list(script), []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def recv(self, timeout=None):
        return json.dumps(self.script.pop(0))

    def send(self, m):
        self.sent.append(json.loads(m))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("ICP_CLIENT_INFO", raising=False)
    calls = {"apple": [], "server": []}

    def apple(method, url, **kw):
        calls["apple"].append((method, url, kw))
        if url.endswith("/lookup"):
            return _Http(URLS)
        if url.endswith("/start"):
            return _Http({"Response": {"spim": "SPIM"}})
        return _Http({"Response": {"ptm": "PTM", "tk": "TK"}})
    monkeypatch.setattr(v3.net, "request", apple)

    state = {"headers_result": {"result": "Headers", "X-Apple-I-MD": "otp",
                                "X-Apple-I-MD-M": "machine", "X-Apple-I-MD-RINFO": 33883392}}

    def get(url, **kw):
        return _Http({"client_info": CLIENT, "user_agent": UA})

    def post(url, json=None, **kw):
        calls["server"].append((url, json))
        return _Http(state["headers_result"])
    monkeypatch.setattr(v3.requests, "get", get)
    monkeypatch.setattr(v3.requests, "post", post)
    return calls, state


def script(adi=b"ADI"):
    return [{"result": "GiveIdentifier"}, {"result": "GiveStartProvisioningData"},
            {"result": "GiveEndProvisioningData", "cpim": "CPIM"},
            {"result": "ProvisioningSuccess", "adi_pb": base64.b64encode(adi).decode()}]


def test_provisioning_runs_the_whole_handshake_from_this_machine(env, monkeypatch):
    calls, _ = env
    ws = FakeWS(script())
    a = v3.AnisetteV3(SERVER)
    a.client_info, a.user_agent = CLIENT, UA
    a.provision(connect=lambda *args, **kw: ws)

    assert ws.sent == [{"identifier": base64.b64encode(a.state.identifier).decode()},
                       {"spim": "SPIM"}, {"ptm": "PTM", "tk": "TK"}]
    assert a.state.adi_pb == b"ADI"
    # Apple got the identity the server reports, our own device id, and the safe Content-Type
    method, url, kw = calls["apple"][1]
    assert (method, url) == ("post", "https://gsd.apple.com/start")
    h = kw["headers"]
    assert h["X-Mme-Client-Info"] == CLIENT and h["User-Agent"] == UA
    assert h["Content-Type"] == "text/xml"
    assert h["X-Mme-Device-Id"] == a.state.device_id
    assert plistlib.loads(calls["apple"][2][2]["data"])["Request"] == {"cpim": "CPIM"}


def test_headers_provision_once_and_persist_the_identity(env, monkeypatch):
    calls, _ = env
    monkeypatch.setattr(v3.AnisetteV3, "provision",
                        lambda self, connect=None: (setattr(self.state, "adi_pb", b"ADI"),
                                                    self.state.save()))
    a = v3.AnisetteV3(SERVER)
    h = a.headers()
    assert h["X-Apple-I-MD"] == "otp" and h["X-Apple-I-MD-M"] == "machine"
    assert h["X-Apple-I-MD-RINFO"] == "33883392"
    assert h["X-Mme-Device-Id"] == a.state.device_id
    assert a.client_info == CLIENT and a.user_agent == UA
    # a second run reuses the saved identity and adi_pb: no new provisioning, same device
    b = v3.AnisetteV3(SERVER)
    assert b.state.identifier == a.state.identifier and b.state.adi_pb == b"ADI"
    assert (v3.state_file().stat().st_mode & 0o777) == 0o600


def test_changed_server_keeps_identity_but_drops_adi_pb(env):
    a = v3.AnisetteV3(SERVER)
    a.state.adi_pb = b"ADI"
    a.state.save()
    b = v3.AnisetteV3("https://other.example.org")
    assert b.state.identifier == a.state.identifier and b.state.adi_pb is None


def test_unprovisioned_error_provisions_again_once(env, monkeypatch):
    _, state = env
    seen = []
    state["headers_result"] = {"result": "GetHeadersError", "message": "-45061 not provisioned"}

    def prov(self, connect=None):
        seen.append(1)
        self.state.adi_pb = b"ADI"
        state["headers_result"] = {"result": "Headers", "X-Apple-I-MD": "o",
                                   "X-Apple-I-MD-M": "m", "X-Apple-I-MD-RINFO": 1}
    monkeypatch.setattr(v3.AnisetteV3, "provision", prov)
    a = v3.AnisetteV3(SERVER)
    a.state.adi_pb = b"STALE"
    a.headers()
    assert seen == [1]


def test_server_failure_is_reported(env, monkeypatch):
    _, state = env
    state["headers_result"] = {"result": "GetHeadersError", "message": "boom"}
    a = v3.AnisetteV3(SERVER)
    a.state.adi_pb = b"ADI"
    with pytest.raises(AnisetteError, match="boom"):
        a.headers()


def test_provisioning_error_from_server_is_reported(env):
    a = v3.AnisetteV3(SERVER)
    a.client_info, a.user_agent = CLIENT, UA
    ws = FakeWS([{"result": "GiveIdentifier"}, {"result": "Error", "message": "ADI refused"}])
    with pytest.raises(AnisetteError, match="ADI refused"):
        a.provision(connect=lambda *args, **kw: ws)


def test_protocol_choice(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("ICP_ANISETTE_PROTOCOL", raising=False)
    assert type(v3.open_anisette("http://127.0.0.1:6969")) is anisette_mod.Anisette
    assert type(v3.open_anisette(SERVER)) is v3.AnisetteV3
    assert type(v3.open_anisette(SERVER, protocol="v1")) is anisette_mod.Anisette
    monkeypatch.setenv("ICP_ANISETTE_PROTOCOL", "v3")
    assert type(v3.open_anisette("http://127.0.0.1:6969")) is v3.AnisetteV3


def test_provisioning_over_a_real_websocket(env):
    """Same handshake, but through the real `websockets` client against a local socket."""
    from websockets.sync.server import serve

    got = []

    def server(ws):
        for msg in script(b"REAL"):
            ws.send(json.dumps(msg))
            if msg["result"] != "ProvisioningSuccess":
                got.append(json.loads(ws.recv()))

    with serve(server, "127.0.0.1", 0) as srv:
        port = srv.socket.getsockname()[1]
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        a = v3.AnisetteV3(f"http://127.0.0.1:{port}")
        a.client_info, a.user_agent = CLIENT, UA
        a.provision()
        srv.shutdown()
    assert a.state.adi_pb == b"REAL"
    assert got[1] == {"spim": "SPIM"} and got[2] == {"ptm": "PTM", "tk": "TK"}
