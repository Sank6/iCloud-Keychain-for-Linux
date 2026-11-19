"""Red-team tests for the Apple-extension host: hostile input must never crash it, and a password
must only leave the vault for an authenticated, explicit single-login request."""

import io
import json
import struct
import sys

import pytest

from icp import applehost as ah
from icp import applehost_main as hm

SECRET = "TOPSECRET-password-123"
CREDS = [{"domain": "example.com", "username": "me", "password": SECRET, "title": "Example"}]


def fake_agent(req):
    if req.get("cmd") == "match":
        return {"ok": True, "credentials": CREDS}
    return {"ok": True}


class ReadySession:
    """A paired session whose decrypted query is whatever the test says."""
    ready = True

    def __init__(self, query):
        self.query = query

    def open_smsg(self, _blob):
        if isinstance(self.query, Exception):
            raise self.query
        return self.query

    def seal_smsg(self, body):
        return body                      # let the test read what would be encrypted


def host_with(query):
    h = hm.Host(call=fake_agent, notify=lambda pin: None)
    h.session = ReadySession(query)
    return h


JUNK = [None, 1, 0, -1, 2 ** 70, 3.5, True, "x", "", "{", "[]", "null", "\x00", [], [1], {}, {"a": 1},
        {"QID": 5}, {"QID": ["m0"]}, {"QID": "m0"}, {"QID": "m0", "PAKE": 5},
        {"QID": "m0", "PAKE": "!!!not-base64"}, {"QID": "m2", "PAKE": "AAAA"},
        '{"QID": "m0", "PAKE": "AAAA"}', '{"QID": "m2", "PAKE": "AAAA"}', "A" * 100_000]


@pytest.mark.parametrize("msg", JUNK)
def test_a_message_of_any_shape_never_raises(msg):
    hm.Host(call=fake_agent, notify=lambda pin: None).handle(msg)


@pytest.mark.parametrize("cmd", sorted(set(ah.CMD.values())))
@pytest.mark.parametrize("field", ["msg", "payload", "url", "tabId", "frameId", "capabilities"])
def test_any_field_of_any_command_never_raises(cmd, field):
    for value in JUNK:
        hm.Host(call=fake_agent, notify=lambda pin: None).handle({"cmd": cmd, field: value})


@pytest.mark.parametrize("query", [None, 1, "x", [], [1], {}, {"URL": None}, {"URL": 5},
                                   {"URL": ["a"]}, {"URL": "example.com", "USR": ["x"]},
                                   {"URL": "\x00" * 50}, ValueError("bad"), ah.ProtocolError("bad")])
@pytest.mark.parametrize("cmd", [ah.CMD["GET_LOGINS"], ah.CMD["GET_PASSWORD"]])
def test_hostile_decrypted_queries_never_raise(query, cmd):
    host_with(query).handle({"cmd": cmd, "payload": json.dumps({"SMSG": "x"})})


def test_the_list_never_contains_a_password():
    replies = host_with({"URL": "example.com"}).handle(
        {"cmd": ah.CMD["GET_LOGINS"], "payload": json.dumps({"SMSG": "x"})})
    assert SECRET not in json.dumps(replies)
    assert replies[0]["payload"]["SMSG"]["Entries"][0]["PWD"] == "Not Included"


def test_a_password_needs_a_session_and_the_exact_username():
    msg = {"cmd": ah.CMD["GET_PASSWORD"], "payload": json.dumps({"SMSG": "x"})}
    unpaired = hm.Host(call=fake_agent, notify=lambda pin: None)
    assert SECRET not in json.dumps(unpaired.handle(msg))                    # no session
    other_user = host_with({"URL": "example.com", "USR": "someone-else"}).handle(msg)
    assert SECRET not in json.dumps(other_user)
    right = host_with({"URL": "example.com", "USR": "me"}).handle(msg)
    assert SECRET in json.dumps(right)


def test_a_page_for_another_site_is_offered_nothing():
    """Matching happens in the agent; the host must pass the page through untouched."""
    seen = []

    def agent(req):
        seen.append(req)
        return {"ok": True, "credentials": []}
    h = hm.Host(call=agent, notify=lambda pin: None)
    h.session = ReadySession({"URL": "https://evil.com\\@example.com/"})
    replies = h.handle({"cmd": ah.CMD["GET_LOGINS"], "payload": json.dumps({"SMSG": "x"})})
    assert seen[0]["domain"] == "https://evil.com\\@example.com/"           # not pre-trusted
    assert replies[0]["payload"]["SMSG"]["STATUS"] == hm.STATUS_NONE


def frames(*items):
    out = b""
    for it in items:
        raw = it if isinstance(it, bytes) else json.dumps(it).encode()
        out += struct.pack("<I", len(raw)) + raw
    return out


def run_main(monkeypatch, data):
    stdout = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(data)})())
    monkeypatch.setattr(sys, "stdout", type("S", (), {"buffer": stdout})())
    code = hm.main()
    return code, stdout.getvalue()


def test_main_survives_garbage_and_keeps_serving(monkeypatch):
    data = frames(b"not json", b"[1,2,3]", b"null", b"\xff\xfe", {"cmd": ah.CMD["HELLO"]})
    code, out = run_main(monkeypatch, data)
    assert code == 0
    (n,) = struct.unpack("<I", out[:4])
    assert json.loads(out[4:4 + n])["cmd"] == ah.CMD["HELLO"]               # the valid one answered


def test_main_refuses_an_oversized_frame(monkeypatch):
    code, out = run_main(monkeypatch, struct.pack("<I", hm.MAX_FRAME + 1) + b"x")
    assert code == 1 and out == b""


def test_main_stops_cleanly_on_a_truncated_frame(monkeypatch):
    code, out = run_main(monkeypatch, struct.pack("<I", 50) + b"short")
    assert code == 0 and out == b""


def test_the_pin_is_not_put_on_a_command_line_when_dbus_works(monkeypatch):
    sent = []
    monkeypatch.setattr(hm, "_notify_dbus", lambda title, body: sent.append(body) or True)
    monkeypatch.setattr(hm.subprocess, "run",
                        lambda *a, **k: pytest.fail("PIN passed to a subprocess's arguments"))
    hm.show_pin("123456")
    assert sent == ["123456"]


def test_notify_send_is_only_the_fallback(monkeypatch):
    calls = []
    monkeypatch.setattr(hm, "_notify_dbus", lambda title, body: False)
    monkeypatch.setattr(hm.shutil, "which", lambda name: "/usr/bin/notify-send")
    monkeypatch.setattr(hm.subprocess, "run", lambda argv, **k: calls.append(argv))
    hm.show_pin("654321")
    assert calls and calls[0][-1] == "654321"
