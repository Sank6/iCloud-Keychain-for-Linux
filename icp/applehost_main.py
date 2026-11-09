"""Native-messaging host for Apple's official "iCloud Passwords" extension.

Speaks the extension's protocol (see icp/applehost.py and docs/apple-extension-protocol.md) and
answers lookups from the local agent. Read-only: save/update requests are ignored.

Pairing: when the extension asks to pair, a fresh random 6-digit PIN is shown in a desktop
notification (never logged, never written to disk). Wrong PINs are rate-limited."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time

from . import applehost as ah
from .applehost import CMD, STATUS_NONE, STATUS_OK

LOCKOUT_AFTER = 3          # wrong PINs
LOCKOUT_SECONDS = 600
CAPABILITIES = {
    "shouldUseBase64": False,
    "secretSessionVersion": 0,
    "canFillOneTimeCodes": False,       # TOTP over this protocol is UNVERIFIED; not offered
    "operatingSystem": {"name": "Linux"},
    "supportsSubURLs": False,
    "scanForOTPURI": False,
    "canSaveAccountWithEmptyUserName": False,
    "canOpenPasswordsAppToNewPasswordSheet": False,
}


def agent_socket() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/icp-{os.getuid()}"
    return os.path.join(base, "icp", "agent.sock")


def agent_call(req: dict) -> dict:
    """One request to the running agent (same framing as the browser). Starts it if needed."""
    for attempt in (0, 1):
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(30)  # an unlock may show the keyring prompt
                s.connect(agent_socket())
                raw = json.dumps(req).encode()
                s.sendall(struct.pack("<I", len(raw)) + raw)
                head = s.recv(4, socket.MSG_WAITALL)
                (n,) = struct.unpack("<I", head)
                return json.loads(s.recv(n, socket.MSG_WAITALL))
        except OSError:
            if attempt:
                return {"ok": False, "error": "agent unreachable"}
            _start_agent()
    return {"ok": False, "error": "agent unreachable"}


def _start_agent() -> None:
    from . import hosts
    cmd_file = hosts.DATA / "icp" / "agent-cmd"
    try:
        cmd = cmd_file.read_text().split()
    except OSError:
        return
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(50):
        if os.path.exists(agent_socket()):
            return
        time.sleep(0.1)


def show_pin(pin: str) -> None:
    exe = shutil.which("notify-send")
    if exe:
        subprocess.run([exe, "-a", "iCloud Passwords", "-i", "dialog-password", "-u", "critical",
                        "Pairing code for the iCloud Passwords extension", pin],
                       timeout=5, check=False)


class Host:
    def __init__(self, call=agent_call, notify=show_pin, new_pin=None):
        self.call, self.notify = call, notify
        self.new_pin = new_pin or (lambda: "%06d" % secrets.randbelow(10**6))
        self.session: ah.Session | None = None
        self.failures: list[float] = []

    # -- helpers ----------------------------------------------------------------------------
    def _locked_out(self) -> bool:
        now = time.monotonic()
        self.failures = [t for t in self.failures if now - t < LOCKOUT_SECONDS]
        return len(self.failures) >= LOCKOUT_AFTER

    def _query(self, req: dict) -> dict | None:
        r = self.call(req)
        if r.get("locked"):
            self.call({"cmd": "unlock"})
            r = self.call(req)
        return r if r.get("ok") else None

    @staticmethod
    def _entry(c: dict, url: str, with_password: bool) -> dict:
        e = {"USR": c.get("username", ""), "sites": [url], "highLevelDomain": url,
             "PWD": c.get("password", "") if with_password else "Not Included"}
        if c.get("title"):
            e["customTitle"] = c["title"]
        return e

    def _reply(self, base: dict, body: dict) -> dict:
        return {**base, "payload": {"SMSG": self.session.seal_smsg(body)}}

    # -- dispatch ---------------------------------------------------------------------------
    def handle(self, msg: dict) -> list[dict]:
        cmd = msg.get("cmd")
        if cmd == CMD["HELLO"]:
            self.session = None
            return [{"cmd": CMD["HELLO"], "capabilities": CAPABILITIES}]
        if cmd == CMD["CHALLENGE_PIN"]:
            return self._pairing(msg)
        if cmd == CMD["CANCEL_PIN"]:
            self.session = None
            return []
        if cmd == CMD["SET_ICON"]:
            return [{"cmd": CMD["SET_ICON"], "tabId": msg.get("tabId"),
                     "frameId": msg.get("frameId"), "payload": "UnknownPage"}]
        if cmd in (CMD["GET_LOGINS"], CMD["GET_PASSWORD"]):
            return self._lookup(msg)
        return []   # tab events, save/update, TOTP, open-URL: not supported (read-only)

    def _pairing(self, msg: dict) -> list[dict]:
        try:
            m = json.loads(msg["msg"])
            if m.get("QID") == "m0":
                if self._locked_out():
                    return [{"cmd": CMD["DISABLED"]}]
                pin = self.new_pin()
                self.session = ah.Session(pin)
                reply = self.session.msg1(ah._unb64(m["PAKE"]))
                self.notify(pin)
                return [{"cmd": CMD["CHALLENGE_PIN"], "payload": {"QID": "m0", "PAKE": reply}}]
            if m.get("QID") == "m2" and self.session:
                out = self.session.msg3(ah._unb64(m["PAKE"]))
                if not self.session.ready:
                    self.failures.append(time.monotonic())
                    self.session = None
                return [{"cmd": CMD["CHALLENGE_PIN"], "payload": {"QID": "m2", "PAKE": out}}]
        except (ah.ProtocolError, KeyError, ValueError):
            self.session = None
        return []

    def _lookup(self, msg: dict) -> list[dict]:
        s = self.session
        base = {"cmd": msg["cmd"], "tabId": msg.get("tabId"), "frameId": msg.get("frameId")}
        if msg["cmd"] == CMD["GET_PASSWORD"]:
            base["url"] = msg.get("url")
        if not s or not s.ready:
            return [{"cmd": CMD["RELOGIN"]}]
        try:
            q = s.open_smsg(json.loads(msg["payload"])["SMSG"])
        except (ah.ProtocolError, KeyError, ValueError):
            return [{"cmd": CMD["RELOGIN"]}]
        url = str(q.get("URL", ""))
        r = self._query({"cmd": "match", "domain": url})
        if r is None:
            return [self._reply(base, {"STATUS": 1})]
        creds = r.get("credentials", [])
        if msg["cmd"] == CMD["GET_PASSWORD"]:
            creds = [c for c in creds if c.get("username") == q.get("USR")]
            if creds:   # remember the choice, as our own extension does
                self.call({"cmd": "chose", "domain": creds[0].get("domain", url),
                           "username": creds[0].get("username", "")})
        if not creds:
            return [self._reply(base, {"STATUS": STATUS_NONE})]
        entries = [self._entry(c, url, msg["cmd"] == CMD["GET_PASSWORD"]) for c in creds]
        return [self._reply(base, {"STATUS": STATUS_OK, "Entries": entries,
                                   "RequiresUserAuthenticationToFill": False})]


def main() -> int:
    host = Host()
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    while True:
        head = stdin.read(4)
        if len(head) < 4:
            return 0
        (n,) = struct.unpack("<I", head)
        if n > 1 << 20:
            return 1
        for out in host.handle(json.loads(stdin.read(n))):
            raw = json.dumps(out).encode()
            stdout.write(struct.pack("<I", len(raw)) + raw)
            stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
