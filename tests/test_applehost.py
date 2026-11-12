"""Pairing + channel tests for icp.applehost against Apple's own extension code.

The extension (SecretSession/sjcl from background.js) is run under node as the *client*. The test
is skipped if node or the installed extension is not available; it never modifies either."""

import glob
import json
import os
import subprocess
import unittest
from pathlib import Path

from icp import applehost

HARNESS = Path(__file__).parent / "ext" / "apple_client.js"
EXT_GLOB = os.path.expanduser(
    "~/.config/*/*/Extensions/pejdijmoenmkgeppbflobdenhhabjlaj/*/background.js")


def _ext():
    env = os.environ.get("ICP_APPLE_EXT_JS")
    if env and os.path.exists(env):
        return env
    found = sorted(glob.glob(EXT_GLOB))
    return found[-1] if found else None


HAVE = bool(_ext() and subprocess.run(["which", "node"], capture_output=True).returncode == 0)


class Client:
    def setUp(self):
        self.p = subprocess.Popen(["node", str(HARNESS), _ext()], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)

    def tearDown(self):
        self.p.kill()
        self.p.wait()
        self.p.stdin.close()
        self.p.stdout.close()

    def js(self, **m):
        self.p.stdin.write(json.dumps(m) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def pair(self, host_pin, user_pin):
        host = applehost.Session(host_pin)
        m0 = applehost._unb64(self.js(op="init")["pake"])
        self.assertEqual(m0["MSG"], 0)
        msg1 = host.msg1(m0)
        m2 = self.js(op="pin", pin=user_pin, pake=msg1)
        self.assertNotIn("error", m2, m2)
        msg3 = host.msg3(applehost._unb64(m2["pake"]))
        return host, msg3


@unittest.skipUnless(HAVE, "node or the Apple extension is not installed")
class AgainstRealClient(Client, unittest.TestCase):
    def test_correct_pin_pairs_and_channel_works(self):
        host, msg3 = self.pair("123456", "123456")
        self.assertTrue(host.ready)
        self.assertTrue(self.js(op="msg3", pake=msg3)["ok"])
        smsg = self.js(op="smsg", obj={"ACT": 2, "URL": "example.com"})["smsg"]
        self.assertEqual(host.open_smsg(smsg), {"ACT": 2, "URL": "example.com"})
        reply = host.seal_smsg({"STATUS": 0, "Entries": []})
        self.assertEqual(self.js(op="parse", smsg=reply)["obj"], {"STATUS": 0, "Entries": []})

    def test_wrong_pin_is_rejected(self):
        host, msg3 = self.pair("123456", "654321")
        self.assertFalse(host.ready)
        self.assertIsNone(host.key)
        self.assertIn("error", self.js(op="msg3", pake=msg3))


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAVE, "node or the Apple extension is not installed")
class KeyDerivationStress(Client, unittest.TestCase):
    """Leading-zero bytes in S / odd bit lengths are where hand-rolled SRP usually breaks."""

    def test_many_pairings(self):
        for i in range(int(os.environ.get("ICP_STRESS", "60"))):
            host, msg3 = self.pair("%06d" % (i * 7919 % 10**6), "%06d" % (i * 7919 % 10**6))
            self.assertTrue(host.ready, f"pairing {i} failed")
            smsg = self.js(op="smsg", obj={"i": i})["smsg"]
            self.assertEqual(host.open_smsg(smsg), {"i": i})


@unittest.skipUnless(HAVE, "node or the Apple extension is not installed")
class HostEndToEnd(Client, unittest.TestCase):
    """Whole message flow as the extension sends it, with a fake agent behind the host."""

    def setUp(self):
        super().setUp()
        from icp import applehost_main as hm
        self.calls = []
        self.shown = []

        def agent(req):
            self.calls.append(req)
            if req["cmd"] == "match":
                return {"ok": True, "credentials": [
                    {"domain": req["domain"], "username": "me@example.com",
                     "password": "s3cret-pw", "title": "Example"}]}
            return {"ok": True}
        self.host = hm.Host(call=agent, notify=self.shown.append, new_pin=lambda: "424242")
        self.hm = hm

    def send(self, msg):
        return self.host.handle(msg)

    def pair(self, pin="424242"):
        hello = self.send({"cmd": 14})
        self.assertEqual(hello[0]["cmd"], 14)
        m0 = self.js(op="init", caps=hello[0]["capabilities"])["pake"]
        out = self.send({"cmd": 2, "msg": json.dumps({"QID": "m0", "PAKE": m0, "HSTBRSR": "x"})})
        self.assertEqual(self.shown[-1], "424242")
        m2 = self.js(op="pin", pin=pin, pake=out[0]["payload"]["PAKE"])["pake"]
        out = self.send({"cmd": 2, "msg": json.dumps({"QID": "m2", "PAKE": m2})})
        return self.js(op="msg3", pake=out[0]["payload"]["PAKE"])

    def ask(self, cmd, obj, **extra):
        smsg = self.js(op="smsg", obj=obj)["smsg"]
        out = self.send({"cmd": cmd, "tabId": 7, "frameId": 0, **extra,
                         "payload": json.dumps({"QID": "q", "SMSG": smsg})})
        self.assertEqual((out[0]["tabId"], out[0]["frameId"]), (7, 0))
        return self.js(op="parse", smsg=out[0]["payload"]["SMSG"])["obj"]

    def test_pair_list_and_fill(self):
        self.assertTrue(self.pair()["ok"])
        lst = self.ask(4, {"ACT": 5, "URL": "example.com"}, url="example.com")
        self.assertEqual(lst["STATUS"], 0)
        e = lst["Entries"][0]
        self.assertEqual((e["USR"], e["PWD"], e["sites"]), ("me@example.com", "Not Included",
                                                             ["example.com"]))
        got = self.ask(5, {"ACT": 2, "URL": "example.com", "USR": "me@example.com"},
                       url="example.com")
        self.assertEqual(got["Entries"][0]["PWD"], "s3cret-pw")
        self.assertIn({"cmd": "chose", "domain": "example.com", "username": "me@example.com"},
                      self.calls)

    def test_wrong_pin_then_lockout(self):
        for _ in range(self.hm.LOCKOUT_AFTER):
            self.pair(pin="000000")
        out = self.send({"cmd": 2, "msg": json.dumps({"QID": "m0", "PAKE": self.js(op="init")["pake"]})})
        self.assertEqual(out[0]["cmd"], 9)   # paired-off / disabled while locked out

    def test_lookup_without_pairing_asks_to_pair(self):
        out = self.send({"cmd": 4, "tabId": 1, "frameId": 0, "payload": "{}"})
        self.assertEqual(out[0]["cmd"], 10)

    def test_save_requests_are_ignored(self):
        self.pair()
        self.assertEqual(self.send({"cmd": 6, "payload": "{}"}), [])


class PatcherTests(unittest.TestCase):
    def _fake_ext(self, root, body):
        d = Path(root) / "ext"
        (d / "_metadata").mkdir(parents=True)
        (d / "background.js").write_text(body)
        return d

    def test_patches_exactly_one_gate_and_drops_signature_data(self):
        import tempfile
        from icp import applehost_install as ai
        with tempfile.TemporaryDirectory() as t:
            src = self._fake_ext(t, "a();function checkForValidOS(){return 0}b();")
            out = ai.patch_extension(src, Path(t) / "out")
            js = (out / "background.js").read_text()
            self.assertIn(ai.PATCH, js)
            self.assertFalse((out / "_metadata").exists())
            self.assertEqual((src / "background.js").read_text().count(ai.PATCH), 0)  # source untouched

    def test_refuses_unknown_version(self):
        import tempfile
        from icp import applehost_install as ai
        with tempfile.TemporaryDirectory() as t:
            src = self._fake_ext(t, "nothing here")
            with self.assertRaises(SystemExit):
                ai.patch_extension(src, Path(t) / "out")
            self.assertFalse((Path(t) / "out").exists())
