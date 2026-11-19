"""Agent request handling: lock gate, unlock, idle lock (no sockets, no keyring)."""
import asyncio
import unittest
from unittest import mock

from icp import agent
from icp.vault.host import Credential, CredentialStore


def run(coro):
    return asyncio.run(coro)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.a = agent.Agent()
        self.store = CredentialStore([Credential(domain="example.com", username="u", password="pw")])
        # never look at the real vault file from a test
        p = mock.patch.object(agent.Agent, "_fresh", lambda self: None)
        p.start()
        self.addCleanup(p.stop)

    def _loaded(self):
        def load():
            self.a.store, self.a.aliases = self.store, []
        return mock.patch.object(agent.Agent, "load", side_effect=lambda: load())

    def test_locked_by_default_and_gates_secrets(self):
        self.assertTrue(self.a.locked)
        for cmd in ("match", "search", "totp"):
            r = run(self.a.handle({"cmd": cmd, "domain": "example.com", "query": "ex"}))
            self.assertEqual((r["ok"], r["locked"]), (False, True), cmd)
        self.assertEqual(run(self.a.handle({"cmd": "ping"}))["count"], 0)

    def test_unlock_then_match_then_lock(self):
        with self._loaded():
            self.assertEqual(run(self.a.handle({"cmd": "unlock"})), {"ok": True, "locked": False})
        r = run(self.a.handle({"cmd": "match", "domain": "example.com"}))
        self.assertTrue(r["ok"])
        self.assertEqual(r["credentials"][0]["password"], "pw")
        self.assertEqual(run(self.a.handle({"cmd": "lock"}))["locked"], True)
        self.assertIsNone(self.a.store)

    def test_unlock_failure_stays_locked(self):
        with mock.patch.object(agent.Agent, "load", side_effect=RuntimeError("dismissed")):
            r = run(self.a.handle({"cmd": "unlock"}))
        self.assertEqual((r["ok"], r["locked"]), (False, True))


if __name__ == "__main__":
    unittest.main()
