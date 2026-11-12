"""icp.net: retries, Retry-After, no retry on auth errors, circuit breaker, redacted logging."""
import os
import tempfile
import unittest
from unittest import mock

import requests

from icp import net, ratelimit


class FakeResp:
    def __init__(self, status=200, headers=None, content=b"x"):
        self.status_code, self.headers, self.content = status, headers or {}, content
        self.url = "https://gsa.apple.com/x"


class NetTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for p in (mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp.name}),
                  mock.patch.object(net, "MIN_GAP", 0), mock.patch.object(net, "_last", {})):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(net.set_background, False)
        self.sleeps = []

    def call(self, responses, **kw):
        seq = iter(responses)

        def fake(url, **k):
            r = next(seq)
            if isinstance(r, Exception):
                raise r
            return r
        with mock.patch.object(requests, "post", side_effect=fake) as m:
            try:
                return m, net.request("post", "https://gsa.apple.com/p?secret=1",
                                      sleep=self.sleeps.append, **kw)
            except net.AppleNetError as e:
                return m, e

    def test_retries_5xx_then_succeeds_with_growing_delays(self):
        m, r = self.call([FakeResp(503), FakeResp(502), FakeResp(200)], retries=2)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(m.call_count, 3)
        self.assertEqual(len(self.sleeps), 2)
        self.assertLess(self.sleeps[0], self.sleeps[1] + 1)   # exponential (+ jitter)
        self.assertGreaterEqual(self.sleeps[1], 2.0)

    def test_403_and_401_are_never_retried(self):
        for status, kind in ((403, "blocked"), (401, "auth")):
            m, r = self.call([FakeResp(status), FakeResp(200)], retries=3)
            self.assertEqual((r.status_code, m.call_count), (status, 1))
            self.assertEqual(net.auth_error(r, "x").kind, kind)
        self.assertEqual(self.sleeps, [])

    def test_retry_after_is_honoured_or_raised_when_long(self):
        _, r = self.call([FakeResp(429, {"Retry-After": "7"}), FakeResp(200)], retries=1)
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(self.sleeps[0], 7)
        _, e = self.call([FakeResp(429, {"Retry-After": "3600"}), FakeResp(200)], retries=3)
        self.assertIsInstance(e, net.Throttled)
        self.assertEqual(e.retry_after, 3600)

    def test_exhausted_5xx_raises_server_error(self):
        _, e = self.call([FakeResp(500), FakeResp(500)], retries=1)
        self.assertIsInstance(e, net.ServerError)

    def test_network_failure_is_typed_and_redacted(self):
        m, e = self.call([requests.ConnectionError("https://gsa.apple.com/p?secret=1 refused")],
                         retries=0)
        self.assertIsInstance(e, net.NetworkDown)
        self.assertNotIn("secret", str(e))

    def test_circuit_opens_for_unattended_calls_only(self):
        net.set_background(True)
        for _ in range(ratelimit.CIRCUIT_AFTER):
            self.call([FakeResp(403)])
        m, e = self.call([FakeResp(200)])
        self.assertIsInstance(e, net.CircuitOpen)
        self.assertEqual(m.call_count, 0)              # no request left the machine
        self.assertIn("gsa.apple.com", ratelimit.circuit_status())
        net.set_background(False)                      # an interactive run goes through...
        _, r = self.call([FakeResp(200)])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ratelimit.circuit_status(), "")   # ...and closes the breaker

    def test_circuit_pause_doubles_when_it_retrips(self):
        now = 1000.0
        for _ in range(ratelimit.CIRCUIT_AFTER):
            ratelimit.circuit_record("h", False, "HTTP 403", now=now)
        first = ratelimit.circuit_remaining("h", now=now)
        for _ in range(ratelimit.CIRCUIT_AFTER):
            ratelimit.circuit_record("h", False, "HTTP 403", now=now)
        self.assertEqual(first, ratelimit.CIRCUIT_BASE)
        self.assertEqual(ratelimit.circuit_remaining("h", now=now), 2 * ratelimit.CIRCUIT_BASE)

    def test_safe_url_drops_query_and_credentials(self):
        self.assertEqual(net.safe_url("https://u:p@h.apple.com/a/b?token=1#f"), "h.apple.com/a/b")


class BackoffTests(unittest.TestCase):
    def test_backoff_shapes(self):
        self.assertEqual([ratelimit.backoff(i, 5, 100) for i in range(6)], [5, 10, 20, 40, 80, 100])
        self.assertEqual(ratelimit.backoff(0, 5, 100, retry_after=60), 60)
        self.assertEqual(ratelimit.backoff(0, 5, 100, retry_after=9999), 100)
        self.assertTrue(10 <= ratelimit.backoff(1, 5, 100, jitter=0.5) <= 15)


class StateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)

    def test_transient_failure_delays_without_counting(self):
        st = {}
        for _ in range(10):
            ratelimit.record_failure(st, "cannot reach gsa.apple.com", transient=True, now=0)
        self.assertEqual(st.get("failures", 0), 0)
        self.assertFalse(st.get("needs_login"))
        self.assertEqual(st["next_allowed"], ratelimit.BACKOFF_BASE)

    def test_save_keeps_a_breaker_tripped_meanwhile(self):
        st = ratelimit.load()
        for _ in range(ratelimit.CIRCUIT_AFTER):
            ratelimit.circuit_record("h", False, "HTTP 500")
        ratelimit.save(st)    # `st` was loaded before the breaker tripped
        self.assertGreater(ratelimit.circuit_remaining("h"), 0)

    def test_published_status_file_has_no_secrets_or_circuit(self):
        from icp import status
        ratelimit.circuit_record("h", False, "x")
        ratelimit.record_failure({}, "boom", auth=True)
        shown = status.read()
        self.assertEqual(set(shown), set(ratelimit._PUBLISHED))
        self.assertTrue(shown["needs_login"])


if __name__ == "__main__":
    unittest.main()
