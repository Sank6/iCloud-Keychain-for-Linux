"""Anisette configuration (loopback default) and the doctor's exposure check."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from icp import config, doctor
from icp.auth.anisette import Anisette, AnisetteError

TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"


def proc(tmp, v4=(), v6=()):
    row = "   0: {a}:{p} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000  1000"
    Path(tmp, "tcp").write_text(TCP_HEADER + "\n".join(row.format(a=a, p=p, st=st) for a, p, st in v4))
    Path(tmp, "tcp6").write_text(TCP_HEADER + "\n".join(row.format(a=a, p=p, st=st) for a, p, st in v6))
    return tmp


class ConfigTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        p = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("ICP_ANISETTE_URL", None)

    def test_there_is_no_default_server(self):
        self.assertIsNone(config.anisette_url())
        with self.assertRaisesRegex(AnisetteError, "no anisette server URL configured"):
            Anisette()

    def test_precedence_explicit_env_file_default(self):
        (Path(self.dir) / "icp").mkdir(exist_ok=True)
        (Path(self.dir) / "icp" / "config.toml").write_text('anisette_url = "http://127.0.0.1:7000/"\n')
        self.assertEqual(config.anisette_url(), "http://127.0.0.1:7000")
        with mock.patch.dict(os.environ, {"ICP_ANISETTE_URL": "http://127.0.0.1:7001"}):
            self.assertEqual(config.anisette_url(), "http://127.0.0.1:7001")
            self.assertEqual(config.anisette_url("http://127.0.0.1:7002"), "http://127.0.0.1:7002")
        self.assertEqual(Anisette().url, "http://127.0.0.1:7000")

    def test_bad_config_file_is_ignored(self):
        (Path(self.dir) / "icp").mkdir(exist_ok=True)
        (Path(self.dir) / "icp" / "config.toml").write_text("anisette_url = [broken")
        self.assertIsNone(config.anisette_url())

    def test_is_loopback(self):
        for u in ("http://localhost:6969", "http://127.0.0.2:1", "http://[::1]:6969", "127.0.0.1:6969"):
            self.assertTrue(config.is_loopback(u), u)
        for u in ("http://192.168.1.5:6969", "http://anisette.example.com", "http://0.0.0.0:6969"):
            self.assertFalse(config.is_loopback(u), u)


class ExposureTests(unittest.TestCase):
    def test_wildcard_listener_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            proc(d, v4=[("00000000", "1B39", "0A")])      # 0.0.0.0:6969 LISTEN
            self.assertEqual(doctor.listening_exposed(6969, d), ["0.0.0.0"])

    def test_loopback_only_is_fine(self):
        with tempfile.TemporaryDirectory() as d:
            proc(d, v4=[("0100007F", "1B39", "0A")],
                 v6=[("00000000000000000000000001000000", "1B39", "0A")])   # ::1
            self.assertEqual(doctor.listening_exposed(6969, d), [])

    def test_other_ports_and_non_listening_states_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            proc(d, v4=[("00000000", "0050", "0A"), ("00000000", "1B39", "01")])
            self.assertEqual(doctor.listening_exposed(6969, d), [])

    def test_ipv6_wildcard_and_lan_address(self):
        with tempfile.TemporaryDirectory() as d:
            proc(d, v4=[("0501A8C0", "1B39", "0A")], v6=[("0" * 32, "1B39", "0A")])
            self.assertEqual(doctor.listening_exposed(6969, d), ["192.168.1.5", "::"])

    def test_doctor_warns_when_exposed_and_ok_when_not(self):
        resp = mock.Mock(ok=True, status_code=200)
        with mock.patch("requests.get", return_value=resp), \
                mock.patch.object(doctor, "listening_exposed", return_value=["0.0.0.0"]):
            sev, msg, hint = doctor.check_anisette("http://127.0.0.1:6969")
        self.assertEqual(sev, doctor.WARN)
        self.assertIn("0.0.0.0", msg)
        with mock.patch("requests.get", return_value=resp), \
                mock.patch.object(doctor, "listening_exposed", return_value=[]):
            self.assertEqual(doctor.check_anisette("http://127.0.0.1:6969")[0], doctor.OK)

    def test_run_command_binds_loopback(self):
        cmd = doctor.anisette_run_command("docker")
        self.assertIn("127.0.0.1:6969:6969", cmd)


if __name__ == "__main__":
    unittest.main()
