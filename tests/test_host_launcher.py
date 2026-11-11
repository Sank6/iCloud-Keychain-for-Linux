"""The native-messaging host has to reach the GNOME keyring when the browser spawns it.

A browser starts the host without DBUS_SESSION_BUS_ADDRESS in its environment. The master key
of the vault lives in the keyring, which is reached over the session bus, so without it the
host would fall back to a different key and see an empty vault - no passwords in the popup.
"""

import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LAUNCHER = REPO / "host" / "icp-host.sh"


def _session_bus():
    candidates = [Path(os.environ.get("XDG_RUNTIME_DIR", "")) / "bus",
                  Path(f"/run/user/{os.getuid()}/bus")]
    for path in candidates:
        if str(path.parent) and path.exists():
            return path
    return None


def _keyring_reachable():
    """Is the Secret Service reachable when the bus address is set?"""
    bus = _session_bus()
    if bus is None:
        return False
    code = ("import sys; sys.path.insert(0, %r);"
            "from icp.auth import session;"
            "print('yes' if session._key_from_secret_service() else 'no')" % str(REPO))
    try:
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=60,
                             env={**os.environ, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}"})
    except (OSError, subprocess.TimeoutExpired):
        return False
    return b"yes" in out.stdout


def _ping(env):
    """Send one native-messaging ping to the host and return (reply, stderr)."""
    payload = json.dumps({"cmd": "ping"}).encode()
    try:
        proc = subprocess.run([str(LAUNCHER)], input=struct.pack("<I", len(payload)) + payload,
                              capture_output=True, timeout=60, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None, b""
    if len(proc.stdout) < 4:
        return None, proc.stderr
    (length,) = struct.unpack("<I", proc.stdout[:4])
    return json.loads(proc.stdout[4:4 + length]), proc.stderr


def test_host_launcher_finds_the_keyring_without_a_session_bus(tmp_path):
    if not LAUNCHER.exists():
        pytest.skip("no host launcher in this checkout")
    if not _keyring_reachable():
        pytest.skip("no keyring reachable on this machine")

    # A vault file, so that the host really looks for the master key. Its content
    # is garbage - all this test cares about is which key gets used.
    vault = tmp_path / ".config" / "icp" / "vault.enc"
    vault.parent.mkdir(parents=True, exist_ok=True)
    vault.write_bytes(b"not a vault")

    # What a browser passes: no DBUS_SESSION_BUS_ADDRESS.
    env = {"HOME": str(tmp_path), "PATH": "/usr/local/bin:/usr/bin:/bin", "DISPLAY": ":0"}
    reply, stderr = _ping(env)

    assert reply is not None, stderr.decode()[:400]
    assert reply.get("ok") is True
    assert b"Secret Service unavailable" not in stderr, stderr.decode()[:400]
    # The keyring was reached, so no fallback key file was written.
    assert not (tmp_path / ".config" / "icp" / "master.key").exists()
    # ...and the vault was not thrown away.
    assert vault.exists()
