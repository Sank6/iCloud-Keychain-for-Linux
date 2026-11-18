"""Corrupt, truncated, hand-edited or hostile state files must never crash the app or the
background timer: they read as "nothing saved" (except device.json, which must not silently
create a new Apple device)."""

import os

import pytest

from icp import choices, config, mirror, paths, ratelimit, status
from icp.auth import anisette_v3
from icp.auth.device import Device, DeviceError

GARBAGE = {
    "empty": b"", "null": b"null", "list": b"[1,2]", "string": b'"x"', "number": b"7",
    "truncated": b'{"a": ', "binary": bytes(range(256)), "bad-utf8": b"\xff\xfe\x00",
    "wrong-types": b'{"identifier": [1], "adi_pb": 5, "server": {}, "fingerprint": 3, "failures": "x"}',
    "deep": b"[" * 200_000, "deep-object": b'{"a":' * 50_000,
}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return paths.config_dir()


def put(cfg, name, blob):
    (cfg / name).write_bytes(blob)


@pytest.mark.parametrize("kind", GARBAGE)
def test_state_loaders_survive_any_garbage(cfg, kind):
    blob = GARBAGE[kind]
    for name in ("state.json", "sync-status.json", "choices.json", "mirror.json",
                 "anisette-v3.json", "config.toml"):
        put(cfg, name, blob)
    assert isinstance(ratelimit.load(), dict)
    assert isinstance(status.read(), dict)
    assert choices.preferred_first("example.com", []) == []
    assert isinstance(mirror._last_fingerprint(), str)
    assert isinstance(config.load(), dict)
    assert config.anisette_url() in (None, "")
    state = anisette_v3._State.load("https://x.example")
    assert len(state.identifier) == 16 and state.adi_pb is None


@pytest.mark.parametrize("kind", GARBAGE)
def test_a_damaged_device_file_is_an_explained_error_not_a_new_device(cfg, kind):
    put(cfg, "device.json", GARBAGE[kind])
    before = (cfg / "device.json").read_bytes()
    with pytest.raises(DeviceError, match="damaged"):
        Device.load_or_create()
    assert (cfg / "device.json").read_bytes() == before            # never overwritten


def test_a_good_device_file_still_loads_and_a_missing_one_is_created(cfg):
    dev = Device.load_or_create()
    again = Device.load_or_create()
    assert dev.device_id == again.device_id and oct(os.stat(cfg / "device.json").st_mode & 0o777) == "0o600"


def test_valid_anisette_state_round_trips(cfg):
    a = anisette_v3._State.load("https://x.example")
    a.adi_pb, a.claim = b"blob", "<c>"
    a.save()
    b = anisette_v3._State.load("https://x.example")
    assert (b.identifier, b.adi_pb, b.claim) == (a.identifier, b"blob", "<c>")
    assert anisette_v3._State.load("https://other.example").adi_pb is None       # other server


def test_typed_errors_print_a_message_not_a_traceback(cfg, capsys):
    from icp.cli import app
    put(cfg, "device.json", b"null")
    code = app.main(["login", "--no-save-password"])
    err = capsys.readouterr().err
    assert code == 1 and "damaged" in err and "Traceback" not in err
