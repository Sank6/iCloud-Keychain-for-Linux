from types import SimpleNamespace

from icp import paths
from icp.cli import app


def test_logout_removes_session_and_local_caches(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    for path_fn in (
        paths.session_file,
        paths.vault_file,
        paths.aliases_file,
        paths.sync_lock_file,
        paths.sync_attempt_file,
        paths.device_file,
        paths.fallback_key_file,
    ):
        path_fn().write_bytes(b"test")

    messages = []
    monkeypatch.setattr(app.ui, "out", messages.append)

    assert app.cmd_logout(SimpleNamespace(wipe_device=False)) == 0

    assert not paths.session_file().exists()
    assert not paths.vault_file().exists()
    assert not paths.aliases_file().exists()
    assert not paths.sync_lock_file().exists()
    assert not paths.sync_attempt_file().exists()

    # Device registration and the legacy import key are not caches and remain.
    assert paths.device_file().exists()
    assert paths.fallback_key_file().exists()
    assert any("local password caches removed" in message for message in messages)


def test_logout_wipe_device_removes_device_identity(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    paths.device_file().write_bytes(b"device")

    monkeypatch.setattr(app.ui, "out", lambda _message: None)

    assert app.cmd_logout(SimpleNamespace(wipe_device=True)) == 0
    assert not paths.device_file().exists()
