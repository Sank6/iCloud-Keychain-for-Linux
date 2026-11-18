"""Everything the installer writes is private to the user: another local user (or a group member)
must not be able to replace a launcher the browser executes or read a command file."""

import os
import stat

import pytest

from icp import applehost_install as ah
from icp import hosts, paths


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def home(tmp_path, monkeypatch):
    old = os.umask(0o002)                       # the common Ubuntu default: group-writable files
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(hosts, "DATA", tmp_path / "data")
    root = tmp_path / "config/net.imput.helium"
    monkeypatch.setattr(hosts, "CFG", tmp_path / "config")
    monkeypatch.setattr(hosts, "CHROMIUM", [("Helium", root, root / "NativeMessagingHosts")])
    monkeypatch.setattr(hosts, "FIREFOX", [])
    monkeypatch.setattr(ah, "BACKUPS", tmp_path / "data/icp/apple-extension-orig")
    root.mkdir(parents=True)
    yield tmp_path
    os.umask(old)


def test_the_data_folder_and_every_command_file_are_owner_only(home):
    launcher = hosts.write_launcher()
    data = home / "data/icp"
    assert mode(data) == 0o700
    for name in ("agent-cmd", "sync-cmd", "login-cmd", "gui-cmd"):
        assert mode(data / name) == 0o600, name
    assert mode(launcher) == 0o700


def test_the_apple_host_launcher_is_owner_only(home):
    ah.install()
    assert mode(home / "data/icp") == 0o700
    assert mode(home / "data/icp/apple-host") == 0o700


def test_a_widely_open_folder_from_an_older_install_is_tightened(home):
    d = home / "data/icp"
    d.mkdir(parents=True)
    os.chmod(d, 0o775)
    (d / "agent-cmd").write_text("python -m evil\n")
    os.chmod(d / "agent-cmd", 0o666)
    hosts.write_launcher()
    assert mode(d) == 0o700 and mode(d / "agent-cmd") == 0o600


def test_installed_binaries_are_owner_only(home, tmp_path):
    built = tmp_path / "built"
    built.write_bytes(b"#!/bin/sh\n")
    built.chmod(0o755)
    hosts._install_binary(built, home / "data/icp/icp-agent")
    assert mode(home / "data/icp/icp-agent") == 0o700 and mode(home / "data/icp") == 0o700


def test_the_sync_lock_is_owner_only(home):
    lock = paths.open_sync_lock()
    try:
        assert mode(paths.sync_lock_file()) == 0o600
    finally:
        lock.close()


def test_the_config_folder_is_owner_only(home):
    assert mode(paths.config_dir()) == 0o700


def test_write_private_replaces_atomically_and_never_widens(home):
    target = home / "f"
    paths.write_private(target, "one")
    paths.write_private(target, "two")
    assert target.read_text() == "two" and mode(target) == 0o600
    assert not list(home.glob("f.tmp"))
