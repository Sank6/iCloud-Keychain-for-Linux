"""`icp uninstall` removes what setup installed, nothing else, and never the user's data
unless asked."""

import argparse
import json

import pytest

from icp import applehost_install as ah
from icp import hosts, paths, setup, uninstall

STOCK = 'x();function checkForValidOS(){if(1)return 1}y();'


@pytest.fixture
def machine(tmp_path, monkeypatch):
    cfg, data = tmp_path / "config", tmp_path / "data"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg))
    monkeypatch.setattr(hosts, "CFG", cfg)
    monkeypatch.setattr(hosts, "DATA", data)
    root = cfg / "net.imput.helium"
    monkeypatch.setattr(hosts, "CHROMIUM", [("Helium", root, root / "NativeMessagingHosts")])
    monkeypatch.setattr(hosts, "FIREFOX", [])
    monkeypatch.setattr(ah, "BACKUPS", data / "icp/apple-extension-orig")
    monkeypatch.setattr(ah, "UNPACKED", data / "icp/apple-extension")
    monkeypatch.setattr(setup, "UNIT_DIR", cfg / "systemd/user")
    monkeypatch.setattr(uninstall.shutil, "which", lambda name: None)     # never run systemctl
    monkeypatch.setattr(setup.shutil, "which", lambda name: None)

    root.mkdir(parents=True)                       # the browser has been run once
    hosts.write_launcher()
    hosts.install()
    ah.install()
    setup.install_desktop_entry()
    ext = root / "Default/Extensions" / ah.APPLE_EXTENSION_ID / "3.4.0_0"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({"version": "3.4.0"}))
    (ext / "background.js").write_text(STOCK)
    ah.patch_in_place()
    (setup.UNIT_DIR).mkdir(parents=True)
    for name in uninstall.UNITS:
        (setup.UNIT_DIR / name).write_text("[Unit]\n")
    # the user's own data
    paths.config_dir()
    for name in ("vault.enc", "session.enc", "device.json"):
        (cfg / "icp" / name).write_text("precious")
    return {"cfg": cfg, "data": data, "root": root, "ext": ext}


def args(**kw):
    return argparse.Namespace(**{"yes": True, "dry_run": False, "purge": False, **kw})


def test_uninstall_removes_everything_setup_installed(machine):
    assert uninstall.run(args()) == 0
    m = machine
    assert not (m["data"] / "icp").exists()
    assert not list((m["root"] / "NativeMessagingHosts").glob("*.json"))
    assert uninstall.host_manifests() == []
    assert not any(f.exists() for f in uninstall.desktop_files())
    assert not any((setup.UNIT_DIR / u).exists() for u in uninstall.UNITS)
    assert (m["ext"] / "background.js").read_text() == STOCK          # Apple's original is back


def test_uninstall_keeps_the_users_vault_login_and_device(machine):
    uninstall.run(args())
    for name in ("vault.enc", "session.enc", "device.json"):
        assert (machine["cfg"] / "icp" / name).read_text() == "precious"


def test_a_host_manifest_that_is_not_ours_is_left_alone(machine):
    foreign = machine["root"] / "NativeMessagingHosts/org.other.json"
    foreign.write_text(json.dumps({"name": "org.other", "path": "/usr/bin/other"}))
    lookalike = machine["root"] / "NativeMessagingHosts/org.icp.native.json"
    lookalike.write_text(json.dumps({"name": "org.icp.native", "path": "/opt/someone-elses-host"}))
    uninstall.run(args())
    assert foreign.exists() and lookalike.exists()
    assert not (machine["root"] / "NativeMessagingHosts/com.apple.passwordmanager.json").exists()


def test_dry_run_changes_nothing(machine, capsys):
    before = sorted(str(p) for p in machine["data"].rglob("*"))
    assert uninstall.run(args(dry_run=True)) == 0
    assert sorted(str(p) for p in machine["data"].rglob("*")) == before
    assert "This will:" in capsys.readouterr().out
    assert ah.PATCH in (machine["ext"] / "background.js").read_text()      # still patched


def test_declining_the_prompt_changes_nothing(machine, monkeypatch):
    monkeypatch.setattr(uninstall.ui, "confirm_yn", lambda msg: False)
    assert uninstall.run(args(yes=False)) == 1
    assert (machine["data"] / "icp").exists()


def test_purge_deletes_the_data_after_the_integration(machine, monkeypatch):
    calls = []
    from icp import mirror
    from icp.auth import session
    monkeypatch.setattr(mirror, "remove_all", lambda **k: calls.append("mirror"))
    monkeypatch.setattr(session, "clear", lambda: calls.append("clear"))
    monkeypatch.setattr(session, "reset_keys", lambda: calls.append("keys") or [])
    uninstall.run(args(purge=True))
    assert calls == ["mirror", "clear", "keys"] and not (machine["cfg"] / "icp").exists()


def test_a_second_run_has_nothing_to_do(machine, capsys):
    uninstall.run(args())
    capsys.readouterr()
    assert uninstall.run(args()) == 0
    assert "Nothing to remove" in capsys.readouterr().out


def test_the_units_are_sandboxed_and_the_patcher_has_no_network():
    units = setup._units(), setup._extension_units()
    sync = units[0]["icp-sync.service"]
    patcher = units[1]["icp-apple-extension.service"]
    for text in (sync, patcher):
        assert "NoNewPrivileges=yes" in text and "RestrictAddressFamilies=" in text
    assert "AF_INET" in sync
    assert "AF_UNIX\n" in patcher and "AF_INET" not in patcher
