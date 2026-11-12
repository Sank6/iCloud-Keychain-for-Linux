"""Apple's own extension on Linux: launcher with a Windows user agent, patched copy, status."""

import json

import pytest

from icp import applehost_install as ah
from icp import doctor, hosts

VENDOR = """[Desktop Entry]
Name=Helium
Exec=helium %U
Icon=helium

[Desktop Action new-window]
Name=New Window
Exec=helium

[Desktop Action new-private-window]
Name=New Incognito Window
Exec=helium --incognito
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    data = tmp_path / "data"
    cfg = tmp_path / "config"
    vendor = tmp_path / "usr/applications"
    vendor.mkdir(parents=True)
    (vendor / "helium.desktop").write_text(VENDOR)
    monkeypatch.setattr(hosts, "DATA", data)
    monkeypatch.setattr(hosts, "CFG", cfg)
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path / "usr"))
    monkeypatch.setattr(hosts, "CHROMIUM", [
        ("Helium", cfg / "net.imput.helium", cfg / "net.imput.helium/NativeMessagingHosts")])
    monkeypatch.setattr(hosts, "FIREFOX", [])
    (cfg / "net.imput.helium").mkdir(parents=True)
    return tmp_path


def test_windows_ua_entry_rewrites_every_exec_line(home):
    p = ah.windows_ua_entry("helium.desktop", 150)
    text = p.read_text()
    assert p == home / "data/applications/helium.desktop"
    assert text.count("--user-agent=") == 3
    assert 'Exec=helium --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)' in text
    assert "Chrome/150.0.0.0" in text
    assert "--incognito" in text and "%U" in text            # original arguments survive
    assert text.splitlines()[0] == "[Desktop Entry]" and ah.UA_MARKER in text
    assert ah.windows_ua_active("helium.desktop")
    assert ah.exec_binary("helium.desktop") == "helium"


def test_restore_only_removes_a_file_we_wrote(home):
    assert not ah.restore_entry("helium.desktop")
    ah.windows_ua_entry("helium.desktop")
    assert ah.restore_entry("helium.desktop") and not ah.windows_ua_active("helium.desktop")
    mine = home / "data/applications/helium.desktop"
    mine.parent.mkdir(parents=True, exist_ok=True)
    mine.write_text("[Desktop Entry]\nExec=helium\n")         # the user's own override
    assert not ah.restore_entry("helium.desktop") and mine.exists()


def test_unknown_browser_has_no_entry(home):
    with pytest.raises(FileNotFoundError):
        ah.windows_ua_entry("nope.desktop")


def test_status_reports_hosts_and_mode(home, monkeypatch):
    monkeypatch.setattr(ah, "running_without_windows_ua", lambda b, proc="/proc": False)
    ah.install()
    st = ah.status()
    assert st["hosts"] == [("Helium", True, "")] and st["mode"] is None
    ah.windows_ua_entry("helium.desktop")
    assert ah.status()["mode"] == "useragent" and ah.status()["entries"] == ["helium.desktop"]


def test_status_flags_a_broken_host(home):
    ah.install()
    manifest = home / "config/net.imput.helium/NativeMessagingHosts/com.apple.passwordmanager.json"
    data = json.loads(manifest.read_text())
    data["path"] = str(home / "gone")
    manifest.write_text(json.dumps(data))
    assert ah.status()["hosts"][0][1] is False
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.FAIL and "launcher" in msg and "icp setup" in hint


def test_doctor_warns_until_a_mode_is_chosen(home, monkeypatch):
    monkeypatch.setattr(ah, "running_without_windows_ua", lambda b, proc="/proc": False)
    ah.install()
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.WARN and "useragent" in hint
    ah.windows_ua_entry("helium.desktop")
    assert doctor.check_apple_extension()[0] == doctor.OK


def test_autofill_panel_text():
    from icp.gui.model import autofill_summary
    none = {"hosts": [], "mode": None}
    assert autofill_summary(none)[0] == "No supported browser found"
    broken = {"hosts": [("Helium", False, "launcher is missing")], "mode": None}
    assert "launcher is missing" in autofill_summary(broken)[1]
    todo = {"hosts": [("Helium", True, "")], "mode": None}
    assert "--apple-extension useragent" in autofill_summary(todo)[1]
    ua = {"hosts": [("Helium", True, "")], "mode": "useragent"}
    heading, body = autofill_summary(ua)
    assert "ready" in heading and "Windows user agent" in body and "Helium" in body
    patched = {"hosts": [("Helium", True, "")], "mode": "patched"}
    assert "Load unpacked" in autofill_summary(patched)[1]


def test_installing_a_binary_over_a_running_one_works(tmp_path):
    """`icp setup` used to crash with "Text file busy" while the agent was running."""
    import subprocess
    import sys
    dest = tmp_path / "icp-agent"
    dest.write_bytes(b"#!/bin/sh\nexec sleep 30\n")
    dest.chmod(0o755)
    running = subprocess.Popen([str(dest)])
    try:
        new = tmp_path / "built"
        new.write_bytes(b"#!/bin/sh\nexit 0\n")
        new.chmod(0o755)
        hosts._install_binary(new, dest)
        assert dest.read_bytes() == b"#!/bin/sh\nexit 0\n"
        assert not (tmp_path / "icp-agent.new").exists()
    finally:
        running.kill()
        running.wait()


def _fake_proc(tmp_path, procs):
    root = tmp_path / "proc"
    for pid, (comm, argv) in procs.items():
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    return str(root)


def test_a_running_browser_without_the_flag_is_detected(tmp_path):
    ua = "--user-agent=Mozilla/5.0 (Windows NT 10.0)"
    old = _fake_proc(tmp_path / "a", {1: ("helium", ["/opt/helium/helium"]),
                                     2: ("helium", ["/opt/helium/helium", "--type=renderer"])})
    new = _fake_proc(tmp_path / "b", {1: ("helium", ["/opt/helium/helium", ua]),
                                     2: ("helium", ["/opt/helium/helium", "--type=renderer"])})
    none = _fake_proc(tmp_path / "c", {1: ("bash", ["bash"])})
    assert ah.running_without_windows_ua("helium", proc=old) is True
    assert ah.running_without_windows_ua("helium", proc=new) is False
    assert ah.running_without_windows_ua("helium", proc=none) is False      # not running: fine


def test_doctor_and_panel_tell_you_to_restart(home, monkeypatch):
    ah.install()
    ah.windows_ua_entry("helium.desktop")
    monkeypatch.setattr(ah, "running_without_windows_ua", lambda b, proc="/proc": True)
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.WARN and "still running" in msg and "Exit" in hint
    from icp.gui.model import autofill_summary
    heading, body = autofill_summary(ah.status())
    assert heading == "Restart your browser to finish" and "patched" in body
