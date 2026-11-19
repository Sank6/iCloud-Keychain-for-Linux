"""Apple's own extension on Linux: patched in place, restored, re-patched, reported."""

import json
import os
import threading
import time

import pytest

from icp import applehost_install as ah
from icp import doctor, hosts, setup

STOCK = "var a=1;function checkForValidOS(){if(navigator.platform===\"MacIntel\")return 1}var b=2;"


@pytest.fixture
def browser(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    monkeypatch.setattr(hosts, "DATA", tmp_path / "data")
    monkeypatch.setattr(hosts, "CFG", cfg)
    root = cfg / "net.imput.helium"
    monkeypatch.setattr(hosts, "CHROMIUM", [("Helium", root, root / "NativeMessagingHosts")])
    monkeypatch.setattr(hosts, "FIREFOX", [])
    monkeypatch.setattr(ah, "BACKUPS", tmp_path / "data/icp/apple-extension-orig")
    monkeypatch.setattr(ah, "UNPACKED", tmp_path / "data/icp/apple-extension")
    (root / "Default/Extensions").mkdir(parents=True)
    return root


def install_extension(root, version="3.4.0", js=STOCK):
    d = root / "Default/Extensions" / ah.APPLE_EXTENSION_ID / f"{version}_0"
    (d / "_metadata").mkdir(parents=True)
    (d / "_metadata/verified_contents.json").write_text("{}")
    (d / "manifest.json").write_text(json.dumps({"version": version, "key": "k"}))
    (d / "background.js").write_text(js)
    return d


def test_patch_in_place_changes_only_the_gate_and_keeps_a_backup(browser):
    d = install_extension(browser)
    assert ah.patch_in_place() == [(d, "patched")]
    text = (d / "background.js").read_text()
    assert text == STOCK.replace(ah.GATE, ah.PATCH)
    assert (d / "_metadata/verified_contents.json").exists()      # signature data left alone
    assert not list(d.glob("*.icp-new"))
    assert (ah.BACKUPS / "3.4.0/background.js").read_text() == STOCK


def test_patching_twice_is_a_no_op(browser):
    d = install_extension(browser)
    ah.patch_in_place()
    assert ah.patch_in_place() == [(d, "already")]
    assert (ah.BACKUPS / "3.4.0/background.js").read_text() == STOCK    # backup stays the original


def test_an_unrecognised_version_is_left_untouched(browser):
    d = install_extension(browser, "9.9.9", js="function other(){}")
    assert ah.patch_in_place() == [(d, "unknown")]
    assert (d / "background.js").read_text() == "function other(){}"


def test_restore_puts_the_original_back(browser):
    d = install_extension(browser)
    ah.patch_in_place()
    assert ah.restore_in_place() == [d]
    assert (d / "background.js").read_text() == STOCK
    assert ah.restore_in_place() == []


def test_a_new_version_after_an_update_is_patched_too(browser):
    old = install_extension(browser, "3.4.0")
    ah.patch_in_place()
    new = install_extension(browser, "3.5.0")
    results = dict(ah.patch_in_place())
    assert results == {old: "already", new: "patched"}


def test_wait_covers_a_browser_that_is_still_unpacking(browser):
    def unpack():
        time.sleep(0.4)
        install_extension(browser)
    threading.Thread(target=unpack).start()
    results = ah.patch_in_place(wait=5)
    assert [state for _d, state in results] == ["patched"]


def test_status_modes(browser):
    ah.install()
    assert ah.status()["mode"] is None and ah.status()["installed"] == []
    d = install_extension(browser)
    assert ah.status()["mode"] is None and ah.status()["installed"] == [(d, "stock")]
    ah.patch_in_place()
    st = ah.status()
    assert st["mode"] == "inplace" and st["hosts"] == [("Helium", True, "")]


def test_status_notices_a_browser_that_disabled_the_extension(browser):
    ah.install()
    install_extension(browser)
    ah.patch_in_place()
    (browser / "Default/Preferences").write_text(json.dumps({"extensions": {"settings": {
        ah.APPLE_EXTENSION_ID: {"disable_reasons": [2048]}}}}))
    assert ah.status()["disabled"] == ["Helium/Default"]
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.FAIL and "disabled" in msg and "unpacked" in hint


def test_status_flags_a_broken_host(browser):
    ah.install()
    manifest = browser / "NativeMessagingHosts/com.apple.passwordmanager.json"
    data = json.loads(manifest.read_text())
    data["path"] = str(browser / "gone")
    manifest.write_text(json.dumps(data))
    assert ah.status()["hosts"][0][1] is False
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.FAIL and "launcher" in msg and "icp setup" in hint


def test_doctor_walks_through_the_states(browser):
    ah.install()
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.WARN and "not installed" in msg and "Chrome Web Store" in hint
    install_extension(browser)
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.WARN and "not patched" in msg and "icp setup" in hint
    ah.patch_in_place()
    assert doctor.check_apple_extension()[0] == doctor.OK


def test_unpacked_copy_is_a_separate_patched_folder(browser):
    ah.install()
    d = install_extension(browser)
    out = ah.patch_unpacked_copy()
    assert out == ah.UNPACKED and not (out / "_metadata").exists()
    assert (out / "background.js").read_text() == STOCK.replace(ah.GATE, ah.PATCH)
    assert (d / "background.js").read_text() == STOCK                       # store copy untouched
    assert ah.status()["mode"] == "unpacked"


def test_unpacked_copy_warns_after_an_apple_update(browser):
    ah.install()
    install_extension(browser, "3.4.0")
    ah.patch_unpacked_copy()
    install_extension(browser, "3.5.0")
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.WARN and "3.4.0 -> 3.5.0" in msg and "unpacked" in hint


def test_watcher_units_watch_every_profile_and_repatch(browser):
    (browser / "Profile 1/Extensions").mkdir(parents=True)
    install_extension(browser)
    units = setup._extension_units()
    path, service = units["icp-apple-extension.path"], units["icp-apple-extension.service"]
    assert f"PathChanged={browser}/Default/Extensions\n" in path
    assert f"PathChanged={browser}/Profile 1/Extensions\n" in path
    assert f"PathChanged={browser}/Default/Extensions/{ah.APPLE_EXTENSION_ID}\n" in path
    assert "apple-extension patch --wait" in service and "StartLimitIntervalSec=0" in service


def test_autofill_panel_text():
    from icp.gui.model import autofill_summary
    host = [("Helium", True, "")]
    assert autofill_summary({"hosts": [], "mode": None})[0] == "No supported browser found"
    broken = {"hosts": [("Helium", False, "launcher is missing")], "mode": None}
    assert "launcher is missing" in autofill_summary(broken)[1]
    none = {"hosts": host, "installed": [], "mode": None, "disabled": []}
    assert autofill_summary(none)[0] == "Install Apple's extension"
    unpatched = {"hosts": host, "installed": [("x", "stock")], "mode": None, "disabled": []}
    assert "icp setup" in autofill_summary(unpatched)[1]
    ready = {"hosts": host, "installed": [("x", "patched")], "mode": "inplace", "disabled": []}
    heading, body = autofill_summary(ready)
    assert "ready" in heading and "pairing code" in body
    off = dict(ready, disabled=["Helium/Default"])
    assert "disabled" in autofill_summary(off)[0]
    assert "Load unpacked" in autofill_summary(
        {"hosts": host, "installed": [], "mode": "unpacked", "disabled": []})[1]


def test_installing_a_binary_over_a_running_one_works(tmp_path):
    """`icp setup` used to crash with "Text file busy" while the agent was running."""
    import subprocess
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


def test_a_symlinked_version_folder_is_never_followed(browser, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "background.js").write_text(STOCK)
    (outside / "manifest.json").write_text(json.dumps({"version": "9.9"}))
    base = browser / "Default/Extensions" / ah.APPLE_EXTENSION_ID
    base.mkdir(parents=True)
    os.symlink(outside, base / "9.9_0")
    assert ah.extension_dirs() == [] and ah.patch_in_place() == []
    assert (outside / "background.js").read_text() == STOCK
    assert sorted(p.name for p in outside.iterdir()) == ["background.js", "manifest.json"]


def test_a_symlinked_background_js_is_left_alone(browser, tmp_path):
    d = install_extension(browser)
    target = tmp_path / "elsewhere.js"
    target.write_text(STOCK)
    (d / "background.js").unlink()
    os.symlink(target, d / "background.js")
    assert ah.patch_in_place() == [(d, "unknown")]
    assert target.read_text() == STOCK and (d / "background.js").is_symlink()
    assert ah.restore_in_place() == []


def test_a_symlinked_extension_root_is_not_followed(browser, tmp_path):
    outside = tmp_path / "ext-elsewhere"
    (outside / "3.4.0_0").mkdir(parents=True)
    (outside / "3.4.0_0/background.js").write_text(STOCK)
    (outside / "3.4.0_0/manifest.json").write_text(json.dumps({"version": "3.4.0"}))
    base = browser / "Default/Extensions"
    base.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, base / ah.APPLE_EXTENSION_ID)
    assert ah.patch_in_place() == []
    assert (outside / "3.4.0_0/background.js").read_text() == STOCK


# ---- the browser's cached script -----------------------------------------------------------
def _cache(prof, patched, mtime):
    cache = prof / "Service Worker/ScriptCache"
    cache.mkdir(parents=True, exist_ok=True)
    body = (STOCK.replace(ah.GATE, ah.PATCH) if patched else STOCK).encode() + b" " * 60_000
    f = cache / f"entry_{mtime}"
    f.write_bytes(body)
    os.utime(f, (mtime, mtime))


def test_the_cached_script_state_follows_the_newest_copy(browser):
    prof = browser / "Default"
    assert ah.cached_script_state(prof) is None
    _cache(prof, patched=False, mtime=1000)
    assert ah.cached_script_state(prof) == "original"
    _cache(prof, patched=True, mtime=2000)
    assert ah.cached_script_state(prof) == "patched"


def test_a_patched_file_with_an_original_cache_is_reported_everywhere(browser, monkeypatch):
    ah.install()
    install_extension(browser)
    ah.patch_in_place()
    _cache(browser / "Default", patched=False, mtime=1000)
    assert ah.stale_cache() == ["Helium/Default"]
    sev, msg, hint = doctor.check_apple_extension()
    assert sev == doctor.WARN and "blank window" in msg and "reload" in hint
    from icp.gui.model import autofill_summary
    heading, body = autofill_summary(ah.status())
    assert heading == "Reload the extension to finish" and "restarting" in body
    _cache(browser / "Default", patched=True, mtime=3000)          # after the reload
    assert ah.stale_cache() == [] and doctor.check_apple_extension()[0] == doctor.OK


def test_an_unpatched_file_is_not_a_stale_cache_problem(browser):
    install_extension(browser)
    _cache(browser / "Default", patched=False, mtime=1000)
    assert ah.stale_cache() == []


def test_the_watcher_notifies_when_it_patched_or_the_cache_is_stale(browser, monkeypatch, capsys):
    from icp.cli import app
    import argparse
    sent = []
    monkeypatch.setattr(ah, "notify_reload", lambda: sent.append(1) or True)
    install_extension(browser)
    ns = argparse.Namespace(action="patch", wait=0, quiet=True)
    assert app.cmd_apple_extension(ns) == 0 and sent == [1]        # it just patched
    assert app.cmd_apple_extension(ns) == 0 and sent == [1]        # nothing new, cache unknown
    _cache(browser / "Default", patched=False, mtime=1000)
    assert app.cmd_apple_extension(ns) == 0 and sent == [1, 1]     # stale cache: remind again
