"""`icp setup`: one command that registers the native host in every detected browser and installs
a systemd user timer for background sync. Nothing here talks to Apple; it asks before starting
containers or enabling units."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from . import hosts
from .cli import ui
from .doctor import OK, check_anisette

UNIT_DIR = hosts.CFG / "systemd/user"


def _units() -> dict[str, str]:
    py = sys.executable
    return {
        "icp-sync.service": (
            "[Unit]\nDescription=iCloud Passwords sync\n\n"
            f"[Service]\nType=oneshot\nExecStart={py} -m icp.cli.app sync --background\n"),
        "icp-sync.timer": (
            "[Unit]\nDescription=iCloud Passwords sync every 6 hours\n\n"
            "[Timer]\nOnBootSec=5min\nOnUnitActiveSec=6h\nRandomizedDelaySec=10min\n"
            "Persistent=true\n\n[Install]\nWantedBy=timers.target\n"),
    }


def install_timer() -> bool:
    if not shutil.which("systemctl"):
        ui.warn("systemd not found; skipping the sync timer")
        return False
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in _units().items():
        (UNIT_DIR / name).write_text(text)
    for cmd in (["daemon-reload"], ["enable", "--now", "icp-sync.timer"]):
        r = subprocess.run(["systemctl", "--user", *cmd], capture_output=True, text=True)
        if r.returncode:
            ui.warn(f"systemctl --user {' '.join(cmd)}: {r.stderr.strip()}")
            return False
    return True


def apple_extension(mode: str | None) -> None:
    """Register the host Apple's own extension talks to, and (when asked) make the extension
    start on Linux. See icp/applehost_install.py for the two modes."""
    from . import applehost_install as ah
    done = ah.install()
    for label, f in done:
        ui.out(f"  host registered for {label}: {f}")
    if mode == "useragent":
        entries = ah.desktop_ids_for_detected()
        if not entries:
            ui.warn("no browser desktop entry found to add the Windows user agent to")
        for label, did in entries:
            major = ah.browser_major(ah.exec_binary(did) or "") or ah.DEFAULT_MAJOR
            p = ah.windows_ua_entry(did, major)
            ui.out(f"  {label}: launcher with a Windows user agent -> {p}")
        if entries:
            ui.out("  Install Apple's 'iCloud Passwords' extension from the Chrome Web Store. Every\n"
                   "  site in that browser will see a Windows user agent.")
            running = ah.status()["running_without_ua"]
            if running:
                ui.warn("the browser is already running, so it ignores the new flag: quit it "
                        "completely (browser menu -> Exit; it can keep running in the background "
                        "after its windows close), then reopen it from the app grid")
    elif mode == "patched":
        for _, did in ah.desktop_ids_for_detected():
            if ah.restore_entry(did):
                ui.out(f"  removed the Windows user agent from {did}")
        out = ah.patch_extension()     # exits with a message when the store version is missing
        ui.out(f"  patched copy of your installed extension: {out}")
        ui.out("  chrome://extensions -> Developer mode -> Load unpacked -> that folder, and turn\n"
               "  the store copy off (both share one extension id). Re-run after Apple updates it.")
    elif mode == "off":
        for _, did in ah.desktop_ids_for_detected():
            if ah.restore_entry(did):
                ui.out(f"  restored the original launcher {did}")
    else:
        st = ah.status()
        ui.out("  Apple's extension refuses to start on Linux. Choose how to get past that:\n"
               "    icp setup --apple-extension useragent   unmodified store extension, browser\n"
               "                                            reports a Windows user agent\n"
               "    icp setup --apple-extension patched     local patched copy, normal user agent")
        if st["mode"]:
            ui.out(f"  currently prepared: {st['mode']}")


def run(args) -> int:
    ui.step("1/4 Browser integration")
    if hosts.agent_source():
        ui.out("  Rust agent: " + ("built and installed" if hosts.build_agent() else
               "not built (needs cargo) - using the Python agent"))
    if hosts.shim_source():
        ui.out("  Rust shim: " + ("built and installed" if hosts.build_shim() else
               "not built (needs cargo) - using the slower Python host"))
    done = hosts.install(extra_ids=args.extension_id or ())
    if not done:
        ui.warn("no supported browser profile found - open your browser once, then re-run")
    for label, f in done:
        ui.out(f"  registered for {label}: {f}")
    if done:
        ui.out("  Load the extension/ folder unpacked (its id is pinned), then reload it.")

    ui.step("2/4 Apple's iCloud Passwords extension")
    apple_extension(args.apple_extension)

    ui.step("3/4 Anisette server")
    sev, msg, hint = check_anisette(args.anisette)
    ui.out(f"  {msg}")
    if sev != OK and hint:
        ui.out(f"  -> {hint}")

    ui.step("4/4 Background sync")
    if args.no_timer:
        ui.out("  skipped (--no-timer)")
    elif args.yes or ui.confirm_yn("  Install a systemd user timer to sync every 6 hours? [y/N] "):
        ui.out("  timer enabled" if install_timer() else "  timer not installed")
    else:
        ui.out("  skipped")

    ui.out(f"\nApp entry: {install_desktop_entry()}")
    ui.out("\nNext: `icp login` if you haven't signed in, then `icp doctor` to check everything.")
    return 0


ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="#6e7a8a"/><stop offset="1" stop-color="#3a4452"/></linearGradient></defs>
<rect x="8" y="8" width="112" height="112" rx="26" fill="url(#g)"/>
<circle cx="48" cy="64" r="20" fill="none" stroke="#fff" stroke-width="10"/>
<path d="M66 64h42M96 64v16M84 64v12" stroke="#fff" stroke-width="10" stroke-linecap="round"/>
</svg>
"""


def install_desktop_entry() -> Path:
    """Desktop entry + icon for the GTK app, so it shows in the app grid and Activities."""
    data = hosts.DATA
    icon_dir = data / "icons/hicolor/scalable/apps"
    app_dir = data / "applications"
    icon_dir.mkdir(parents=True, exist_ok=True)
    app_dir.mkdir(parents=True, exist_ok=True)
    (icon_dir / "org.icp.Passwords.svg").write_text(ICON_SVG)
    entry = app_dir / "org.icp.Passwords.desktop"
    entry.write_text(
        "[Desktop Entry]\nType=Application\nName=Passwords\nComment=iCloud Keychain logins\n"
        f"Exec={sys.executable} -m icp.gui\nIcon=org.icp.Passwords\nTerminal=false\n"
        "Categories=Utility;Security;GTK;\nStartupWMClass=org.icp.Passwords\n"
        "Keywords=passwords;icloud;keychain;\nDBusActivatable=true\n")
    # D-Bus activation lets GNOME Shell start the app in the background for a search
    svc = data / "dbus-1/services"
    svc.mkdir(parents=True, exist_ok=True)
    (svc / "org.icp.Passwords.service").write_text(
        f"[D-BUS Service]\nName=org.icp.Passwords\nExec={sys.executable} -m icp.gui\n")
    sp = data / "gnome-shell/search-providers"
    sp.mkdir(parents=True, exist_ok=True)
    (sp / "org.icp.Passwords.search-provider.ini").write_text(
        "[Shell Search Provider]\nDesktopId=org.icp.Passwords.desktop\n"
        "BusName=org.icp.Passwords\nObjectPath=/org/icp/Passwords/SearchProvider\nVersion=2\n")
    return entry
