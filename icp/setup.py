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


# Seccomp-only hardening (no mount/user namespaces, so it also works where those are restricted).
_SANDBOX = ("NoNewPrivileges=yes\nLockPersonality=yes\nRestrictRealtime=yes\n"
            "RestrictSUIDSGID=yes\nSystemCallArchitectures=native\n")


def _units() -> dict[str, str]:
    py = sys.executable
    return {
        "icp-sync.service": (
            "[Unit]\nDescription=iCloud Passwords sync\n\n"
            f"[Service]\nType=oneshot\nExecStart={py} -m icp.cli.app sync --background\n"
            + _SANDBOX + "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"),
        "icp-sync.timer": (
            "[Unit]\nDescription=iCloud Passwords sync every 6 hours\n\n"
            "[Timer]\nOnBootSec=5min\nOnUnitActiveSec=6h\nRandomizedDelaySec=10min\n"
            "Persistent=true\n\n[Install]\nWantedBy=timers.target\n"),
    }


def _install_units(units: dict[str, str], enable: str) -> bool:
    if not shutil.which("systemctl"):
        ui.warn("systemd not found; skipping " + enable)
        return False
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in units.items():
        (UNIT_DIR / name).write_text(text)
    for cmd in (["daemon-reload"], ["enable", "--now", enable]):
        r = subprocess.run(["systemctl", "--user", *cmd], capture_output=True, text=True)
        if r.returncode:
            ui.warn(f"systemctl --user {' '.join(cmd)}: {r.stderr.strip()}")
            return False
    return True


def install_timer() -> bool:
    return _install_units(_units(), "icp-sync.timer")


def _extension_units() -> dict[str, str]:
    """A path unit that re-applies the OS-check patch whenever the browser (re)installs or updates
    Apple's extension: it watches each profile's Extensions folder (new versions appear there)."""
    from . import applehost_install as ah
    watched = []
    for _label, prof in ah.profiles():
        watched.append(prof / "Extensions")
        if (prof / "Extensions" / ah.APPLE_EXTENSION_ID).is_dir():
            watched.append(prof / "Extensions" / ah.APPLE_EXTENSION_ID)
    return {
        "icp-apple-extension.path": (
            "[Unit]\nDescription=Re-apply the iCloud Passwords patch when the browser updates it\n\n"
            "[Path]\n" + "".join(f"PathChanged={w}\n" for w in watched)
            + "Unit=icp-apple-extension.service\n\n[Install]\nWantedBy=default.target\n"),
        "icp-apple-extension.service": (
            "[Unit]\nDescription=Patch Apple's iCloud Passwords extension for Linux\n"
            "StartLimitIntervalSec=0\n\n"
            f"[Service]\nType=oneshot\nExecStart={sys.executable} -m icp.cli.app "
            "apple-extension patch --wait 90 --quiet\n"
            + _SANDBOX + "RestrictAddressFamilies=AF_UNIX\n"),       # the patcher needs no network
    }


def _disable_extension_watcher() -> None:
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now", "icp-apple-extension.path"],
                       capture_output=True)
    for name in ("icp-apple-extension.path", "icp-apple-extension.service"):
        (UNIT_DIR / name).unlink(missing_ok=True)


def apple_extension(mode: str | None) -> None:
    """Register the host Apple's own extension talks to and make the extension start on Linux:
    patch the installed copy in place and keep it patched (see icp/applehost_install.py)."""
    from . import applehost_install as ah
    for label, f in ah.install():
        ui.out(f"  host registered for {label}: {f}")
    if mode == "off":
        _disable_extension_watcher()
        for folder in ah.restore_in_place():
            ui.out(f"  restored the original extension in {folder}")
        ui.out("  Apple's extension is back to stock; reload it in the browser.")
        return
    if mode == "unpacked":
        _disable_extension_watcher()
        out = ah.patch_unpacked_copy()      # exits with a message when the store copy is missing
        ui.out(f"  patched copy: {out}\n  Developer mode -> Load unpacked -> that folder, and turn "
               "the store copy off (both share one extension id). Re-run after Apple updates it.")
        return
    if ah.UNPACKED.exists():
        shutil.rmtree(ah.UNPACKED, ignore_errors=True)
        ui.out("  removed the old separate copy (the installed extension is patched in place now)")
    results = ah.patch_in_place()
    for folder, state in results:
        ui.out(f"  {state}: {folder}")
    if not results:
        ui.out("  Apple's 'iCloud Passwords' extension is not installed yet. Install it from the\n"
               "  Chrome Web Store: the watcher below patches it as soon as it appears.")
    if any(state == "unknown" for _f, state in results):
        ui.warn("an extension version this project does not recognise was left untouched")
    if _install_units(_extension_units(), "icp-apple-extension.path"):
        ui.out("  watcher enabled: the patch is re-applied after every extension update")
    if any(state == "patched" for _f, state in results) or ah.stale_cache():
        ui.out("  Now reload iCloud Passwords on the browser's extensions page: a browser keeps "
               "running the\n  copy it cached earlier, and a restart does not refresh it.")


def run(args) -> int:
    ui.step("1/4 Browser integration")
    if hosts.agent_source():
        ui.out("  Rust agent: " + ("built and installed" if hosts.build_agent() else
               "not built (needs cargo) - using the Python agent"))
    if hosts.shim_source():
        ui.out("  Rust shim: " + ("built and installed" if hosts.build_shim() else
               "not built (needs cargo) - using the slower Python host"))
    ui.out("  command: " + hosts.link_cli())
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
