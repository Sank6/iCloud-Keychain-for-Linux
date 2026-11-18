"""`icp uninstall`: undo everything `icp setup` put on the machine.

Removes, in this order: the systemd timer and extension watcher, the patch on Apple's extension
(the original file is put back), the native-messaging host manifests, the desktop entry, search
provider and icon, and the launchers/binaries under ~/.local/share/icp. A file is only removed when
it is provably ours (a host manifest that points somewhere else is left alone). Your vault, saved
sign-in and device identity stay unless `--purge` is given, because deleting them is the one step
that cannot be undone from here (your passwords remain in iCloud)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from . import applehost_install as ah
from . import hosts, paths, setup
from .cli import ui

UNITS = ("icp-sync.timer", "icp-sync.service", "icp-apple-extension.path",
         "icp-apple-extension.service")
ENABLED = ("icp-sync.timer", "icp-apple-extension.path")


def _ours(manifest: Path) -> bool:
    """True when a native-messaging manifest launches a program inside our data folder."""
    try:
        target = Path(json.loads(manifest.read_text()).get("path", "")).resolve()
    except (OSError, ValueError, AttributeError):
        return False
    return (hosts.DATA / "icp").resolve() in target.parents or target.parent == hosts.SYSTEM_LIB


def desktop_files() -> list[Path]:
    d = hosts.DATA
    return [d / "applications/org.icp.Passwords.desktop",
            d / "icons/hicolor/scalable/apps/org.icp.Passwords.svg",
            d / "dbus-1/services/org.icp.Passwords.service",
            d / "gnome-shell/search-providers/org.icp.Passwords.search-provider.ini"]


def host_manifests() -> list[Path]:
    found = []
    for _label, _kind, nmh in hosts.detected():
        for name in (hosts.HOST_NAME, ah.APPLE_HOST_NAME):
            f = nmh / f"{name}.json"
            if f.is_file() and _ours(f):
                found.append(f)
    return found


def plan(purge: bool = False) -> list[tuple[str, callable]]:
    """[(what it does, action)] in the order it will run."""
    steps: list[tuple[str, callable]] = []
    present = [u for u in UNITS if (setup.UNIT_DIR / u).exists()]
    if present:
        steps.append((f"stop and remove the systemd units ({', '.join(present)})", _remove_units))
    if ah.extension_dirs() and any(state == "patched" for _d, state in ah.status()["installed"]):
        steps.append(("restore Apple's original iCloud Passwords extension", ah.restore_in_place))
    for f in host_manifests():
        steps.append((f"remove the browser host manifest {f}", f.unlink))
    for f in desktop_files():
        if f.exists():
            steps.append((f"remove {f}", f.unlink))
    if hosts.CLI_LINK.is_symlink() and hosts.CLI_LINK.resolve().name == "icp":
        steps.append((f"remove the command link {hosts.CLI_LINK}", hosts.unlink_cli))
    data = hosts.DATA / "icp"
    if data.exists():
        steps.append((f"remove {data} (launchers, helper programs, saved original extension)",
                      lambda: shutil.rmtree(data, ignore_errors=True)))
    if purge:
        steps.append((f"DELETE your saved sign-in, vault and device identity in {paths.config_dir()}",
                      _purge_data))
    return steps


def _remove_units() -> None:
    if shutil.which("systemctl"):
        for unit in ENABLED:
            subprocess.run(["systemctl", "--user", "disable", "--now", unit], capture_output=True)
    for unit in UNITS:
        (setup.UNIT_DIR / unit).unlink(missing_ok=True)
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)


def _purge_data() -> None:
    from . import mirror
    from .auth import session
    try:
        mirror.remove_all(interactive=False)
    except Exception as e:  # noqa: BLE001 - the keyring may be locked or absent
        ui.warn(f"keyring mirror not removed: {e}")
    session.clear()
    session.reset_keys()                # forgets the master key
    shutil.rmtree(paths.config_dir(), ignore_errors=True)


def run(args) -> int:
    steps = plan(purge=args.purge)
    if not steps:
        ui.out("Nothing to remove: icp is not installed here.")
        return 0
    ui.out("This will:")
    for what, _action in steps:
        ui.out(f"  - {what}")
    if not args.purge:
        ui.out("\nYour vault, saved sign-in and device identity are kept (use --purge to delete).")
    if args.dry_run:
        return 0
    if not args.yes and not ui.confirm_yn("\nContinue? [y/N] "):
        ui.out("Cancelled; nothing was changed.")
        return 1
    for what, action in steps:
        try:
            action()
            ui.out(f"  done: {what}")
        except OSError as e:
            ui.warn(f"{what}: {e}")
    ui.out("\nUninstalled. If the Passwords app or its agent is still running, log out and back in "
           "(or `pkill -f icp`) to stop it.")
    return 0
