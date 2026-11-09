"""Native-messaging host registration for Chromium-family and Firefox-family browsers, plus the
launcher script the browser executes. Replaces the logic that used to live only in
host/install.sh, and works from a pip/pipx install as well as from a checkout."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from .const import EXTENSION_ID, GECKO_ID, HOST_NAME

HOME = Path.home()
CFG = Path(os.environ.get("XDG_CONFIG_HOME") or HOME / ".config")
DATA = Path(os.environ.get("XDG_DATA_HOME") or HOME / ".local/share")

# (label, browser profile dir whose existence means "installed", NativeMessagingHosts dir)
CHROMIUM = [
    ("Google Chrome", CFG / "google-chrome", CFG / "google-chrome/NativeMessagingHosts"),
    ("Chromium", CFG / "chromium", CFG / "chromium/NativeMessagingHosts"),
    ("Helium", CFG / "net.imput.helium", CFG / "net.imput.helium/NativeMessagingHosts"),
    ("Helium (legacy dir)", CFG / "helium", CFG / "helium/NativeMessagingHosts"),
    ("Brave", CFG / "BraveSoftware/Brave-Browser",
     CFG / "BraveSoftware/Brave-Browser/NativeMessagingHosts"),
    ("Microsoft Edge", CFG / "microsoft-edge", CFG / "microsoft-edge/NativeMessagingHosts"),
    ("Vivaldi", CFG / "vivaldi", CFG / "vivaldi/NativeMessagingHosts"),
    ("Opera", CFG / "opera", CFG / "opera/NativeMessagingHosts"),
]
FIREFOX = [
    ("Firefox", HOME / ".mozilla", HOME / ".mozilla/native-messaging-hosts"),
    ("LibreWolf", HOME / ".librewolf", HOME / ".librewolf/native-messaging-hosts"),
]


def launcher_path() -> Path:
    return DATA / "icp" / "icp-host"


def shim_source() -> Path | None:
    """The Rust shim crate in a checkout (None for a plain pip install)."""
    d = Path(__file__).resolve().parent.parent / "native" / "icp-shim"
    return d if (d / "Cargo.toml").exists() else None


def shim_path() -> Path:
    user = DATA / "icp" / "icp-shim"
    return user if user.exists() or not (SYSTEM_LIB / "icp-shim").exists() else SYSTEM_LIB / "icp-shim"


def agent_source() -> Path | None:
    d = Path(__file__).resolve().parent.parent / "native" / "icp-agent"
    return d if (d / "Cargo.toml").exists() else None


SYSTEM_LIB = Path("/usr/lib/icp")  # where the .deb installs the Rust binaries


def agent_path() -> Path:
    user = DATA / "icp" / "icp-agent"
    return user if user.exists() or not (SYSTEM_LIB / "icp-agent").exists() else SYSTEM_LIB / "icp-agent"


def build_agent() -> bool:
    """Compile the Rust agent (same protocol as icp/agent.py) and install it. Needs cargo."""
    import shutil
    import subprocess
    src = agent_source()
    if not src or not shutil.which("cargo"):
        return False
    r = subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=src)
    built = src / "target" / "release" / "icp-agent"
    if r.returncode or not built.exists():
        return False
    agent_path().parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, agent_path())
    return True


def build_shim() -> bool:
    """Compile the Rust shim and install it next to the launcher. Needs cargo; harmless to skip."""
    import shutil
    import subprocess
    src = shim_source()
    if not src or not shutil.which("cargo"):
        return False
    r = subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=src)
    built = src / "target" / "release" / "icp-shim"
    if r.returncode or not built.exists():
        return False
    shim_path().parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, shim_path())
    return True


def write_launcher() -> Path:
    """Return the program the browser should run, and record how to start the agent.

    Preferred: the Rust shim (forwards to the long-running agent, ~1 ms per message). Fallback: a
    tiny sh wrapper around the Python host, which decrypts the vault per message (slow but needs
    nothing compiled). Both live in XDG data so they survive moving the checkout; re-run
    `icp setup` after changing Python environments."""
    DATA.joinpath("icp").mkdir(parents=True, exist_ok=True)
    d = DATA / "icp"
    # the Rust agent when it has been built, else the Python one (same socket, same protocol)
    agent = f"{agent_path()}" if agent_path().exists() else f"{sys.executable} -m icp.agent"
    (d / "agent-cmd").write_text(agent + "\n")
    (d / "sync-cmd").write_text(f"{sys.executable} -m icp.cli.app sync\n")
    (d / "gui-cmd").write_text(f"{sys.executable} -m icp.gui\n")
    if shim_path().exists():
        return shim_path()
    p = launcher_path()
    p.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m icp.vault.host\n')
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def chromium_manifest(launcher: Path, extra_ids=()) -> dict:
    ids = [EXTENSION_ID, *[i for i in extra_ids if i and i != EXTENSION_ID]]
    return {"name": HOST_NAME, "description": "Apple Passwords native messaging host",
            "path": str(launcher), "type": "stdio",
            "allowed_origins": [f"chrome-extension://{i}/" for i in ids]}


def firefox_manifest(launcher: Path) -> dict:
    return {"name": HOST_NAME, "description": "Apple Passwords native messaging host",
            "path": str(launcher), "type": "stdio", "allowed_extensions": [GECKO_ID]}


def detected():
    """[(label, kind, nmh_dir)] for every browser whose profile dir exists."""
    out = [(n, "chromium", nmh) for n, prof, nmh in CHROMIUM if prof.is_dir()]
    out += [(n, "firefox", nmh) for n, prof, nmh in FIREFOX if prof.is_dir()]
    return out


def install(extra_ids=()) -> list[tuple[str, Path]]:
    launcher = write_launcher()
    done = []
    for label, kind, nmh in detected():
        manifest = (chromium_manifest(launcher, extra_ids) if kind == "chromium"
                    else firefox_manifest(launcher))
        nmh.mkdir(parents=True, exist_ok=True)
        f = nmh / f"{HOST_NAME}.json"
        f.write_text(json.dumps(manifest, indent=2) + "\n")
        done.append((label, f))
    return done


def inspect(nmh: Path, kind: str) -> list[str]:
    """Problems with an installed manifest ([] when healthy)."""
    f = nmh / f"{HOST_NAME}.json"
    if not f.exists():
        return ["host manifest missing"]
    try:
        m = json.loads(f.read_text())
    except ValueError:
        return ["host manifest is not valid JSON"]
    problems = []
    path = Path(m.get("path", ""))
    if not path.exists():
        problems.append(f"launcher {path} does not exist")
    elif not os.access(path, os.X_OK):
        problems.append(f"launcher {path} is not executable")
    if kind == "chromium":
        want = f"chrome-extension://{EXTENSION_ID}/"
        if want not in m.get("allowed_origins", []):
            problems.append(f"extension id {EXTENSION_ID} is not allowed (run `icp setup`)")
    elif GECKO_ID not in m.get("allowed_extensions", []):
        problems.append("add-on id not allowed (run `icp setup`)")
    return problems
