"""Find the browsers on this machine and connect the autofill extension to them.

Qt-free so it is testable. For each installed browser (system package, Flatpak or Snap) it
reports whether the native-messaging host is registered and whether the extension is loaded,
by reading the browser's own profile files. Registering the host is automatic; adding the
extension needs one click in the browser, which `open_extensions_page` takes the user to.

Chromium-family browsers give an unpacked extension an ID derived from its folder path, so
the host can be registered before the extension is loaded (`predicted_chromium_id`). Once it
is loaded, the real ID is read back from the profile's Preferences."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import zipfile
from pathlib import Path

from .setup import REPO

FIREFOX, CHROMIUM = "firefox", "chromium"
SYSTEM, FLATPAK, SNAP = "system", "flatpak", "snap"
HOST_NAME = "org.icp.native"
GECKO_ID = "icp-linux@local"     # browser_specific_settings.gecko.id in extension/manifest.json
EXTENSION_DIR = REPO / "extension"
FLATPAK_TALK = "org.freedesktop.Flatpak"


@dataclasses.dataclass(frozen=True)
class Spec:
    key: str
    name: str
    family: str
    bins: tuple = ()
    opt: tuple = ()             # absolute paths of tarball/opt installs
    data: str = ""              # Firefox family: profile root under home; Chromium: config dir name
    flatpak: str = ""
    snap: str = ""
    scheme: str = "chrome"      # Chromium family: <scheme>://extensions


SPECS = (
    Spec("firefox", "Firefox", FIREFOX,
         ("firefox", "firefox-esr", "firefox-developer-edition", "firefox-nightly", "firefox-beta"),
         ("/opt/firefox/firefox",), ".mozilla/firefox", "org.mozilla.firefox", "firefox"),
    Spec("zen", "Zen", FIREFOX, ("zen-browser", "zen"), ("/opt/zen-browser-bin/zen-bin",
                                                          "/opt/zen/zen"), ".zen",
         "app.zen_browser.zen"),
    Spec("librewolf", "LibreWolf", FIREFOX, ("librewolf",), ("/opt/librewolf/librewolf",),
         ".librewolf", "io.gitlab.librewolf-community"),
    Spec("floorp", "Floorp", FIREFOX, ("floorp",), ("/opt/floorp/floorp",), ".floorp",
         "one.ablaze.floorp"),
    Spec("waterfox", "Waterfox", FIREFOX, ("waterfox",), ("/opt/waterfox/waterfox",), ".waterfox",
         "net.waterfox.waterfox"),
    Spec("chrome", "Google Chrome", CHROMIUM, ("google-chrome-stable", "google-chrome"),
         ("/opt/google/chrome/chrome",), "google-chrome", "com.google.Chrome"),
    Spec("chrome-dev", "Google Chrome Dev", CHROMIUM, ("google-chrome-unstable",),
         ("/opt/google/chrome-unstable/chrome",), "google-chrome-unstable", "com.google.ChromeDev"),
    Spec("chromium", "Chromium", CHROMIUM, ("chromium", "chromium-browser"), (), "chromium",
         "org.chromium.Chromium", "chromium"),
    Spec("brave", "Brave", CHROMIUM, ("brave", "brave-browser", "brave-browser-stable"),
         ("/opt/brave.com/brave/brave",), "BraveSoftware/Brave-Browser", "com.brave.Browser",
         "brave"),
    Spec("edge", "Microsoft Edge", CHROMIUM, ("microsoft-edge-stable", "microsoft-edge"),
         ("/opt/microsoft/msedge/msedge",), "microsoft-edge", "com.microsoft.Edge",
         scheme="edge"),
    Spec("vivaldi", "Vivaldi", CHROMIUM, ("vivaldi", "vivaldi-stable"),
         ("/opt/vivaldi/vivaldi",), "vivaldi", "com.vivaldi.Vivaldi", scheme="vivaldi"),
    Spec("opera", "Opera", CHROMIUM, ("opera",), ("/usr/lib/x86_64-linux-gnu/opera/opera",),
         "opera", "com.opera.Opera", "opera", scheme="opera"),
    Spec("helium", "Helium", CHROMIUM, ("helium", "helium-browser"),
         ("/opt/helium-browser-bin/helium",), "net.imput.helium"),
    Spec("thorium", "Thorium", CHROMIUM, ("thorium-browser",), ("/opt/chromium.org/thorium/thorium",),
         "thorium"),
)


@dataclasses.dataclass(frozen=True)
class Install:
    """One browser install found on this machine."""
    spec: Spec
    kind: str                   # SYSTEM | FLATPAK | SNAP
    launch: tuple               # argv that starts it; empty if only its profile was found
    root: Path                  # what the browser sees as home for its data

    @property
    def key(self) -> str:
        return f"{self.spec.key}:{self.kind}"

    @property
    def label(self) -> str:
        return self.spec.name + {SYSTEM: "", FLATPAK: " (Flatpak)", SNAP: " (Snap)"}[self.kind]

    @property
    def sandboxed(self) -> bool:
        return self.kind != SYSTEM

    def data_dir(self) -> Path:
        """Firefox family: the profiles root. Chromium family: the config (user data) dir."""
        if self.spec.family == FIREFOX:
            return self.root / self.spec.data
        if self.kind == FLATPAK:
            return self.root / "config" / self.spec.data
        if self.kind == SNAP:
            return self.root / self.spec.data
        return self.root / ".config" / self.spec.data

    def host_dirs(self) -> list[Path]:
        if self.spec.family == CHROMIUM:
            return [self.data_dir() / "NativeMessagingHosts"]
        # Firefox reads ~/.mozilla/native-messaging-hosts; forks read their own dot-dir too.
        own = self.root / self.spec.data.split("/")[0] / "native-messaging-hosts"
        moz = self.root / ".mozilla" / "native-messaging-hosts"
        return [own] if own == moz else [own, moz]


# --- discovery ------------------------------------------------------------------------------

def _home() -> Path:
    return Path.home()


def _flatpak_installed(app_id: str) -> bool:
    return any(Path(p).expanduser().is_dir() for p in
               (f"/var/lib/flatpak/app/{app_id}", f"~/.local/share/flatpak/app/{app_id}"))


def scan() -> list[Install]:
    """Every supported browser found, as system package, Flatpak or Snap."""
    found = []
    home = _home()
    for spec in SPECS:
        exe = next((p for p in (shutil.which(b) for b in spec.bins) if p), None)
        exe = exe or next((p for p in spec.opt if os.access(p, os.X_OK)), None)
        system = Install(spec, SYSTEM, (exe,) if exe else (), home)
        if exe or system.data_dir().is_dir():
            found.append(system)
        if spec.flatpak and _flatpak_installed(spec.flatpak):
            found.append(Install(spec, FLATPAK, ("flatpak", "run", spec.flatpak),
                                 home / ".var" / "app" / spec.flatpak))
        if spec.snap and Path(f"/snap/bin/{spec.snap}").exists():
            found.append(Install(spec, SNAP, (f"/snap/bin/{spec.snap}",),
                                 home / "snap" / spec.snap / "common"))
    return found


# --- extension identity and state ----------------------------------------------------------

def predicted_chromium_id(path: Path = EXTENSION_DIR) -> str:
    """The ID Chromium gives an unpacked extension loaded from `path`: the first 16 bytes of
    the SHA-256 of its absolute path, hex-encoded with 0-f mapped to a-p."""
    digest = hashlib.sha256(os.path.realpath(path).encode()).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


def _our_manifest_name() -> str:
    try:
        return json.loads((EXTENSION_DIR / "manifest.json").read_text()).get("name", "")
    except (OSError, ValueError):
        return ""


def _is_ours(path: str) -> bool:
    if not path:
        return False
    if os.path.realpath(path) == os.path.realpath(EXTENSION_DIR):
        return True
    try:
        m = json.loads((Path(path) / "manifest.json").read_text())
    except (OSError, ValueError):
        return False
    gecko = ((m.get("browser_specific_settings") or {}).get("gecko") or {}).get("id")
    return gecko == GECKO_ID


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


@dataclasses.dataclass
class Status:
    extension: str              # "installed" | "disabled" | "missing"
    ext_id: str                 # Chromium: the real ID if loaded, else the predicted one
    host: bool                  # native host manifest present and pointing at this extension
    sandbox_ok: bool            # Flatpak: may reach the host (talk-name granted); else True
    unsigned_ok: bool           # Firefox family: a profile allows unsigned add-ons


def _chromium_extension(inst: Install) -> tuple[str, str]:
    state, ext_id = "missing", ""
    data = inst.data_dir()
    for prefs in [*data.glob("Default/*Preferences"), *data.glob("Profile */*Preferences")]:
        if prefs.name not in ("Preferences", "Secure Preferences"):
            continue
        settings = ((_read_json(prefs) or {}).get("extensions") or {}).get("settings") or {}
        for eid, v in settings.items():
            if not isinstance(v, dict) or not _is_ours(v.get("path", "")):
                continue
            ext_id = eid
            enabled = v.get("state", 1) == 1 and not v.get("disable_reasons")
            if enabled:
                return "installed", eid
            state = "disabled"
    return state, ext_id


def _firefox_extension(inst: Install) -> str:
    state = "missing"
    for f in inst.data_dir().glob("*/extensions.json"):
        for addon in (_read_json(f) or {}).get("addons", []):
            if addon.get("id") == GECKO_ID:
                if addon.get("active"):
                    return "installed"
                state = "disabled"
    return state


def unsigned_allowed(inst: Install) -> bool:
    """Whether a profile turned off add-on signature checks (needed to keep our unsigned
    extension installed; Firefox release builds ignore it and only allow a temporary add-on)."""
    for f in [*inst.data_dir().glob("*/prefs.js"), *inst.data_dir().glob("*/user.js")]:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if 'user_pref("xpinstall.signatures.required", false)' in text:
            return True
    return False


def flatpak_talk_granted(app_id: str) -> bool:
    for f in (Path("~/.local/share/flatpak/overrides").expanduser() / app_id,
              Path("/var/lib/flatpak/overrides") / app_id):
        try:
            if f"{FLATPAK_TALK}=talk" in f.read_text():
                return True
        except OSError:
            pass
    return False


def status(inst: Install) -> Status:
    if inst.spec.family == CHROMIUM:
        ext, real_id = _chromium_extension(inst)
        ext_id = real_id or predicted_chromium_id()
        unsigned = True
    else:
        ext, ext_id = _firefox_extension(inst), GECKO_ID
        unsigned = unsigned_allowed(inst)
    manifest = _read_json(inst.host_dirs()[0] / f"{HOST_NAME}.json") or {}
    allowed = manifest.get("allowed_origins" if inst.spec.family == CHROMIUM
                           else "allowed_extensions") or []
    wanted = f"chrome-extension://{ext_id}/" if inst.spec.family == CHROMIUM else GECKO_ID
    host = wanted in allowed and Path(manifest.get("path", "")).exists()
    sandbox_ok = flatpak_talk_granted(inst.spec.flatpak) if inst.kind == FLATPAK else True
    return Status(ext, ext_id, host, sandbox_ok, unsigned)


# --- actions --------------------------------------------------------------------------------

def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or "~/.local/share").expanduser()


def host_wrapper(anisette_url: str) -> Path:
    """A launcher for the native host that carries the anisette URL, since a browser started
    from the desktop doesn't see shell variables (background syncs need it)."""
    target = REPO / "host" / "icp-host.sh"
    target.chmod(target.stat().st_mode | 0o111)
    f = _data_home() / "icp" / "icp-host.sh"
    f.parent.mkdir(parents=True, exist_ok=True)
    env = f"export ICP_ANISETTE_URL={shlex.quote(anisette_url)}\n" if anisette_url else ""
    f.write_text(f"#!/usr/bin/env bash\n{env}exec {shlex.quote(str(target))} \"$@\"\n")
    f.chmod(0o755)
    return f


def register_host(inst: Install, anisette_url: str, ext_id: str = "") -> list[Path]:
    """Write the native-messaging manifest for `inst`; returns the files written. A Flatpak
    browser gets a small script inside its sandbox that hands over to the host via
    flatpak-spawn (which needs the talk-name permission, see `flatpak_permission_command`)."""
    path = host_wrapper(anisette_url)
    if inst.kind == FLATPAK:
        inner = inst.root / "data" / "icp" / "icp-host.sh"
        inner.parent.mkdir(parents=True, exist_ok=True)
        inner.write_text(f"#!/bin/sh\nexec flatpak-spawn --host {shlex.quote(str(path))} \"$@\"\n")
        inner.chmod(0o755)
        path = inner
    manifest = {"name": HOST_NAME, "description": "Apple Passwords native messaging host",
                "path": str(path), "type": "stdio"}
    if inst.spec.family == CHROMIUM:
        manifest["allowed_origins"] = [f"chrome-extension://{ext_id or predicted_chromium_id()}/"]
    else:
        manifest["allowed_extensions"] = [GECKO_ID]
    written = []
    for d in inst.host_dirs():
        d.mkdir(parents=True, exist_ok=True)
        f = d / f"{HOST_NAME}.json"
        f.write_text(json.dumps(manifest, indent=2) + "\n")
        written.append(f)
    return written


def flatpak_permission_command(inst: Install) -> str:
    return f"flatpak override --user --talk-name={FLATPAK_TALK} {inst.spec.flatpak}"


def build_xpi() -> Path:
    """Package extension/ as an .xpi a Firefox-family browser can install from a file."""
    out = _data_home() / "icp" / "icp-linux.xpi"
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(EXTENSION_DIR.iterdir()):
            if f.is_file():
                z.write(f, f.name)
    return out


def extensions_url(inst: Install) -> str:
    return f"{inst.spec.scheme}://extensions"


def extensions_page_argv(inst: Install, st: Status) -> list[str]:
    """argv that opens the place to add the extension: the .xpi install prompt (Firefox forks
    allowing unsigned add-ons) or about:debugging. Chromium-family browsers refuse to open
    chrome:// pages handed to them by another program (they show a new tab instead), so for
    those this only brings the browser up and the user pastes `extensions_url` themselves."""
    if not inst.launch:
        return []
    if inst.spec.family == CHROMIUM:
        return [*inst.launch, "--new-window"]
    if st.unsigned_ok:
        return [*inst.launch, str(build_xpi())]
    return [*inst.launch, "about:debugging#/runtime/this-firefox"]


def next_step(inst: Install, st: Status) -> str:
    """What the user still has to do in the browser, in one sentence or two."""
    if st.extension == "installed" and st.host and st.sandbox_ok:
        return "Ready - click the extension's toolbar icon on a login page."
    if st.extension == "disabled":
        return f"The extension is turned off - enable it on {inst.spec.name}'s extensions page."
    if st.extension == "missing":
        if inst.spec.family == CHROMIUM:
            return (f"Click Add extension for step-by-step help: open {extensions_url(inst)}, "
                    f"turn on Developer mode, click Load unpacked and choose {EXTENSION_DIR}.")
        if st.unsigned_ok:
            return "Click Add in the install prompt, then scan again."
        return ("Click Load Temporary Add-on and choose "
                f"{EXTENSION_DIR / 'manifest.json'}. Firefox removes it when it restarts; "
                "browsers that allow unsigned add-ons (xpinstall.signatures.required = false "
                "in about:config) can keep it.")
    if not st.sandbox_ok:
        return ("Flatpak keeps the browser from starting icp. Allowing it lets the browser "
                "run programs outside its sandbox.")
    return "Click Install to connect the extension to icp."


def launch(argv: list[str]) -> tuple[bool, str]:
    try:
        subprocess.Popen(argv, start_new_session=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    except OSError as e:
        return False, str(e)
    return True, ""


def any_connected(installs=None) -> tuple[int, int]:
    """-> (browsers fully set up, browsers found)."""
    installs = scan() if installs is None else installs
    ready = 0
    for inst in installs:
        st = status(inst)
        ready += st.extension == "installed" and st.host and st.sandbox_ok
    return ready, len(installs)


def manual_command(ext_id: str = "") -> str:
    return f"{shlex.quote(str(REPO / 'host' / 'install.sh'))} {ext_id or '<EXTENSION_ID>'}"
