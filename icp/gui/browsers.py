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
import threading
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
            legacy = self.root / self.spec.data
            if self.spec.data.startswith(".mozilla/"):
                # Firefox 147+ keeps new profiles under $XDG_CONFIG_HOME/mozilla.
                xdg = self.root / ".config" / "mozilla" / self.spec.data.split("/", 1)[1]
                if xdg.is_dir() or not legacy.is_dir():
                    return xdg if xdg.is_dir() else legacy
            return legacy
        if self.kind == FLATPAK:
            return self.root / "config" / self.spec.data
        if self.kind == SNAP:
            return self.root / self.spec.data
        return self.root / ".config" / self.spec.data

    def host_dirs(self) -> list[Path]:
        if self.spec.family == CHROMIUM:
            return [self.data_dir() / "NativeMessagingHosts"]
        # Firefox reads ~/.mozilla/native-messaging-hosts, or ~/.config/mozilla/... once it has
        # moved to XDG directories; forks read their own dot-dir. Write to all of them.
        dirs = [self.root / self.spec.data.split("/")[0] / "native-messaging-hosts",
                self.root / ".mozilla" / "native-messaging-hosts",
                self.root / ".config" / "mozilla" / "native-messaging-hosts"]
        return list(dict.fromkeys(dirs))


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
    temporary: bool = False     # Firefox: loaded as a temporary add-on (gone after a restart)


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


def _firefox_extension(inst: Install) -> tuple[str, bool]:
    """-> (state, loaded as a temporary add-on)."""
    state = "missing"
    for f in inst.data_dir().glob("*/extensions.json"):
        for addon in (_read_json(f) or {}).get("addons", []):
            if addon.get("id") == GECKO_ID:
                if addon.get("active"):
                    return "installed", addon.get("location") == "app-temporary"
                state = "disabled"
    return state, False


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
        (ext, temporary), ext_id = _firefox_extension(inst), GECKO_ID
        unsigned = unsigned_allowed(inst)
    wanted = f"chrome-extension://{ext_id}/" if inst.spec.family == CHROMIUM else GECKO_ID
    key = "allowed_origins" if inst.spec.family == CHROMIUM else "allowed_extensions"
    host = all(
        wanted in (m.get(key) or []) and Path(m.get("path", "")).exists()
        for m in [_read_json(d / f"{HOST_NAME}.json") or {} for d in inst.host_dirs()])
    sandbox_ok = flatpak_talk_granted(inst.spec.flatpak) if inst.kind == FLATPAK else True
    return Status(ext, ext_id, host, sandbox_ok, unsigned,
                  temporary if inst.spec.family == FIREFOX else False)


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
    return [*inst.launch, "--new-window"]


def guided(inst: Install, st: Status) -> bool:
    """Whether adding the extension needs the step-by-step window (pasting an internal page
    address), rather than an install prompt the browser shows by itself."""
    return inst.spec.family == CHROMIUM or not st.unsigned_ok


FIREFOX_DEBUG_URL = "about:debugging#/runtime/this-firefox"


def next_step(inst: Install, st: Status) -> str:
    """What the user still has to do in the browser, in one sentence or two."""
    if st.extension == "installed" and st.host and st.sandbox_ok:
        if st.temporary:
            return ("Ready until Firefox restarts - it removes temporary add-ons when it quits, "
                    "so add it again after a restart.")
        return "Ready - click the extension's toolbar icon on a login page."
    if st.extension == "disabled":
        return f"The extension is turned off - enable it on {inst.spec.name}'s extensions page."
    if st.extension == "missing":
        if inst.spec.family == CHROMIUM:
            return (f"Click Add extension for step-by-step help: open {extensions_url(inst)}, "
                    f"turn on Developer mode, click Load unpacked and choose {EXTENSION_DIR}.")
        if st.unsigned_ok:
            return "Click Add in the install prompt, then scan again."
        return (f"Click Add extension: {inst.spec.name} only keeps add-ons signed by Mozilla, "
                "so you can add it temporarily (until it restarts) or permanently.")
    if not st.sandbox_ok:
        return ("Flatpak keeps the browser from starting icp. Allowing it lets the browser "
                "run programs outside its sandbox.")
    return "Click Install to connect the extension to icp."


def launch(argv: list[str]) -> tuple[bool, str]:
    try:
        p = subprocess.Popen(argv, start_new_session=True, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    except OSError as e:
        return False, str(e)
    # Reap it when it exits (browsers often hand off to a running instance and quit at once),
    # so it doesn't linger as a zombie for as long as the app runs.
    threading.Thread(target=p.wait, daemon=True).start()
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


# --- keeping the add-on in Firefox-family browsers -----------------------------------------
#
# Release Firefox only keeps add-ons signed by Mozilla, and is built so that turning off
# xpinstall.signatures.required does nothing (MOZ_REQUIRE_SIGNING). Forks and Developer/Nightly
# builds honour that preference. Distribution builds (Arch, Debian, ...) also accept unsigned
# add-ons from the system-wide extensions folder (MOZ_UNSIGNED_SYSTEM_SCOPE), where distro
# packages put add-ons; installing there needs admin rights.

FIREFOX_APP_ID = "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"
SYSTEM_EXTENSIONS = Path("/usr/lib/mozilla/extensions") / FIREFOX_APP_ID


def install_dir(inst: Install) -> Path | None:
    """The browser's program folder (where omni.ja lives), following wrapper scripts."""
    if not inst.launch or inst.kind != SYSTEM:
        return None
    exe = Path(os.path.realpath(inst.launch[0]))
    candidates = [exe.parent]
    try:
        head = exe.read_bytes()[:4096]
        if head.startswith(b"#!"):  # e.g. /usr/bin/firefox: exec /usr/lib/firefox/firefox "$@"
            for word in head.decode(errors="replace").split():
                word = word.strip('"\'')
                if word.startswith("/") and not word.startswith(("/bin/", "/usr/bin/env")):
                    candidates.append(Path(os.path.realpath(word)).parent)
    except OSError:
        pass
    return next((d for d in candidates if (d / "omni.ja").exists()), None)


def build_flags(inst: Install) -> dict:
    """MOZ_* build constants that decide how unsigned add-ons are treated; {} if unknown."""
    d = install_dir(inst)
    if d is None or not shutil.which("unzip"):
        return {}
    try:  # omni.ja is an "optimized" jar that Python's zipfile can't read; unzip copes
        p = subprocess.run(["unzip", "-p", str(d / "omni.ja"), "modules/AppConstants.sys.mjs"],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {}
    flags = {}
    for name in ("MOZ_REQUIRE_SIGNING", "MOZ_UNSIGNED_SYSTEM_SCOPE", "MOZ_UNSIGNED_APP_SCOPE"):
        for line in p.stdout.splitlines():
            if line.strip().startswith(f"{name}:"):
                flags[name] = "true" in line
                break
    return flags


@dataclasses.dataclass
class KeepOption:
    kind: str        # "pref" (turn off the signature check) | "system" (system folder) | ""
    title: str
    warning: str
    command: str = ""


def keep_option(inst: Install) -> KeepOption:
    """How the add-on can stay installed in this Firefox-family browser, if at all."""
    flags = build_flags(inst)
    enforced = flags.get("MOZ_REQUIRE_SIGNING", inst.spec.key == "firefox")
    if not enforced:
        return KeepOption(
            "pref", "Turn off the add-on signature check",
            f"{inst.spec.name} will then install add-ons that Mozilla hasn't reviewed - not just "
            "this one. Only install add-on files you trust while it's off. It's set in each "
            f"profile's user.js and takes effect after {inst.spec.name} restarts.")
    if inst.spec.key == "firefox" and flags.get("MOZ_UNSIGNED_SYSTEM_SCOPE"):
        dest = SYSTEM_EXTENSIONS / f"{GECKO_ID}.xpi"
        return KeepOption(
            "system", "Install for all users (system add-on folder)",
            "This Firefox can't turn off its signature check (Mozilla builds it in), but it "
            "loads unsigned add-ons from the system-wide folder where Linux packages put "
            "add-ons. That skips Mozilla's review for this add-on, applies to every user on "
            "this computer, and needs your admin password. After restarting Firefox, enable it "
            "once when Firefox asks (or in about:addons). Re-run this after updating icp.",
            f"sudo install -Dm644 {shlex.quote(str(build_xpi()))} {shlex.quote(str(dest))}")
    return KeepOption("", "", f"{inst.spec.name} only keeps add-ons signed by Mozilla, so the "
                              "extension can only be added as a temporary add-on.")


def turn_off_signing(inst: Install) -> int:
    """Add xpinstall.signatures.required = false to each profile's user.js; -> profiles."""
    line = 'user_pref("xpinstall.signatures.required", false);'
    done = 0
    for prefs in inst.data_dir().glob("*/prefs.js"):
        user = prefs.parent / "user.js"
        try:
            text = user.read_text() if user.exists() else ""
            if line not in text:
                with user.open("a") as f:
                    f.write(("\n" if text and not text.endswith("\n") else "") +
                            "// Added by icp-gui: allow the unsigned iCloud Passwords add-on\n"
                            f"{line}\n")
            done += 1
        except OSError:
            continue
    return done


def system_install(inst: Install) -> tuple[bool, str]:
    """Copy the packaged add-on into the system extensions folder via pkexec (admin prompt)."""
    if not shutil.which("pkexec"):
        return False, "pkexec isn't available - copy the command and run it in a terminal"
    xpi = build_xpi()
    dest = SYSTEM_EXTENSIONS / f"{GECKO_ID}.xpi"
    try:
        p = subprocess.run(["pkexec", "install", "-Dm644", str(xpi), str(dest)],
                           capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    if p.returncode != 0:
        return False, (p.stderr or p.stdout).strip() or "cancelled"
    return True, str(dest)


def system_installed() -> bool:
    return (SYSTEM_EXTENSIONS / f"{GECKO_ID}.xpi").exists()
