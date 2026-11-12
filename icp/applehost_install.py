"""Register the Apple-extension host (`com.apple.passwordmanager`) for installed Chromium browsers.

Separate from our own host (`org.icp.native`), so both extensions can be installed side by side.
Run: python -m icp.applehost_install"""

from __future__ import annotations

import json
import stat
import sys

from . import hosts

APPLE_HOST_NAME = "com.apple.passwordmanager"
APPLE_EXTENSION_ID = "pejdijmoenmkgeppbflobdenhhabjlaj"   # public Chrome Web Store ID


def launcher() -> "hosts.Path":
    d = hosts.DATA / "icp"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "apple-host"
    p.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m icp.applehost_main\n')
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def install() -> list[tuple[str, "hosts.Path"]]:
    exe = launcher()
    done = []
    for label, kind, nmh in hosts.detected():
        if kind != "chromium":
            continue    # Apple ships no Firefox build of this extension
        nmh.mkdir(parents=True, exist_ok=True)
        f = nmh / f"{APPLE_HOST_NAME}.json"
        f.write_text(json.dumps({
            "name": APPLE_HOST_NAME, "description": "iCloud Passwords host (icp)",
            "path": str(exe), "type": "stdio",
            "allowed_origins": [f"chrome-extension://{APPLE_EXTENSION_ID}/"]}, indent=2) + "\n")
        done.append((label, f))
    return done




# ---- Linux OS gate ----------------------------------------------------------------------------
# Apple's extension only starts when navigator.platform is "MacIntel" or the user agent says
# Windows (checkForValidOS in background.js), so on Linux it never contacts a native host.
# Two ways past that, both verified with Apple's real extension 3.4.0:
#   * "useragent": start the browser with a Windows user agent (--user-agent). The unmodified
#     Chrome Web Store extension then runs and keeps auto-updating; every site in that browser
#     sees a Windows UA.
#   * "patched": a local copy of the user's own installed extension with that one function
#     short-circuited, loaded unpacked. The browser keeps its real UA; the copy must be rebuilt
#     after Apple updates the extension. We never ship Apple's code.
WINDOWS_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/{major}.0.0.0 Safari/537.36")
UA_MARKER = "X-ICP-Windows-UserAgent=true"
DEFAULT_MAJOR = 138

# browser label (icp.hosts) -> its desktop entry ids, first that exists wins
DESKTOP_IDS = {
    "Google Chrome": ["google-chrome.desktop"],
    "Chromium": ["chromium.desktop", "chromium-browser.desktop"],
    "Helium": ["helium.desktop"],
    "Brave": ["brave-browser.desktop"],
    "Microsoft Edge": ["microsoft-edge.desktop"],
    "Vivaldi": ["vivaldi-stable.desktop"],
    "Opera": ["opera.desktop"],
}


def _entry_dirs() -> "list[hosts.Path]":
    import os
    dirs = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    return [hosts.Path(d) / "applications" for d in dirs.split(":") if d]


def system_entry(desktop_id: str) -> "hosts.Path | None":
    """The vendor's desktop entry (never our own override)."""
    for d in _entry_dirs():
        if (d / desktop_id).is_file():
            return d / desktop_id
    return None


def override_path(desktop_id: str) -> "hosts.Path":
    return hosts.DATA / "applications" / desktop_id


def windows_ua_active(desktop_id: str) -> bool:
    p = override_path(desktop_id)
    return p.is_file() and UA_MARKER in p.read_text()


def windows_ua_entry(desktop_id: str, major: int = DEFAULT_MAJOR) -> "hosts.Path":
    """Write ~/.local/share/applications/<id> = the vendor entry with --user-agent on every Exec
    line (it shadows the system entry, so the app grid / Activities start the browser that way).
    Remove it with `restore_entry`. Raises FileNotFoundError when the browser has no entry."""
    src = system_entry(desktop_id)
    if src is None:
        raise FileNotFoundError(desktop_id)
    flag = f'--user-agent="{WINDOWS_UA.format(major=major)}"'
    out = []
    for line in src.read_text().splitlines():
        if line.startswith("Exec="):
            cmd, _, rest = line[5:].partition(" ")
            line = f"Exec={cmd} {flag}" + (f" {rest}" if rest else "")
        out.append(line)
        if line == "[Desktop Entry]":
            out.append(UA_MARKER)
    dest = override_path(desktop_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(out) + "\n")
    return dest


def restore_entry(desktop_id: str) -> bool:
    """Delete our override so the vendor's entry is used again. Only ever removes a file we wrote."""
    p = override_path(desktop_id)
    if p.is_file() and UA_MARKER in p.read_text():
        p.unlink()
        return True
    return False


def browser_major(binary: str) -> int | None:
    """Chromium major version, so the claimed UA is not suspiciously old."""
    import re
    import subprocess
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Chromium (\d+)\.", out) or re.search(r"(\d+)\.\d+\.\d+\.\d+", out)
    return int(m.group(1)) if m else None


def exec_binary(desktop_id: str) -> str | None:
    src = override_path(desktop_id) if windows_ua_active(desktop_id) else system_entry(desktop_id)
    if src is None or not src.is_file():
        return None
    for line in src.read_text().splitlines():
        if line.startswith("Exec="):
            return line[5:].split()[0] if line[5:].split() else None
    return None


def running_without_windows_ua(binary: str, proc="/proc") -> bool:
    """True when `binary` is running (its main process, not a renderer) without our --user-agent.
    A browser that keeps running in the background reuses that process for every new window and
    ignores a flag on the new command line, so the Windows UA silently never applies."""
    import os
    main = []
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        try:
            with open(f"{proc}/{pid}/comm") as f:
                comm = f.read().strip()
            with open(f"{proc}/{pid}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        if comm == os.path.basename(binary)[:15] and not any(a.startswith(b"--type=") for a in argv):
            main.append(argv)
    return bool(main) and not any(any(a.startswith(b"--user-agent=") for a in argv) for argv in main)


def status() -> dict:
    """Where the Apple-extension integration stands (no network, nothing written):
    {"hosts": [(browser, ok, problem)], "mode": "useragent"|"patched"|None,
     "entries": [desktop ids with the Windows UA], "patched_copy": Path|None,
     "store_extension": Path|None}"""
    out_hosts = []
    for label, kind, nmh in hosts.detected():
        if kind != "chromium":
            continue
        f = nmh / f"{APPLE_HOST_NAME}.json"
        problem = ""
        if not f.exists():
            problem = "host manifest missing"
        else:
            try:
                m = json.loads(f.read_text())
                path = hosts.Path(m.get("path", ""))
                if not path.is_file() or not path.stat().st_mode & stat.S_IXUSR:
                    problem = f"launcher {path} is missing or not executable"
                elif f"chrome-extension://{APPLE_EXTENSION_ID}/" not in m.get("allowed_origins", []):
                    problem = "manifest does not allow Apple's extension id"
            except ValueError:
                problem = "host manifest is not valid JSON"
        out_hosts.append((label, not problem, problem))
    entries = [did for _, did in desktop_ids_for_detected() if windows_ua_active(did)]
    stale = [did for did in entries
             if (b := exec_binary(did)) and running_without_windows_ua(b)]
    patched = hosts.DATA / "icp" / "apple-extension"
    patched_ok = patched if (patched / "background.js").exists() else None
    return {"hosts": out_hosts,
            "mode": "useragent" if entries else ("patched" if patched_ok else None),
            "entries": entries, "running_without_ua": stale, "patched_copy": patched_ok, "store_extension": find_installed()}


def desktop_ids_for_detected() -> list[tuple[str, str]]:
    """[(browser label, desktop id)] for installed Chromium browsers that have a desktop entry."""
    out = []
    for label, kind, _nmh in hosts.detected():
        if kind == "chromium":
            for did in DESKTOP_IDS.get(label, []):
                if system_entry(did) or override_path(did).is_file():
                    out.append((label, did))
                    break
    return out
GATE = "function checkForValidOS(){"
PATCH = GATE + 'return g_urlToDownloadNativeSupport="https://www.apple.com/macos",!0;'


def find_installed() -> "hosts.Path | None":
    import glob
    pat = str(hosts.CFG / "*" / "*" / "Extensions" / APPLE_EXTENSION_ID / "*")
    found = sorted(glob.glob(pat))
    return hosts.Path(found[-1]) if found else None


def patch_extension(src=None, dest=None) -> "hosts.Path":
    import shutil
    src = hosts.Path(src) if src else find_installed()
    if not src or not (src / "background.js").exists():
        raise SystemExit("The official iCloud Passwords extension is not installed in a "
                         "Chromium profile under ~/.config.")
    dest = hosts.Path(dest) if dest else hosts.DATA / "icp" / "apple-extension"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    js = dest / "background.js"
    text = js.read_text()
    if text.count(GATE) != 1:
        shutil.rmtree(dest)
        raise SystemExit("Unrecognised extension version: the OS check was not found exactly "
                         "once, so nothing was patched.")
    js.write_text(text.replace(GATE, PATCH, 1))
    shutil.rmtree(dest / "_metadata", ignore_errors=True)   # signature data no longer matches
    return dest


if __name__ == "__main__":
    if sys.argv[1:] == ["patch-extension"]:
        out = patch_extension()
        print(f"Patched copy written to {out}\nLoad it in chrome://extensions (Developer mode -> "
              "Load unpacked) and turn the store version off: both share one extension ID.")
    else:
        for label, f in install():
            print(f"{label}: {f}")
