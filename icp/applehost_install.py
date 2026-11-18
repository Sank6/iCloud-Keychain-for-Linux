"""Apple's own "iCloud Passwords" extension on Linux.

Two jobs: register the native host it talks to (`com.apple.passwordmanager`, separate from our own
`org.icp.native`), and get the extension past its OS check. Apple's extension only starts when
`navigator.platform` is "MacIntel" or the user agent says Windows (`checkForValidOS` in
background.js), so on Linux it never contacts a host. We change that one function in the user's
own installed copy, in place (verified on Helium/Chromium 157 with the signature data kept, with
Developer mode on or off). The original file is saved first, `restore_in_place` puts it back, and a
systemd path unit re-applies the patch when Apple updates the extension. Apple's code is never
shipped in this repo. Browsers that enforce extension content verification reject an edited store
extension; `patch_unpacked_copy` builds a separate copy to load unpacked instead.

Run: python -m icp.applehost_install [patch|restore|status|unpacked]"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import time

from . import hosts, paths

APPLE_HOST_NAME = "com.apple.passwordmanager"
APPLE_EXTENSION_ID = "pejdijmoenmkgeppbflobdenhhabjlaj"   # public Chrome Web Store ID


def launcher() -> "hosts.Path":
    return paths.write_private(paths.private_dir(hosts.DATA / "icp") / "apple-host",
                               f'#!/bin/sh\nexec "{sys.executable}" -m icp.applehost_main\n',
                               executable=True)


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


# ---- the OS gate ------------------------------------------------------------------------------
GATE = "function checkForValidOS(){"
PATCH = GATE + 'return g_urlToDownloadNativeSupport="https://www.apple.com/macos",!0;'
BACKUPS = hosts.DATA / "icp" / "apple-extension-orig"
UNPACKED = hosts.DATA / "icp" / "apple-extension"


def profiles() -> "list[tuple[str, hosts.Path]]":
    """[(browser label, profile dir)] for every Chromium profile that has an Extensions folder."""
    out = []
    for label, kind, nmh in hosts.detected():
        if kind != "chromium":
            continue
        for prof in sorted(nmh.parent.iterdir()) if nmh.parent.is_dir() else []:
            if (prof / "Extensions").is_dir():
                out.append((label, prof))
    return out


def extension_dirs() -> "list[hosts.Path]":
    """Every installed version folder of Apple's extension, in every profile."""
    found = []
    for _label, prof in profiles():
        base = prof / "Extensions" / APPLE_EXTENSION_ID
        if base.is_dir() and not base.is_symlink():
            # A symlinked version folder could point anywhere: never follow it to edit a file
            found += [v for v in sorted(base.iterdir())
                      if not v.is_symlink() and (v / "background.js").is_file()]
    return found


def find_installed() -> "hosts.Path | None":
    dirs = extension_dirs()
    return dirs[-1] if dirs else None


def _version(folder) -> str | None:
    try:
        return json.loads((hosts.Path(folder) / "manifest.json").read_text()).get("version")
    except (OSError, ValueError):
        return None


def file_state(folder) -> str:
    """"patched", "stock" (gate found exactly once, untouched) or "unknown" (another version)."""
    js = hosts.Path(folder) / "background.js"
    try:
        if js.is_symlink():
            return "unknown"            # not a file the browser unpacked: leave it alone
        text = js.read_text()
    except OSError:
        return "unknown"
    if PATCH in text:
        return "patched"
    return "stock" if text.count(GATE) == 1 else "unknown"


def patch_in_place(wait: float = 0) -> list[tuple["hosts.Path", str]]:
    """Patch every installed copy of the extension. Results: "patched", "already" or "unknown".
    With `wait`, poll that many seconds for a copy to appear and finish unpacking (the browser
    writes a new version while the path unit is already running)."""
    deadline = time.monotonic() + wait
    while True:
        dirs = [d for d in extension_dirs() if _version(d)]
        if dirs or time.monotonic() >= deadline:
            break
        time.sleep(1)
    results = []
    for d in dirs:
        state = file_state(d)
        if state == "stock":
            js = d / "background.js"
            text = js.read_text()
            keep = BACKUPS / (_version(d) or "unknown")
            paths.private_dir(keep)
            if not (keep / "background.js").exists():
                shutil.copy2(js, keep / "background.js")
            tmp = js.with_name("background.js.icp-new")
            tmp.write_text(text.replace(GATE, PATCH, 1))
            shutil.copymode(js, tmp)
            os.replace(tmp, js)
            state = "patched"
        else:
            state = "already" if state == "patched" else "unknown"
        results.append((d, state))
    return results


def restore_in_place() -> list["hosts.Path"]:
    """Put the saved original background.js back in every copy we patched."""
    restored = []
    for d in extension_dirs():
        saved = BACKUPS / (_version(d) or "unknown") / "background.js"
        if file_state(d) == "patched" and saved.is_file():
            shutil.copy2(saved, d / "background.js")
            restored.append(d)
    return restored


def patch_unpacked_copy(dest=None, src=None) -> "hosts.Path":
    """Fallback for browsers that reject an edited store extension: a separate patched copy to
    load with Developer mode -> Load unpacked (it keeps Apple's extension id)."""
    src = hosts.Path(src) if src else find_installed()
    if not src:
        raise SystemExit("The official iCloud Passwords extension is not installed in a "
                         "Chromium profile under ~/.config.")
    dest = hosts.Path(dest) if dest else UNPACKED
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


def disabled_by_browser() -> list[str]:
    """Profiles whose browser disabled the extension (e.g. content verification). Reads each
    profile's Preferences; nothing is written."""
    bad = []
    for label, prof in profiles():
        try:
            prefs = json.loads((prof / "Preferences").read_text())
            entry = prefs["extensions"]["settings"][APPLE_EXTENSION_ID]
        except (OSError, ValueError, KeyError):
            continue
        if entry.get("disable_reasons") or entry.get("state") == 0:
            bad.append(f"{label}/{prof.name}")
    return bad


def status() -> dict:
    """Where the Apple-extension integration stands (no network, nothing written):
    {"hosts": [(browser, ok, problem)], "installed": [(folder, state)], "mode": "inplace" |
     "unpacked" | None, "outdated_copy": (patched_version, store_version) | None,
     "disabled": [profiles], "unpacked_copy": Path | None}"""
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
    installed = [(d, file_state(d)) for d in extension_dirs()]
    unpacked = UNPACKED if (UNPACKED / "background.js").exists() else None
    mode = None
    if installed and all(state == "patched" for _d, state in installed):
        mode = "inplace"
    elif unpacked:
        mode = "unpacked"
    outdated = None
    if mode == "unpacked" and installed:
        have, new = _version(unpacked), _version(installed[-1][0])
        if have and new and have != new:
            outdated = (have, new)
    return {"hosts": out_hosts, "installed": installed, "mode": mode, "outdated_copy": outdated,
            "disabled": disabled_by_browser() if mode == "inplace" else [],
            "unpacked_copy": unpacked}


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "patch":
        for folder, state in patch_in_place():
            print(f"{state}: {folder}")
    elif arg == "restore":
        for folder in restore_in_place():
            print(f"restored: {folder}")
    elif arg == "unpacked":
        out = patch_unpacked_copy()
        print(f"Patched copy written to {out}\nLoad it in the extensions page (Developer mode -> "
              "Load unpacked) and turn the store version off: both share one extension ID.")
    else:
        for label, f in install():
            print(f"{label}: {f}")
