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
# Windows (checkForValidOS in background.js), so on Linux it never contacts a native host. The only
# non-spoofing fix is a local copy with that one function short-circuited. We never ship Apple's
# code: the copy is built from the user's own installed extension under ~/.local/share/icp.
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
