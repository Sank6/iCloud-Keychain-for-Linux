#!/usr/bin/env bash
# Launcher for the native-messaging host. The browser execs this with the extension's stdio.
# Pick an interpreter that can import `icp`: the repo venv if present, else the venv behind an
# installed `icp` entry point (uv tool / pipx), else whatever python3 is on PATH. The last case
# matters in containers/flatpaks where the repo venv is absent but an `icp` install is shared.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The master key of the vault lives in the GNOME keyring, which is reached over the session bus.
# A browser spawns this host without DBUS_SESSION_BUS_ADDRESS in its environment, so the keyring
# would be unreachable and the vault would decrypt with a different key - showing an empty
# password list. Point at the session bus explicitly when it is missing.
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  for bus in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus" "/run/user/$(id -u)/bus"; do
    if [ -S "$bus" ]; then
      export DBUS_SESSION_BUS_ADDRESS="unix:path=$bus"
      break
    fi
  done
fi

PY="$REPO/.venv/bin/python"
if [ ! -x "$PY" ]; then
  for entry in "$HOME/.local/bin/icp" icp; do
    path="$(command -v "$entry" 2>/dev/null)" || continue
    shebang="$(sed -n '1s/^#!//p' "$path")"
    [ -x "$shebang" ] && { PY="$shebang"; break; }
  done
fi
[ -x "$PY" ] || PY="$(command -v python3)"

exec "$PY" -m icp.vault.host
