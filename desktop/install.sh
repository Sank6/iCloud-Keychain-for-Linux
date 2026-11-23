#!/usr/bin/env bash
# Add "iCloud Passwords" (icp-gui) to the desktop's application launcher.
#
# Usage: desktop/install.sh
# Uses this repo's .venv if present, else an `icp-gui` on PATH. If ICP_ANISETTE_URL is set when
# you run this, it is baked into the launcher so `Sync now` works when started from the menu,
# where shell variables aren't set. Re-run after moving the repo or changing the URL.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/.venv/bin/icp-gui"
[ -x "$BIN" ] || BIN="$(command -v icp-gui || true)"
if [ -z "$BIN" ]; then
  echo "icp-gui not found - install it first: .venv/bin/pip install -e '.[gui]'" >&2
  exit 1
fi

EXEC="$BIN"
if [ -n "${ICP_ANISETTE_URL:-}" ]; then
  EXEC="env ICP_ANISETTE_URL=$ICP_ANISETTE_URL $BIN"
else
  echo "note: ICP_ANISETTE_URL is not set; Sync now will only work if it is set in your session." >&2
fi

DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DIR"
sed -e "s#__EXEC__#$EXEC#" "$REPO/desktop/icp-gui.desktop.template" > "$DIR/icp-gui.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DIR" || true
echo "installed: $DIR/icp-gui.desktop"
