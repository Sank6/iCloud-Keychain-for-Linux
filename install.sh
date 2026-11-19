#!/usr/bin/env bash
# One-command, per-user install of iCloud Passwords for Linux. No root needed, and re-running it is
# safe: it only adds or refreshes what is missing.
#
#   ./install.sh               install (asks before each system-level thing)
#   ./install.sh -y            don't ask
#   ./install.sh --no-timer    skip the 6-hourly background sync
#
# Anything after the first argument that `icp setup` understands is passed through. To remove
# everything again:  icp uninstall
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
VENV=".venv"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

case "${1:-}" in -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0;; esac

say "Checking prerequisites"
command -v python3 >/dev/null || fail "python3 is not installed (sudo apt install python3)."
python3 - <<'PY' || fail "Python 3.11 or newer is required (found $(python3 --version))."
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
PY
python3 -c 'import venv, ensurepip' 2>/dev/null \
  || fail "python3-venv is missing (sudo apt install python3-venv)."

# The Passwords window and the sign-in dialog need GTK 4 + libadwaita through PyGObject. Everything
# else (browser autofill, the CLI) works without them, so this is a warning, not an error.
if ! python3 -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")' 2>/dev/null; then
  printf '\033[33mnote:\033[0m the GTK app needs:  sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\n'
  printf '      (the command line and browser autofill work without it)\n'
fi
command -v systemctl >/dev/null \
  || printf '\033[33mnote:\033[0m systemd was not found: background sync will not be scheduled.\n'
command -v notify-send >/dev/null || python3 -c 'import gi' 2>/dev/null \
  || printf '\033[33mnote:\033[0m no desktop notifications available: the Apple extension pairing code needs them.\n'

say "Creating the environment ($VENV)"
# --system-site-packages: the GTK bindings come from the distribution, not from pip.
python3 -m venv --system-site-packages "$VENV"
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -e . \
  || fail "pip could not install the dependencies (is the network reachable?)."

say "Setting up the browser, the app and background sync"
"$VENV/bin/icp" setup "$@"

cat <<'EOF'

Done. Next:
  1. Sign in:       icp login --gui
  2. Check:         icp doctor
  3. Open the app:  press Super and type "Passwords"
  Apple's own iCloud Passwords extension: install it from the Chrome Web Store, then re-run
  `icp setup` (or just wait: a watcher patches it for Linux as soon as it appears).
Remove everything later with:  icp uninstall
EOF
