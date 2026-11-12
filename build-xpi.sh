#!/usr/bin/env bash
# Build the extension as an XPI - the package addons.mozilla.org signs.
#
# The XPI is a plain zip of the extension's own files. The native-messaging host is NOT
# part of it: an add-on cannot ship a native host, so the host is installed on the machine
# separately with host/install.sh.
#
# Works both in this repository (the extension files are at the top) and in the icp
# repository (they are in extension/).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/dist}"

if [ -f "$HERE/manifest.json" ]; then
  EXT_DIR="$HERE"
elif [ -f "$HERE/extension/manifest.json" ]; then
  EXT_DIR="$HERE/extension"
else
  echo "no manifest.json found next to this script or in extension/" >&2
  exit 1
fi

NAME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"].lower().replace(" ", "-"))' "$EXT_DIR/manifest.json")"
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$EXT_DIR/manifest.json")"
XPI="$OUT/$NAME-$VERSION.xpi"

mkdir -p "$OUT"
rm -f "$XPI"

# The extension's own files, and nothing else: no README, no host/, no repository.
cd "$EXT_DIR"
zip -q -X "$XPI" manifest.json background.js content.js popup.html popup.js

echo "built $XPI"
unzip -l "$XPI" | sed 's/^/  /'
