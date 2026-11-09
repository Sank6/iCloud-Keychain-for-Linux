#!/usr/bin/env bash
# Build icp-linux_<ver>_amd64.deb without installing anything (no sudo needed to BUILD it).
# Layout: Python package in /usr/lib/icp (own dir, not dist-packages, so system Python is untouched),
# Rust agent+shim in /usr/lib/icp, a /usr/bin/icp launcher, the extension in /usr/share/icp.
# Python deps come from Debian packages; after install each user runs `icp setup`.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VER="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml" | head -1)"
OUT="${1:-$REPO/dist}"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/icp-linux_${VER}_amd64"

(cd "$REPO/native/icp-agent" && cargo build --release --quiet)
(cd "$REPO/native/icp-shim" && cargo build --release --quiet)

install -d "$ROOT/DEBIAN" "$ROOT/usr/lib/icp" "$ROOT/usr/bin" "$ROOT/usr/share/icp" "$ROOT/usr/share/doc/icp-linux"
cp -r "$REPO/icp" "$ROOT/usr/lib/icp/icp"
find "$ROOT" -name __pycache__ -type d -prune -exec rm -rf {} +
install -m755 "$REPO/native/icp-agent/target/release/icp-agent" "$ROOT/usr/lib/icp/icp-agent"
install -m755 "$REPO/native/icp-shim/target/release/icp-shim" "$ROOT/usr/lib/icp/icp-shim"
cp -r "$REPO/extension" "$ROOT/usr/share/icp/extension"
install -m644 "$REPO/LICENSE.md" "$ROOT/usr/share/doc/icp-linux/copyright"
cat > "$ROOT/usr/bin/icp" <<'SH'
#!/bin/sh
PYTHONPATH=/usr/lib/icp exec python3 -m icp.cli.app "$@"
SH
chmod 755 "$ROOT/usr/bin/icp"
cat > "$ROOT/DEBIAN/control" <<CTL
Package: icp-linux
Version: $VER
Section: utils
Priority: optional
Architecture: amd64
Depends: python3 (>= 3.10), python3-requests, python3-srp, python3-cryptography, python3-nacl, python3-secretstorage, python3-gi, gir1.2-adw-1, gir1.2-gtk-4.0, gnome-keyring
Maintainer: local build <nobody@localhost>
Description: Unofficial iCloud Keychain client for Linux
 Autofill extension, native host (Rust agent + shim), keyring mirror and a GTK
 Passwords app. Not affiliated with Apple. Run "icp setup" after installing.
CTL
mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$ROOT" "$OUT/icp-linux_${VER}_amd64.deb" >/dev/null
echo "built $OUT/icp-linux_${VER}_amd64.deb"
