"""Identity strings and constants for Apple's authentication services.

Apple requires the client identity it is told (X-Mme-Client-Info) to describe the SAME machine
the anisette data came from; a mismatch is rejected ("-80045", "Apple ID or password entered
incorrectly"). The anisette client therefore decides the claimed device; this module only holds
the fallbacks and fixed values.
"""

XCODE_VERSION = "27.0 (27A5218g)"

# Claimed when the anisette data comes from Apple's Android libraries (our local Docker server
# reports a MacBook; Apple rejects that mismatch).
ANDROID_CLIENT_INFO = (
    "<Pixel 7> <Android;14;UQ1A.240205.002> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Claimed with real-Mac v3 anisette. Those servers report a 2016 MacBook Pro on macOS 10.12.6;
# Apple refuses that for accounts with Advanced Data Protection (needs macOS >= 13.1) with
# "Can't Use Your Apple ID on This Device" and sends no trusted-device 2FA code.
MAC_CLIENT_INFO = (
    "<Mac15,7> <macOS;14.5;23F79> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Since ~2026-10-29 Apple's edge firewall answers an HTML 403 for the plist Content-Types
# sideloaders used (text/x-xml-plist, application/x-xml-plist). text/xml passes on every
# GrandSlam host and Apple parses the body identically.
GSA_CONTENT_TYPE = "text/xml"

# Default anisette server: loopback only. Override with --anisette, ICP_ANISETTE_URL or
# `anisette_url` in ~/.config/icp/config.toml (see icp/config.py).
ANISETTE_PORT = 6969
DEFAULT_ANISETTE_URL = f"http://127.0.0.1:{ANISETTE_PORT}"
ANISETTE_IMAGE = "docker.io/dadoum/anisette-v3-server:latest"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"

# Browser-extension id. Fixed because extension/manifest.json carries the matching public `key`
# (the private key is extension.pem, which must never be committed).
EXTENSION_ID = "oienjgojkmebeibfajgflpaajlaaolkg"
# Firefox add-on id; must match browser_specific_settings.gecko.id in the manifest.
GECKO_ID = "icp-linux@local"
HOST_NAME = "org.icp.native"
