"""Static identity strings used to impersonate a Mac to Apple's GrandSlam service.

These mirror what AltServer / pypush send. Apple tracks some of these, so they are
kept stable and Mac-like. The volatile per-request machine data (X-Apple-I-MD*) comes
from the anisette server, not from here.
"""

# Sent as the GsService2 User-Agent.
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

# Fallback AuthKit device description, used only when the anisette server does not report the
# identity its data was generated for (it normally does: /v3/client_info). It must describe the
# SAME machine as the anisette data: Apple rejects a mismatch (e.g. a Windows string with
# Mac-generated X-Apple-I-MD). The default v3 server generates Mac data, so this is Mac-like.
GSA_CLIENT_INFO = (
    "<MacBookPro13,2> <macOS;13.1;22C65> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Apple requires the claimed client to match the anisette's origin (-80045 otherwise, since
# 2026-10-12). The local dadoum server generates data with Apple's Android libraries but reports
# a MacBook, so for a loopback server we claim Android.
ANDROID_CLIENT_INFO = (
    "<Pixel 7> <Android;14;UQ1A.240205.002> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Claimed to Apple when the anisette comes from a real-Mac v3 server. Those servers report a
# 2016 MacBook Pro on macOS 10.12.6; Apple refuses that for accounts with Advanced Data Protection
# (needs macOS >= 13.1): "Can't Use Your Apple ID on This Device", no trusted-device 2FA code.
MAC_CLIENT_INFO = (
    "<Mac15,7> <macOS;14.5;23F79> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Default anisette server: loopback only. Override with --anisette, ICP_ANISETTE_URL or
# `anisette_url` in ~/.config/icp/config.toml (see icp/config.py).
ANISETTE_PORT = 6969
DEFAULT_ANISETTE_URL = f"http://127.0.0.1:{ANISETTE_PORT}"
ANISETTE_IMAGE = "docker.io/dadoum/anisette-v3-server:latest"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"

# Since ~2026-10-29 Apple's edge firewall answers an HTML 403 for the plist Content-Types
# sideloaders used (text/x-xml-plist, application/x-xml-plist). text/xml passes on every
# GrandSlam host and Apple parses the body identically.
GSA_CONTENT_TYPE = "text/xml"

# Browser-extension id. Fixed because extension/manifest.json carries the matching public `key`
# (the private key is extension.pem, which must never be committed).
EXTENSION_ID = "oienjgojkmebeibfajgflpaajlaaolkg"
# Firefox add-on id; must match browser_specific_settings.gecko.id in the manifest.
GECKO_ID = "icp-linux@local"
HOST_NAME = "org.icp.native"
