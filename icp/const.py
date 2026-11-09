"""Static identity strings used to impersonate a Mac to Apple's GrandSlam service.

These mirror what AltServer / pypush send. Apple tracks some of these, so they are
kept stable and Mac-like. The volatile per-request machine data (X-Apple-I-MD*) comes
from the anisette server, not from here.
"""

# Sent as the GsService2 User-Agent.
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

# AuthKit device description used by GrandSlam and its 2FA endpoints.
GSA_CLIENT_INFO = (
    "<PC> <Windows;6.2(0,0);9200> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Default anisette server (SideStore ecosystem). Override with ICP_ANISETTE_URL.
DEFAULT_ANISETTE_URL = "http://localhost:6969"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"

# Browser-extension id. Fixed because extension/manifest.json carries the matching public `key`
# (the private key is extension.pem, which must never be committed).
EXTENSION_ID = "oienjgojkmebeibfajgflpaajlaaolkg"
# Firefox add-on id; must match browser_specific_settings.gecko.id in the manifest.
GECKO_ID = "icp-linux@local"
HOST_NAME = "org.icp.native"
