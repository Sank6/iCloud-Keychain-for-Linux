"""Static identity strings used to impersonate a Mac to Apple's GrandSlam service.

These mirror what AltServer / pypush send. Apple tracks some of these, so they are
kept stable and Mac-like. The volatile per-request machine data (X-Apple-I-MD*) comes
from the anisette server, not from here.
"""

# Sent as the GsService2 User-Agent.
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

# AuthKit device description used by GrandSlam and its 2FA endpoints.
GSA_CLIENT_INFO = (
    "<MacBookPro13,2> <Mac OS X;10.15.2;19C57> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# Default anisette server (SideStore ecosystem). Override with ICP_ANISETTE_URL.
DEFAULT_ANISETTE_URL = "http://localhost:6969"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
