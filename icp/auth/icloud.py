"""Reach iCloud services with the long-lived mmeAuthToken (no password, no 2FA): loginDelegates
mints it from a fresh PET, get_account_settings returns the service-URL map. See RESEARCH.md."""

import base64
import logging
import plistlib as plist

import urllib3

from .. import net
from .anisette import Anisette
from .device import Device
from .headers import identity_headers
from .. import const
from ..errors import AppleError

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

LOGIN_DELEGATES_URL = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
ACCOUNT_SETTINGS_URL = "https://setup.icloud.com/setup/get_account_settings"

# Windows AOSKit/accountsd identity for both iCloud setup endpoints.
ICLOUD_USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
ICLOUD_CLIENT_INFO = (
    "<PC> <Windows;6.2(0,0);9200> "
    "<com.apple.AOSKit/282 (com.apple.accountsd/113)>"
)


class ICloudError(AppleError):
    def __init__(self, message: str = "", *, retry_after: float | None = None, kind: str = ""):
        super().__init__(message)
        self.retry_after = retry_after
        self.kind = kind   # icp.net error kind when the HTTP layer failed ("blocked", "network", ...)


def _post(what: str, url: str, **kw):
    try:
        return net.request("post", url, **kw)
    except net.AppleNetError as e:
        raise ICloudError(f"{what}: {e}", retry_after=e.retry_after, kind=e.kind) from e


class ICloudAuthExpired(ICloudError):
    """The mmeAuthToken itself is no longer accepted (HTTP 401) - only a sign-in repairs it."""


def _basic(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def login_mobileme(username: str, pet: str, adsid: str, client_id: str,
                   device: Device, anisette: Anisette,
                   url: str = LOGIN_DELEGATES_URL) -> tuple[str, str, dict, dict]:
    """Exchange the fresh PET for the persistent mmeAuthToken.
    Returns (dsid, mme_auth_token, service_data, raw_response)."""
    body = plist.dumps({
        "apple-id": username,
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": client_id,
    })
    # Same device identity as GSA, so loginDelegates sees the device that just passed 2FA.
    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": ICLOUD_USER_AGENT,
        "Accept": "*/*",
    }
    headers.update(identity_headers(device, anisette))
    headers["X-Mme-Client-Info"] = const.with_device(ICLOUD_CLIENT_INFO, anisette.client_info)
    headers["Authorization"] = _basic(username, pet)  # apple-id:PET (NOT dsid:PET)

    resp = _post("loginDelegates", url, headers=headers, data=body, verify=False)
    logger.debug("loginDelegates -> HTTP %s (%d bytes)", resp.status_code, len(resp.content))
    try:
        data = plist.loads(resp.content)
    except Exception:  # noqa: BLE001 - HTML/empty error page
        if ne := net.auth_error(resp, "the token exchange"):
            raise ICloudError(f"loginDelegates: {ne}", kind=ne.kind) from None
        raise ICloudError(f"loginDelegates: unreadable reply (HTTP {resp.status_code})") from None

    mm = data.get("delegates", {}).get("com.apple.mobileme", {})
    status = mm.get("status", data.get("status"))
    if status != 0:
        msg = mm.get("status-message") or data.get("status-message") or "unknown error"
        raise ICloudError(f"loginDelegates status {status}: {msg}")

    service_data = mm.get("service-data", {})
    dsid = data.get("dsid") or service_data.get("appleAccountInfo", {}).get("dsid")
    token = service_data.get("tokens", {}).get("mmeAuthToken")
    return str(dsid), token, service_data, data


def fetch_account_settings(record: dict, device: Device, anisette: Anisette,
                           url: str = ACCOUNT_SETTINGS_URL) -> tuple[int, dict]:
    """With the stored mmeAuthToken, fetch the account/webservices settings. Auth is
    `Basic base64(dsid:mmeAuthToken)`. Returns (http_status, parsed_plist)."""
    mme = record.get("mme") or {}
    dsid = mme.get("dsid")
    token = mme.get("mmeAuthToken")
    if not token or not dsid:
        raise ICloudError("no mmeAuthToken stored; run `login` to mint one")

    headers = {
        "Authorization": _basic(str(dsid), token),
        "User-Agent": ICLOUD_USER_AGENT,
        "Accept": "*/*",
    }
    headers.update(identity_headers(device, anisette))
    headers["X-Mme-Client-Info"] = const.with_device(ICLOUD_CLIENT_INFO, anisette.client_info)

    resp = _post("account settings", url, headers=headers, data="", verify=False)
    logger.debug("get_account_settings -> HTTP %s (%d bytes)",
                 resp.status_code, len(resp.content))
    if resp.status_code == 403 and (ne := net.auth_error(resp, "the account request")):
        raise ICloudError(f"account settings: {ne}", kind=ne.kind)
    try:
        return resp.status_code, plist.loads(resp.content)
    except Exception as e:
        if resp.status_code == 401:
            return 401, {}
        raise ICloudError(f"unreadable account settings response (HTTP {resp.status_code})") from e


def extract_webservices(settings: dict) -> dict:
    """Flatten the service-URL map from get_account_settings, tolerating both shapes:

      - modern:  settings["webservices"][name] = {"url": ..., "status": ...}
      - classic: settings["com.apple.mobileme"]["com.apple.Dataclass.X"] = {"url": ...}

    Returns {name: {"url": ...}} so callers can read ckdatabasews / keyvalue / escrowproxy.
    """
    out: dict = {}
    ws = settings.get("webservices")
    if isinstance(ws, dict):
        for name, v in ws.items():
            if isinstance(v, dict) and v.get("url"):
                out[name] = {"url": v["url"], "status": v.get("status")}

    # Some services carry their endpoint under a non-"url" key (KeychainSync -> escrowProxyUrl,
    # KeyValue -> configURL, Ubiquity -> wsUrl); capture those too.
    _alt_url_keys = ("url", "escrowProxyUrl", "configURL", "wsUrl")
    mm = settings.get("com.apple.mobileme")
    if isinstance(mm, dict):
        for name, v in mm.items():
            if not isinstance(v, dict):
                continue
            url = next((v[k] for k in _alt_url_keys if v.get(k)), None)
            if not url:
                continue
            entry = {"url": url, "status": v.get("status")}
            if v.get("escrowProxyUrl"):
                entry["escrowProxyUrl"] = v["escrowProxyUrl"]
            # Normalise "com.apple.Dataclass.Foo" -> "foo" alongside the raw key.
            out.setdefault(name, entry)
            out.setdefault(name.rsplit(".", 1)[-1].lower(), entry)

    return out
