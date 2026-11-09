"""GrandSlam (GSA) SRP-6a authentication.

Takes an explicit Device + Anisette instead of module globals. Produces the decrypted
server provisioning data (spd), which contains the account DSID and the PET
(password-equivalent token).
"""

import base64
import hashlib
import hmac
import logging
import plistlib as plist

import requests  # noqa: F401 - tests patch gsa.requests.*
import srp._pysrp as srp
import urllib3
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .. import const, net
from .anisette import Anisette
from .device import Device
from .headers import identity_headers
from ..errors import AppleError

# Apple's SRP variant.
srp.rfc5054_enable()
srp.no_username_in_x()
urllib3.disable_warnings()

logger = logging.getLogger(__name__)


class GSAError(AppleError):
    """A GrandSlam failure. `kind` mirrors icp.net's error kinds ("blocked", "network", ...) when
    the cause was the HTTP layer; `retry_after` is Apple's requested delay in seconds."""

    def __init__(self, message: str = "", *, kind: str = "", retry_after: float | None = None):
        super().__init__(message)
        self.kind, self.retry_after = kind, retry_after


def _net(operation: str, **kw):
    """requests-style call through icp.net, with network-layer errors re-raised as GSAError."""
    try:
        return net.request(**kw)
    except net.AppleNetError as e:
        raise GSAError(f"GSA {operation}: {e}", kind=e.kind, retry_after=e.retry_after) from e


class GSAClient:
    def __init__(self, device: Device, anisette: Anisette):
        self.device = device
        self.anisette = anisette
        # Stashed for diagnostics (set by authenticate()).
        self.last_init_response: dict | None = None
        self.last_complete_response: dict | None = None
        self.last_session_key: bytes | None = None

    def _cpd(self) -> dict:
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(identity_headers(self.device, self.anisette))
        return cpd

    def _request(self, parameters: dict) -> dict:
        body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": self._cpd()}}
        body["Request"].update(parameters)
        operation = parameters.get("o", "request")
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": const.GSA_USER_AGENT,
            "X-MMe-Client-Info": const.GSA_CLIENT_INFO,
        }
        resp = _net(operation, method="post", url=const.GSA_ENDPOINT, headers=headers,
                    data=plist.dumps(body), verify=False)

        try:
            payload = plist.loads(resp.content)
            response = payload["Response"]
        except Exception:
            if ne := net.auth_error(resp, "the sign-in request"):
                raise GSAError(f"GSA {operation} failed: {ne}", kind=ne.kind) from None
            raise GSAError(
                f"GSA {operation} failed: HTTP {resp.status_code}: "
                f"non-plist reply ({len(resp.content)} bytes)", kind="protocol"
            ) from None

        if not resp.ok:
            raise GSAError(
                f"GSA {operation} failed: HTTP {resp.status_code}: {_status(response)}"
            )
        return response

    def authenticate(self, username: str, password: str, stage: str) -> tuple[dict, dict]:
        usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, A = usr.start_authentication()

        init = self._request({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})
        self.last_init_response = init
        logger.debug("GSA init response keys: %s", list(init))
        if "sp" not in init:
            raise GSAError(f"{stage}: init failed: {_status(init)}")
        if init["sp"] not in ("s2k", "s2k_fo"):
            raise GSAError(f"unsupported protocol {init['sp']}")

        # We could not derive the password without the salt, so inject it now.
        usr.p = _encrypt_password(password, init["s"], init["i"], init["sp"])
        M = usr.process_challenge(init["s"], init["B"])
        if M is None:
            raise GSAError("failed to process SRP challenge (wrong password?)")

        complete = self._request({"c": init["c"], "M1": M, "u": username, "o": "complete"})
        self.last_complete_response = complete
        logger.debug("GSA complete response keys: %s", list(complete))
        if "M2" not in complete:
            raise GSAError(f"{stage}: complete failed: {_status(complete)}",
                           kind=_status_kind(complete))
        usr.verify_session(complete["M2"])
        if not usr.authenticated():
            raise GSAError("server session verification failed (imposter?)")

        self.last_session_key = usr.get_session_key()
        spd = plist.loads(_decrypt_cbc(usr, complete["spd"]), fmt=plist.FMT_XML)
        logger.debug("GSA spd top-level keys: %s", list(spd))
        return complete, spd

    def trigger_trusted_factor(self, dsid: str, idms_token: str) -> None:
        _net("2FA trigger", method="get", url="https://gsa.apple.com/auth/verify/trusteddevice",
             headers=self._twofa_headers(dsid, idms_token), verify=False)

    def submit_trusted_factor(self, code: str, dsid: str, idms_token: str) -> None:
        h = self._twofa_headers(dsid, idms_token)
        h["security-code"] = code
        resp = _net("2FA validate", method="get",
                    url="https://gsa.apple.com/grandslam/GsService2/validate",
                    headers=h, verify=False)
        _check_code(resp, "trusted-device")

    def trigger_sms_factor(self, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        _net("SMS trigger", method="put", url="https://gsa.apple.com/auth/verify/phone/",
             json={"phoneNumber": {"id": phone_id}, "mode": "sms"},
             headers=self._twofa_headers(dsid, idms_token), verify=False)

    def submit_sms_factor(self, code: str, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        body = {
            "phoneNumber": {"id": phone_id},
            "mode": "sms",
            "securityCode": {"code": code},
        }
        resp = _net("SMS validate", method="post",
                    url="https://gsa.apple.com/auth/verify/phone/securitycode",
                    json=body, headers=self._twofa_headers(dsid, idms_token), verify=False)
        _check_code(resp, "SMS")

    def _twofa_headers(self, dsid: str, idms_token: str) -> dict:
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        h = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": const.GSA_CLIENT_INFO,
        }
        h.update(identity_headers(self.device, self.anisette))
        return h


def _encrypt_password(password: str, salt: bytes, iterations: int, protocol: str) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)


def _session_key(usr, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None:
        raise GSAError("no SRP session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def _decrypt_cbc(usr, data: bytes) -> bytes:
    key = _session_key(usr, "extra data key:")
    iv = _session_key(usr, "extra data iv:")[:16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# Apple status codes meaning "Apple ID or password is incorrect" (seen from GrandSlam/pypush).
_BAD_CREDENTIALS = {-20101, -22406}


def _status_kind(r: dict) -> str:
    ec = r.get("Status", r).get("ec")
    return "credentials" if ec in _BAD_CREDENTIALS else ""


def _status(r: dict) -> str:
    s = r.get("Status", r)
    return f"ec={s.get('ec')} em={s.get('em')!r} au={s.get('au')!r}"


def _check_code(resp, kind: str) -> None:
    """A rejected code comes back as HTTP 200 with a bare plist."""
    try:
        body = plist.loads(resp.content)
    except Exception:  # noqa: BLE001 - a rejected identity token answers 401 with no body
        body = {}
    if body.get("ec") or not resp.ok:
        raise GSAError(f"{kind} 2FA code rejected: {body.get('em') or resp.status_code}",
                       kind="code")
