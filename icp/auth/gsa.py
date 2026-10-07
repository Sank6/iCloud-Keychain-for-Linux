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

import requests
import srp._pysrp as srp
import urllib3
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .. import const
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
    pass


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
        try:
            resp = requests.post(
                const.GSA_ENDPOINT, headers=headers, data=plist.dumps(body),
                verify=False, timeout=10,
            )
        except requests.RequestException as e:
            raise GSAError(f"GSA {operation} request failed: {e}") from e

        try:
            payload = plist.loads(resp.content)
        except plist.InvalidFileException as e:
            content_type = resp.headers.get("Content-Type", "unknown")
            raise GSAError(
                f"GSA {operation} returned HTTP {resp.status_code}; expected a plist, "
                f"received {content_type} ({len(resp.content)} bytes)"
            ) from e

        response = payload.get("Response") if isinstance(payload, dict) else None
        if not isinstance(response, dict):
            raise GSAError(f"GSA {operation} returned a plist without a Response dictionary")
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
            raise GSAError(f"{stage}: complete failed: {_status(complete)}")
        usr.verify_session(complete["M2"])
        if not usr.authenticated():
            raise GSAError("server session verification failed (imposter?)")

        self.last_session_key = usr.get_session_key()
        spd = plist.loads(_decrypt_cbc(usr, complete["spd"]), fmt=plist.FMT_XML)
        logger.debug("GSA spd top-level keys: %s", list(spd))
        return complete, spd

    def trigger_trusted_factor(self, dsid: str, idms_token: str) -> None:
        requests.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=self._twofa_headers(dsid, idms_token),
            verify=False, timeout=10,
        )

    def submit_trusted_factor(self, code: str, dsid: str, idms_token: str) -> None:
        h = self._twofa_headers(dsid, idms_token)
        h["security-code"] = code
        resp = requests.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=h, verify=False, timeout=10,
        )
        _check_code(resp, "trusted-device")

    def trigger_sms_factor(self, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        requests.put(
            "https://gsa.apple.com/auth/verify/phone/",
            json={"phoneNumber": {"id": phone_id}, "mode": "sms"},
            headers=self._twofa_headers(dsid, idms_token),
            verify=False, timeout=10,
        )

    def submit_sms_factor(self, code: str, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        body = {
            "phoneNumber": {"id": phone_id},
            "mode": "sms",
            "securityCode": {"code": code},
        }
        resp = requests.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body, headers=self._twofa_headers(dsid, idms_token),
            verify=False, timeout=10,
        )
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
        raise GSAError(f"{kind} 2FA code rejected: {body.get('em') or resp.status_code}")
