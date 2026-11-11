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
import time

import requests
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .. import const
from . import apple_tls
from .anisette import Anisette
from .device import Device
from .headers import identity_headers
from ..errors import AppleError
from ..ratelimit import retry_after_seconds

# Apple's SRP variant.
srp.rfc5054_enable()
srp.no_username_in_x()
logger = logging.getLogger(__name__)

# Apple answers with 429 when the sign-in rate is too high. That is the one
# answer worth another try: the request was not processed, so sending it again
# is safe. A 5xx is surfaced right away - it can mean the request was
# processed after all, and retrying it would burn an attempt or push another
# 2FA code.
RETRY_STATUS = (429,)
RETRY_ATTEMPTS = 3
RETRY_DELAY = 5.0            # seconds, grows with every attempt
RETRY_DELAY_MAX = 60.0       # cap for Apple's Retry-After


class GSAError(AppleError):
    pass


class GSAServiceError(GSAError):
    pass


class GSAClient:
    def __init__(self, device: Device, anisette: Anisette):
        self.device = device
        self.anisette = anisette
        # Stashed for diagnostics (set by authenticate()).
        self.last_init_response: dict | None = None
        self.last_complete_response: dict | None = None
        self.last_session_key: bytes | None = None

    def _cpd(self, anisette_headers: dict) -> dict:
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(self.device.meta_headers())
        cpd.update(anisette_headers)
        return cpd

    def _post(self, headers: dict, body: dict, operation: str):
        """POST to GrandSlam, retrying a rate-limited answer."""
        data = plist.dumps(body)
        for attempt in range(RETRY_ATTEMPTS + 1):
            resp = apple_tls.request_once(
                "POST", const.GSA_ENDPOINT,
                headers=headers, data=data, timeout=10,
            )
            if resp.status_code not in RETRY_STATUS or attempt == RETRY_ATTEMPTS:
                return resp
            delay = retry_after_seconds(resp)
            delay = min(delay, RETRY_DELAY_MAX) if delay else RETRY_DELAY * (attempt + 1)
            logger.warning("GSA %s answered HTTP %s, retrying in %.0f s",
                           operation, resp.status_code, delay)
            time.sleep(delay)
        return resp

    def _request(self, parameters: dict, *, anisette_headers: dict) -> dict:
        anisette_headers = dict(anisette_headers)
        anisette_headers["X-Mme-Client-Info"] = self.anisette.client_info
        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {"cpd": self._cpd(anisette_headers)},
        }
        body["Request"].update(parameters)
        operation = parameters.get("o", "request")
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "Connection": "close",
            "User-Agent": self.anisette.user_agent,
            "X-MMe-Client-Info": self.anisette.client_info,
        }
        try:
            resp = self._post(headers, body, operation)
        except (requests.ConnectionError, requests.Timeout) as e:
            raise GSAServiceError(f"GSA {operation} request failed: {e}") from e
        except requests.RequestException as e:
            raise GSAError(f"GSA {operation} request failed: {e}") from e

        try:
            payload = plist.loads(resp.content)
        except (plist.InvalidFileException, ValueError, TypeError) as e:
            content_type = resp.headers.get("Content-Type", "unknown content type")
            retry_after = resp.headers.get("Retry-After")
            retry_hint = f", Retry-After {retry_after}" if retry_after else ""
            error_type = GSAServiceError if resp.status_code >= 500 else GSAError
            raise error_type(
                f"GSA {operation} returned HTTP {resp.status_code}; expected a plist, "
                f"got {content_type} ({len(resp.content)} bytes{retry_hint})"
            ) from e
        response = payload.get("Response") if isinstance(payload, dict) else None
        if not isinstance(response, dict):
            raise GSAError(
                f"GSA {operation} returned HTTP {resp.status_code} without a Response dictionary"
            )

        if not resp.ok:
            error_type = GSAServiceError if resp.status_code >= 500 else GSAError
            raise error_type(
                f"GSA {operation} failed: HTTP {resp.status_code}: {_status(response)}"
            )
        return response

    def authenticate(self, username: str, password: str, stage: str) -> tuple[dict, dict]:
        usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, A = usr.start_authentication()

        init_parameters = {"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"}
        # Machine validation must remain stable across both SRP requests.
        anisette_headers = self.anisette.headers()
        init = self._request(init_parameters, anisette_headers=anisette_headers)
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

        complete = self._request(
            {"c": init["c"], "M1": M, "u": username, "o": "complete"},
            anisette_headers=anisette_headers,
        )
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
        apple_tls.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=self._twofa_headers(dsid, idms_token),
            timeout=10,
        )

    def submit_trusted_factor(self, code: str, dsid: str, idms_token: str) -> None:
        h = self._twofa_headers(dsid, idms_token)
        h["security-code"] = code
        resp = apple_tls.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=h, timeout=10,
        )
        _check_code(resp, "trusted-device")

    def trigger_sms_factor(self, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        apple_tls.put(
            "https://gsa.apple.com/auth/verify/phone/",
            json={"phoneNumber": {"id": phone_id}, "mode": "sms"},
            headers=self._twofa_headers(dsid, idms_token),
            timeout=10,
        )

    def submit_sms_factor(self, code: str, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        body = {
            "phoneNumber": {"id": phone_id},
            "mode": "sms",
            "securityCode": {"code": code},
        }
        resp = apple_tls.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body, headers=self._twofa_headers(dsid, idms_token),
            timeout=10,
        )
        _check_code(resp, "SMS")

    def _twofa_headers(self, dsid: str, idms_token: str) -> dict:
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        h = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": self.anisette.user_agent,
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": const.XCODE_VERSION,
            "X-Mme-Client-Info": self.anisette.client_info,
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
