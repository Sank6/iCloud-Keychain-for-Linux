"""One-time codes (RFC 6238) for the `totp` block iCloud Keychain stores in a login's metadata
sidecar - see RESEARCH.md. The secret stays here and in the vault; only generated codes are
handed to the browser extension."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
import urllib.parse

_ALGORITHMS = {0: "SHA1", 1: "SHA256", 2: "SHA512"}
_HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def _int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def uri_from_sidecar(block) -> str:
    """An `otpauth://totp` URI for a sidecar's `totp` dict, or "" when it holds no usable secret.

    The sidecar also keeps the scanned `originalURL` verbatim, but an enrolment typed in as a
    setup key has none, so the URI is rebuilt from the structured fields instead.
    """
    if not isinstance(block, dict):
        return ""
    secret = block.get("secret")
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        return ""
    issuer, account = str(block.get("issuer") or ""), str(block.get("accountName") or "")
    label = ":".join(p for p in (issuer, account) if p) or "icloud"
    params = {
        "secret": base64.b32encode(bytes(secret)).decode().rstrip("="),
        "algorithm": _ALGORITHMS.get(block.get("algorithm"), "SHA1"),
        "digits": _int(block.get("digits"), 6),
        "period": _int(block.get("period"), 30),
    }
    if issuer:
        params["issuer"] = issuer
    return f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"


def sidecar_from_input(text: str) -> dict:
    """Inverse of uri_from_sidecar: a sidecar `totp` dict from an `otpauth://totp` URI or a bare
    base32 setup key (spaces allowed). Raises ValueError for anything else."""
    import datetime
    text = (text or "").strip()
    if text.lower().startswith("otpauth://"):
        parsed = urllib.parse.urlparse(text)
        if parsed.netloc.lower() != "totp":
            raise ValueError("only time-based (otpauth://totp) codes are supported")
        query = urllib.parse.parse_qs(parsed.query)

        def param(name, default=""):
            return (query.get(name) or [default])[0]

        label = urllib.parse.unquote(parsed.path.lstrip("/"))
        issuer, _, account = label.rpartition(":")
        issuer = param("issuer") or issuer
        raw, original = param("secret"), text
        algorithm = param("algorithm", "SHA1").upper()
        digits, period = _int(param("digits"), 6), _int(param("period"), 30)
    else:
        raw, original, issuer, account = text, "", "", ""
        algorithm, digits, period = "SHA1", 6, 30
    raw = raw.replace(" ", "").upper()
    try:
        secret = base64.b32decode(raw + "=" * (-len(raw) % 8))
    except binascii.Error:
        raise ValueError("2FA key is not valid base32") from None
    # Only SHA1 (0) has been seen in a real sidecar; the codes for SHA256/SHA512 are a guess, so
    # they are read but never written.
    if algorithm != "SHA1":
        raise ValueError(f"only SHA1 2FA codes can be saved (got {algorithm})")
    if not secret or not 6 <= digits <= 10 or period < 1:
        raise ValueError("unsupported 2FA parameters")
    block = {"secret": secret, "algorithm": 0, "digits": digits,
             "period": period, "issuer": issuer, "accountName": account,
             "_initialDate": datetime.datetime(1970, 1, 1)}   # as the Passwords app leaves it
    if original:
        block["originalURL"] = original
    return block


def generate(uri: str, at: float | None = None) -> dict:
    """-> {"code", "expires", "period"} for an `otpauth://totp` URI, or {} if it is unusable.
    `expires` is the unix second the code rolls over, so a caller can show a countdown."""
    if not uri:
        return {}
    query = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)

    def param(name, default=""):
        return (query.get(name) or [default])[0]

    raw = param("secret").replace(" ", "").upper()
    try:
        key = base64.b32decode(raw + "=" * (-len(raw) % 8))
    except binascii.Error:
        return {}
    digest = _HASHES.get(param("algorithm", "SHA1").upper())
    if not key or digest is None:
        return {}

    digits = min(max(_int(param("digits"), 6), 6), 10)
    period = max(_int(param("period"), 30), 1)
    counter = int((time.time() if at is None else at) // period)
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return {"code": f"{code:0{digits}d}", "expires": (counter + 1) * period, "period": period}
