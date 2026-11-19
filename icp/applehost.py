"""Host side of Apple's "iCloud Passwords" browser extension protocol (native host name
`com.apple.passwordmanager`), backed by our own agent instead of Apple's Windows/macOS app.

Derived by reading the installed extension (v3.4.0) and checked against its own SecretSession code
(tests/ext/apple_client.js). Everything not confirmed that way is marked UNVERIFIED in
docs/apple-extension-protocol.md.

Session: SRP-6a, RFC 5054 3072-bit group, SHA-256. The 6-digit PIN is the SRP password. Messages
after pairing are AES-128-GCM (key = first 16 bytes of SHA-256(S)), wrapped as {"TID","SDATA"}.
This module is pure logic (no I/O) so it can be tested; icp/applehost_main.py does the framing."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# RFC 5054 appendix A, 3072-bit group (public constant).
N = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff",
    16)
G = 5
N_LEN = 384  # bytes
PIN_ATTEMPTS = 3
SESSION_TTL = 8 * 3600
CMD = dict(END=0, CHALLENGE_PIN=2, SET_ICON=3, GET_LOGINS=4, GET_PASSWORD=5, SET_PASSWORD=6,
           NEW_ACCOUNT=7, TAB_EVENT=8, DISABLED=9, RELOGIN=10, HELLO=14, OTP_AVAILABLE=15,
           GET_OTP=16, DID_FILL_OTP=17, CANCEL_PIN=19)
STATUS_OK, STATUS_NONE = 0, 3


class ProtocolError(Exception):
    pass


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def _pad(n: int) -> bytes:
    return n.to_bytes(N_LEN, "big")


def _b64(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def _unb64(s: str) -> dict:
    try:
        return json.loads(base64.b64decode(s))
    except Exception as e:  # noqa: BLE001
        raise ProtocolError("bad PAKE message") from e


def _hex_int(s: str) -> int:
    s = s[2:] if s[:2] in ("0x", "0X") else s
    return int(s, 16)


class Session:
    """One pairing attempt + the encrypted channel that follows."""

    def __init__(self, pin: str):
        self.pin = pin
        self.key: bytes | None = None
        self.created = time.monotonic()
        self.attempts = 0
        self.tid = ""
        self._v = 0
        self._state = "new"

    # -- pairing ----------------------------------------------------------------------------
    def msg1(self, m0: dict) -> str:
        """Answer the extension's m0 ({TID, A, MSG:0, PROTO:[..]}) with our msg1."""
        self.tid = m0["TID"]
        a_pub = _hex_int(m0["A"])
        if a_pub % N == 0:
            raise ProtocolError("illegal A")
        salt = os.urandom(16)
        x = int.from_bytes(_h(salt, _h(f"{self.tid}:{self.pin}".encode())), "big")
        self._v = pow(G, x, N)
        k = int.from_bytes(_h(_pad(N), _pad(G)), "big")
        b = secrets.randbelow(N - 2) + 1
        b_pub = (k * self._v + pow(G, b, N)) % N
        u = int.from_bytes(_h(_pad(a_pub), _pad(b_pub)), "big")
        s = pow(a_pub * pow(self._v, u, N) % N, b, N)
        self.key = hashlib.sha256(self._s_bytes(s)).digest()[:16]
        self._state = "msg1"
        return _b64({"TID": self.tid, "MSG": 1, "s": salt.hex(), "B": format(b_pub, "x"),
                     "VER": "1.0", "PROTO": 0})

    @staticmethod
    def _s_bytes(s: int) -> bytes:
        return s.to_bytes((s.bit_length() + 7) // 8 or 1, "big")

    def msg3(self, m2: dict) -> str:
        """Verify the extension's m2 (proof that it knew the PIN) and finish pairing."""
        if self._state != "msg1":
            raise ProtocolError("unexpected message")
        self.attempts += 1
        try:
            proof = self.decrypt_client(bytes.fromhex(m2["v"]))
            ok = _hex_int(proof.decode()) == self._v
        except Exception:  # noqa: BLE001  (GCM tag failure == wrong PIN)
            ok = False
        if not ok:
            self.key = None
            self._state = "failed"
            return _b64({"TID": self.tid, "MSG": 3, "ErrCode": 1})
        self._state = "ready"
        return _b64({"TID": self.tid, "MSG": 3, "ErrCode": 0})

    @property
    def ready(self) -> bool:
        return self._state == "ready" and self.key is not None \
            and time.monotonic() - self.created < SESSION_TTL

    # -- channel ----------------------------------------------------------------------------
    def decrypt_client(self, blob: bytes) -> bytes:
        """Extension -> host: ciphertext||tag||iv(16)."""
        ct, iv = blob[:-16], blob[-16:]
        return AESGCM(self.key).decrypt(iv, ct, None)

    def encrypt_host(self, plain: bytes) -> bytes:
        """Host -> extension: iv(16)||ciphertext||tag."""
        iv = os.urandom(16)
        return iv + AESGCM(self.key).encrypt(iv, plain, None)

    def open_smsg(self, smsg) -> dict:
        obj = json.loads(smsg) if isinstance(smsg, str) else smsg
        if _hex_int(obj["TID"]) != _hex_int(self.tid):
            raise ProtocolError("message for another session")
        return json.loads(self.decrypt_client(bytes.fromhex(obj["SDATA"])))

    def seal_smsg(self, body: dict) -> str:
        data = self.encrypt_host(json.dumps(body, separators=(",", ":")).encode())
        return json.dumps({"TID": self.tid, "SDATA": data.hex()}, separators=(",", ":"))
