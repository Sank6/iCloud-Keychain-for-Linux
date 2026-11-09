"""escrowproxy SRP recovery - turns the device passcode into the bottle entropy.

IRREVERSIBLE: escrowproxy enforces a hard 10-attempt limit; the HSM cluster destroys the escrow
record on the 10th failed attempt.
`try_recover_escrow` is live but refuses to run without `confirm_irreversible=True`, which the CLI
passes only after a typed confirmation. `list_records` (GETRECORDS) is non-destructive and spends
no attempt.

See RESEARCH.md "Stage 4 - Joining the trust" for the escrowproxy commands (the non-destructive
GETRECORDS device listing and the SRP_INIT/RECOVER recovery) and the SRP-6a / KDF parameters.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import plistlib
import uuid as _uuid

from ..errors import AppleError

# RFC 5054 2048-bit group (N, g=2). Standard public constant.
_N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
)
N = int(_N_HEX, 16)
g = 2
_N_BYTES = (N.bit_length() + 7) // 8


def _H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _pad(x: int) -> bytes:
    """Left-pad an integer to the modulus byte length (PAD() in RFC 5054)."""
    return x.to_bytes(_N_BYTES, "big")


def _trim(x: int) -> bytes:
    """Minimal big-endian bytes (no left-zero padding)."""
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def unpack_message(bin_: bytes, header_len: int, section_count: int):
    """msg_from_bin: -> (header, [section bytes]). Layout: len(4) | header | (n+1) BE offsets
    | body, where each section in the body is len(4)||data."""
    header = bin_[4:header_len + 4]
    total_header_size = header_len + 4 + (section_count + 1) * 4
    offsets_region = bin_[header_len + 4:header_len + 4 + section_count * 4]
    sections = []
    for i in range(section_count):
        offset = _int(offsets_region[i * 4:i * 4 + 4])
        start = total_header_size + offset
        size = _int(bin_[start:start + 4])
        sections.append(bin_[start + 4:start + 4 + size])
    return header, sections


@dataclasses.dataclass
class KeyVaultMessage:
    header: bytes
    sections: list = dataclasses.field(default_factory=list)

    def section(self, data: bytes):
        self.sections.append(len(data).to_bytes(4, "big") + data)

    def section_sized(self, data: bytes, size: int):
        total = len(data).to_bytes(4, "big") + data
        if len(total) > size:
            raise ValueError(f"section size {size} < actual {len(total)}")
        self.sections.append(total + b"\x00" * (size - len(total)))

    def pack(self) -> bytes:
        body = b""
        idx = []
        for s in self.sections:
            idx.append(len(body))
            body += s
        idx.append(len(body))
        result = bytearray(b"\x00\x00\x00\x00" + self.header
                           + b"".join(o.to_bytes(4, "big") for o in idx) + body)
        result[:4] = len(result).to_bytes(4, "big")
        return bytes(result)


@dataclasses.dataclass
class SrpClient:
    """SRP-6a client (RFC 5054 2048-bit group, SHA-256; trimmed-A/B convention)."""

    a: int

    @classmethod
    def new(cls, a_bytes: bytes) -> "SrpClient":
        return cls(a=_int(a_bytes))

    @property
    def A(self) -> int:
        return pow(g, self.a, N)

    def public_a(self) -> bytes:
        """A, trimmed (minimal big-endian) - escrowproxy hashes the trimmed form, so M1/M2 must too."""
        return _trim(self.A)

    def process(self, username: bytes, password: bytes, salt: bytes, b_pub: bytes):
        """Return (K, M1). A/B are fed trimmed (not padded) into compute_u/compute_m1; escrowproxy
        hashes the trimmed form."""
        B = _int(b_pub)
        a_pub = _trim(self.A)                         # a_pub.to_bytes_be()
        b_pub_norm = _trim(B)                         # b_pub.to_bytes_be() - re-serialized, trimmed
        k = _int(_H(_pad(N), _pad(g)))               # compute_k: H(N || PAD(g))
        x = _int(_H(salt, _H(username + b":" + password)))
        u = _int(_H(a_pub, b_pub_norm))              # compute_u: H(trim(A) || trim(B)), NO padding
        # S = (B - k*g^x)^(a + u*x) mod N
        base = (B - (k * pow(g, x, N)) % N) % N
        S = pow(base, self.a + u * x, N)
        K = _H(_trim(S))                             # D::digest(S.to_bytes_be())
        # compute_m1: H( (H(N_trimmed) XOR H(PAD(g))) || H(username) || salt || trim(A) || trim(B) || K )
        h_xor = bytes(p ^ q for p, q in zip(_H(_pad(N)), _H(_pad(g))))
        M1 = _H(h_xor, _H(username), salt, a_pub, b_pub_norm, K)
        return K, M1

    @staticmethod
    def server_proof(a_pub: bytes, M1: bytes, K: bytes) -> bytes:
        """Expected server proof M2 = H(A || M1 || K), with the same trimmed A we sent."""
        return _H(a_pub, M1, K)


def encode_fetch_viable_bottles_request() -> bytes:
    from ..proto.codec import Writer
    return Writer().uint64(1, 1).bytes(2, b"").finish()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = dec.update(ct) + dec.finalize()
    pad = out[-1]                       # PKCS7 unpad (OpenSSL default)
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
    return out


class EscrowGateError(AppleError):
    """Raised when a live escrowproxy call is attempted without explicit irreversible consent."""


class EscrowRecovery:
    """Drives the two-POST escrowproxy SRP that turns the passcode into the bottle entropy.

     Every `try_recover_escrow` call consumes one of 10 irreversible attempts (the 10th failed
    attempt destroys the record forever). It refuses to run unless `confirm_irreversible=True` is
    passed explicitly - the CLI only sets that after an interactive typed confirmation. The
    non-destructive `list_records` (GETRECORDS) spends no attempt. `host` is the M1 escrow
    webservices URL; auth is HTTP Basic(apple-id email : fresh GSA PET).
    """

    USER_ACTION = "com.apple.sbd: escrow recovery"
    # The body `command` is SCREAMING_SNAKE_CASE, not the URL slug or PascalCase variant.
    _COMMAND_VARIANT = {"srp_init": "SRP_INIT", "recover": "RECOVER", "get_records": "GETRECORDS",
                        "get_club_cert": "GETCLUB", "enroll": "ENROLL", "delete": "DELETE"}

    # escrowproxy wants the sbd UA + a fixed X-Mme-Client-Info that overwrites anisette's.
    ESCROW_USER_AGENT = "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282"
    ESCROW_MME_CLIENT_INFO = ("<PC> <Windows;6.2(0,0);9200> "
                              "<com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>")

    def __init__(self, host: str, email: str, pet: str, anisette, *, timeout: int = 30):
        self.host = host.rstrip("/")
        self.email = email
        self.pet = pet
        self.anisette = anisette
        self.timeout = timeout

    def _headers(self) -> dict:
        h = {
            "User-Agent": self.ESCROW_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Apple-I-Locale": "en_US",
            "x-apple-i-device-type": "1",
            "Content-Type": "application/x-apple-plst",
        }
        h.update(self.anisette.headers())
        h["X-Mme-Client-Info"] = self.ESCROW_MME_CLIENT_INFO  # overrides anisette's
        return h

    def _invoke(self, command: str, request: dict) -> dict:
        """POST a single escrowproxy command. LIVE."""
        import requests
        body = plistlib.dumps(request)
        # verify=True: carries the PET + drives the irreversible flow, must not be MITM'd
        resp = requests.post(f"{self.host}/escrowproxy/api/{command}",
                             headers=self._headers(), data=body,
                             auth=(self.email, self.pet), verify=True, timeout=self.timeout)
        data = plistlib.loads(resp.content)
        if not (200 <= resp.status_code < 300):
            raise EscrowGateError(f"escrowproxy/{command} HTTP {resp.status_code}: {data}")
        return data

    def _request(self, command_url: str, label: str, txn: str, **extra) -> dict:
        # command_url is the URL slug; the body `command` is its SCREAMING_SNAKE_CASE form.
        req = {"command": self._COMMAND_VARIANT.get(command_url, command_url),
               "label": label, "transactionUUID": txn,
               "userActionLabel": self.USER_ACTION, "version": 1}
        req.update({k: v for k, v in extra.items() if v is not None})
        return req

    def list_records(self, label: str = "com.apple.securebackup.record") -> list[dict]:
        """GETRECORDS - list the account's escrow records with the metadata that identifies each
        backed-up device. NON-DESTRUCTIVE: spends no escrow attempt and needs no passcode.

        Returns `[{"label": <bottle id>, "meta": {...}}]`; `meta` keys include `serial`, `build`,
        `com.apple.securebackup.timestamp`, `passcode_generation`, `bottleID`, `ClientMetadata`."""
        txn = str(_uuid.uuid4()).upper()
        resp = self._invoke("get_records", self._request("get_records", label, txn))
        # escrowproxy returns the camelCase key `metadataList`.
        entries = resp.get("metadataList") or resp.get("metadata_list") or []
        out = []
        for entry in entries:
            meta_b64 = entry.get("metadata")
            meta = plistlib.loads(base64.b64decode(meta_b64)) if meta_b64 else {}
            out.append({"label": entry.get("label", ""), "meta": meta})
        return out

    def try_recover_escrow(self, label: str, passcode: bytes, *,
                           confirm_irreversible: bool = False) -> bytes:
        """Run the full SRP recovery and return the EscrowBottle's BottledPeerEntropy.

        IRREVERSIBLE (consumes 1 of 10 attempts).
        """
        if not confirm_irreversible:
            raise EscrowGateError(
                "REFUSED: try_recover_escrow consumes one of 10 irreversible escrow attempts "
                "(the 10th failed passcode destroys the record forever). Pass "
                "confirm_irreversible=True only after the user has explicitly confirmed.")

        txn = str(_uuid.uuid4()).upper()
        client = SrpClient.new(os.urandom(32))

        # 1) srp_init: send A, get salt + B + dsid (+ optional clubTypeID)
        init = self._invoke("srp_init", self._request(
            "srp_init", label, txn, blob=base64.b64encode(client.public_a()).decode()))
        dsid = init["dsid"]
        club_type_id = init.get("clubTypeID")
        header, sections = unpack_message(base64.b64decode(init["respBlob"]), 24, 3)
        id_section, salt, b_pub = sections[0], sections[1], sections[2]

        # 2) SRP-6a: derive K + proof M1 (username = the dsid escrowproxy returned)
        K, M1 = client.process(dsid.encode("utf-8"), passcode, salt, b_pub)

        # 3) recover: send header(unk1=165, ver) + id + M1
        ver = 2 if club_type_id == 1 else 0
        hdr = bytearray(header)
        hdr[0:4] = (165).to_bytes(4, "big")
        hdr[4:8] = ver.to_bytes(4, "big")
        payload = KeyVaultMessage(bytes(hdr))
        payload.section_sized(id_section, 20)
        payload.section(M1)
        rec = self._invoke("recover", self._request(
            "recover", label, txn, blob=base64.b64encode(payload.pack()).decode()))

        # 4) verify server proof + decrypt with the SRP session key K
        h, payloads = unpack_message(base64.b64decode(rec["respBlob"]),
                                     40 if club_type_id == 1 else 24, 3)
        if SrpClient.server_proof(client.public_a(), M1, K) != payloads[0]:
            raise EscrowGateError("escrowproxy server proof (M2) mismatch - aborting")
        version = _int(h[4:8])
        if version == 0:
            inner = _aes_cbc_decrypt(K, payloads[1], payloads[2])
        elif version == 2:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            inner = AESGCM(K).decrypt(payloads[1], payloads[2], None)
        else:
            raise EscrowGateError(f"unsupported escrow record version {version}")

        # 5) inner blob -> PBKDF2(passcode) -> AES-128-CBC -> EscrowBottle plist
        ih, ipayloads = unpack_message(inner, 16, 6)
        rounds = _int(ih[8:12])
        salt2 = ipayloads[1]
        derived = hashlib.pbkdf2_hmac("sha256", passcode, salt2, rounds, dklen=16)
        bottle_plist = _aes_cbc_decrypt(derived, salt2[:16], ipayloads[3])
        bottle = plistlib.loads(bottle_plist)
        entropy = bottle["BottledPeerEntropy"]
        return bytes(entropy)
