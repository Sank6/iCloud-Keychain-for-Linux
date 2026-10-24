"""Decrypt ProtectedCloudStorage data for shared-password groups.

See RESEARCH.md for the key hierarchy and wire format.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

from ..errors import AppleError
from ..proto.codec import decode_fields, first


class PCSError(AppleError):
    pass


UNIVERSAL, APPLICATION, CONTEXT = 0, 1, 2


@dataclass
class Node:
    cls: int
    constructed: bool
    tag: int
    value: bytes  # Content bytes.
    raw: bytes  # Encoded TLV.

    def children(self) -> list["Node"]:
        return parse_all(self.value)

    def unwrap(self) -> "Node":
        """Content of an EXPLICIT tag: the single TLV inside."""
        kids = self.children()
        if len(kids) != 1:
            raise PCSError(f"explicit tag holds {len(kids)} elements")
        return kids[0]

    def int(self) -> int:
        return int.from_bytes(self.value, "big", signed=True)


def _parse_one(buf: bytes, pos: int) -> tuple[Node, int]:
    start = pos
    if pos + 2 > len(buf):
        raise PCSError("truncated DER")
    b = buf[pos]
    cls, constructed, tag = b >> 6, bool(b & 0x20), b & 0x1F
    pos += 1
    if tag == 0x1F:  # High-tag-number form.
        tag = 0
        while True:
            c = buf[pos]
            pos += 1
            tag = (tag << 7) | (c & 0x7F)
            if not c & 0x80:
                break
    n = buf[pos]
    pos += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        raise PCSError("DER length past end of buffer")
    return Node(cls, constructed, tag, buf[pos:pos + n], buf[start:pos + n]), pos + n


def parse(buf: bytes) -> Node:
    node, _ = _parse_one(buf, 0)
    return node


def parse_all(buf: bytes) -> list[Node]:
    out, pos = [], 0
    while pos < len(buf):
        node, pos = _parse_one(buf, pos)
        out.append(node)
    return out


def _ctx(nodes: list[Node], tag: int) -> Node | None:
    return next((n for n in nodes if n.cls == CONTEXT and n.tag == tag), None)


def kdf_ctr_hmac(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """Derive bytes with the NIST SP 800-108 counter-mode HMAC-SHA256 KDF."""
    suffix = label + b"\x00" + context + struct.pack(">I", length * 8)
    out, i = b"", 1
    while len(out) < length:
        out += hmac.new(key, struct.pack(">I", i) + suffix, hashlib.sha256).digest()
        i += 1
    return out[:length]


def _public_from_x(x: bytes) -> ec.EllipticCurvePublicKey:
    """Restore a P-256 point; either Y works because ECDH uses the shared point's X."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x03" + x)


def private_from_compact(raw: bytes) -> ec.EllipticCurvePrivateKey:
    """Compact private key: X(32) || d(32), or just d(32)."""
    d = raw[32:] if len(raw) == 64 else raw
    if len(d) != 32:
        raise PCSError(f"unexpected compact private key size {len(raw)}")
    return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())


def compact_x(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_numbers().x.to_bytes(32, "big")


_P256_OID = bytes([0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])


def rfc6637_unwrap(key: ec.EllipticCurvePrivateKey, wrapped: bytes,
                   fingerprint: bytes = b"fingerprint") -> bytes:
    """Unwrap `[u16 bits][ephemeral X][u8 len][AES-KW blob]` with ECDH + the RFC 6637 KDF."""
    bits = int.from_bytes(wrapped[:2], "big")
    elen = bits // 8
    eph = wrapped[2:2 + elen]
    wlen = wrapped[2 + elen]
    blob = wrapped[3 + elen:3 + elen + wlen]
    secret = key.exchange(ec.ECDH(), _public_from_x(eph))
    kek = hashlib.sha256(b"\x00\x00\x00\x01" + secret + _P256_OID + bytes([18, 0x03, 0x01, 8, 7])
                         + b"Anonymous Sender    " + fingerprint.ljust(20, b"\x00")).digest()[:16]
    try:
        msg = aes_key_unwrap(kek, blob)
    except InvalidUnwrap as e:
        raise PCSError("PCS key unwrap failed") from e
    pad = msg[-1]
    if pad == 0 or pad > len(msg) - 3 or msg[-pad:] != bytes([pad]) * pad:
        raise PCSError("bad RFC 6637 padding")
    k = msg[1:len(msg) - pad - 2]
    if sum(k) & 0xFFFF != int.from_bytes(msg[1 + len(k):3 + len(k)], "big"):
        raise PCSError("bad RFC 6637 checksum")
    return k


class PCSKey:
    """A PCS master key and its label-derived working keys."""

    def __init__(self, raw: bytes):
        self.raw = raw

    def _derive(self, label: bytes) -> bytes:
        return kdf_ctr_hmac(self.raw, label, b"", len(self.raw))

    def key_id(self) -> bytes:
        return hmac.new(self._derive(b"master key id labell"), b"M key input data 2 u",
                        hashlib.sha256).digest()

    def share_variant(self) -> "PCSKey":
        return PCSKey(self._derive(b"MsaeEooevaX fooo 012"))

    def hmac(self, data: bytes) -> bytes:
        return hmac.new(self._derive(b"hmackey-of-masterkey"), data, hashlib.sha256).digest()

    def decrypt(self, ct: bytes, aad: bytes = b"") -> bytes:
        """Ciphertext v3: 0x03 || id[0:2] || n || id[2:2+n] || iv(12) || tag(12) || data.
        The header is authenticated together with the caller's AAD."""
        want, hlen = ciphertext_key_id(ct)
        if self.key_id()[:len(want)] != want:
            raise PCSError("ciphertext is for a different key")
        iv, tag, data = ct[hlen:hlen + 12], ct[hlen + 12:hlen + 24], ct[hlen + 24:]
        try:
            dec = Cipher(algorithms.AES(self._derive(b"encryption key key m")),
                         modes.GCM(iv, tag, min_tag_length=12)).decryptor()
            dec.authenticate_additional_data(ct[:hlen] + aad)
            return dec.update(data) + dec.finalize()
        except InvalidTag as e:
            raise PCSError("PCS ciphertext authentication failed") from e


def ciphertext_key_id(ct: bytes) -> tuple[bytes, int]:
    if not ct or ct[0] != 3:
        raise PCSError(f"unsupported PCS ciphertext version {ct[:1].hex()}")
    n = ct[3]
    return ct[1:3] + ct[4:4 + n], 4 + n


def decrypt_with_any(keys: list[PCSKey], ct: bytes, aad: bytes) -> bytes:
    want, _ = ciphertext_key_id(ct)
    for k in keys:
        if k.key_id()[:len(want)] == want:
            return k.decrypt(ct, aad)
    raise PCSError("no key for this ciphertext")


def private_key_from_der(der: bytes) -> ec.EllipticCurvePrivateKey:
    """PCSPrivateKey, either V1 SEQUENCE{OCTET compact-key, public OPTIONAL} or
    V2 [APPLICATION 5]{OCTET protobuf{1: {1: compact encryption key}, 2: signing key}}."""
    node = parse(der)
    if node.cls == APPLICATION and node.tag == 5:
        pb = node.children()[0].value
        enc = first(decode_fields(pb), 1)
        if enc is None:
            raise PCSError("V2 PCS key without encryption key")
        return private_from_compact(first(decode_fields(enc), 1))
    return private_from_compact(node.children()[0].value)


@dataclass
class ShareKey:
    public_x: bytes
    wrapped: bytes
    flags: int = 0


@dataclass
class ShareProtection:
    """PCSShareProtection: [APPLICATION 1] SEQUENCE { keyset, [0] meta, [1] signature data,
    hmac, [2] truncated key id, [3] signature OPTIONAL, [4] attributes OPTIONAL }."""
    keyset_raw: bytes
    share_keys: list[ShareKey]
    meta: bytes
    sig_version: int
    sig_data: bytes
    hmac: bytes
    truncated_key_id: bytes
    extra: dict = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: bytes) -> "ShareProtection":
        outer = parse(raw)
        seq = outer.unwrap() if outer.cls == APPLICATION else outer
        kids = seq.children()
        keyset = next(n for n in kids if n.cls == UNIVERSAL and n.tag == 0x10)
        hmac_node = next(n for n in kids if n.cls == UNIVERSAL and n.tag == 0x04)
        share_keys = []
        ks = keyset.children()
        for entry in next(n for n in ks if n.tag == 0x11).children():  # SET OF PCSShareKey
            e = entry.children()
            keyref = e[0].children()  # {keytype, pub_key}
            flags = e[2].int() if len(e) > 2 and e[2].tag == 0x02 else 0
            share_keys.append(ShareKey(keyref[1].value, e[1].value, flags))
        sig = _ctx(kids, 1).unwrap().children()
        return cls(keyset_raw=keyset.raw, share_keys=share_keys,
                   meta=_ctx(kids, 0).unwrap().value,
                   sig_version=sig[0].int(), sig_data=sig[1].value,
                   hmac=hmac_node.value, truncated_key_id=_ctx(kids, 2).unwrap().value)

    def public_keys(self) -> list[bytes]:
        return [k.public_x for k in self.share_keys]

    def open(self, privs: list[ec.EllipticCurvePrivateKey]
             ) -> tuple[list[PCSKey], list[ec.EllipticCurvePrivateKey]]:
        """Return symmetric and identity keys opened by the matching private key."""
        by_x = {compact_x(p): p for p in privs}
        match = next(((by_x[k.public_x], k) for k in self.share_keys if k.public_x in by_x), None)
        if match is None:
            raise PCSError("none of our keys opens this share protection")
        priv, share = match
        master = PCSKey(rfc6637_unwrap(priv, share.wrapped))
        readonly = bool(share.flags & 1)
        if self.sig_version != 5 and not readonly:
            master = master.share_variant()
        if master.key_id()[:len(self.truncated_key_id)] != self.truncated_key_id:
            raise PCSError("unwrapped key does not match the protection's key id")
        if master.hmac(self.keyset_raw + self.meta + self.sig_data) != self.hmac:
            raise PCSError("share protection HMAC mismatch")

        meta = parse(master.decrypt(self.meta)).children()
        symm = [PCSKey(n.value) for n in (_ctx(meta, 0).unwrap().children() if _ctx(meta, 0) else [])]
        idents = []
        ident_set = _ctx(meta, 2)
        for ident in (ident_set.unwrap().children() if ident_set else []):
            keyset = parse(ident.children()[1].value)  # [APPLICATION 2]{...}
            inner = keyset.unwrap().children() if keyset.cls == APPLICATION else keyset.children()
            for k in inner[1].children():  # SET OF PCSPrivateKey
                idents.append(private_key_from_der(k.raw))
        return [master, *symm], idents


def keychain_key_index(items: list[dict]) -> dict[bytes, bytes]:
    """Index PCS service-key DER by the public X coordinate stored in `acct`."""
    out = {}
    for it in items:
        if not str(it.get("agrp") or "").startswith("com.apple.ProtectedCloudStorage"):
            continue
        acct, data = it.get("acct"), it.get("v_Data")
        if not isinstance(acct, str) or not isinstance(data, (bytes, bytearray)):
            continue
        try:
            out[base64.b64decode(acct)] = bytes(data)
        except (ValueError, TypeError):
            continue
    return out
