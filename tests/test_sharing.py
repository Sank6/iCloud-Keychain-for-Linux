"""Tests for shared-password decryption."""

import hashlib
import hmac as _hmac
import os
import struct
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from icp.proto.codec import Writer
from icp.sharing import groups, pcs


def _wrap(pub_x: bytes, key: bytes) -> bytes:
    """Test-side inverse of pcs.rfc6637_unwrap."""
    eph = ec.generate_private_key(ec.SECP256R1())
    secret = eph.exchange(ec.ECDH(), pcs._public_from_x(pub_x))
    kek = hashlib.sha256(b"\x00\x00\x00\x01" + secret + pcs._P256_OID + bytes([18, 3, 1, 8, 7])
                         + b"Anonymous Sender    " + b"fingerprint".ljust(20, b"\x00")).digest()[:16]
    msg = bytearray(40)
    msg[0] = 1
    msg[1:1 + len(key)] = key
    msg[1 + len(key):3 + len(key)] = (sum(key) & 0xFFFF).to_bytes(2, "big")
    pad = 40 - (len(key) + 3)
    msg[3 + len(key):] = bytes([pad]) * pad
    blob = aes_key_wrap(kek, bytes(msg))
    return (256).to_bytes(2, "big") + pcs.compact_x(eph) + bytes([len(blob)]) + blob


def _encrypt(key: pcs.PCSKey, plain: bytes, aad: bytes) -> bytes:
    kid = key.key_id()
    header = b"\x03" + kid[0:2] + b"\x02" + kid[2:4]
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(key._derive(b"encryption key key m")), modes.GCM(iv)).encryptor()
    enc.authenticate_additional_data(header + aad)
    ct = enc.update(plain) + enc.finalize()
    return header + iv + enc.tag[:12] + ct


class PrimitiveTests(unittest.TestCase):
    def test_kdf_is_sp800_108_counter_hmac(self):
        block = lambda i: _hmac.new(b"k" * 16, struct.pack(">I", i) + b"label\x00ctx"
                                    + struct.pack(">I", 40 * 8), hashlib.sha256).digest()
        self.assertEqual(pcs.kdf_ctr_hmac(b"k" * 16, b"label", b"ctx", 40), (block(1) + block(2))[:40])

    def test_rfc6637_round_trip(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        key = os.urandom(16)
        self.assertEqual(pcs.rfc6637_unwrap(priv, _wrap(pcs.compact_x(priv), key)), key)
        wrapped = bytearray(_wrap(pcs.compact_x(priv), key))
        wrapped[-1] ^= 1
        with self.assertRaises(pcs.PCSError):
            pcs.rfc6637_unwrap(priv, bytes(wrapped))

    def test_compact_private_key_forms(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        d = priv.private_numbers().private_value.to_bytes(32, "big")
        for raw in (pcs.compact_x(priv) + d, d):
            self.assertEqual(pcs.compact_x(pcs.private_from_compact(raw)), pcs.compact_x(priv))

    def test_pcs_key_decrypt_round_trip_and_aad(self):
        key = pcs.PCSKey(os.urandom(16))
        ct = _encrypt(key, b"secret", b"group-x-item-1-payload")
        self.assertEqual(key.decrypt(ct, b"group-x-item-1-payload"), b"secret")
        with self.assertRaises(pcs.PCSError):
            key.decrypt(ct, b"group-x-item-2-payload")
        with self.assertRaises(pcs.PCSError):
            pcs.PCSKey(os.urandom(16)).decrypt(ct, b"")

    def test_v2_private_key_der(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        compact = pcs.compact_x(priv) + priv.private_numbers().private_value.to_bytes(32, "big")
        pb = Writer().message(1, Writer().bytes(1, compact)).finish()
        octet = b"\x04" + bytes([len(pb)]) + pb
        der = b"\x65" + bytes([len(octet)]) + octet  # [APPLICATION 5]
        self.assertEqual(pcs.compact_x(pcs.private_key_from_der(der)), pcs.compact_x(priv))


class SharingItemTests(unittest.TestCase):
    def test_internet_password_maps_to_keychain_item(self):
        ip = (Writer().string(1, "com.apple.cfnetwork")
              .bytes(2, None).string(4, "bastian").string(6, "example.com")
              .bytes(9, b"pw").string(12, "Example").finish())
        ip = ip + b"\x11" + struct.pack("<d", 700000000.0)  # Field 2, fixed64.
        item = groups.sharing_item_to_keychain(Writer().bytes(3, ip).finish())
        self.assertEqual((item["agrp"], item["acct"], item["srvr"], item["v_Data"], item["labl"]),
                         ("com.apple.cfnetwork", "bastian", "example.com", b"pw", "Example"))
        self.assertEqual(item["mdat"], 700000000.0)

    def test_private_key_items_are_skipped(self):
        self.assertIsNone(groups.sharing_item_to_keychain(Writer().bytes(2, b"\x0a\x00").finish()))


if __name__ == "__main__":
    unittest.main()
