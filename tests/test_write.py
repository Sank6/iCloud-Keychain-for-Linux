"""Offline tests for the write path (keychain/write.py): item encryption round trip, the save
request bytes, the edit logic and the pacing. Nothing here touches the network.

Run: .venv/bin/python -m unittest tests.test_write
"""

import base64
import datetime
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from icp.keychain import crypto as kc, pipeline, write
from icp.proto import codec as _proto
from icp.proto.codec import decode_fields, first, first_str
from icp.transport import ckks, cloudkit

ZONE, OWNER = "Passwords", "_owner"


def _identifier(name, type_):
    return _proto.Writer().string(1, name).uint64(2, type_).finish()


def _record_id(name, zone=ZONE):
    zid = (_proto.Writer().message(1, _identifier(zone, 6))
           .message(2, _identifier(OWNER, 7)).finish())
    return _proto.Writer().message(1, _identifier(name, 1)).message(2, zid).finish()


def _value(kind, v):
    w = _proto.Writer()
    if kind == "bytes":
        return w.uint64(1, 1).bytes(2, v).finish()
    if kind == "str":
        return w.uint64(1, 3).string(7, v).finish()
    if kind == "int":
        return w.uint64(1, 7).uint64(4, v).finish()
    if kind == "ref":
        ref = _proto.Writer().uint64(1, 3).message(2, _record_id(v)).finish()
        return w.uint64(1, 5).message(9, ref).finish()
    raise ValueError(kind)


def _record(name, rtype, fields, etag="etag-1", zone=ZONE):
    type_msg = _proto.Writer().string(1, rtype).finish()
    w = _proto.Writer().string(1, etag).message(2, _record_id(name, zone)).message(3, type_msg)
    for fname, kind, v in fields:
        f = _proto.Writer().message(1, _proto.Writer().string(1, fname).finish()) \
            .message(2, _value(kind, v)).finish()
        w.message(7, f)
    return ckks.parse_record(w.finish())


CLASS_KEY = bytes(range(64))
CLASS_UUID = "KEY-A"


def _keyring(current=CLASS_UUID):
    return write.Keyring(class_keys={CLASS_UUID: CLASS_KEY}, key_class={CLASS_UUID: "classA"},
                         key_zone={CLASS_UUID: ZONE}, current={(ZONE, "classA"): current})


def _item_record(uuid, item, *, etag="etag-1", extra=(), gen=0, zone=ZONE):
    """An encrypted `item` record the way the server hands it out."""
    stub = _record(uuid, "item", [("parentkeyref", "ref", CLASS_UUID), ("gen", "int", gen),
                                  ("encver", "int", 2), *extra], zone=zone)
    payload = pipeline.encrypt_record_payload(stub, CLASS_KEY, item)
    return _record(uuid, "item", [
        ("data", "bytes", payload["data"]), ("encver", "int", 2), ("gen", "int", gen),
        ("parentkeyref", "ref", CLASS_UUID), ("server_wascurrent", "int", 1),
        ("uploadver", "str", "iOS 26"), ("wrappedkey", "str", payload["wrappedkey"]), *extra,
    ], etag=etag, zone=zone)


def _login(srvr="example.com", acct="anna", pw=b"old-pass"):
    return {"class": "inet", "agrp": write.AGRP_LOGIN, "srvr": srvr, "acct": acct,
            "v_Data": pw, "labl": f"{srvr} ({acct})", "pdmn": "ak", "tomb": 0,
            "sha1": b"\x01" * 20, "mdat": datetime.datetime(2024, 1, 1)}


def _sidecar(srvr="example.com", acct="anna", **payload):
    body = {"title": b"Example", "notes": b"", "s_as": [{"s": "login.example.com"}], **payload}
    return {"class": "inet", "agrp": write.AGRP_SIDECAR, "srvr": srvr, "acct": acct,
            "labl": f"{write.SIDECAR_LABEL}{srvr} ({acct})", "tomb": 0,
            "v_Data": plistlib.dumps(body, fmt=plistlib.FMT_BINARY),
            "mdat": datetime.datetime(2024, 1, 1)}


class CryptoTests(unittest.TestCase):
    def test_pad_item_blocks(self):
        for n in (0, 1, 19, 20, 39, 40, 41, 100):
            p = kc.pad_item(b"x" * n)
            self.assertEqual(len(p) % 20, 0)
            self.assertGreaterEqual(len(p), 40)
            self.assertEqual(p[n], 0x80)
            self.assertEqual(kc._strip_iso7816_padding(p), b"x" * n)

    def test_encrypt_decrypt_item(self):
        key = os.urandom(64)
        data = kc.encrypt_item(key, b"bplist00 hello", [b"a", b"b"])
        self.assertEqual(kc.decrypt_item(key, data, [b"a", b"b"]), b"bplist00 hello")
        with self.assertRaises(Exception):
            kc.decrypt_item(key, data, [b"a", b"c"])

    def test_siv_wrap_roundtrip(self):
        k = os.urandom(64)
        self.assertEqual(kc.siv_unwrap(CLASS_KEY, kc.siv_wrap(CLASS_KEY, k)), k)


class RecordTests(unittest.TestCase):
    def test_parse_keeps_etag_and_raw(self):
        rec = _item_record("U-1", _login())
        self.assertEqual(rec.etag, "etag-1")
        self.assertEqual(write.record_zone(rec), ZONE)
        self.assertEqual([n for n, _ in rec.raw["fields"]][:3], ["data", "encver", "gen"])

    def test_record_decrypts(self):
        rec = _item_record("U-1", _login())
        self.assertEqual(pipeline.decrypt_record(rec, {CLASS_UUID: CLASS_KEY})["acct"], "anna")

    def test_build_update_record_unchanged_is_identity(self):
        rec = _item_record("U-1", _login(), extra=(("musr", "bytes", b""),))
        again = ckks.parse_record(ckks.build_update_record(rec, {}))
        self.assertEqual(again.fields, rec.fields)
        self.assertEqual(again.raw["fields"], rec.raw["fields"])

    def test_build_update_record_rejects_new_fields(self):
        rec = _item_record("U-1", _login())
        with self.assertRaises(ValueError):
            ckks.build_update_record(rec, {"bogus": ckks.encode_string_value("x")})

    def test_save_request_layout(self):
        rec = _item_record("U-1", _login())
        new = _login(pw=b"new-pass")
        req = write.build_save(rec, new, _keyring())
        f = decode_fields(req)
        self.assertEqual(first_str(f, 4), "etag-1")
        self.assertEqual(first(f, 6), ckks.SAVE_SEMANTICS_UPDATE)
        saved = ckks.parse_record(first(f, 1))
        self.assertEqual(saved.record_name, "U-1")
        self.assertEqual(write.record_zone(saved), ZONE)
        # only data + wrappedkey differ, everything else byte-identical and in order
        old = dict(rec.raw["fields"])
        for name, fld in saved.raw["fields"]:
            if name not in ("data", "wrappedkey"):
                self.assertEqual(fld, old[name], name)
        self.assertEqual([n for n, _ in saved.raw["fields"]], [n for n, _ in rec.raw["fields"]])
        self.assertEqual(pipeline.decrypt_record(saved, {CLASS_UUID: CLASS_KEY})["v_Data"],
                         b"new-pass")

    def test_save_requires_etag(self):
        rec = _item_record("U-1", _login(), etag="")
        with self.assertRaises(write.WriteError):
            write.build_save(rec, _login(pw=b"x"), _keyring())

    def test_save_refuses_rotated_class_key(self):
        rec = _item_record("U-1", _login())
        with self.assertRaises(write.WriteError):
            write.build_save(rec, _login(pw=b"x"), _keyring(current="KEY-NEWER"))

    def test_insert_layout(self):
        tpl = _item_record("U-1", {**_login(), "UUID": "U-1"})
        new_uuid, req, item = write.build_insert(tpl, {**_login("b.org"), "UUID": "U-1"},
                                                 _keyring())
        self.assertNotEqual(new_uuid, "U-1")
        self.assertEqual(item["UUID"], new_uuid)
        f = decode_fields(req)
        self.assertEqual(first(f, 6), ckks.SAVE_SEMANTICS_INSERT)
        self.assertNotIn(4, f)                                  # no etag on an insert
        rec = ckks.parse_record(first(f, 1))
        self.assertEqual(rec.record_name, new_uuid)
        self.assertEqual(write.record_zone(rec), ZONE)
        self.assertEqual(rec.fields["server_wascurrent"], 0)
        self.assertEqual(rec.fields["uploadver"], "iOS 26")
        back = pipeline.decrypt_record(rec, {CLASS_UUID: CLASS_KEY})
        self.assertEqual((back["srvr"], back["UUID"]), ("b.org", new_uuid))

    def test_delete_request(self):
        rec = _item_record("U-1", _login())
        f = decode_fields(ckks.build_delete_request(rec))
        self.assertEqual(first(f, 1), rec.raw["id"])
        self.assertEqual(first_str(f, 2), "etag-1")
        with self.assertRaises(ValueError):
            ckks.build_delete_request(_item_record("U-1", _login(), etag=""))

    def test_parse_save_response(self):
        server = _proto.Writer().string(1, "etag-2").finish()
        self.assertEqual(ckks.parse_save_response(_proto.Writer().message(4, server).finish()),
                         "etag-2")
        self.assertEqual(ckks.parse_save_response(_proto.Writer().string(2, "e3").finish()), "e3")
        self.assertEqual(ckks.parse_save_response(b""), "")

    def test_client_error_code_parsed(self):
        client = _proto.Writer().uint64(1, 15).finish()
        err = _proto.Writer().message(1, client).string(4, "oplock").finish()
        result = _proto.Writer().uint64(1, 2).message(2, err).finish()
        r = cloudkit.parse_response_operation(_proto.Writer().message(3, result).finish())
        self.assertFalse(r.ok)
        self.assertEqual((r.client_code, r.error_description), (15, "oplock"))


class KeyringTests(unittest.TestCase):
    def test_build_keyring_current_pointer(self):
        tlk = os.urandom(64)
        sk = _record(CLASS_UUID, "synckey", [
            ("class", "str", "classA"), ("parentkeyref", "ref", "TLK-1"),
            ("wrappedkey", "str", base64.b64encode(kc.siv_wrap(tlk, CLASS_KEY)).decode())])
        cur = _record("classA", "currentkey", [("parentkeyref", "ref", CLASS_UUID)])
        kr = write.build_keyring({"synckey": [sk], "currentkey": [cur]}, {"TLK-1": tlk})
        self.assertEqual(kr.class_keys[CLASS_UUID], CLASS_KEY)
        self.assertEqual(kr.check_current(_item_record("U-1", _login())), CLASS_KEY)


class EditLogicTests(unittest.TestCase):
    def _entry(self, sidecar=True):
        e = write.Entry(_item_record("U-1", _login()), _login())
        if sidecar:
            e.sidecar_record, e.sidecar = _item_record("U-2", _sidecar()), _sidecar()
        return e

    def test_find_and_select(self):
        pairs = [(None, _login()), (None, _sidecar()), (None, _login("other.org", "bob")),
                 (None, {**_login("gone.org"), "tomb": 1})]
        entries = write.find_entries(pairs)
        self.assertEqual(len(entries), 2)
        e = write.select_entry(entries, "EXAMPLE.com", "Anna")
        self.assertIsNotNone(e.sidecar)
        with self.assertRaises(write.WriteError):
            write.select_entry(entries, "gone.org", "anna")

    def test_password_only_touches_login(self):
        ed = write.apply_changes(self._entry(), write.Changes(password="n3w"))
        self.assertIsNone(ed.sidecar)
        self.assertFalse(ed.rekey)
        self.assertEqual(ed.login["v_Data"], b"n3w")
        self.assertNotIn("sha1", ed.login)
        self.assertGreater(ed.login["mdat"], datetime.datetime(2025, 1, 1))
        self.assertEqual(ed.diff, ["password: changed"])
        self.assertNotIn("n3w", " ".join(ed.diff))

    def test_add_and_remove_sites(self):
        ed = write.apply_changes(self._entry(), write.Changes(
            add_sites=("https://shop.example.com/login", "example.com"),
            remove_sites=("login.example.com",)))
        payload = plistlib.loads(ed.sidecar["v_Data"])
        self.assertEqual(payload["s_as"], [{"s": "shop.example.com"}])
        self.assertEqual(payload["title"], b"Example")       # untouched, type kept
        self.assertIn("extra website added: shop.example.com", ed.diff)
        self.assertFalse(ed.rekey)

    def test_extra_site_equal_to_primary_is_skipped(self):
        with self.assertRaises(write.WriteError):   # nothing left to change
            write.apply_changes(self._entry(), write.Changes(add_sites=("example.com",)))

    def test_title_needs_sidecar(self):
        with self.assertRaises(write.WriteError):
            write.apply_changes(self._entry(sidecar=False), write.Changes(title="X"))

    def test_title_keeps_bytes(self):
        ed = write.apply_changes(self._entry(), write.Changes(title="Neu"))
        self.assertEqual(plistlib.loads(ed.sidecar["v_Data"])["title"], b"Neu")

    def test_totp_add_change_remove(self):
        uri = "otpauth://totp/ACME:anna?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=6"
        ed = write.apply_changes(self._entry(), write.Changes(totp=uri))
        block = plistlib.loads(ed.sidecar["v_Data"])["totp"]
        self.assertEqual((block["issuer"], block["accountName"], block["digits"]),
                         ("ACME", "anna", 6))
        self.assertEqual(ed.diff, ["2FA code: added"])
        from icp import totp as totp_codes
        self.assertEqual(totp_codes.generate(totp_codes.uri_from_sidecar(block), at=59)["code"],
                         totp_codes.generate(uri, at=59)["code"])
        e = self._entry()
        e.sidecar = _sidecar(totp=block)
        with self.assertRaises(write.WriteError):            # same key: nothing to do
            write.apply_changes(e, write.Changes(totp="jbsw y3dp ehpk 3pxp"))
        ed = write.apply_changes(e, write.Changes(totp=""))
        self.assertNotIn("totp", plistlib.loads(ed.sidecar["v_Data"]))
        self.assertEqual(ed.diff, ["2FA code: removed"])

    def test_totp_rejects_garbage(self):
        for bad in ("otpauth://hotp/x?secret=JBSWY3DP", "not base32 !!", "otpauth://totp/x",
                    "otpauth://totp/x?secret=JBSWY3DP&algorithm=SHA256"):
            with self.assertRaises(write.WriteError):
                write.apply_changes(self._entry(), write.Changes(totp=bad))

    def test_site_change_is_a_rekey_of_both(self):
        ed = write.apply_changes(self._entry(), write.Changes(site="https://new.example/x"))
        self.assertTrue(ed.rekey)
        self.assertEqual((ed.login["srvr"], ed.login["labl"]), ("new.example", "new.example (anna)"))
        self.assertEqual((ed.sidecar["srvr"], ed.sidecar["acct"]), ("new.example", "anna"))
        self.assertEqual(ed.sidecar["labl"], f"{write.SIDECAR_LABEL}new.example (anna)")
        self.assertEqual(ed.diff, ["website: example.com -> new.example"])

    def test_username_change_is_a_rekey(self):
        ed = write.apply_changes(self._entry(sidecar=False), write.Changes(username="anna2"))
        self.assertTrue(ed.rekey)
        self.assertEqual(ed.login["acct"], "anna2")
        self.assertIsNone(ed.sidecar)

    def test_same_site_other_case_is_no_rekey(self):
        with self.assertRaises(write.WriteError):
            write.apply_changes(self._entry(), write.Changes(site="EXAMPLE.com"))

    def test_rekey_refuses_existing_target(self):
        mine, other = self._entry(), write.Entry(_item_record("U-3", _login("b.org")),
                                                 _login("b.org"))
        with self.assertRaises(write.WriteError):
            write.apply_changes(mine, write.Changes(site="b.org"), [mine, other])

    def test_trash_moves_both_to_recently_deleted(self):
        ed = write.apply_changes(self._entry(), write.Changes(trash=True))
        self.assertTrue(ed.rekey)
        self.assertEqual(ed.login["agrp"], "com.apple.cfnetwork-recently-deleted")
        self.assertEqual(ed.sidecar["agrp"], "com.apple.password-manager-recently-deleted")
        self.assertEqual((ed.login["srvr"], ed.login["acct"], ed.login["v_Data"]),
                         ("example.com", "anna", b"old-pass"))   # nothing else changes
        self.assertNotIn("sha1", ed.login)
        self.assertEqual(ed.diff, ["moved to Recently Deleted"])

    def test_trash_alone(self):
        with self.assertRaises(write.WriteError):
            write.apply_changes(self._entry(), write.Changes(trash=True, password="x"))

    def test_no_op_is_refused(self):
        with self.assertRaises(write.WriteError):
            write.apply_changes(self._entry(), write.Changes(password="old-pass"))
        with self.assertRaises(write.WriteError):
            write.apply_changes(self._entry(), write.Changes())

    def test_bad_site(self):
        for bad in ("not a site", "example.org:8443", "user@example.org"):
            with self.assertRaises(write.WriteError):
                write.apply_changes(self._entry(), write.Changes(add_sites=(bad,)))

    def test_ambiguous_metadata_is_refused(self):
        pairs = [(None, _login()), (None, _sidecar()), (None, _sidecar())]
        e = write.select_entry(write.find_entries(pairs), "example.com", "anna")
        self.assertEqual((e.sidecar, e.sidecar_count), (None, 2))
        for ch in (write.Changes(title="X"), write.Changes(site="new.example")):
            with self.assertRaises(write.WriteError):
                write.apply_changes(e, ch)
        self.assertIsNotNone(write.apply_changes(e, write.Changes(password="n3w")).login)


class _FakeServer:
    """Stands in for OctagonClient + transport: keeps records by name, records every call."""

    def __init__(self, records, corrupt_reads=False):
        self.store = {r.record_name: r for r in records}
        self.calls = []
        self.corrupt_reads = corrupt_reads
        self.transport = self

    def save_record(self, req):
        f = decode_fields(req)
        rec = ckks.parse_record(first(f, 1))
        if first(f, 6) == ckks.SAVE_SEMANTICS_UPDATE:
            assert self.store[rec.record_name].etag == first_str(f, 4)
        else:
            assert rec.record_name not in self.store
        self.calls.append(("save", rec.record_name))
        rec.etag = "etag-new"
        if self.corrupt_reads:
            rec = _item_record(rec.record_name, _login("evil.org"))
        self.store[rec.record_name] = rec
        return "etag-new"

    def delete_record(self, req):
        f = decode_fields(req)
        name = first_str(decode_fields(first(decode_fields(first(f, 1)), 1)), 1)
        assert self.store[name].etag == first_str(f, 2)
        self.calls.append(("delete", name))
        del self.store[name]

    def fetch(self, _client):
        return {"item": list(self.store.values())}, {}


class _Sandbox(unittest.TestCase):
    """Write state, backups and the vault key in a temp dir; one fixed class key."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [mock.patch.object(write.paths, "config_dir", lambda: Path(self.tmp.name)),
                        mock.patch.object(write, "_master_key", lambda: b"k" * 32),
                        mock.patch.object(write, "OP_GAP", 0),
                        mock.patch.object(write, "build_keyring", lambda r, t: _keyring())]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()


class EditFlowTests(_Sandbox):
    def _server(self, **kw):
        login = {**_login(), "UUID": "U-1"}
        side = {**_sidecar(), "UUID": "U-2"}
        srv = _FakeServer([_item_record("U-1", login), _item_record("U-2", side)], **kw)
        return srv, mock.patch.object(write, "fetch", srv.fetch)

    def _twins(self):
        """Two logins with the same website + user (http and https), one shared sidecar."""
        a = {**_login(), "UUID": "U-1", "ptcl": "htps"}
        b = {**_login(), "UUID": "U-3", "ptcl": "http", "v_Data": b"other"}
        side = {**_sidecar(), "UUID": "U-2"}
        srv = _FakeServer([_item_record("U-1", a), _item_record("U-3", b),
                           _item_record("U-2", side)])
        return srv, mock.patch.object(write, "fetch", srv.fetch)

    def test_twins_need_the_uuid(self):
        srv, p = self._twins()
        with p, self.assertRaises(write.WriteError):
            write.edit(srv, "example.com", "anna", write.Changes(password="x"), apply=True)
        with p:
            write.edit(srv, "example.com", "anna", write.Changes(password="x"), apply=True,
                       uuid="U-3")
        self.assertEqual(srv.calls, [("save", "U-3")])

    def test_trash_twin_keeps_shared_metadata(self):
        srv, p = self._twins()
        with p:
            write.edit(srv, "example.com", "anna", write.Changes(trash=True), apply=True,
                       uuid="U-3")
        self.assertEqual([c[0] for c in srv.calls], ["save", "delete"])
        self.assertEqual(srv.calls[1][1], "U-3")
        self.assertIn("U-2", srv.store)            # sidecar still describes U-1
        self.assertIn("U-1", srv.store)

    def test_rekey_twin_copies_metadata_but_keeps_it(self):
        srv, p = self._twins()
        with p:
            write.edit(srv, "example.com", "anna", write.Changes(site="new.example"),
                       apply=True, uuid="U-3")
        self.assertEqual([c[0] for c in srv.calls], ["save", "save", "delete"])
        self.assertEqual(srv.calls[2][1], "U-3")
        self.assertIn("U-2", srv.store)

    def test_update_in_place(self):
        srv, p = self._server()
        with p:
            res = write.edit(srv, "example.com", "anna", write.Changes(password="n3w"), apply=True)
        self.assertEqual(srv.calls, [("save", "U-1")])
        self.assertFalse(res["rekey"])
        self.assertEqual(res["backups"], ["U-1"])

    def test_restore_after_update(self):
        srv, p = self._server()
        with p:
            write.edit(srv, "example.com", "anna", write.Changes(password="n3w"), apply=True)
            write.save_state({"writes": [], "blocked": None})     # skip the pacing gap
            self.assertTrue(write.restore(srv, "U-1", apply=False)["dry_run"])
            write.restore(srv, "U-1", apply=True)
        back = pipeline.decrypt_record(srv.store["U-1"], {CLASS_UUID: CLASS_KEY})
        self.assertEqual(back["v_Data"], b"old-pass")

    def test_restore_after_rekey_reinserts_old_record(self):
        srv, p = self._server()
        with p:
            write.edit(srv, "example.com", "anna", write.Changes(site="new.example"), apply=True)
            write.save_state({"writes": [], "blocked": None})
            write.restore(srv, "U-1", apply=True)
        self.assertEqual(srv.calls[-1], ("save", "U-1"))
        back = pipeline.decrypt_record(srv.store["U-1"], {CLASS_UUID: CLASS_KEY})
        self.assertEqual(back["srvr"], "example.com")
        with self.assertRaises(write.WriteError):
            write.load_backup("../U-1")

    def test_read_back_failure_blocks_and_deletes_nothing(self):
        srv, p = self._server()
        reads = []

        def flaky(client):
            reads.append(1)
            if len(reads) > 1:
                raise OSError("network down")
            return srv.fetch(client)
        with p, mock.patch.object(write, "fetch", flaky), self.assertRaises(write.WriteError):
            write.edit(srv, "example.com", "anna", write.Changes(site="new.example"), apply=True)
        self.assertEqual([c[0] for c in srv.calls], ["save", "save"])
        self.assertIn("U-1", srv.store)
        self.assertTrue(write.load_state()["blocked"])

    def test_rekey_inserts_verifies_then_deletes(self):
        srv, p = self._server()
        with p:
            res = write.edit(srv, "example.com", "anna", write.Changes(site="new.example"),
                             apply=True)
        ops = [c[0] for c in srv.calls]
        self.assertEqual(ops, ["save", "save", "delete", "delete"])
        self.assertEqual([c[1] for c in srv.calls[2:]], ["U-2", "U-1"])  # metadata first
        self.assertNotIn("U-1", srv.store)
        self.assertEqual(res["uuid"], srv.calls[0][1])
        new = pipeline.decrypt_record(srv.store[res["uuid"]], {CLASS_UUID: CLASS_KEY})
        self.assertEqual((new["srvr"], new["UUID"]), ("new.example", res["uuid"]))

    def test_trash_flow(self):
        srv, p = self._server()
        with p:
            res = write.edit(srv, "example.com", "anna", write.Changes(trash=True), apply=True)
        self.assertEqual([c[0] for c in srv.calls], ["save", "save", "delete", "delete"])
        self.assertTrue(res["trashed"])
        agrps = sorted(pipeline.decrypt_record(r, {CLASS_UUID: CLASS_KEY})["agrp"]
                       for r in srv.store.values())
        self.assertEqual(agrps, ["com.apple.cfnetwork-recently-deleted",
                                 "com.apple.password-manager-recently-deleted"])

    def test_rekey_bad_read_back_deletes_nothing(self):
        srv, p = self._server(corrupt_reads=True)
        with p, self.assertRaises(write.WriteError):
            write.edit(srv, "example.com", "anna", write.Changes(site="new.example"), apply=True)
        self.assertEqual([c[0] for c in srv.calls], ["save", "save"])
        self.assertIn("U-1", srv.store)
        self.assertTrue(write.load_state()["blocked"])

    def test_dry_run_sends_nothing(self):
        srv, p = self._server()
        with p:
            res = write.edit(srv, "example.com", "anna", write.Changes(site="new.example"),
                             apply=False)
        self.assertEqual(srv.calls, [])
        self.assertTrue(res["dry_run"] and res["rekey"])


def _real_login(srvr="example.com", acct="anna", pw=b"old-pass"):
    """A login with the attribute set a real device writes (names/types as `icp diag write`)."""
    return {**_login(srvr, acct, pw), "UUID": "", "atyp": "form", "ptcl": "htps", "port": 443,
            "path": "/signin", "sdmn": "", "desc": "web form password", "icmt": "a comment",
            "musr": b"", "sync": True, "type": 0, "cusi": 0, "invi": 0, "nega": 0, "scrp": 0,
            "cdat": datetime.datetime(2024, 1, 1), "odd1": "kept out"}


def _real_sidecar(srvr="example.com", acct="anna"):
    return {**_sidecar(srvr, acct), "UUID": "", "atyp": "form", "ptcl": "htps", "port": 0,
            "path": "", "sdmn": "", "desc": "", "pdmn": "ak", "musr": b"", "sync": True,
            "type": 0, "bin0": b"\x01\x02", "cdat": datetime.datetime(2024, 1, 1)}


SECRETS = ("s3cret-Pass", "private notes", "JBSWY3DPEHPK3PXP")
NEW = {"site": "https://new.example/login", "user": "bob", "password": "s3cret-Pass"}


class CreateFlowTests(_Sandbox):
    def _server(self, sidecar=True, **kw):
        recs = [_item_record("U-1", {**_real_login(), "UUID": "U-1"}, gen=7)]
        if sidecar:
            recs.append(_item_record("U-2", {**_real_sidecar(), "UUID": "U-2"}, gen=3))
        srv = _FakeServer(recs, **kw)
        return srv, mock.patch.object(write, "fetch", srv.fetch)

    def _create(self, srv, p, apply=True, **kw):
        args = {**NEW, **kw}
        with p:
            return write.create(srv, args.pop("site"), args.pop("user"), args.pop("password"),
                                apply=apply, **args)

    def _stored(self, srv, uuid):
        return pipeline.decrypt_record(srv.store[uuid], {CLASS_UUID: CLASS_KEY})

    def test_new_login_layout(self):
        srv, p = self._server()
        res = self._create(srv, p)
        self.assertEqual(srv.calls, [("save", res["uuid"])])     # no metadata asked for
        self.assertFalse(res["sidecar"])
        rec = srv.store[res["uuid"]]
        self.assertEqual(write.record_zone(rec), ZONE)
        self.assertEqual(rec.fields["gen"], 0)                   # fresh item, template had 7
        self.assertEqual(rec.fields["server_wascurrent"], 0)
        item = self._stored(srv, res["uuid"])
        self.assertEqual(item["UUID"], res["uuid"])
        self.assertEqual(sorted(item), sorted(set(_real_login()) - {"sha1", "odd1"}))
        self.assertEqual((item["class"], item["agrp"], item["srvr"], item["acct"], item["labl"]),
                         ("inet", write.AGRP_LOGIN, "new.example", "bob", "new.example (bob)"))
        self.assertEqual(item["v_Data"], b"s3cret-Pass")
        self.assertEqual((item["ptcl"], item["port"], item["path"], item["desc"], item["icmt"]),
                         ("htps", 0, "", "", ""))
        self.assertEqual((item["pdmn"], item["atyp"], item["sync"], item["tomb"]),
                         ("ak", "form", True, 0))
        self.assertEqual(item["cdat"], item["mdat"])
        self.assertEqual(res["skipped_attrs"], ["odd1"])
        self.assertEqual(res["login_attrs"]["v_Data"], "bytes")

    def test_http_site_keeps_its_protocol(self):
        srv, p = self._server()
        res = self._create(srv, p, site="http://old.example")
        self.assertEqual(self._stored(srv, res["uuid"])["ptcl"], "http")

    def test_metadata_when_title_notes_totp_given(self):
        srv, p = self._server()
        res = self._create(srv, p, title="New Example", notes="private notes",
                           totp="otpauth://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP&issuer=ACME")
        self.assertTrue(res["sidecar"])
        self.assertEqual([c[0] for c in srv.calls], ["save", "save"])
        self.assertEqual(srv.calls[0][1], res["uuid"])            # login first
        side = self._stored(srv, srv.calls[1][1])
        self.assertEqual((side["agrp"], side["srvr"], side["acct"], side["labl"]),
                         (write.AGRP_SIDECAR, "new.example", "bob",
                          f"{write.SIDECAR_LABEL}new.example (bob)"))
        self.assertNotIn("bin0", side)
        self.assertEqual(srv.store[srv.calls[1][1]].fields["gen"], 0)
        body = plistlib.loads(side["v_Data"])
        self.assertEqual((body["title"], body["notes"], body["s_as"]),
                         (b"New Example", b"private notes", []))
        self.assertEqual(body["totp"]["issuer"], "ACME")
        # the vault reads it back as one login with its metadata
        from icp.vault.host import CredentialStore
        cred, = CredentialStore.from_items([self._stored(srv, res["uuid"]), side]).all()
        self.assertEqual((cred.title, cred.uuid, cred.notes), ("New Example", res["uuid"],
                                                               "private notes"))
        self.assertTrue(cred.totp)

    def test_no_metadata_template_creates_login_only(self):
        srv, p = self._server(sidecar=False)
        res = self._create(srv, p, title="X")
        self.assertEqual(srv.calls, [("save", res["uuid"])])
        self.assertFalse(res["sidecar"])
        self.assertTrue(res["warnings"])

    def test_duplicate_is_refused(self):
        srv, p = self._server()
        with self.assertRaises(write.ExistsError):
            self._create(srv, p, site="EXAMPLE.com", user="Anna")
        self.assertEqual(srv.calls, [])

    def test_orphan_metadata_is_refused(self):
        srv, p = self._server()
        srv.store["U-9"] = _item_record("U-9", {**_real_sidecar("new.example", "bob"),
                                                "UUID": "U-9"})
        with self.assertRaises(write.WriteError):
            self._create(srv, p, title="X")
        self.assertEqual(srv.calls, [])

    def test_template_needs_current_key_and_no_pcs(self):
        srv, p = self._server()
        srv.store["U-1"] = _item_record("U-1", {**_real_login(), "UUID": "U-1"},
                                        extra=(("pcsservice", "int", 1),))
        with self.assertRaises(write.WriteError):
            self._create(srv, p)
        srv, p = self._server()
        with mock.patch.object(write, "build_keyring", lambda r, t: _keyring("KEY-NEWER")), \
                self.assertRaises(write.WriteError):
            self._create(srv, p)
        self.assertEqual(srv.calls, [])

    def test_bad_input(self):
        srv, p = self._server()
        for kw in ({"site": "not a site"}, {"user": ""}, {"password": ""},
                   {"totp": "otpauth://hotp/x?secret=JBSWY3DP"}):
            with self.assertRaises(write.WriteError):
                self._create(srv, p, **kw)
        self.assertEqual(srv.calls, [])

    def test_dry_run_sends_nothing(self):
        srv, p = self._server()
        res = self._create(srv, p, apply=False, title="T", notes="private notes")
        self.assertEqual(srv.calls, [])
        self.assertTrue(res["dry_run"] and res["sidecar"])
        self.assertNotIn(res["uuid"], srv.store)
        self.assertNotIn("login_item", res)
        self.assertEqual(write.load_state().get("writes"), [])

    def test_bad_read_back_blocks(self):
        srv, p = self._server(corrupt_reads=True)
        with self.assertRaises(write.WriteError):
            self._create(srv, p)
        self.assertEqual([c[0] for c in srv.calls], ["save"])
        self.assertTrue(write.load_state()["blocked"])

    def test_read_back_fetch_failure_blocks(self):
        srv, p = self._server()
        reads = []

        def flaky(client):
            reads.append(1)
            if len(reads) > 1:
                raise OSError("network down")
            return srv.fetch(client)
        with mock.patch.object(write, "fetch", flaky), self.assertRaises(write.WriteError):
            write.create(srv, "new.example", "bob", "s3cret-Pass", apply=True)
        self.assertTrue(write.load_state()["blocked"])

    def test_blocked_state_sends_nothing(self):
        write.save_state({"writes": [], "blocked": "earlier error"})
        srv, p = self._server()
        with self.assertRaises(write.WriteError):
            self._create(srv, p)
        self.assertEqual(srv.calls, [])

    def test_report_has_no_secrets(self):
        import json
        srv, p = self._server()
        for apply in (False, True):
            write.save_state({"writes": [], "blocked": None})
            res = self._create(srv, p, apply=apply, user=f"bob{apply}", title="T",
                               notes="private notes", totp="JBSWY3DPEHPK3PXP")
            public = {k: v for k, v in res.items() if k not in ("login_item", "sidecar_item")}
            text = json.dumps(public)
            for secret in SECRETS:
                self.assertNotIn(secret, text)


class AddCommandTests(_Sandbox):
    """`icp add` end to end against the fake server: stdin JSON in, report out."""

    def _run(self, payload, *argv):
        import io
        import json
        from contextlib import redirect_stdout
        from icp.cli import app
        srv = _FakeServer([_item_record("U-1", {**_real_login(), "UUID": "U-1"}),
                           _item_record("U-2", {**_real_sidecar(), "UUID": "U-2"})])
        session = mock.Mock(side_effect=lambda args: (io.StringIO(), srv))
        appended = []
        out = io.StringIO()
        stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload) + "\n")
        with mock.patch.object(write, "fetch", srv.fetch), \
                mock.patch.object(app, "_write_session", session), \
                mock.patch.object(app, "_append_vault", lambda *a: appended.append(a)), \
                mock.patch("sys.stdin", stdin), redirect_stdout(out):
            code = app.main(["add", "--stdin-json", *argv])
        return code, out.getvalue(), srv, appended, session

    def test_dry_run_json(self):
        import json
        code, out, srv, appended, _ = self._run({**NEW, "notes": "private notes"}, "--json")
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertEqual((res["ok"], res["dryRun"], res["uuid"], res["site"], res["user"],
                          res["sidecar"]), (True, True, None, "new.example", "bob", True))
        self.assertEqual((srv.calls, appended), ([], []))
        for secret in SECRETS:
            self.assertNotIn(secret, out)

    def test_apply_appends_to_vault(self):
        import json
        code, out, srv, appended, _ = self._run(NEW, "--apply", "--json")
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertEqual((res["dryRun"], res["sidecar"]), (False, False))
        self.assertEqual(srv.calls, [("save", res["uuid"])])
        (login, sidecar), = appended
        self.assertEqual((login["UUID"], sidecar), (res["uuid"], None))
        self.assertNotIn("s3cret-Pass", out)

    def test_text_dry_run_lists_names_only(self):
        code, out, *_ = self._run({**NEW, "title": "T", "totp": "JBSWY3DPEHPK3PXP"})
        self.assertEqual(code, 0)
        self.assertIn("v_Data:bytes", out)
        self.assertIn("Dry run", out)
        for secret in SECRETS:
            self.assertNotIn(secret, out)

    def test_exists_exit_code(self):
        import json
        code, out, srv, *_ = self._run({**NEW, "site": "example.com", "user": "anna"}, "--json")
        self.assertEqual(code, 3)
        res = json.loads(out)
        self.assertEqual((res["ok"], res["exists"]), (False, True))
        self.assertIn("exists", res["error"])
        self.assertEqual(srv.calls, [])

    def test_validation_before_any_network(self):
        for payload in ({"site": "a.example", "user": "bob"}, {**NEW, "notes": 5}, "not json\n",
                        "[1]\n"):
            code, _out, srv, _a, session = self._run(payload, "--json")
            self.assertEqual(code, 1)
            session.assert_not_called()


class PacingTests(unittest.TestCase):
    def test_gap_hourly_and_block(self):
        st = {"writes": [], "blocked": None}
        self.assertTrue(write.may_write(st, now=1000)[0])
        st["writes"] = [995]
        self.assertFalse(write.may_write(st, now=1000)[0])
        self.assertTrue(write.may_write(st, now=1006)[0])
        st["writes"] = [1000 + i * 20 for i in range(write.WRITE_MAX_PER_HOUR)]
        self.assertFalse(write.may_write(st, now=1000 + 30 * 20 + 20)[0])
        self.assertTrue(write.may_write({"writes": [], "blocked": None}, now=0)[0])
        self.assertFalse(write.may_write({"writes": [], "blocked": "x"}, now=0)[0])


class BackupTests(unittest.TestCase):
    def test_backup_roundtrip(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(write.paths, "config_dir", lambda: Path(d)), \
                mock.patch.object(write, "_master_key", lambda: b"k" * 32):
            rec = _item_record("U-9", _login())
            write.backup_record(rec)
            back = write.load_backup("U-9")
            self.assertEqual(back.raw["fields"], rec.raw["fields"])
            self.assertEqual(oct(os.stat(next(Path(d, "backup").iterdir())).st_mode & 0o777),
                             "0o600")


if __name__ == "__main__":
    unittest.main()
