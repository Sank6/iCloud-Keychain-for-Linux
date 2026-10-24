"""Native-messaging host for the browser autofill extension. Speaks Chrome's native-messaging
protocol on stdin/stdout (4-byte LE length prefix + UTF-8 JSON) and answers domain queries from
the decrypted vault, read-only.

Protocol (JSON):
  -> {"cmd":"ping"}                              <- {"ok":true,"count":N}
  -> {"cmd":"match","domain":"login.example.com"} <- {"ok":true,"credentials":[{...}]}
  -> {"cmd":"totp","domain":...,"username":...}   <- {"ok":true,"totp":{"code":...}}

A credential's one-time-code secret never crosses this protocol: `match` carries the code
generated at request time, and `totp` re-generates it when the browser's copy has rolled over.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import plistlib
import re
import struct
import sys

from .. import totp as totp_codes


@dataclasses.dataclass(frozen=True)
class Credential:
    domain: str
    username: str
    password: str
    title: str = ""
    mdat: float = 0.0
    notes: str = ""
    last_used: float = 0.0
    totp: str = ""
    group: str = ""  # Empty for the user's keychain.

    @property
    def recency(self) -> float:
        return self.last_used or self.mdat

    def public_dict(self) -> dict:
        return {"domain": self.domain, "username": self.username,
                "password": self.password, "title": self.title, "mdat": self.mdat,
                "notes": self.notes, "last_used": self.last_used, "totp": self.totp,
                "group": self.group}

    def wire_dict(self) -> dict:
        """The extension's view: the `totp` URI is replaced by a code generated now."""
        return {**self.public_dict(), "totp": totp_codes.generate(self.totp) or None}


_APPLE_EPOCH = 978307200  # 2001-01-01 UTC in unix seconds (Apple "absolute time" origin)


def _to_unix(value) -> float:
    """Best-effort convert a keychain date (`mdat`/`cdat`) to unix epoch seconds; 0 if unknown.
    plistlib yields a datetime for binary-plist <date>; a CKKS dateValue arrives as `CKDate`;
    a bare number is Apple absolute time (secs since 2001) when small, already-unix when large."""
    if isinstance(value, datetime.datetime):
        return value.timestamp()
    value = getattr(value, "time", value)  # ckks.CKDate -> its .time (unix seconds)
    if isinstance(value, (int, float)) and value > 0:
        return float(value) + _APPLE_EPOCH if value < 1e9 else float(value)
    return 0.0


def _normalize_host(value: str) -> str:
    """Reduce a URL or host to a bare lowercase hostname (strip scheme/port/path/leading www)."""
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split("?", 1)[0]
    v = v.split("@")[-1]          # strip userinfo
    v = v.split(":", 1)[0]        # strip port
    if v.startswith("www."):
        v = v[4:]
    return v


def domains_match(page: str, stored: str) -> bool:
    """True if a stored item's domain should autofill on `page`.

    Matches exact host, and either being a sub-domain of the other (so `example.com` fills on
    `login.example.com` and vice-versa). Conservative: requires a dotted-boundary suffix so
    `notexample.com` never matches `example.com`.
    """
    p, s = _normalize_host(page), _normalize_host(stored)
    if not p or not s:
        return False
    if p == s:
        return True
    return p.endswith("." + s) or s.endswith("." + p)


def match_aliases(page_domain: str, aliases: list) -> list:
    """Hide My Email aliases (icp.hme.client.HmeAlias) whose recorded domain matches the
    page, same domains_match() rule as Credential. Duck-typed on `.domain` rather than
    importing HmeAlias - vault/ stays free of any import from the hme/ extension."""
    return [a for a in aliases if a.domain and domains_match(page_domain, a.domain)]


def _is_credential(domain: str, title: str) -> bool:
    """False for the non-login records iCloud Keychain also syncs: Protected Cloud Storage service
    blobs (label "PCS com.apple.*", whose `acct` is a base64 key) and per-site "Website Metadata"
    records. Checks the final domain/title so the marker is caught wherever it lands; real web
    logins are reverse-DNS free and never carry these names."""
    for tag in (domain, title):
        t = (tag or "").strip().lower()
        if t.startswith(("pcs ", "pcs-", "website metadata")) or "com.apple." in t:
            return False
    return True


_GENERIC_NAME_TOKENS = {
    "account", "accounts", "admin", "app", "dashboard", "login", "password", "passwords",
    "signin", "sign", "web", "www",
}


def _name_matches_host(page: str, name: str) -> bool:
    """Fallback for Passwords entries that decrypt as generic items with only a saved label.

    The iOS Passwords app can show a useful account name (for example "Cloudflare") even when
    the decrypted item has no `srvr` host. Match only whole hostname labels so this stays much
    narrower than substring matching.
    """
    labels = {label for label in _normalize_host(page).split(".") if label}
    if not labels:
        return False
    tokens = {
        token for token in re.findall(r"[a-z0-9]+", name.lower())
        if len(token) >= 4 and token not in _GENERIC_NAME_TOKENS
    }
    return bool(labels & tokens)

# `agrp` is the access group of the subsystem that wrote an item, and identifies its record type.
_AGRP_LOGIN = {"com.apple.cfnetwork", "apple"}
_AGRP_SIDECAR_PREFIX = "com.apple.password-manager"
_AGRP_CARD = "com.apple.safari.credit-cards"
_AGRP_PASSKEY = "com.apple.webkit.webauthn"

_SIDECAR_LABEL_PREFIX = "password manager metadata:"
# Allowlist: unknown keys are dropped. `s_hi` is excluded deliberately - it holds previous
# passwords in cleartext, which have no autofill use and do not belong in the vault.
_SIDECAR_KEEP = {"notes", "title", "ctxt", "totp"}
_PLUMBING_KEYSETS = ({"tlkUUID", "srcIdentity"}, {"viewName", "encryptedData"})
_CARD_KEYS = {"CardNumber", "FPANHash", "PrimaryAccountIdentifier", "CardSecurityCode"}


def _load_plist(blob: bytes):
    """Parse a binary-plist payload, or None if it isn't one."""
    if not blob.startswith(b"bplist00"):
        return None
    try:
        return plistlib.loads(blob, fmt=plistlib.FMT_BINARY)
    except Exception:  # noqa: BLE001 - a malformed payload is simply "not a plist" here
        return None


def classify_payload(value, label: str = ""):
    """Classify an item's `v_Data` -> (kind, payload).

    kind is one of:
      "password" - credential text; payload is the decoded `str`
      "sidecar"  - a metadata record; payload is its plist dict
      "card"     - a payment card; payload is its plist dict
      "plumbing" - keychain-sync internals
      "binary"   - key material

    A password is text, so a payload that is not valid UTF-8 is classified rather than decoded.
    """
    if isinstance(value, str):
        return "password", value
    if not isinstance(value, (bytes, bytearray)):
        return "password", ""
    blob = bytes(value)
    if not blob:
        return "password", ""

    parsed = _load_plist(blob)
    if parsed is not None:
        keys = set(parsed) if isinstance(parsed, dict) else set()
        if any(keyset <= keys for keyset in _PLUMBING_KEYSETS):
            return "plumbing", parsed
        if keys & _CARD_KEYS:
            return "card", parsed
        return "sidecar", parsed
    if blob.lstrip()[:5] == b"<?xml":
        return "plumbing", None
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", None
    # Some records decode as valid UTF-8 but are not text; a password has no C0 control bytes.
    if any(ord(ch) < 0x20 and ch not in "\t\n\r" or ord(ch) == 0x7f for ch in text):
        return "binary", None
    return "password", text


def classify_item(item) -> tuple:
    """Classify a decrypted keychain item -> (kind, payload), keying on its `agrp` access group.

    Adds "passkey" and "subsystem" to the kinds `classify_payload` returns. An item whose group
    is unrecognised falls back to inspecting the payload.
    """
    agrp = str(item.get("agrp") or "")
    raw = item.get("v_Data") or item.get("password") or b""
    label = str(item.get("labl") or "")

    if agrp.startswith(_AGRP_SIDECAR_PREFIX):
        payload = classify_payload(raw, label)[1]
        return "sidecar", payload if isinstance(payload, dict) else {}
    if agrp == _AGRP_CARD:
        payload = classify_payload(raw, label)[1]
        return "card", payload if isinstance(payload, dict) else {}
    if agrp == _AGRP_PASSKEY:
        return "passkey", None
    if agrp in _AGRP_LOGIN:
        # A login group still holds the odd non-text blob.
        kind, payload = classify_payload(raw, label)
        return (kind, payload) if kind in ("password", "sidecar") else ("binary", None)
    if agrp.startswith("com.apple."):
        return "subsystem", None
    return classify_payload(raw, label)


def _sidecar_last_used(ctxt) -> float:
    """Last-used time from a sidecar's `ctxt`, keyed by browser profile:
    {"<profile>": {"lUsed": <apple-absolute-seconds>}}. Takes the most recent across profiles."""
    if not isinstance(ctxt, dict):
        return 0.0
    best = 0.0
    for per_profile in ctxt.values():
        if not isinstance(per_profile, dict):
            continue
        best = max(best, _to_unix(per_profile.get("lUsed") or per_profile.get("slUsed")))
    return best


def _sidecar_text(value) -> str:
    """A sidecar string field, which plistlib may hand back as bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value) if value else ""


def decode_payment_cards(items) -> list[dict]:
    """Payment-card records, decoded. Diagnostic only: `from_items` drops these, so they never
    reach the vault or the browser extension."""
    cards = []
    for it in items:
        kind, payload = classify_item(it)
        if kind == "card" and payload:
            cards.append({"id": it.get("acct") or "", **payload})
    return cards


class CredentialStore:
    """In-memory read-only store. The pipeline builds this from decrypted keychain items."""

    def __init__(self, credentials=None):
        self._creds: list[Credential] = list(credentials or [])

    def __len__(self) -> int:
        return len(self._creds)

    def all(self) -> list["Credential"]:
        return list(self._creds)

    def match(self, page_domain: str) -> list[Credential]:
        def match_rank(c: Credential) -> int | None:
            if not _is_credential(c.domain, c.title):  # filters an older, unfiltered vault too
                return None
            if domains_match(page_domain, c.domain):
                return 0 if _normalize_host(page_domain) == _normalize_host(c.domain) else 1
            stored = _normalize_host(c.domain)
            if ("." not in stored) and _name_matches_host(page_domain, c.title or c.domain):
                return 2
            return None

        ranked = [(rank, c) for c in self._creds if (rank := match_rank(c)) is not None]
        # exact-host matches first, then parent/subdomain, then label-only fallbacks; within a
        # tier, most-recently-used first, then title for a stable order.
        ranked.sort(key=lambda rc: (rc[0], -rc[1].recency, rc[1].title, rc[1].username))
        return [c for _, c in ranked]

    @classmethod
    def from_items(cls, items) -> "CredentialStore":
        """Build from decrypted keychain item dicts (plist form). Apple `inet` password items use
        `srvr` (server/domain), `acct` (username), `v_Data` (plaintext password), `labl` (title);
        tolerate the common variants.

        A login and its metadata sidecar are separate keychain items joined on `(srvr, acct)`,
        so this runs in two passes: collect both, then fold each sidecar onto its login. Cards,
        sync plumbing and key material are dropped.
        """
        logins, sidecars = [], {}
        for it in items:
            domain = (it.get("srvr") or it.get("server") or it.get("domain")
                      or it.get("url") or it.get("svce") or "")
            username = it.get("acct") or it.get("username") or it.get("user") or ""
            label = str(it.get("labl") or "")
            kind, payload = classify_item(it)
            # The label names the login the sidecar describes, so trust it over an empty payload.
            if label.lower().startswith(_SIDECAR_LABEL_PREFIX):
                kind, payload = "sidecar", payload if isinstance(payload, dict) else {}

            key = (str(domain).lower(), str(username).lower())
            if kind == "sidecar":
                if domain or username:
                    kept = {k: v for k, v in payload.items() if k in _SIDECAR_KEEP}
                    sidecars.setdefault(key, {}).update(kept)
                continue
            if kind != "password":
                continue

            title = label or str(domain)
            if not _is_credential(str(domain), title):
                continue
            # Need a host/label to match against and at least a username or password to fill.
            if (not domain and not username) or not (username or payload):
                continue
            logins.append((key, str(domain), str(username), payload, title,
                           _to_unix(it.get("mdat") or it.get("cdat"))))

        creds = []
        for key, domain, username, pw, title, mdat in logins:
            side = sidecars.get(key, {})
            title = _sidecar_text(side.get("title")) or title
            creds.append(Credential(
                domain=domain, username=username, password=pw, title=title, mdat=mdat,
                notes=_sidecar_text(side.get("notes")),
                last_used=_sidecar_last_used(side.get("ctxt")),
                totp=totp_codes.uri_from_sidecar(side.get("totp")),
            ))
        return cls(creds)


# native-messaging framing
def read_message(stream=None) -> dict | None:
    stream = stream or sys.stdin.buffer
    raw_len = stream.read(4)
    if len(raw_len) < 4:
        return None
    (length,) = struct.unpack("<I", raw_len)
    data = stream.read(length)
    if len(data) < length:
        return None
    return json.loads(data.decode("utf-8"))


def write_message(message: dict, stream=None) -> None:
    stream = stream or sys.stdout.buffer
    encoded = json.dumps(message).encode("utf-8")
    stream.write(struct.pack("<I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def handle(request: dict, store: CredentialStore, aliases: list | None = None) -> dict:
    cmd = request.get("cmd")
    if cmd == "ping":
        return {"ok": True, "count": len(store)}
    if cmd == "match":
        domain = request.get("domain", "")
        if not domain:
            return {"ok": False, "error": "missing domain"}
        matched = match_aliases(domain, aliases or [])
        return {"ok": True, "credentials": [c.wire_dict() for c in store.match(domain)],
                "aliases": [a.public_dict() for a in matched]}
    if cmd == "totp":
        domain, username = request.get("domain", ""), request.get("username", "")
        for c in store.match(domain):
            if c.username == username and c.totp:
                return {"ok": True, "totp": totp_codes.generate(c.totp)}
        return {"ok": False, "error": "no code for that login"}
    return {"ok": False, "error": f"unknown cmd {cmd!r}"}


def serve(store: CredentialStore, *, aliases: list | None = None,
         instream=None, outstream=None) -> None:
    """Blocking native-messaging loop. Returns when the extension disconnects (EOF)."""
    while True:
        request = read_message(instream)
        if request is None:
            return
        write_message(handle(request, store, aliases), outstream)


def _maybe_trigger_sync() -> None:
    """If the vault is older than ICP_SYNC_MAX_AGE (default 6h), kick off a detached `sync`
    in the background and return immediately - the current request is still served from the
    existing vault, and the refreshed data is picked up on the next host spawn.

    Best-effort: never blocks and never raises. A debounce marker stops a multi-frame page from
    launching many syncs at once; `sync` itself holds a lock so only one ever runs."""
    import os
    import subprocess
    import time

    from .. import paths
    try:
        max_age = int(os.environ.get("ICP_SYNC_MAX_AGE", str(6 * 3600)))
        if max_age <= 0:
            return  # auto-sync disabled
        vault = paths.vault_file()
        if vault.exists() and (time.time() - vault.stat().st_mtime) < max_age:
            return  # fresh enough
        attempt = paths.sync_attempt_file()
        if attempt.exists() and (time.time() - attempt.stat().st_mtime) < 300:
            return  # already triggered recently
        attempt.touch()
        subprocess.Popen(
            [sys.executable, "-m", "icp.cli.app", "sync"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass


def main(argv=None) -> int:
    """Serve the decrypted vault; fall back to an empty store so the extension can still
    connect/ping when no vault has been synced yet. Hide My Email aliases are a best-effort
    add-on (empty list if no cache exists yet - the host never touches the network itself,
    the cache is only ever populated by `icp show`/`icp sync`)."""
    _maybe_trigger_sync()
    try:
        from .store import load_vault
        store = load_vault()
    except Exception:
        store = CredentialStore([])
    try:
        from ..hme.store import load_aliases
        aliases = load_aliases()
    except Exception:
        aliases = []
    serve(store, aliases=aliases)
    return 0


if __name__ == "__main__":
    sys.exit(main())
