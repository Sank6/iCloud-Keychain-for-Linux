"""Native-messaging host for the browser autofill extension. Speaks Chrome's native-messaging
protocol on stdin/stdout (4-byte LE length prefix + UTF-8 JSON) and answers domain queries from
the decrypted vault, read-only.

Protocol (JSON):
  -> {"cmd":"ping"}                              <- {"ok":true,"count":N}
  -> {"cmd":"match","domain":"login.example.com"} <- {"ok":true,"credentials":[{...}]}
"""

from __future__ import annotations

import dataclasses
import datetime
import base64
import hashlib
import hmac
import json
import plistlib
import re
import struct
import sys
import time
from urllib.parse import parse_qs, unquote, urlparse


@dataclasses.dataclass(frozen=True)
class Credential:
    domain: str
    username: str
    password: str
    title: str = ""
    # Unix epoch seconds of the item's last change (keychain `mdat`, falling back to `cdat`);
    # 0 when unknown. Used to sort newest-first and to render a "last used N ago" line.
    mdat: float = 0.0
    notes: str = ""
    otp_uri: str = ""

    def public_dict(self) -> dict:
        result = {"domain": self.domain, "username": self.username,
                  "password": self.password, "title": self.title, "mdat": self.mdat,
                  "notes": self.notes}
        if self.otp_uri:
            result["totp"] = current_totp(self.otp_uri)
        return result


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


def _text_key(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", (value or "").casefold()))


def _walk_plist(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_plist(child)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield "", child
            yield from _walk_plist(child)


def _merge_text(a: str, b: str) -> str:
    parts = []
    for value in (a, b):
        value = (value or "").strip()
        if value and value not in parts:
            parts.append(value)
    return "\n".join(parts)


def _expand_keyed_archive(obj):
    """Resolve a plistlib NSKeyedArchiver object graph into ordinary Python values."""
    if not isinstance(obj, dict) or obj.get("$archiver") != "NSKeyedArchiver":
        return obj
    objects = obj.get("$objects")
    if not isinstance(objects, list):
        return obj

    def resolve(node, seen=frozenset()):
        if isinstance(node, plistlib.UID):
            index = node.data
            if index < 0 or index >= len(objects) or index in seen:
                return None
            return resolve(objects[index], seen | {index})
        if node == "$null":
            return None
        if isinstance(node, list):
            return [resolve(value, seen) for value in node]
        if isinstance(node, dict):
            out = {key: resolve(value, seen) for key, value in node.items()
                   if not str(key).startswith("$")}
            if "$class" in node:
                for wrapper in ("NS.data", "NS.string", "NS.objects", "NS.keys"):
                    if wrapper in out and len(out) == 1:
                        return out[wrapper]
                # NSDictionary archives store parallel NS.keys / NS.objects arrays.
                keys, values = out.get("NS.keys"), out.get("NS.objects")
                if isinstance(keys, list) and isinstance(values, list):
                    return {str(k): v for k, v in zip(keys, values)}
            return out
        return node

    top = obj.get("$top")
    if isinstance(top, dict) and "root" in top:
        return resolve(top["root"])
    return resolve(top)


def _decode_item_value(raw) -> tuple[str, str, str, dict[str, str]]:
    """Return ``(password, notes, otp_uri)`` from a keychain value.

    Binary plists are recursively inspected rather than decoded as replacement-character text.
    This prevents visible ``bplist00...`` garbage and handles Apple's changing metadata keys.
    """
    if raw is None:
        return "", "", "", {}
    if isinstance(raw, str):
        if raw.startswith("otpauth://"):
            return "", "", raw, {}
        return raw, "", "", {}
    if not isinstance(raw, (bytes, bytearray)):
        return str(raw), "", "", {}
    data = bytes(raw)
    if not data.startswith(b"bplist00"):
        return data.decode("utf-8", "replace"), "", "", {}
    try:
        obj = _expand_keyed_archive(plistlib.loads(data))
    except Exception:
        return "", "", "", {}

    otp_uri = ""
    notes: list[str] = []
    password = ""
    password_score = -1
    metadata: dict[str, str] = {}
    note_keys = {"note", "notes", "comment", "comments", "txt", "text"}
    # Avoid treating security-recommendation fields named merely "value" or "secret" as the
    # login password. Explicit password fields win; generic fields are accepted only as a
    # last-resort when their surrounding key is not warning/security metadata.
    password_key_scores = {
        "password": 100, "passwd": 100, "secretvalue": 90,
        "credentialpassword": 100, "cleartextpassword": 100,
        "secret": 20, "value": 10,
    }
    warning_tokens = {"compromised", "weak", "reused", "breach", "warning",
                      "recommendation", "security", "risk", "score", "status"}
    domain_keys = {"srvr", "server", "domain", "url", "website", "site", "relyingparty"}
    username_keys = {"acct", "account", "username", "user", "login", "email"}
    title_keys = {"labl", "label", "title", "name", "displayname"}
    group_keys = {"group", "groupname", "sharedgroup", "sharedgroupname", "collection"}
    for key, value in _walk_plist(obj):
        key_l = key.casefold()
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        match = re.search(r"otpauth://totp/[^\s\x00]+", text, re.IGNORECASE)
        if match and not otp_uri:
            otp_uri = match.group(0)
        elif key_l in note_keys and not text.startswith("otpauth://"):
            notes.append(text)
        elif key_l in password_key_scores and not text.startswith("otpauth://"):
            key_is_warning = any(token in key_l for token in warning_tokens)
            looks_like_warning_value = text.casefold() in {
                "true", "false", "yes", "no", "weak", "compromised", "reused",
                "high", "medium", "low", "warning", "dismissed",
            }
            score = password_key_scores[key_l]
            if not key_is_warning and not looks_like_warning_value and score > password_score:
                password, password_score = text, score
        elif key_l in domain_keys and "domain" not in metadata:
            metadata["domain"] = text
        elif key_l in username_keys and "username" not in metadata:
            metadata["username"] = text
        elif key_l in title_keys and "title" not in metadata:
            metadata["title"] = text
        elif key_l in group_keys and "shared_group" not in metadata:
            metadata["shared_group"] = text
    if otp_uri:
        try:
            otp_label = unquote(urlparse(otp_uri).path.lstrip("/"))
            if ":" in otp_label and "username" not in metadata:
                issuer, account = otp_label.split(":", 1)
                if account.strip():
                    metadata["username"] = account.strip()
                if issuer.strip() and "title" not in metadata:
                    metadata["title"] = issuer.strip()
        except Exception:
            pass
    return password, "\n".join(dict.fromkeys(notes)), otp_uri, metadata


def _merge_credentials(a: Credential, b: Credential) -> Credential:
    newest, older = (b, a) if b.mdat > a.mdat else (a, b)
    return Credential(
        domain=newest.domain or older.domain,
        username=newest.username or older.username,
        password=newest.password or older.password,
        title=newest.title or older.title,
        mdat=max(a.mdat, b.mdat),
        notes=_merge_text(a.notes, b.notes),
        otp_uri=newest.otp_uri or older.otp_uri,
    )


def current_totp(uri: str, now: float | None = None) -> dict:
    """Generate the current RFC 6238 code represented by an ``otpauth://totp`` URI."""
    try:
        parsed = urlparse(uri)
        if parsed.scheme.casefold() != "otpauth" or parsed.netloc.casefold() != "totp":
            return {}
        query = parse_qs(parsed.query)
        secret = query.get("secret", [""])[0].replace(" ", "").upper()
        if not secret:
            return {}
        padding = "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(secret + padding, casefold=True)
        digits = int(query.get("digits", ["6"])[0])
        period = int(query.get("period", ["30"])[0])
        algorithm = query.get("algorithm", ["SHA1"])[0].replace("-", "").lower()
        digest = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
                  "sha512": hashlib.sha512}.get(algorithm)
        if digest is None or digits < 6 or digits > 10 or period <= 0:
            return {}
        timestamp = time.time() if now is None else now
        counter = int(timestamp // period)
        mac = hmac.new(key, counter.to_bytes(8, "big"), digest).digest()
        offset = mac[-1] & 0x0F
        binary = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
        code = str(binary % (10 ** digits)).zfill(digits)
        return {"code": code, "period": period, "digits": digits,
                "expires_at": (counter + 1) * period,
                "label": unquote(parsed.path.lstrip("/"))}
    except Exception:
        return {}


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
        # tier, most-recently-used first (newest `mdat`), then title for a stable order.
        ranked.sort(key=lambda rc: (rc[0], -rc[1].mdat, rc[1].title, rc[1].username))
        return [c for _, c in ranked]

    @classmethod
    def from_items(cls, items) -> "CredentialStore":
        """Build credentials and merge Apple's auxiliary plist records.

        Passwords may sync a normal ``inet`` item plus separate binary-plist values containing
        notes or an ``otpauth://`` URI.  Those records are metadata for the same login, not extra
        browser rows.  Group by normalized site/title and account, then retain the newest password
        while combining notes and OTP metadata.
        """
        merged: dict[tuple[str, str, str], Credential] = {}
        for it in items:
            domain = str(it.get("srvr") or it.get("server") or it.get("domain")
                         or it.get("url") or it.get("svce") or "")
            username = str(it.get("acct") or it.get("username") or it.get("user") or "")
            title = str(it.get("labl") or domain)

            raw = it.get("v_Data") if "v_Data" in it else it.get("password", b"")
            password, notes, otp_uri, metadata = _decode_item_value(raw)
            # Shared Password Groups and newer Website Metadata records often keep the useful
            # website/account/title inside v_Data rather than the outer keychain attributes.
            outer_domain, outer_title = domain, title
            domain = metadata.get("domain", "") or domain
            username = metadata.get("username", "") or username
            # Prefer a useful inner title over an Apple wrapper label.
            inner_title = metadata.get("title", "")
            if inner_title and (not title or not _is_credential(outer_domain, outer_title)):
                title = inner_title
            title = title or domain
            explicit_notes = it.get("notes") or it.get("note") or it.get("comment") or ""
            if explicit_notes:
                notes = _merge_text(notes, str(explicit_notes))

            # Filter only after decoding the inner plist. Apple wrapper records frequently have
            # labels such as "Website Metadata" or com.apple.* while containing a valid shared
            # login inside v_Data. Keep the record when the decoded payload supplies login data.
            has_inner_login = bool(metadata.get("domain") or metadata.get("username")
                                   or password or otp_uri)
            if not has_inner_login and not _is_credential(domain, title):
                continue
            mdat = _to_unix(it.get("mdat") or it.get("cdat"))

            # Auxiliary records sometimes omit srvr but retain the same label/account.  A
            # normalized title fallback lets them merge with the corresponding login.
            site_key = _normalize_host(domain) or _text_key(title)
            key = (site_key, username.casefold(), _text_key(title))
            incoming = Credential(domain=domain, username=username, password=password,
                                  title=title, mdat=mdat, notes=notes, otp_uri=otp_uri)
            prior = merged.get(key)
            if prior is None:
                merged[key] = incoming
            else:
                merged[key] = _merge_credentials(prior, incoming)

        # Collapse Apple's multiple physical records into one logical Passwords row.  Exact
        # equality is not enough: shared entries and Website Metadata commonly vary between a
        # parent host and login subdomain, omit the account on the auxiliary record, or use the
        # display title in place of a host.
        collapsed: list[Credential] = []

        def same_login(a: Credential, b: Credential) -> bool:
            au, bu = a.username.casefold().strip(), b.username.casefold().strip()
            ad, bd = _normalize_host(a.domain), _normalize_host(b.domain)
            at, bt = _text_key(a.title), _text_key(b.title)

            sites_match = bool(ad and bd and domains_match(ad, bd))
            exact_user = bool(au and bu and au == bu)
            exact_title = bool(at and bt and at == bt)
            same_secret = bool(a.password and b.password and a.password == b.password)
            auxiliary = lambda c: not c.password and bool(c.otp_uri or c.notes)

            # Two complete password rows are distinct unless account+site match or their secret
            # itself is identical. This prevents a username-less wrapper from swallowing several
            # accounts for the same service.
            if a.password and b.password:
                return exact_user and (sites_match or exact_title or (same_secret and (not ad or not bd)))

            # Metadata-only rows may attach to a password row, but require a strong shared
            # identity. A missing username alone is no longer enough to merge by title.
            if auxiliary(a) or auxiliary(b):
                if exact_user and (sites_match or exact_title):
                    return True
                if same_secret:
                    return True
                return sites_match and exact_title and (au == bu)

            return exact_user and (sites_match or exact_title)

        for cred in sorted(merged.values(), key=lambda c: c.mdat, reverse=True):
            for index, prior in enumerate(collapsed):
                if same_login(prior, cred):
                    collapsed[index] = _merge_credentials(prior, cred)
                    break
            else:
                collapsed.append(cred)

        return cls(c for c in collapsed
                   if (c.domain or c.username or c.title) and (c.username or c.password or c.otp_uri))


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
        return {"ok": True, "credentials": [c.public_dict() for c in store.match(domain)],
                "aliases": [a.public_dict() for a in matched]}
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
