"""Command-line interface.

Interactive: the Apple ID password and 2FA code are read from the terminal and never
stored. Only the resulting tokens are persisted, encrypted.

Commands: login, show, sync, edit, restore, logout. `show` also folds in Hide My Email aliases.
Reading is the default; `edit` and `restore` write to iCloud only with an explicit --apply.
"""
import argparse
import base64
import logging
import sys
import time
import uuid
from datetime import datetime, timezone
import shutil
import subprocess

from . import ui
from .. import diag
from ..auth import grandslam as auth, icloud, session
from ..auth.anisette import Anisette, AnisetteError
from ..auth.device import Device
from ..auth.gsa import GSAClient, GSAError
from ..auth.session import SessionError
from ..octagon import client as octagon
from ..octagon.client import OctagonError
from ..totp import generate as totp_generate
from ..transport.cloudkit import CloudKitError

ICLOUD_AUTH_TOKEN = "com.apple.gs.icloud.auth"


def _utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, timezone.utc)


def _twofa_prompt(kind: str) -> str:
    where = "your trusted Apple devices" if kind == "trusted" else "SMS"
    ui.step(f"A 2FA code was sent to {where}.")
    return ui.ask("6-digit code: ")


def _mint_pet(device, anisette, username: str, password: str) -> str:
    """Mint a fresh GSA PET (password-equivalent token) for escrowproxy Basic auth. Silent on an
    already-trusted device (no 2FA re-prompt). Kept fresh per phase because the PET is short-lived."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, _twofa_prompt)
    _, pet, _ = auth.extract_pet(spd)
    return pet


def _describe_bottle(b: dict) -> str:
    """Device name + serial for an escrow bottle.
    Prefers the descriptive marketing name over the bare class."""
    meta = b.get("meta") or {}
    cm = meta.get("ClientMetadata") or {}
    name = (cm.get("device_model") or cm.get("model") or cm.get("ProductType")
            or cm.get("device_name") or cm.get("deviceName"))
    return f"{name} ({meta.get('serial')})"


def _select_bottle(bottles: list[dict]) -> dict | None:
    """Let the user pick which device's escrow bottle to recover. Auto-selects a lone bottle.
    Returns the chosen `{id, otbottle, meta}` dict, or None to abort."""
    if len(bottles) == 1:
        ui.step(f"Using the only escrow bottle: {_describe_bottle(bottles[0])}")
        return bottles[0]
    ui.step("Multiple escrow bottles found. Pick the device you want to use:\n")
    for i, b in enumerate(bottles, 1):
        ui.step(f"  {i})  {_describe_bottle(b)}")
    ui.step("")
    while True:
        raw = ui.ask(f"Select 1-{len(bottles)} (blank to abort): ")
        if not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(bottles):
            return bottles[int(raw) - 1]
        ui.err("invalid selection")


def _refresh_webservices(s: dict, device, anisette, log=None, debug=False) -> int | None:
    """Fetch account settings and cache the webservices URL map + cloudKitToken. Returns the
    endpoint count, or None on failure."""
    status, data = icloud.fetch_account_settings(s, device, anisette)
    if debug and log is not None:
        diag.dump(log, "account-settings response", data)
    if status == 401 or data.get("ErrorID") == "UNAUTHORIZED":
        raise icloud.ICloudAuthExpired(
            f"iCloud credentials expired ({data.get('description') or 'unauthorized'}) - "
            "run `icp login` to re-authenticate")
    if data.get("status") not in (0, None):
        raise icloud.ICloudError(f"iCloud rejected the token: {data.get('status-message')}")
    ws = icloud.extract_webservices(data)
    if not ws:
        return None
    s["webservices"] = {k: (v.get("url") if isinstance(v, dict) else v) for k, v in ws.items()}
    tokens = data.get("tokens") or {}
    if tokens.get("cloudKitToken"):
        s.setdefault("mme", {}).setdefault("tokens", {}).update(tokens)
    return len(ws)


def _mint_tokens(record: dict, username: str, password: str, device, anisette,
                 *, twofa=_twofa_prompt, log=None, debug=False, interactive: bool = True) -> None:
    """SRP login with the password, then exchange the fresh 5-min PET for a new ~7-day
    mmeAuthToken; update `record`'s token fields in place. Preserves any already-cached
    cloudKitUserId (so a re-auth need not re-run ckAppInit). Raises on failure."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, twofa, interactive=interactive)
    dsid, pet, pet_expiry = auth.extract_pet(spd)
    if debug and log is not None:
        diag.dump(log, "GSA init response", gsa.last_init_response)
        diag.dump(log, "GSA complete response", gsa.last_complete_response)
        diag.dump(log, "Full spd", spd)
        diag.dump_token_dict(log, spd)

    sk = gsa.last_session_key
    app_tokens = spd.get("t") or {}
    record.update({
        "username": username,
        "dsid": dsid,
        "dsid_numeric": spd.get("DsPrsId"),  # mobileme auth uses the numeric dsid
        "pet": pet,
        "pet_expiry": pet_expiry,
        "logged_in_at": int(time.time()),
        "gsidms": spd.get("GsIdmsToken"),
        "sk_b64": base64.b64encode(sk).decode() if sk else None,
        "app_tokens": {
            name: {"token": e.get("token"), "expiry": e.get("expiry"),
                   "duration": e.get("duration")}
            for name, e in app_tokens.items() if isinstance(e, dict)
        },
    })

    mme_dsid, mme_token, service_data, raw = icloud.login_mobileme(
        username, pet, dsid, device.local_user_uuid, device, anisette)
    if debug and log is not None:
        diag.dump(log, "loginDelegates response", raw if isinstance(raw, dict) else {})
    mme = record.setdefault("mme", {})
    ck_uid = mme.get("cloudKitUserId")   # keep the per-container id resolved by an earlier ckAppInit
    mme.update({
        "dsid": mme_dsid,
        "mmeAuthToken": mme_token,
        "tokens": service_data.get("tokens") or {},
        "minted_at": int(time.time()),
    })
    if ck_uid:
        mme["cloudKitUserId"] = ck_uid


def _noninteractive_twofa(kind: str) -> str:
    """2FA callback for the unattended sync path: never blocks on stdin."""
    raise GSAError(
        "Apple asked for a 2FA code during the automatic token refresh (the anisette machine "
        "identity likely changed) - run `icp login` once interactively to re-establish trust")


def _ensure_fresh_tokens(s: dict, device, anisette, *, interactive: bool,
                         allow_password: bool = True) -> None:
    """Make the cloudKitToken fresh before a sync. Re-mint it from the mmeAuthToken; only if
    Apple rejects that token itself (HTTP 401) re-authenticate with the saved password - and
    only when `allow_password` (never from background runs: a password sign-in can push a 2FA
    prompt to the user's devices, and repeated ones risk an account lock). A throttled or
    unavailable endpoint is NOT an auth problem and is raised as-is for the caller's backoff.
    Raises icloud.ICloudError / AnisetteError / GSAError if it cannot recover."""
    try:
        _refresh_webservices(s, device, anisette)
        return
    except icloud.ICloudAuthExpired:
        password = s.get("password")
        username = s.get("username")
        if not allow_password or not password or not username:
            raise
    ui.step("iCloud token expired - re-authenticating with the saved password...")
    twofa = _twofa_prompt if interactive else _noninteractive_twofa
    _mint_tokens(s, username, password, device, anisette, twofa=twofa, interactive=interactive)
    _refresh_webservices(s, device, anisette)   # retry with the fresh mmeAuthToken


def cmd_login(args) -> int:
    """Sign in to Apple, cache the persistent tokens, then join the keychain and sync.

    A single onboarding flow: the password entered here is reused for the join's escrow
    re-authentication, so it is never prompted twice. The irreversible escrow recovery is
    still gated by an explicit y/N prompt - answer No to stop after sign-in with tokens saved.
    """
    debug_path = diag.start() if args.debug else None
    log = logging.getLogger("icp.login")

    device = Device.load_or_create()
    anisette = Anisette(args.anisette)
    try:
        anisette.headers()  # fail fast if the anisette server is down
    except AnisetteError as e:
        ui.err(str(e))
        return 2

    # Preserve the Octagon peer identity (and cached cloudKitUserId) across re-logins: keychain
    # trust membership is permanent and tied to that keypair, not to the short-lived auth tokens.
    prior = session.load() or {}

    saved_user = prior.get("username")
    username = args.username or ui.ask(
        f"Apple ID [{saved_user}]: " if saved_user else "Apple ID: ") or saved_user
    if not username:
        ui.err("no Apple ID given")
        return 2
    password = ui.secret("Password: ")

    record: dict = {}
    if prior.get("octagon", {}).get("peer_id"):
        record["octagon"] = prior["octagon"]
    if prior.get("mme", {}).get("cloudKitUserId"):
        record.setdefault("mme", {})["cloudKitUserId"] = prior["mme"]["cloudKitUserId"]
    if not args.no_save_password:
        record["password"] = password   # in the keyring-encrypted session; enables silent refresh

    # SRP login + mint the mmeAuthToken (the one hop that needs the password).
    mme_ok = False
    try:
        _mint_tokens(record, username, password, device, anisette, log=log, debug=args.debug)
        mme_ok = True
    except (GSAError, AnisetteError) as e:
        ui.err(f"sign-in failed: {e}")
        return 1
    except icloud.ICloudError as e:
        log.warning("loginDelegates failed: %s", e)
        ui.warn(f"could not mint the persistent mmeAuthToken: {e}")

    # With the fresh mmeAuthToken, fetch the iCloud service URLs (needed for join/sync).
    n_ws = None
    if mme_ok:
        try:
            n_ws = _refresh_webservices(record, device, anisette, log, args.debug)
        except (icloud.ICloudError, AnisetteError) as e:
            ui.warn(f"could not fetch iCloud service URLs: {e}")

    session.save(record)
    ui.out(f"Signed in as {username}.")

    if not (mme_ok and n_ws):
        ui.err("sign-in succeeded but iCloud service URLs are unavailable - cannot join the keychain")
        if debug_path:
            ui.out(f"Debug transcript (redacted): {debug_path}")
        return 1

    rc = _join_and_sync(record, device, anisette, username, password)
    if rc == 0:
        from .. import ratelimit
        ratelimit.clear_login_block()
    # Fetch Hide My Email here (interactive): its web session is a separate auth surface that may
    # need its own 2FA, so handle that during login rather than surprising a later `icp sync`.
    n_aliases = len(_fetch_aliases_best_effort(interactive=True))
    if n_aliases:
        ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
    if debug_path:
        ui.out(f"Debug transcript (redacted): {debug_path}")
    return rc


def _status_fields() -> list[tuple[str, object]]:
    """The full account/session state as (label, value) rows - shown by `show`."""
    s = session.load()
    if not s:
        return [("Status", "not signed in - run: icp login")]
    rows = [("Apple ID", s.get("username")), ("DSID", s.get("dsid")),
            ("Signed in", _utc(s.get("logged_in_at", 0) * 1000).isoformat())]
    now = datetime.now(timezone.utc)
    app_tokens = s.get("app_tokens") or {}
    icloud_auth = app_tokens.get(ICLOUD_AUTH_TOKEN)
    if icloud_auth and icloud_auth.get("expiry"):
        exp = _utc(icloud_auth["expiry"])
        state = "valid" if exp > now else "EXPIRED"
        rows.append(("iCloud token", f"{state}, until {exp.date()} (~{(exp - now).days} days)"))
    rows.append(("App tokens", len(app_tokens)))
    mme = s.get("mme") or {}
    rows.append(("mmeAuthToken",
                 f"present (dsid {mme.get('dsid')}) - persistent" if mme.get("mmeAuthToken")
                 else "none - run login"))
    ws = s.get("webservices") or {}
    rows.append(("Service URLs", f"{len(ws)} cached" if ws else "none - run login"))
    octagon = s.get("octagon") or {}
    rows.append(("Octagon peer", octagon.get("peer_id") or "not yet joined"))
    rows.append(("Device ID", Device.load_or_create().device_id))
    return rows


def _status_summary() -> str:
    """One-line account state for the TUI header."""
    s = session.load()
    if not s:
        return "not signed in - run: icp login"
    joined = "joined" if octagon.is_joined(s) else "not joined"
    token = ""
    icloud_auth = (s.get("app_tokens") or {}).get(ICLOUD_AUTH_TOKEN) or {}
    if icloud_auth.get("expiry"):
        exp = _utc(icloud_auth["expiry"])
        valid = "valid" if exp > datetime.now(timezone.utc) else "EXPIRED"
        token = f"  |  token {valid} {exp.date()}"
    return f"{s.get('username')}  |  dsid {s.get('dsid')}  |  {joined}{token}"


def _match(c, q: str) -> bool:
    """Case-insensitive substring match (q already lowercased) across domain/title/username."""
    return (not q or q in c.domain.lower() or q in c.title.lower()
            or q in c.username.lower())


def _alias_match(a, q: str) -> bool:
    """Same idea as `_match`, over a Hide My Email alias's searchable fields."""
    return (not q or q in a.address.lower() or q in a.label.lower()
            or q in a.note.lower() or q in a.forward_to.lower())


def _fetch_aliases_best_effort(interactive: bool) -> list:
    """Hide My Email aliases for `show`, fetched via the web session (auth/webauth.py). Never
    fails `show`: no saved password skips silently, any other error warns and falls back to the
    cached aliases. On success, refreshes that cache (hme/store.py) for the native host."""
    from ..auth import webauth
    from ..hme.client import HmeClient, HmeError
    from ..hme.store import load_aliases, save_aliases

    s = session.load()
    if not s or not s.get("password"):
        return []
    try:
        sess, account_data = _ensure_web_session(s, interactive=interactive)
        session.save(s)
        base = webauth.extract_webservices(account_data).get("premiummailsettings")
        if not base:
            return load_aliases()
        aliases = HmeClient(base, sess.http).list()
        save_aliases(aliases)
        return aliases
    except (webauth.WebAuthError, HmeError) as e:
        ui.warn(f"Hide My Email unavailable: {e}")
        return load_aliases()


def cmd_show(args) -> int:
    """Browse/search stored credentials, Hide My Email aliases, and account status.

    With a TTY and no arguments, opens a full-screen browser over the vault (offline); a query,
    --plain, --show-passwords, or non-terminal stdout falls back to plain text (which also folds
    in aliases). Status to stderr, rows to stdout so the list stays pipe/grep-friendly.
    """
    from ..vault.store import load_vault

    try:
        store = load_vault()
    except Exception as e:  # noqa: BLE001 - surface keyring/decrypt failures cleanly
        ui.err(f"could not open the vault: {e}")
        return 1

    use_tui = (not args.plain and not args.query and not args.show_passwords
               and sys.stdin.isatty() and sys.stdout.isatty())
    if use_tui:
        try:
            return _run_tui(store)
        except Exception as e:  # noqa: BLE001 - curses missing/unusable -> plain fallback
            ui.warn(f"TUI unavailable ({e}); showing plain output")
    return _show_plain(store, args)


def _show_plain(store, args) -> int:
    for label, value in _status_fields():
        ui.step(f"{label:<14}{value}")

    query = (args.query or "").strip().lower()
    creds = store.all()
    if query:
        creds = [c for c in creds if _match(c, query)]
    aliases = _fetch_aliases_best_effort(sys.stdin.isatty())
    if query:
        aliases = [a for a in aliases if _alias_match(a, query)]

    if query and not creds and not aliases:
        ui.err(f"no credentials or aliases match {args.query!r}")
        return 1
    if not creds and not aliases:
        ui.step("vault is empty - run: icp login")
        return 0

    if creds:
        creds.sort(key=lambda c: (c.title.lower(), c.username.lower()))
        dom_w = min(max(len(c.domain) for c in creds), 40)
        user_w = min(max(len(c.username) for c in creds), 40)
        for c in creds:
            pw = c.password if args.show_passwords else "******"
            ui.out(f"{c.domain:<{dom_w}}  {c.username:<{user_w}}  {pw}{_totp_suffix(c)}")
        ui.step(f"{len(creds)} credential(s).")

    if aliases:
        aliases.sort(key=lambda a: a.label.lower())
        label_w = min(max(len(a.label) for a in aliases), 32)
        ui.step("")
        ui.step("Hide My Email:")
        for a in aliases:
            state = "" if a.is_active else "  (inactive)"
            ui.out(f"{a.label:<{label_w}}  {a.address}{state}")
        ui.step(f"{len(aliases)} alias(es).")
    return 0


def _totp_suffix(c) -> str:
    """The trailing `123456 (12s)` column for a credential carrying a verification code."""
    code = totp_generate(c.totp)
    if not code:
        return ""
    return f"  {code['code']} ({max(0, int(code['expires'] - time.time()))}s)"


def _printable(s: str) -> str:
    """Replace non-printable bytes with a dot so untrusted values (passwords are arbitrary binary;
    some keychain items are cert/key blobs full of \\n, \\r, ESC) can't inject terminal escape
    sequences. Normal printable Unicode is preserved."""
    return "".join(ch if ch.isprintable() else "." for ch in s)


_CLIPBOARDS = (
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
)


def _copy_to_clipboard(text: str) -> bool:
    """Copy `text` to the clipboard with the first available tool; False if none works."""
    for cmd in _CLIPBOARDS:
        if not shutil.which(cmd[0]): continue
        try:
            subprocess.run(cmd, input=text.encode(), check=True, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def _run_tui(store) -> int:
    """A very basic full-screen browser: status header, live-filter search box, and reveal a
    selected password with Enter. Type to filter, up/down to move, Esc to clear the query (or quit
    when it is empty)."""
    import curses

    creds = sorted(store.all(), key=lambda c: (c.title.lower(), c.username.lower()))
    dom_w = min(max((len(c.domain) for c in creds), default=6), 32)
    user_w = min(max((len(c.username) for c in creds), default=4), 32)
    summary = _printable(f"{_status_summary()}  |  {len(creds)} credential(s)")
    footer = "type to search | up/down move | Enter reveal | Ctrl+P copy password | Ctrl+U copy user | Esc clear/quit"

    def draw(stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(1000)  # redraw every second so the code countdowns tick

        def put(y, x, s, attr=curses.A_NORMAL):
            # addnstr raises curses.error on the bottom-right cell and other edges; a draw glitch
            # must never tear the whole TUI down (that drops everything back to the console).
            try:
                stdscr.addnstr(y, x, s, max(0, w - 1 - x), attr)
            except curses.error:
                pass

        query, sel, offset, revealed, msg = "", 0, 0, set(), ""
        while True:
            shown = [c for c in creds if _match(c, query.lower())]
            sel = max(0, min(sel, len(shown) - 1))
            h, w = stdscr.getmaxyx()
            view_h = max(1, h - 4)
            if sel < offset:
                offset = sel
            elif sel >= offset + view_h:
                offset = sel - view_h + 1

            stdscr.erase()
            put(0, 0, summary, curses.A_BOLD)
            put(1, 0, _printable(f"Search: {query}"))
            if not shown:
                put(3, 0, "(no matching credentials)", curses.A_DIM)
            for idx, c in enumerate(shown[offset:offset + view_h]):
                i = offset + idx
                pw = c.password if id(c) in revealed else "******"
                line = _printable(
                    f"{c.domain:<{dom_w}}  {c.username:<{user_w}}  {pw}{_totp_suffix(c)}")
                put(3 + idx, 0, line, curses.A_REVERSE if i == sel else curses.A_NORMAL)
            put(h - 1, 0, msg or footer, curses.A_BOLD if msg else curses.A_DIM)
            stdscr.refresh()

            ch = stdscr.getch()
            if ch == -1:  # timeout: just redraw
                continue
            msg = ""
            if ch in (16, 21):  # Ctrl+P / Ctrl+U 
                if shown:
                    c = shown[sel]
                    what, value = ("password", c.password) if ch == 16 else ("username", c.username)
                    msg = (f"{what} copied" if _copy_to_clipboard(value)
                           else "copy failed (install wl-clipboard or xclip)")
                continue
            if ch == 27:  # Esc: clear the query, or quit when it is already empty
                if query:
                    query, sel, offset = "", 0, 0
                else:
                    return 0
            elif ch == curses.KEY_UP:
                sel = max(0, sel - 1)
            elif ch == curses.KEY_DOWN:
                sel = min(len(shown) - 1, sel + 1) if shown else 0
            elif ch in (curses.KEY_ENTER, 10, 13):
                if shown:
                    revealed ^= {id(shown[sel])}
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                query, sel, offset = query[:-1], 0, 0
            elif 32 <= ch < 127:
                query, sel, offset = query + chr(ch), 0, 0

    try:
        curses.wrapper(draw)
    except KeyboardInterrupt:
        pass
    return 0


def _join_and_sync(s: dict, device, anisette, username: str, password: str) -> int:
    """Join the iCloud Keychain Octagon trust via escrow recovery, then sync.

    Escrow recovery is IRREVERSIBLE - escrowproxy destroys the record after 10 wrong
    passcodes. Gated: safe discovery first; an attempt is only spent after a y/N proceed
    prompt that defaults to No. The given password (entered during sign-in) is reused for
    the escrow re-authentication, so it is never prompted twice.
    """
    # Already a trusted keychain peer (e.g. a token-refresh re-login)? Octagon membership is
    # permanent, so skip the irreversible escrow join and just sync. Gate on is_joined, not a bare
    # peer_id: aborting bottle selection persists peer_id without ever joining.
    if octagon.is_joined(s):
        ui.step("Already joined; syncing...")
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)
            n = client.sync_and_decrypt()
            session.save(s)
        except (OctagonError, CloudKitError) as e:
            ui.err(f"sync failed: {e}")
            return 1
        ui.out(f"Synced {n} credential(s) into the vault.")
        return 0

    escrow_host = (s.get("webservices") or {}).get("keychainsync")
    if not escrow_host:
        ui.err("no escrow URL cached - cannot join the keychain")
        return 1

    octagon.ensure_peer_identity(s, device)  # generate the peer identity once
    session.save(s)

    try:
        client = octagon.OctagonClient(s, device, anisette)
        session.save(s)  # persist the cloudKitUserId resolved by ckAppInit
        ui.step("Discovering escrow bottles...")
        # A PET here only lists device metadata via GETRECORDS (non-destructive, spends no
        # attempt) so the user can see WHICH device each bottle belongs to before choosing.
        list_pet = _mint_pet(device, anisette, username, password)
        bottles = client.list_recoverable_bottles(escrow_host, username, list_pet, warn=ui.warn)
    except (OctagonError, CloudKitError, GSAError, AnisetteError) as e:
        ui.err(str(e))
        return 1

    if not bottles:
        ui.err("no recoverable escrow bottle - cannot join via this path")
        return 1

    chosen = _select_bottle(bottles)
    if chosen is None:
        ui.out("Aborted before selecting a bottle - no escrow attempt spent. You're signed in "
               "but NOT joined; run `icp login` again to retry the keychain join.")
        return 0

    ui.out(f"Joining iCloud Keychain will use the passcode of: {_describe_bottle(chosen)}")
    ui.out("This is IRREVERSIBLE - a wrong passcode spends 1 of ~10 attempts, and the 10th "
           "failed attempt destroys the escrow record permanently.")
    if not ui.confirm_yn("Proceed? (y/N) "):
        ui.out("Aborted - no escrow attempt spent. You're signed in but NOT joined; "
               "run `icp login` again to retry the keychain join.")
        return 0

    # Mint a fresh PET right before the irreversible recovery so it can't expire during the
    # selection/confirmation delay above.
    try:
        pet = _mint_pet(device, anisette, username, password)
    except (GSAError, AnisetteError) as e:
        ui.err(f"sign-in failed: {e}")
        return 1

    passcode = ui.secret("Device passcode / iCloud Security Code for that device: ").encode()
    if not passcode:
        ui.err("empty passcode - aborting before spending an attempt")
        return 1
    try:
        client.join_via_escrow(escrow_host, username, pet, passcode, chosen,
                               confirm_irreversible=True)
    except Exception as e:  # noqa: BLE001 - surface any failure, never crash mid-join
        ui.err(f"join failed: {e}")
        return 1
    session.save(s)  # persist the peer identity + the recovered sponsor key for later syncs

    try:
        n = client.sync_and_decrypt()
        session.save(s)
    except CloudKitError as e:
        ui.err(f"joined, but sync failed: {e}")
        return 1
    ui.out(f"Joined the keychain. Synced {n} credential(s).")
    return 0


def cmd_sync(args) -> int:
    """Fetch the keychain zones and decrypt them into the vault (requires a prior join).

    Guarded by a non-blocking file lock so the periodic background trigger and a manual run
    can never overlap (a second sync exits immediately rather than racing on the vault)."""
    import fcntl
    from ..paths import sync_lock_file

    from .. import ratelimit
    from ..auth.grandslam import TwoFactorUnavailable

    background = getattr(args, "background", False)
    lock = open(sync_lock_file(), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        ui.err("busy - another sync is already running")
        return EXIT_SKIPPED

    try:
        state = ratelimit.load()
        allowed, why = ratelimit.may_sync(state, force=getattr(args, "force", False),
                                          background=background)
        if not allowed:
            ui.err(f"skipped: {why}")
            return EXIT_SKIPPED
        ratelimit.record_attempt(state)
        s = session.load()
        if not s:
            ui.err("not signed in - run: icp login")
            return 1
        if not (s.get("octagon") or {}).get("peer_id"):
            ui.err("not joined to the keychain - run: icp login")
            return 1
        device = Device.load_or_create()
        anisette = Anisette(args.anisette)
        # The cached cloudKitToken is short-lived; re-mint it from the mmeAuthToken before every
        # sync. If the mmeAuthToken has also expired, _ensure_fresh_tokens silently re-authenticates
        # with the saved password (no manual login), unless 2FA is required or no password is saved.
        interactive = sys.stdin.isatty() and not background
        try:
            _ensure_fresh_tokens(s, device, anisette, interactive=interactive,
                                 allow_password=not background)
            session.save(s)  # persist any freshly re-minted tokens
        except (icloud.ICloudAuthExpired, TwoFactorUnavailable) as e:
            ratelimit.record_failure(state, "iCloud login needed - run `icp login`", auth=True)
            ui.err(f"iCloud login needed: {e}")
            return 1
        except (icloud.ICloudError, AnisetteError, GSAError) as e:
            # GSAError here = a password sign-in failed: stop background syncs from retrying it
            ratelimit.record_failure(state, f"token refresh failed: {e}",
                                     auth=isinstance(e, GSAError),
                                     retry_after=getattr(e, "retry_after", None))
            ui.err(f"could not refresh the iCloud token: {e}")
            return 1
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)  # persist the refreshed cloudKitToken + cloudKitUserId from ckAppInit
            n = client.sync_and_decrypt()
            session.save(s)  # persist the shared-groups container user id
        except (OctagonError, CloudKitError) as e:
            ratelimit.record_failure(state, f"sync failed: {e}",
                                     retry_after=getattr(e, "retry_after", None))
            ui.err(f"sync failed: {e}")
            return 1
        ratelimit.record_success(state)
        ui.out(f"Synced {n} credential(s) into the vault.")
        # Best-effort, never interactive, at most once a day: the Hide My Email web session
        # signs in with the password once its trust expires - not something to repeat every
        # few minutes. Its 2FA is handled at login (cmd_login).
        if ratelimit.hme_due(state):
            ratelimit.mark_hme(state)
            n_aliases = len(_fetch_aliases_best_effort(interactive=False))
            if n_aliases:
                ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
        return 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


# `sync` skipped (busy, too early, backing off, login needed) - like sysexits EX_TEMPFAIL
EXIT_SKIPPED = 75


def cmd_status(args) -> int:
    """Sync pacing state for status displays (no network, no secrets)."""
    import json
    import time as _time
    from .. import paths, ratelimit

    st = ratelimit.load()
    now = _time.time()
    vault = paths.vault_file()
    out = {
        "signed_in": paths.session_file().exists(),
        "last_success": st.get("last_success"),
        "last_attempt": st.get("last_attempt"),
        "next_allowed": (max(st.get("next_allowed", 0),
                             st.get("last_attempt", 0) + ratelimit.MIN_INTERVAL)
                         if st.get("last_attempt") else None),
        "failures": st.get("failures", 0),
        "needs_login": bool(st.get("needs_login")),
        "last_error": st.get("last_error", ""),
        "vault_mtime": vault.stat().st_mtime if vault.exists() else None,
        "now": now,
    }
    if getattr(args, "json", False):
        print(json.dumps(out))
        return 0
    for k, v in out.items():
        ui.out(f"{k:<14} {v}")
    return 0


def cmd_diag(args) -> int:
    """Run read-only diagnostics."""
    what = getattr(args, "what", "zones")
    s = session.load()
    if not s:
        ui.err("not signed in - run: icp login")
        return 1
    device = Device.load_or_create()
    anisette = Anisette(args.anisette)
    try:
        _ensure_fresh_tokens(s, device, anisette, interactive=sys.stdin.isatty())
        session.save(s)
        if what == "sharing":
            diag.sharing_report(s, device, anisette, ui.out)
            return 0
        if what == "container":
            if not getattr(args, "container", None):
                ui.err("`diag container` needs --container <id> (and usually --bundle <id>)")
                return 1
            diag.sharing_report(s, device, anisette, ui.out,
                                container=args.container, bundle=getattr(args, "bundle", None))
            return 0
        if not (s.get("octagon") or {}).get("peer_id"):
            ui.err("not joined to the keychain - run: icp login")
            return 1
        client = octagon.OctagonClient(s, device, anisette)
        session.save(s)
        if what == "groups":
            diag.groups_report(client, ui.out)
            session.save(s)  # Persist kcsharingUserId.
        elif what == "write":
            import json
            from ..keychain import write
            ui.out(json.dumps(write.probe(*write.fetch(client)), indent=1))
        else:
            diag.zone_report(client, ui.out)
    except (icloud.ICloudError, AnisetteError, GSAError, OctagonError, CloudKitError) as e:
        ui.err(f"diag failed: {e}")
        return 1
    return 0


def _write_session(args):
    """(lock, OctagonClient) for the write commands. Holds the sync lock so a background sync
    never runs in the middle of an edit."""
    import fcntl
    from ..octagon import client as octagon
    from ..paths import sync_lock_file

    lock = open(sync_lock_file(), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise SessionError("busy - a sync is running, try again in a moment")
    s = session.load()
    if not s or not (s.get("octagon") or {}).get("peer_id"):
        lock.close()
        raise SessionError("not signed in / joined - run: icp login")
    device = Device.load_or_create()
    anisette = Anisette(args.anisette)
    _ensure_fresh_tokens(s, device, anisette, interactive=sys.stdin.isatty(),
                         allow_password=False)
    session.save(s)
    client = octagon.OctagonClient(s, device, anisette)
    session.save(s)
    return lock, client


def _patch_vault(domain: str, username: str, login: dict, sidecar: dict | None,
                 old_uuid: str = "") -> None:
    """Swap the edited login into the local vault right away (the next sync would too). Matched
    by its id where the vault has one - website + username can belong to several logins."""
    import dataclasses
    from ..vault import store as vault
    from ..vault.host import CredentialStore

    def edited(c) -> bool:
        if c.group:
            return False
        if old_uuid and c.uuid:
            return c.uuid == old_uuid
        return c.domain.lower() == domain.lower() and c.username.lower() == username.lower()

    new = CredentialStore.from_items([login] + ([sidecar] if sidecar else [])).all()
    keep, prev = [], None
    for c in vault.load_vault().all():
        if edited(c):
            prev = prev or c
        else:
            keep.append(c)
    if prev and new:   # sidecar-less logins keep their last-used time
        new = [dataclasses.replace(new[0], last_used=new[0].last_used or prev.last_used)]
    vault.save_vault(CredentialStore(keep + new))


def _write_report(args, result: dict | None, error: str | None) -> int:
    import json
    if getattr(args, "json", False):
        out = {"ok": error is None, "error": error}
        if result:
            out.update({k: result[k] for k in ("diff", "saved", "backups", "dry_run", "uuid",
                                               "rekey")
                        if k in result})
        print(json.dumps(out))
    elif error:
        ui.err(error)
    else:
        for line in result.get("diff", []):
            ui.out(f"  {line}")
        if result.get("dry_run"):
            ui.out("Dry run - nothing sent. Add --apply to save it to iCloud.")
        else:
            ui.out(f"Saved to iCloud: {', '.join(result.get('saved') or [])}.")
            for uuid_ in result.get("backups") or []:
                ui.out(f"  backup of {uuid_} - undo with: icp restore {uuid_} --apply")
    return 0 if error is None else 1


def cmd_edit(args) -> int:
    """Edit one login and save it back to iCloud Keychain (dry run unless --apply)."""
    from ..keychain import write
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError

    fields = {"site": args.site, "username": args.new_username, "title": args.title,
              "notes": args.notes, "password": None, "trash": args.delete,
              "add_sites": tuple(args.add_site or ()), "remove_sites": tuple(args.remove_site or ())}
    if args.password_stdin:
        fields["password"] = (ui.secret("New password: ") if sys.stdin.isatty()
                              else sys.stdin.readline().rstrip("\r\n"))
    elif args.stdin_json:
        # Notes and passwords can be secrets: callers (a GUI, a script) pass them here, never
        # as arguments, which every local process can read from /proc.
        import json
        try:
            data = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            return _write_report(args, None, "stdin is not JSON")
        for key in ("site", "username", "title", "notes", "password", "totp"):
            if isinstance(data.get(key), str):
                fields[key] = data[key]
        for key in ("add_sites", "remove_sites"):
            if isinstance(data.get(key), list):
                fields[key] = tuple(str(x) for x in data[key])
        if data.get("trash") is True:
            fields["trash"] = True
    changes = write.Changes(**fields)
    lock = None
    try:
        lock, client = _write_session(args)
        result = write.edit(client, args.domain, args.username, changes, apply=args.apply,
                            uuid=args.uuid)
        if args.apply:
            try:
                _patch_vault(args.domain, args.username, result["login"], result.get("sidecar"),
                             result.get("old_uuid", ""))
            except Exception as e:  # noqa: BLE001 - the save itself went through
                ui.warn(f"saved, but the local vault was not updated ({e}); `icp sync` will")
        return _write_report(args, result, None)
    except (write.WriteError, SessionError, OctagonError, CloudKitError, icloud.ICloudError,
            AnisetteError, GSAError, ValueError) as e:
        return _write_report(args, None, str(e))
    finally:
        if lock:
            lock.close()


def _append_vault(login: dict, sidecar: dict | None) -> None:
    """Add a newly created login to the local vault right away (the next sync would too); the
    other entries stay as they are."""
    from ..vault import store as vault
    from ..vault.host import CredentialStore

    new = CredentialStore.from_items([login] + ([sidecar] if sidecar else [])).all()
    vault.save_vault(CredentialStore(vault.load_vault().all() + new))


EXIT_EXISTS = 3   # `icp add`: a login for this website + username exists (use `icp edit`)


def _add_report(args, result: dict | None, error: str | None, code: int = 1) -> int:
    """`icp add` output. Never prints the password, notes or 2FA code - only names and types."""
    import json
    if getattr(args, "json", False):
        out = {"ok": error is None, "error": error}
        if result:
            out.update({"uuid": None if result["dry_run"] else result["uuid"],
                        "site": result["site"], "user": result["user"],
                        "sidecar": result["sidecar"], "dryRun": result["dry_run"],
                        "zone": result["zone"], "warnings": result["warnings"]})
        if code == EXIT_EXISTS:
            out["exists"] = True
        print(json.dumps(out))
    elif error:
        ui.err(error)
    else:
        for line in result["diff"]:
            ui.out(f"  {line}")
        for line in result["warnings"]:
            ui.warn(line)
        if result["dry_run"]:
            ui.out("  login attributes:    " + ", ".join(f"{k}:{v}" for k, v
                                                         in result["login_attrs"].items()))
            if result["sidecar"]:
                ui.out("  metadata attributes: " + ", ".join(f"{k}:{v}" for k, v
                                                             in result["sidecar_attrs"].items()))
            if result["skipped_attrs"]:
                ui.out("  not taken from the template: " + ", ".join(result["skipped_attrs"]))
            ui.out("Dry run - nothing sent. Add --apply to save it to iCloud.")
        else:
            ui.out(f"Saved to iCloud: {', '.join(result['saved'])} (id {result['uuid']}).")
            import shlex
            ui.out(f"  undo: icp edit {shlex.quote(result['site'])} {shlex.quote(result['user'])} "
                   f"--uuid {result['uuid']} --delete --apply")
    return 0 if error is None else code


def cmd_add(args) -> int:
    """Create a new login in iCloud Keychain (dry run unless --apply). Input is one JSON line on
    stdin - the password, notes and 2FA code are secrets and never go on the command line."""
    import json
    from ..keychain import write
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError

    try:
        data = json.loads(sys.stdin.readline() or "{}")
    except ValueError:
        return _add_report(args, None, "stdin is not JSON")
    if not isinstance(data, dict):
        return _add_report(args, None, "stdin must be a JSON object")
    fields = {}
    for key in ("site", "user", "password", "title", "notes", "totp"):
        value = data.get(key)
        if value is not None and not isinstance(value, str):
            return _add_report(args, None, f"`{key}` must be a string")
        fields[key] = value
    missing = [k for k in ("site", "user", "password") if not fields[k]]
    if missing:
        return _add_report(args, None, "missing: " + ", ".join(missing))
    lock = None
    try:
        lock, client = _write_session(args)
        result = write.create(client, fields["site"], fields["user"], fields["password"],
                              title=fields["title"], notes=fields["notes"], totp=fields["totp"],
                              apply=args.apply)
        if args.apply:
            try:
                _append_vault(result["login_item"], result.get("sidecar_item"))
            except Exception as e:  # noqa: BLE001 - the save itself went through
                ui.warn(f"saved, but the local vault was not updated ({e}); `icp sync` will")
        return _add_report(args, result, None)
    except write.ExistsError as e:
        return _add_report(args, None, str(e), EXIT_EXISTS)
    except (write.WriteError, SessionError, OctagonError, CloudKitError, icloud.ICloudError,
            AnisetteError, GSAError, ValueError) as e:
        return _add_report(args, None, str(e))
    finally:
        if lock:
            lock.close()


def cmd_restore(args) -> int:
    """Put the pre-edit version of a record back (from ~/.config/icp/backup)."""
    from ..keychain import write
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError

    lock = None
    try:
        lock, client = _write_session(args)
        result = write.restore(client, args.uuid, apply=args.apply)
        return _write_report(args, result, None)
    except (write.WriteError, SessionError, OctagonError, CloudKitError, icloud.ICloudError,
            AnisetteError, GSAError, ValueError) as e:
        return _write_report(args, None, str(e))
    finally:
        if lock:
            lock.close()


def cmd_write_state(args) -> int:
    """Write pacing / block state (no network)."""
    import json
    from ..keychain import write

    st = write.load_state()
    if args.clear:
        st["blocked"] = None
        write.save_state(st)
        ui.out("Write block cleared.")
        return 0
    allowed, why = write.may_write(st)
    out = {"blocked": st.get("blocked"), "writes_last_hour":
           len([t for t in st.get("writes", []) if time.time() - t < 3600]),
           "may_write": allowed, "reason": why}
    if args.json:
        print(json.dumps(out))
    else:
        for k, v in out.items():
            ui.out(f"{k:<17} {v}")
    return 0


def _ensure_web_session(s: dict, *, interactive: bool):
    """Reach a valid idmsa web session (auth/webauth.py). Reuses a saved trust token when
    possible; otherwise signs in with the saved password and prompts for 2FA once. Returns
    (WebAuthSession, account_data)."""
    from ..auth import webauth

    wa = s.setdefault("webauth", {})
    frame_tag = wa.get("frame_tag") or f"auth-{uuid.uuid4()}"
    wa["frame_tag"] = frame_tag
    sess = webauth.WebAuthSession(frame_tag, session_data=wa.get("session_data"),
                                  cookies=wa.get("cookies"))

    account_data = None
    if sess.session_data.get("session_token"):
        try:
            account_data = sess.account_login()
            if webauth.hsa_challenge_required(account_data):
                account_data = None  # saved session is stale/untrusted -> fall through to signin
        except webauth.WebAuthError:
            account_data = None

    if account_data is None:
        username, password = s.get("username"), s.get("password")
        if not username or not password:
            raise webauth.WebAuthError(
                "no saved Apple ID password for the web session - run `icp login` "
                "without --no-save-password")
        sess.signin(username, password, trust_token=sess.session_data.get("trust_token"))
        if sess.needs_2fa:
            if not interactive:
                raise webauth.WebAuthError(
                    "Apple asked for a 2FA code for the web session - run `icp show` "
                    "from a terminal once to establish trust")
            sess.request_push_notification()  # the 409 no longer auto-sends this on its own
            sess.submit_2fa(_twofa_prompt("trusted"))
        account_data = sess.account_login()
        if webauth.hsa_challenge_required(account_data):
            raise webauth.WebAuthError("2FA did not clear the web-session challenge")

    wa.update(sess.export())
    return sess, account_data


def cmd_logout(args) -> int:
    session.clear()
    ui.out("Session cleared. Device identity kept (use --wipe-device to remove it).")
    if args.wipe_device:
        from ..paths import device_file
        f = device_file()
        if f.exists():
            f.unlink()
        ui.out("Device identity wiped.")
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(
        prog="icp",
        description="iCloud Passwords for Linux - iCloud Keychain autofill (read-only by default; "
                    "`add`/`edit`/`restore` write only with --apply)")
    p.add_argument("--anisette",
                   help="anisette server URL (default: $ICP_ANISETTE_URL or localhost:6969)")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser(
        "login", help="sign in, join the iCloud Keychain trust, and do the first sync")
    lp.add_argument("-u", "--username", help="Apple ID (prompted if omitted)")
    lp.add_argument("--no-save-password", action="store_true",
                    help="don't store the password for silent token refresh (re-login manually "
                         "each time the ~7-day token expires)")
    lp.add_argument("--debug", action="store_true", help="write a redacted debug transcript")
    lp.set_defaults(func=cmd_login)

    sp = sub.add_parser(
        "show", help="browse/search credentials, Hide My Email aliases, and account status (TUI)")
    sp.add_argument("query", nargs="?",
                    help="filter by substring of domain/title/username, or alias/label/note "
                         "(plain output)")
    sp.add_argument("-s", "--show-passwords", action="store_true",
                    help="reveal passwords in plain output")
    sp.add_argument("--plain", action="store_true",
                    help="print plain text instead of the interactive TUI")
    sp.set_defaults(func=cmd_show)

    syp = sub.add_parser("sync", help="re-fetch and decrypt the keychain into the vault")
    syp.add_argument("--background", action="store_true",
                     help="unattended run: never sign in with the password or prompt for 2FA; "
                          "stops until `icp login` when auth is gone")
    syp.add_argument("--force", action="store_true",
                     help="ignore the minimum interval / backoff (not the login stop)")
    syp.set_defaults(func=cmd_sync)

    stp = sub.add_parser("status", help="sync pacing state (last sync, next allowed, login needed)")
    stp.add_argument("--json", action="store_true", help="machine-readable output")
    stp.set_defaults(func=cmd_status)

    dp = sub.add_parser(
        "diag", help="read-only diagnostics (may print group names and opaque CloudKit IDs)")
    dp.add_argument("what", choices=["zones", "sharing", "container", "groups", "write"],
                    help="zones: keychain CKKS zones this peer sees; "
                         "groups: group names and decrypted record counts; "
                         "sharing: zone/owner IDs and record counts; "
                         "container: probe an arbitrary container (needs --container); "
                         "write: field names/types the edit path relies on (no values)")
    dp.add_argument("--container", help="container id for `diag container`")
    dp.add_argument("--bundle", help="bundle id to use for `diag container`")
    dp.set_defaults(func=cmd_diag)

    ep = sub.add_parser(
        "edit", help="edit one login and save it to iCloud Keychain (dry run unless --apply)")
    ep.add_argument("domain", help="the login's website as stored (e.g. example.com)")
    ep.add_argument("username", help="the login's username as stored")
    ep.add_argument("--site", help="new primary website (new record, old one deleted after "
                                   "the new one was read back)")
    ep.add_argument("--new-username", help="new username (a rekey, like --site)")
    ep.add_argument("--add-site", action="append", help="add an extra website (repeatable)")
    ep.add_argument("--remove-site", action="append", help="remove an extra website (repeatable)")
    ep_in = ep.add_mutually_exclusive_group()
    ep_in.add_argument("--password-stdin", action="store_true",
                       help="read the new password from stdin (first line; prompts on a tty)")
    ep_in.add_argument("--stdin-json", action="store_true",
                       help="read the changes as JSON from stdin: site, username, password, "
                            "title, notes, totp (otpauth:// URI or base32 key, \"\" removes it), "
                            "add_sites, remove_sites, trash (true = --delete) (keeps secrets out "
                            "of the process list)")
    ep.add_argument("--uuid", help="the login's id (record name, `uuid` in the vault) - picks "
                                   "it exactly when several logins share website + username")
    ep.add_argument("--delete", action="store_true",
                    help="move the login to Recently Deleted, like the Passwords app (it can be "
                         "recovered there); not combinable with other changes")
    ep.add_argument("--title", help="new title (Passwords app name)")
    ep.add_argument("--notes", help="new notes")
    ep.add_argument("--apply", action="store_true", help="really save (default: dry run)")
    ep.add_argument("--json", action="store_true", help="machine-readable result")
    ep.set_defaults(func=cmd_edit)

    ap = sub.add_parser(
        "add", help="create a new login in iCloud Keychain (dry run unless --apply)")
    ap.add_argument("--stdin-json", action="store_true", required=True,
                    help="read the login as one JSON line from stdin: site, user, password "
                         "(required), title, notes, totp (otpauth:// URI or base32 key) - keeps "
                         "secrets out of the process list")
    ap.add_argument("--apply", action="store_true", help="really save (default: dry run)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable result (exit code 3: the login exists already)")
    ap.set_defaults(func=cmd_add)

    rp = sub.add_parser("restore", help="put the pre-edit version of a record back")
    rp.add_argument("uuid", help="record uuid of a backup (listed after an edit and in "
                                 "`edit --json` under `backups`)")
    rp.add_argument("--apply", action="store_true", help="really save (default: dry run)")
    rp.add_argument("--json", action="store_true", help="machine-readable result")
    rp.set_defaults(func=cmd_restore)

    wp = sub.add_parser("write-state", help="write pacing and block state")
    wp.add_argument("--clear", action="store_true", help="lift the block after an error")
    wp.add_argument("--json", action="store_true", help="machine-readable output")
    wp.set_defaults(func=cmd_write_state)

    op = sub.add_parser("logout", help="clear the stored session")
    op.add_argument("--wipe-device", action="store_true", help="also remove the device identity")
    op.set_defaults(func=cmd_logout)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ui.err("aborted")
        return 130
    except SessionError as e:
        ui.err(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
