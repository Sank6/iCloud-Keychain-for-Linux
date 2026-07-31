"""Command-line interface.

Interactive: the Apple ID password and 2FA code are read from the terminal and never
stored. Only the resulting tokens are persisted, encrypted.

Commands: login, show, sync, logout. `show` also folds in Hide My Email aliases.
"""
import argparse
import base64
import logging
import sys
import time
import uuid
from datetime import datetime, timezone

from . import ui
from .. import diag
from ..auth import grandslam as auth, icloud, session
from ..auth.anisette import Anisette, AnisetteError
from ..auth.device import Device
from ..auth.gsa import GSAClient, GSAError

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
        raise icloud.ICloudError(
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
                 *, twofa=_twofa_prompt, log=None, debug=False) -> None:
    """SRP login with the password, then exchange the fresh 5-min PET for a new ~7-day
    mmeAuthToken; update `record`'s token fields in place. Preserves any already-cached
    cloudKitUserId (so a re-auth need not re-run ckAppInit). Raises on failure."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, twofa)
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


def _ensure_fresh_tokens(s: dict, device, anisette, *, interactive: bool) -> None:
    """Make the cloudKitToken fresh before a sync. Re-mint it from the mmeAuthToken; if that
    token has expired too, silently re-authenticate with the saved password (no manual login).
    Raises icloud.ICloudError / AnisetteError / GSAError if it cannot recover."""
    try:
        _refresh_webservices(s, device, anisette)
        return
    except icloud.ICloudError:
        # The mmeAuthToken itself expired. Recover with the stored password if we have one.
        password = s.get("password")
        username = s.get("username")
        if not password or not username:
            raise
    ui.step("iCloud token expired - re-authenticating with the saved password...")
    twofa = _twofa_prompt if interactive else _noninteractive_twofa
    _mint_tokens(s, username, password, device, anisette, twofa=twofa)
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
    from ..octagon import client as octagon
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
               and not args.show_totp and sys.stdin.isatty() and sys.stdout.isatty())
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
            otp = c.public_dict().get("totp", {}).get("code", "") if args.show_totp else ""
            suffix = f"  TOTP {otp}" if otp else ""
            ui.out(f"{c.domain:<{dom_w}}  {c.username:<{user_w}}  {pw}{suffix}")
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


def _printable(s: str) -> str:
    """Replace non-printable bytes with a dot so untrusted values (passwords are arbitrary binary;
    some keychain items are cert/key blobs full of \\n, \\r, ESC) can't inject terminal escape
    sequences. Normal printable Unicode is preserved."""
    return "".join(ch if ch.isprintable() else "." for ch in s)


def _run_tui(store) -> int:
    """A very basic full-screen browser: status header, live-filter search box, and reveal a
    selected password with Enter. Type to filter, up/down to move, Esc to clear the query (or quit
    when it is empty)."""
    import curses

    creds = sorted(store.all(), key=lambda c: (c.title.lower(), c.username.lower()))
    dom_w = min(max((len(c.domain) for c in creds), default=6), 32)
    user_w = min(max((len(c.username) for c in creds), default=4), 32)
    summary = _printable(f"{_status_summary()}  |  {len(creds)} credential(s)")
    footer = "type to search | up/down move | Enter reveal password + TOTP | Esc clear/quit"

    def draw(stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)

        def put(y, x, s, attr=curses.A_NORMAL):
            # addnstr raises curses.error on the bottom-right cell and other edges; a draw glitch
            # must never tear the whole TUI down (that drops everything back to the console).
            try:
                stdscr.addnstr(y, x, s, max(0, w - 1 - x), attr)
            except curses.error:
                pass

        query, sel, offset, revealed = "", 0, 0, set()
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
                is_revealed = id(c) in revealed
                pw = c.password if is_revealed else "******"
                otp = c.public_dict().get("totp", {}).get("code", "") if is_revealed else ""
                suffix = f"  TOTP {otp}" if otp else ""
                line = _printable(f"{c.domain:<{dom_w}}  {c.username:<{user_w}}  {pw}{suffix}")
                put(3 + idx, 0, line, curses.A_REVERSE if i == sel else curses.A_NORMAL)
            put(h - 1, 0, footer, curses.A_DIM)
            stdscr.refresh()

            ch = stdscr.getch()
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
    from ..octagon import client as octagon
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError

    # Already a trusted keychain peer (e.g. a token-refresh re-login)? Octagon membership is
    # permanent, so skip the irreversible escrow join and just sync. Gate on is_joined, not a bare
    # peer_id: aborting bottle selection persists peer_id without ever joining.
    if octagon.is_joined(s):
        ui.step("Already joined; syncing...")
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)
            n = client.sync_and_decrypt()
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
    from ..octagon import client as octagon
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError
    from ..paths import sync_lock_file

    lock = open(sync_lock_file(), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        ui.err("another sync is already running")
        return 0

    try:
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
        try:
            _ensure_fresh_tokens(s, device, anisette, interactive=sys.stdin.isatty())
            session.save(s)  # persist any freshly re-minted tokens
        except (icloud.ICloudError, AnisetteError, GSAError) as e:
            ui.err(f"could not refresh the iCloud token: {e}")
            return 1
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)  # persist the refreshed cloudKitToken + cloudKitUserId from ckAppInit
            n = client.sync_and_decrypt()
        except (OctagonError, CloudKitError) as e:
            ui.err(f"sync failed: {e}")
            return 1
        ui.out(f"Synced {n} credential(s) into the vault.")
        # Best-effort, never interactive: refresh the Hide My Email cache only while the web
        # session's trust is still valid, otherwise keep the cache. Its 2FA is handled at login
        # (cmd_login), so sync never prompts - see _fetch_aliases_best_effort.
        n_aliases = len(_fetch_aliases_best_effort(interactive=False))
        if n_aliases:
            ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
        return 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


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
    # Logging out must also remove all locally cached credential material.  The
    # pass-backed master key and device identity are intentionally retained so
    # a later login can reuse the registered device without reinitialising pass.
    session.clear()

    from .. import paths

    removed = []
    for cached_file in (
        paths.vault_file(),
        paths.aliases_file(),
        paths.sync_lock_file(),
        paths.sync_attempt_file(),
    ):
        try:
            cached_file.unlink()
            removed.append(cached_file.name)
        except FileNotFoundError:
            pass

    ui.out("Session cleared and local password caches removed.")
    if removed:
        ui.out("Removed: " + ", ".join(removed))
    ui.out("Device identity and pass master key kept (use --wipe-device to remove the device).")

    if args.wipe_device:
        f = paths.device_file()
        try:
            f.unlink()
        except FileNotFoundError:
            pass
        else:
            ui.out("Device identity wiped.")
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(
        prog="icp",
        description="iCloud Passwords for Linux - read-only iCloud Keychain autofill")
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
    sp.add_argument("--show-totp", action="store_true",
                    help="show the current TOTP verification code in plain output")
    sp.add_argument("--plain", action="store_true",
                    help="print plain text instead of the interactive TUI")
    sp.set_defaults(func=cmd_show)

    sub.add_parser("sync", help="re-fetch and decrypt the keychain into the vault"
                   ).set_defaults(func=cmd_sync)

    op = sub.add_parser("logout", help="clear the stored session")
    op.add_argument("--wipe-device", action="store_true", help="also remove the device identity")
    op.set_defaults(func=cmd_logout)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ui.err("aborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
