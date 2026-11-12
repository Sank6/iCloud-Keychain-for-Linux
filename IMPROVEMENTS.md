# Improvements

Goal: make iCloud Keychain on Linux feel native on GNOME, make the browser extension feel
very close to Apple's own, and (since the maintainer likes Rust) move the long-lived,
security-sensitive parts to Rust over time.

Target setup this was written for: Ubuntu + GNOME, Helium (Chromium-based) browser,
Secret Service (gnome-keyring) already running, Seahorse installed.

Status of claims: items marked **(verified)** were checked on this machine or in the code;
**(unverified)** are based on general knowledge or search snippets and need a check
before building on them.

---

## Progress

- [x] 3.2 `icp doctor` and `icp setup` (host registration for every detected browser incl.
  Helium, anisette check, optional systemd timer). Pinned extension id
  `oienjgojkmebeibfajgflpaajlaaolkg` (public key added to the manifest).
- [x] 3.4 Sync status file, popup status line, desktop notification after 3 failures,
  auto-sync back-off after failures.
- [x] 1.1 Secret Service mirror (`icp/mirror.py`, `icp mirror`, runs after every sync; passwords
  only, no TOTP seeds/notes; `ICP_NO_MIRROR=1` disables). 975 of 985 vault entries mirrored
  (the rest have no password/domain or are duplicates).
- [x] 1.2 GTK4/libadwaita Passwords app (`icp gui`, Python/PyGObject for now; list + search,
  reveal/copy, live codes, sync status, idle lock, clipboard auto-clear, desktop entry + icon
  via `icp setup`). Rust port needs `libadwaita-1-dev` (not installed).
- [x] 1.3 GNOME Shell search provider (`icp/gui/search.py`; `icp setup` installs the provider
  file and D-Bus service). Verified over D-Bus (`GetInitialResultSet`, `GetResultMetas`); not yet
  seen inside Activities. Results show title + username only. Needs a log out/in (or Shell
  restart) to be picked up, and "Passwords" enabled under Settings > Search.
- [x] 1.4 Notifications (after 3 failed syncs). The agent is auto-started by the shim.
- [x] 2.1 Toolbar popup: dark mode, search across all logins, per-row copy, code text,
  locked state, "Open Passwords...", sync line. Rendered in a browser against stubbed data.
  The code now has a countdown ring (turns red under 6 s).
- [x] **Verified in the real browser**: Helium 0.21 (Chromium 157), throwaway profile, extension
  loaded with its pinned id. The popup (via DevTools) showed "985 saved logins" and the real sync
  failure line, i.e. extension -> native messaging -> shim -> Rust agent -> real vault. On
  https://github.com/login a *trusted* click in the username field opened the popover (352x138);
  script-driven focus correctly did not. Not clicked through: actually filling a login.
- [x] 2.2 In-page popover: closed shadow root, light/dark, key icon header, keyboard
  navigation, insecure-page warning, "Passwords...", "Use Strong Password". Tested in a
  browser against stubbed data (not against real sites).
- [x] 2.4 Strong password generator (`xxxxxx-xxxxxx-xxxxxx`, honours maxlength; fills every
  password field in the form; copies to clipboard).
- [x] 2.5 Matching: Public Suffix List (`icp/psl.py`, bundled list, MPL-2.0) so `co.uk` /
  `github.io` never link two sites; IPs match exactly. Related-site sets (`icp/related.py`,
  hand-curated, small) rank below exact/subdomain matches. The login you pick on a site is
  remembered and offered first (`icp/choices.py`, username hash only).
- [x] 2.7 Icons (16/32/48/128), unused permissions removed (`activeTab`, `scripting`,
  `storage`), pinned id.
- [x] 3.1 / 4.1 steps 1-2: agent + shim. `native/icp-shim` and `native/icp-agent` are Rust;
  `icp/agent.py` is the Python fallback with the same socket and protocol (`icp setup` builds the
  Rust ones when cargo is present and points `agent-cmd` at them). The Rust agent reads the real
  keyring + vault, serves match/search/totp/chose/status/lock/unlock/open_app, locks after 15 min
  idle, zeroizes credentials on drop, is non-dumpable, checks `SO_PEERCRED`, and does the same
  back-off'd auto-sync trigger. **Parity-tested against the Python agent on the real vault: 0
  differences over 713 domains, 8 searches and 42 verification codes** (that run also caught a
  float-parsing difference, fixed with serde_json `float_roundtrip`, and a stale Python agent).
  Measured: ~1 ms per message once running. Rust unit tests: `cargo test` (RFC 6238 vector,
  PSL/IP/related rules). It is the agent running on this machine now.
- [x] 3.3 Lock model: agent locks after 15 min idle (`ICP_IDLE_LOCK`), `lock`/`unlock`
  commands, locked state in popup and popover, GTK app locks after 5 min. Unlock uses the
  keyring prompt. A dismissed keyring prompt now raises `KeyringLocked` instead of minting a
  fallback key (before, that made the vault undecryptable and it was deleted). The plaintext
  `master.key` is now used only when there is no Secret Service at all (doctor warns).
- [x] 3.5 (partial) `PR_SET_DUMPABLE=0` in the agent, socket mode 0600 + `SO_PEERCRED`.
  Clipboard password hint (`x-kde-passwordManagerHint`) on password/code copies in the GTK app.
  Threat model written: `SECURITY.md`. NOT done: memory zeroizing/mlock (not reliable in
  Python). The Rust agent zeroizes credentials on drop but does NOT mlockall: `MCL_FUTURE` made
  thread creation fail under the default 8 MiB memlock limit (found by running it), so swap
  protection is left to encrypted swap. Not done: a TPM-wrapped vault key (needs a decision: it
  would tie the vault to this machine's TPM and complicate recovery).
- [x] 5 Hygiene (partial): `.gitignore` for the signing key and caches; 213 Python tests + 5 Rust tests
  (status, hosts, mirror, PSL/related/choices, agent, keyring lock). Field detection fixtures in
  `tests/ext/` (manual, checked in a browser: found and fixed the popover attaching to search and
  postal-code fields on login pages). NOT done: automated browser tests against real sites;
  packaging (AUR/.deb/Flatpak); upstream PRs.

### Not done, and why

- **2.3 Save / update prompts and 4.4 write support**: needs writing encrypted items to
  iCloud's CKKS zone. A mistake could damage a real keychain, and sync is currently failing, so
  there is no way to test a write safely. Needs a throwaway Apple ID and your go-ahead.
- **2.6 Passkeys**: passkey records are classified but discarded before the vault, and they only
  appear during a sync (which fails right now). Signing also needs key material not yet
  researched.
- **4.1 step 3: Rust GTK app**: needs `libadwaita-1-dev` (sudo apt). The Python app works.
- **4.1 step 4-5: Rust port of sync** (GrandSlam SRP, anisette, CloudKit, Octagon, CKKS): a large
  separate project; the Python tests are the intended golden vectors. Python stays for sync.
- **Packaging**: `packaging/debian/build-deb.sh` builds a real `.deb` (built and inspected here;
  NOT installed or run, since installing needs sudo). The PKGBUILD sketch is untested. No Flatpak.
  **Upstream PRs** need your GitHub account and your go-ahead.
- **TPM-wrapped vault key**: this machine has a TPM2, but `systemd-creds encrypt --with-key=tpm2`
  fails for your user (`/dev/tpmrm0` is group `tss`, you are not in it), so it can't be built or
  tested without a system change (sudo `usermod -aG tss`). It also ties the vault to this TPM.
- **Apple flow (done this round)**: `icp login --gui` (also "Sign in to iCloud\u2026" in the app
  menu) asks for password, 2FA code and the join confirmation in dialogs; unattended syncs now
  stop after 5 consecutive failures (not just auth failures) until `icp login`; upstream already
  reuses the saved token, backs off 5 min -> 6 h and never signs in with the password from
  background runs. Still NOT done: generating anisette locally (large; today a third-party/local
  anisette server supplies it) and a Rust port of the sign-in. The GUI login window is import-
  and unit-checked only; it has not been driven against Apple.
- **Apple sign-in**: merged upstream `origin/main` into `fix-gsa-client-identity` (work committed
  first; the only conflict was `GSA_CLIENT_INFO`, resolved to upstream's Windows identity). 247
  tests pass. One non-interactive `icp sync` after the merge no longer gets `ec=-80045` but Apple
  returned a non-plist reply (HTTP error body), so sync still fails. Error text now reports the
  HTTP status instead of a traceback. NOT retried (5-minute back-off, avoid hammering Apple); the
  next step is `icp sync` once more, and if it persists `icp login` (likely needs a fresh sign-in
  and 2FA, which only you can do).
- **Search provider in Activities**: answers correctly over D-Bus, the `.desktop` file validates,
  but I can't see your Shell. Log out/in and enable Settings > Search > Passwords.
- **Extension in your actual Helium profile**: verified in a throwaway profile with the same
  extension id and native host; your real profile still needs "Reload" on the extension.

## 0. Current state (verified)

- Python app, ~5k lines: GrandSlam sign-in, Octagon join, CloudKit sync, local encrypted
  vault (`vault.enc`, libsodium secretbox, master key in the login keyring).
- Browser side: MV3 extension (`background.js`, `content.js`, `popup.*`) talking to a
  native messaging host (`icp.vault.host`, launched through `host/icp-host.sh`).
- Read-only: it never writes to iCloud. No save/update prompts, no generator.
- Native host manifest for Helium is at `~/.config/net.imput.helium/NativeMessagingHosts/`,
  pinned to extension id `lojmiadhjpclhbpijnipcjdfelpkgmgn`.
- The host triggers a detached `icp sync` when the vault is >6h old. A sync run from the
  CLI today failed at Apple sign-in (`ec=-80045`). Not investigated further.
- The host spawns a **fresh Python process per message** from the extension
  (`sendNativeMessage`), decrypting the whole vault each time. That is slow and is the
  main reason the dropdown can feel laggy.
- `install.sh` only registers browser dirs that already exist and needs the extension id
  pasted in by hand.

---

## 1. OS integration (the "see them in the Passwords app" goal)

GNOME has no Apple-style Passwords app. The nearest native things are:
**Secret Service** (the D-Bus API gnome-keyring implements, shown in **Seahorse**
"Passwords and Keys") and a **GNOME Shell search provider**.

### 1.1 Mirror logins into the Secret Service  (high value, small)
- After every sync, write each login as a Secret Service item in a dedicated collection or
  the login collection, with standard attributes: `xdg:schema =
  org.gnome.keyring.NetworkPassword`, `user`, `server`, `protocol`, plus `icp:id`.
- One-way (iCloud is the source of truth). On each sync, diff by `icp:id` and add/update/
  remove, so deleting on the iPhone also deletes here.
- Result: logins show in Seahorse; anything using libsecret can look them up.
- Tradeoff to document: any process running as the user can read items while the keyring is
  unlocked. The master key for `vault.enc` already has this property.
- TOTP secrets and notes: store as extra attributes / the item's notes field, or keep them
  out of the mirror by default (a config switch), since they are the highest-value items.

### 1.2 A real desktop app  (the actual "Passwords app")
- GTK4 + libadwaita app, sidebar (All, Logins, Codes, Hide My Email, Wi-Fi if ever
  supported), search, detail pane with reveal/copy, live TOTP ring, "last synced" status,
  "Sign in again" banner. Follows system light/dark and accent colour.
- Desktop entry + icon, so it appears in the app grid and Activities.
- In Rust this is `gtk4-rs` + `libadwaita` (the crate is published as `libadwaita`; rename
  to `adw` in Cargo) with optionally `relm4` for state management.
- Lock on idle; unlock via the keyring password prompt (see 3.3).

### 1.3 GNOME Shell search provider  (nice, small once 1.2 exists)
- Type a site name in Activities and see matching logins; Enter copies password or opens
  the app. Implemented as a D-Bus service per GNOME's search-provider interface plus a
  key file in `share/gnome-shell/search-providers/`.
- Rust crate `search-provider` wraps this (0.11.0 on lib.rs; **GPL-3.0-or-later**, which
  matters for licensing, see 5).

### 1.4 Other desktop touches
- `xdg-desktop-portal` Secret portal is for sandboxed apps; low priority.
- Notifications for: sync failed, sign-in expired, new device approval needed.
- Autostart a small background agent (user systemd service), see 3.1.

---

## 2. Extension: get close to Apple's official one

Reference: Apple's iCloud Passwords extension for Chrome/Edge/Firefox on Windows (and the
Passwords app on macOS 15+). Details from Apple's support pages and the Chrome Web Store
listing. I have not been able to run the real one here, so visual details are
**(unverified)** and should be checked against screenshots before polishing.

Known behaviour of the official extension:
- Fills saved logins; fills verification codes automatically when a site has one set up.
- Suggests strong passwords and offers to **save** new credentials ("Save Password") and
  **update** changed ones ("Update Password"). Not shown for items in shared groups.
- Pairing: first use asks for a 6-digit code from the companion app; the Windows flow
  requires reopening/re-pairing periodically.
- Known complaints: it interferes with Chrome's credit-card autofill; the code prompt can
  get stuck until the companion app is re-logged-in.

### 2.1 Toolbar popup
- Header: key icon with locked / unlocked state. Locked shows a single "Unlock" button.
- Unlocked: search box on top, rows = favicon, site name, username. Current-site matches
  first, then "All Passwords".
- Section "Verification Codes" with live code and a countdown ring (not text like `23s`).
- Footer: "Open Passwords" (launches the GTK app), settings, sync status.
- Hover copy buttons for username and password; copy clears the clipboard after ~30s.

### 2.2 In-page autofill popover
- Small rounded popover anchored under the focused field, key icon at the left of the field
  like Apple's, rows with username + site, a "Passwords…" row at the bottom, and
  "Use Strong Password" on sign-up / change-password fields.
- Rendered in a **closed shadow root** so page CSS and page JS can't read or restyle it;
  system font stack; follows `prefers-color-scheme`; full keyboard support
  (arrows, Enter, Esc, Tab).
- Don't open it on programmatic focus; require a trusted user event. (Existing code has an
  `__applepwFilled` flag; keep that idea but also check `event.isTrusted`.)

### 2.3 Save and update prompts
- Detect submit of a login or sign-up form (submit event, `fetch`/XHR after a click on the
  submit control, `form` removal, SPA route change) and show "Save password for <site>?" /
  "Update password for <user>?".
- **Needs a write path** to iCloud (CloudKit writes + keychain encryption of new items).
  That is the largest backend piece in this document; see 4.4. Until then, an honest
  interim: offer "Copy to add in Passwords on your iPhone" or store locally in a
  "pending" list, clearly labelled as not synced.

### 2.4 Strong password generator
- Apple-style format `xxxxxx-xxxxxx-xxxxxx` (lowercase + one digit + one uppercase in the
  groups). Honour `minlength`, `maxlength`, `pattern`, and site rules; fill both
  password fields; show the password for a moment before submitting.
- Do this locally in Rust (CSPRNG) or JS `crypto.getRandomValues`.

### 2.5 Matching behaviour
- Rank: exact host > registrable-domain match > related-domain list. Use the **Public
  Suffix List** instead of the current "either is a dotted suffix of the other" rule
  (which will, for example, treat `co.uk` style sites incorrectly).
- Related-domain sets (Apple publishes shared-credentials style relationships), e.g.
  google.com / youtube.com.
- Most-recently-used first; remember last choice per site.
- Warn on `http://` pages and on a login whose saved domain doesn't match the page
  (phishing guard) instead of silently filling.

### 2.6 Passkeys
- Chromium exposes `chrome.webAuthenticationProxy` so an extension can act as a WebAuthn
  provider (**unverified in Helium**; check the API is not stripped).
- Items with access group `com.apple.webkit.webauthn` are already classified in
  `host.py` but dropped. A first step is just listing them in the app; actual passkey
  signing needs the private key to be decryptable here, which is a separate research task.

### 2.7 Packaging and trust
- Pin the extension id (commit the key; the repo already has `extension.pem`/`.crx` as
  untracked files, so decide whether they belong in git; **do not commit the `.pem`
  private key**). A fixed id removes the copy-and-paste step in `install.sh`.
- Real icon set (16/32/48/128), name "Apple Passwords" vs. trademark concerns (the README
  already says "not affiliated"; also avoid Apple's logo).
- Minimise permissions: `host_permissions` for all http/https is needed for autofill, but
  add `optional` ones where possible; drop `activeTab`/`scripting` if unused.

### 2.8 Robustness
- Handle iframes (cross-origin login frames) by deferring to the top frame's origin for
  matching and refusing to fill into a frame whose origin differs.
- Single-page apps: re-scan on mutation with debounce (observer exists; check cost on heavy
  pages).
- Per-site "never fill" list.

---

## 3. Flow and reliability

### 3.1 Long-running agent instead of process-per-message
- Run one **user systemd service** (`icp-agent`) that holds the decrypted vault in memory
  (mlock'd, zeroized), does the periodic sync, owns notifications, and serves:
  - the native-messaging shim (tiny binary that forwards stdin/stdout to a Unix socket)
  - the GTK app
  - the Secret Service mirror
- Native host becomes a ~100 line shim → startup in milliseconds, no Python spawn per
  keystroke.
- Socket in `$XDG_RUNTIME_DIR`, mode 0600, check `SO_PEERCRED` uid.

### 3.2 Setup in one command
- `icp setup`: checks Docker/Podman, starts the anisette container (or a systemd user unit
  for it), runs login, installs the native host for every detected Chromium-family browser
  (Helium, Chrome, Chromium, Brave, Edge, Vivaldi) and Firefox-family, installs the
  systemd units, and prints what it did.
- `icp doctor`: anisette reachable? session age? keyring unlocked? host manifest points to
  an existing launcher? extension id matches? last sync result? Output as a checklist.
- Ship as a single static binary (Rust) or `pipx`/`uv tool install` (Python).

### 3.3 Locking model
- States: locked → unlocked (idle timeout, default 5 min) → locked.
- Unlock = keyring unlock prompt (GNOME's) or polkit auth; the extension shows the locked
  state and a button, like Apple's Windows Hello gate.
- Don't silently fall back to a plaintext `master.key` file when the keyring is locked;
  prompt instead (today it logs a warning and uses the file).

### 3.4 Sync visibility
- Show "Last synced 3 h ago" and the last error text in the popup and app; send a desktop
  notification after N consecutive failures; surface Apple's error codes with a
  human explanation (e.g. `-80045`).
- Back-off + jitter on retries; never retry escrow/passcode attempts automatically
  (the README warns that ~10 wrong attempts permanently lock recovery).

### 3.5 Security hardening
- Zeroize secrets in memory; `PR_SET_DUMPABLE=0`; no secrets in logs (`diag.py` already
  redacts, keep that).
- Clipboard: copy with `x-kde-passwordManagerHint` / Wayland equivalent and auto-clear.
- Verify the extension id on every connection (the host manifest does this per browser).
- Consider storing the vault with a key wrapped by TPM / systemd-creds as an option.
- Threat model written down in `RESEARCH.md` or `SECURITY.md`.

---

## 4. Rust plan (incremental, no big-bang rewrite)

Why Rust here: long-lived daemon holding secrets (memory control), single static binary
(no venv), fast native-messaging shim, good GTK4/libadwaita and D-Bus support. And the
protocol this project follows (OpenBubbles/rustpush) is itself Rust, which makes the
crypto and wire formats easier to cross-check. **License of rustpush must be checked
before copying any code** (unverified); reading it as a reference is fine.

### 4.1 Order of work
1. **`icp-host-shim` (Rust, tiny):** native-messaging ↔ Unix socket. Immediately removes the
   Python cold start. Python keeps doing everything else behind the socket.
2. **`icp-agent` read path (Rust):** load/decrypt the vault, match domains (PSL), TOTP,
   Secret Service mirror, notifications. The Python code only syncs and writes the vault.
3. **GTK4/libadwaita app (Rust)** on top of the agent's API (see 1.2, 1.3).
4. **Port sync (Rust):** GrandSlam SRP, anisette client, CloudKit, Octagon, CKKS. This is the
   large step; port module by module with the existing Python tests as golden vectors
   (the repo has tests for nska, ckks, octagon, escrow SRP, gsa, cloudkit, totp, etc.).
   Only here would writing (save/update, 2.3) become realistic.
5. Retire the Python once the Rust sync matches on real accounts.

### 4.2 Crates worth evaluating
(The following list is partly from search results and partly general knowledge; check
versions and maintenance before depending on them.)

| Need | Candidates |
|---|---|
| D-Bus / Secret Service | `oo7` (zbus-based, from GNOME ecosystem), `secret-service` 3.x, `zbus` directly |
| GTK4 UI | `gtk4`, `libadwaita`, optionally `relm4` |
| Shell search provider | `search-provider` (GPL-3.0-or-later) |
| Crypto | RustCrypto: `aes-gcm`, `aes`, `sha2`, `hkdf`, `p256`/`p384`, `chacha20poly1305`; `srp` for SRP-6a; `crypto_secretbox`/`dryoc` for libsodium-compatible secretbox |
| Protobuf | `prost` (replaces `proto/codec.py`) |
| Plist | `plist` |
| HTTP | `reqwest` (rustls) |
| Secrets in memory | `zeroize`, `secrecy`, `memsec` / `region` for mlock |
| CLI | `clap`, `ratatui` for the `icp show` TUI |
| Async | `tokio` |
| Domain matching | `psl` or `publicsuffix` |

### 4.3 Migration safety
- Keep `vault.enc` format stable across the Python→Rust step, or write a one-time
  migration. Test with a copy of the real vault, never the live one.
- CI: `cargo test` plus the existing `pytest` golden vectors until Python is gone.

### 4.4 Write support (save / update / generate)
- Largest unknown. Needs: build a keychain item, encrypt it with the right class key,
  wrap for the CKKS zone, upload with proper record change tags, handle conflicts.
- Risk: a bad write could corrupt a user's real iCloud Keychain. Do not ship until it has
  been tested on a throwaway Apple ID, and make it opt-in behind a flag at first.
- The existing README promise ("`icp` only reads") would change; update docs and the
  warning text if this lands.

---

## 5. Project hygiene

- Licensing: repo is MIT. A GPL crate (`search-provider`) or copied rustpush code could
  force license changes; decide before adding.
- Untracked `extension.pem` / `extension.crx` in the working tree: the `.pem` is a signing
  private key; keep it out of git (add to `.gitignore`).
- `.venv`, `icp_linux.egg-info`, `.pytest_cache` should be ignored too.
- Tests for the extension (content-script field detection) using Playwright against a few
  saved login pages (Google, GitHub, Microsoft, LinkedIn, split OTP boxes).
- Packaging: AUR / `.deb` / Flatpak (note: Flatpak browsers need
  `--talk-name` / filesystem access to find the native host; the existing launcher
  comment mentions container cases).
- Upstream: this is a clone of Sank6/iCloud-Keychain-for-Linux. Decide whether to send
  these as PRs, or keep a fork. Search found the repo gaining stars and forks recently,
  so upstreaming small pieces (Helium registration, PSL matching, doctor command) is
  likely welcome. Check open issues on GitHub first (I could not load them).

---

## 6. Suggested order

1. 3.2 `icp doctor` + one-command setup, 3.4 sync visibility (so failures are never silent)
2. 1.1 Secret Service mirror (visible in Seahorse right away)
3. 2.1 / 2.2 popup and in-page popover redesign, 2.5 matching with PSL, 3.3 lock/unlock
4. 3.1 + 4.1 steps 1–2: Rust shim and agent
5. 1.2 / 1.3 GTK app and search provider
6. 2.4 generator, 2.6 passkey listing
7. 4.1 step 4 and 4.4: Rust sync, then (carefully) write support

## Sources
- oo7 / Secret Service crates: https://docs.rs/crate/oo7/latest/source/README.md ,
  https://lib.rs/crates/secret-service
- GNOME search provider docs: https://developer.gnome.org/documentation/tutorials/search-provider.html ,
  crate https://lib.rs/crates/search-provider
- libadwaita-rs: https://lib.rs/crates/libadwaita
- Apple, autofill iCloud passwords in a browser on Windows: https://support.apple.com/guide/icloud-windows/icw76039ec0f
- Chrome Web Store, iCloud Passwords: https://chromewebstore.google.com/detail/icloud-passwords/pejdijmoenmkgeppbflobdenhhabjlaj


## Option under evaluation: Apple's Windows client under Wine

Not started; needs your go-ahead (it means downloading Apple's installer).

- **Idea:** run Apple's own iCloud Passwords host under Wine and relay the browser extension's
  native messages to it through a small Linux shim, as a backend alongside this client.
- **Gains:** save/update support, Apple's real device identity (lowest ban risk), real anisette.
- **Costs:** closed source, Windows-only; no Secret Service / GNOME integration; the protocol is
  per-URL lookup, so it probably cannot feed the GTK app or keyring mirror; fragile on updates.
- **Plan with go/no-go gates:** (1) Wine present and installer runs, (2) sign-in under Wine,
  (3) host answers a lookup, (4) relay shim. Cheapest useful variant: use Wine only to obtain
  anisette. Emulating just the needed Windows calls without Wine is not recommended.

### Sync retry result (after the merge)
`GSA init failed: HTTP 403: non-plist reply (146 bytes)`. Apple refuses the very first sign-in
request, before any password is checked, so this is about how the request looks (client identity
or anisette data), not about your credentials. Background syncs are now stopped (`needs_login`).
This is the strongest argument for getting real anisette (see the Wine option above).

## Official Apple extension support (this round)

Status: **works end to end in a throwaway headless Helium profile; not yet tried in your real profile.**

- Protocol read from the installed extension v3.4.0 and written up in `docs/apple-extension-protocol.md`.
- Host implemented in Python (`icp/applehost.py` crypto, `icp/applehost_main.py` message loop,
  `icp/applehost_install.py` manifest + patcher). Tested against Apple's own `SecretSession` code run
  under node (`tests/test_applehost.py`, `tests/ext/apple_client.js`), including 60 random pairings for
  key-derivation edge cases and wrong-PIN/lockout/read-only behaviour.
- Verified in the throwaway profile with Apple's real extension: pair with PIN -> list logins -> fill
  password (only lengths were printed).
- **Blocker found: the official extension refuses to run on Linux** (OS gate in `checkForValidOS`). A
  Linux user needs a local copy with that one check removed (`patch-extension`), loaded unpacked, with
  the store version turned off (same ID). The alternative, spoofing a Windows user agent for the whole
  browser, was rejected.
- Not done: Rust port of the host (Python for now; the Rust agent still serves lookups), TOTP over this
  protocol, PROTO 1 proofs, `icp setup` integration, and trying it in your real Helium profile.


---

## Anisette without Docker (investigation, read-only; nothing downloaded or run)

What anisette is: the `X-Apple-I-MD` / `X-Apple-I-MD-M` headers are a one-time-password plus machine
blob produced by Apple's `AuthKit`/`CoreADI` code (`ADI` = Apple Device Identity). Apple's servers
check that they are consistent with a provisioned "device". Apple publishes no algorithm.

| Option | Needs | Verdict |
|---|---|---|
| `dadoum/anisette-v3-server` (today) | Docker/Podman; the image fetches Apple's `libstoreservicescore` / `libCoreADI` (from the Apple Music Android package) on first start and runs them under an ELF loader shim | works, but it **downloads Apple binaries at runtime** and needs a container runtime; was exposed on 0.0.0.0 (fixed in docs/doctor) |
| Run the same server natively (no container) | the same Apple libraries + the Provision project's loader | removes Docker, not the Apple-binary download; build from source needs a D/C toolchain. Not implemented here (the task forbids downloading Apple binaries) |
| Emulate the Mac `NAC` routine (OpenBubbles `open-absinthe`, older pypush) | an Apple macOS binary plus an x86 emulator (`unicorn`), or a relay | heavier and fragile; same Apple-binary dependency |
| Third-party public anisette servers (SideStore community) | nothing local | sends your device identity to a stranger; `icp doctor` warns about non-loopback URLs. Acceptable only as a stopgap |
| Wine + Apple's Windows client | see the Wine section above | biggest, most fragile |
| Pure-Python/Rust re-implementation of ADI | reverse engineering of `CoreADI` | no known open implementation; **not realistic** |

**Recommendation:** keep a *loopback-only* container (or rootless Podman via the Quadlet in
`packaging/anisette/`) for now; it is a few MB of RAM and survives reboots. The realistic Docker-free
path is a small native service that loads the same Apple libraries the way Provision does, and that
still needs a one-time download, so it requires an explicit go-ahead. Do not spend effort on
re-implementing ADI. Note the current container has **no volume**: deleting it loses its provisioned
identity, so back it up first (`docker cp anisette:/home/Chester/.config/anisette-v3 ./backup`, path
from the image's README, unverified) before re-creating it on 127.0.0.1.

## Reliability and native-feel plan

### What changed in this round
- **Sign-in is a first-class flow.** `icp login --gui` (also the app menu, the app banner and the
  browser popup button) shows a real form (Apple ID, password, "remember in keyring"), then 2FA /
  join confirmation dialogs. Cancel at any prompt aborts without sending anything; a mistyped 2FA
  code is asked again (max 3, no new push); a wrong password and "Apple is refusing the request"
  have their own wording and the form stays. Logic is toolkit-free (`icp/gui/loginflow.py`, tested).
- **"Needs sign-in" state** (`needs_login`) is raised by auth-class failures, 403s, and a missing
  session, and is shown by the GTK app (banner + button), `icp doctor`, `icp status`, the popup
  ("Sign in..." button -> new agent command `login`, ported to the Rust agent) and a desktop
  notification. Offline / open-breaker failures are *transient*: they delay, never demand a sign-in.
- **Keyring**: all Secret Service access goes through `icp/keyring.py` (typed
  unavailable/locked/dismissed errors, no prompts in background runs, `mirror_collection` config).
  The Apple ID (+ optional password) is a normal Seahorse item (`icp/account.py`); with a keyring
  the password is no longer inside `session.enc`. **No silent key regeneration**: a missing key with
  existing encrypted files raises `KeyLost`; undecryptable `vault.enc` is no longer deleted;
  `icp logout --reset-keys` is the explicit, non-destructive (files renamed `.lost-<time>`) start over.
  A key found in `master.key` is moved into the keyring. The mirror never wipes itself from an empty
  vault, skips when nothing changed, and `icp logout` removes mirrored items (`--keep-mirror`).
- **One HTTP layer** (`icp/net.py`): timeouts, per-host spacing, backoff+jitter, `Retry-After`, no
  retry on 401/403, a persisted per-host circuit breaker (unattended calls only), typed errors
  (`NetworkDown`, `AuthRejected`, `BlockedByApple`, `Throttled`, `ServerError`, `CircuitOpen`),
  URL-only logging. GSA, loginDelegates, account settings, CloudKit, escrow, idmsa web and Hide My
  Email all use it. The first-request HTTP 403 now says what it means and what to do.
- **Unattended = no terminal and no `--force`** (even without `--background`), so an older agent
  whose `sync-cmd` lacks the flag can no longer sign in with the password.
- **Slimming**: `status.py` is now a read-only view over `ratelimit` state (one writer, one
  source of truth; `sync-status.json` is a projection for the Rust agent); shared `framing.py`;
  atomic private writes; `doctor` anisette/keyring logic deduplicated.
- **Config**: `~/.config/icp/config.toml` (`anisette_url`, `mirror_collection`), one resolver
  (`icp/config.py`), loopback default `http://127.0.0.1:6969`; hard-coded `localhost`, `6969` hints
  and `~/.config` paths replaced. Anisette packaging: `packaging/anisette/` (Quadlet + systemd unit).
- **Rust parity**: re-run against the Python agent on the real vault: 871 requests (705 domains,
  42 codes, lock/unlock, errors), 0 differences, after fixing two drifts the run found (the
  `group` field of shared-group logins, and the unknown-command error text). New Rust: `login`,
  `signed_in` in `status`, never auto-sync while `needs_login`, `--background` forced on
  `sync-cmd`.

### Still hacky
- GUI sign-in has been exercised only headless (widgets built, outcomes rendered) and with a
  faked `cmd_login`; it has not been driven through real dialogs or against Apple.
- `Adw.MessageDialog` is deprecated in libadwaita 1.6 (works; port to `Adw.AlertDialog`).
- The breaker and pacing are per process / per file with no cross-process lock (last writer wins).
- Python tests must run with `DBUS_SESSION_BUS_ADDRESS` unset (older tests would otherwise read the
  real keyring); a shared test fixture should enforce that.
- The installed Rust agent binary in `~/.local/share/icp` is the old build until `icp setup`.
- Docker volume path for the anisette image is from memory of its README (unverified).

### Next steps (priority order)
1. Re-create the anisette container on 127.0.0.1 (`packaging/anisette/README.md`), then one
   interactive `icp login --gui` once Apple stops answering 403.
2. Local anisette provider without Docker (needs a go-ahead for one Apple-library download).
3. Rust port of sync (GSA/SRP, CloudKit, Octagon, CKKS) using the Python tests as golden vectors;
   then the Rust agent can own sign-in state too.
4. Packaging: install `icp-agent`/`icp-shim` + units from the `.deb`, Flatpak/AUR; drop `setup`'s
   per-user copies.
5. `Adw.AlertDialog`, a Rust GTK app (needs `libadwaita-1-dev`), automated browser tests.


## Windows app analysis (summary)

Full write-up: `docs/WINDOWS_ICLOUD_ANALYSIS.md` (static, read-only, nothing executed).
Key findings: the Windows iCloud app ships Apple's ported keychain stack (`secd`, CKKS, AOSKit,
local anisette via `CoreADI64.dll`); the official extension's host is
`iCloudPasswordsExtensionHelper.exe` (`com.apple.passwordmanager`, allowed origins include
`pejdijmoenmkgeppbflobdenhhabjlaj`); the real client info string is
`<PC> <...> <com.apple.AuthKitWin/x.y (bundle/ver)>`, unlike ours. Next experiment (once,
after back-off): the AuthKitWin-shaped client info. Not done: disassembly of PIN attempt limits.
