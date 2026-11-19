# Security notes and threat model

`icp` holds a decrypted copy of your iCloud Keychain logins on your computer and hands them to a
browser extension. This file says what that does and does not protect against.

## Where secrets live

| What | Where | Protection |
|---|---|---|
| Apple session tokens | `~/.config/icp/session.enc` | libsodium secretbox; key in the login keyring |
| Apple ID + saved password | login keyring item `application=icp type=apple-account` (no keyring: inside `session.enc`) | keyring; shown in Seahorse; `icp logout` removes it |
| Decrypted logins | `~/.config/icp/vault.enc` | same key, file mode 0600 |
| That key | login keyring (Secret Service) | unlocked with your login |
| Same key, only when there is no Secret Service at all | `~/.config/icp/master.key` (0600) | file permissions only (doctor warns) |
| Logins mirrored for Seahorse/libsecret | login keyring items `application=icp` | keyring; readable by any process running as you while unlocked (`ICP_NO_MIRROR=1` disables) |
| Logins in memory | `icp-agent` process | dumpable=0; locks (drops them) after 15 min idle |
| Remembered login choice per site | `~/.config/icp/choices.json` | username hash only |

## What this defends against

- Another user on the machine (0700/0600 files, per-user socket checked with `SO_PEERCRED`).
- Someone copying your disk while you are logged out (keyring-encrypted key; no plaintext vault).
- A web page reading or restyling the autofill UI (closed shadow root) or triggering it from
  script (`isTrusted` check). Sites cannot call the native host; only the pinned extension id is
  allowed in the host manifest.
- Filling into the wrong site: matching uses the Public Suffix List, so shared suffixes
  (`github.io`, `co.uk`) never link two sites. Related-site sets are a small hand-curated list.
- A dismissed or missing keyring entry wiping your vault: it raises instead of minting a new key, and
  an undecryptable vault is never deleted (`icp logout --reset-keys` is the explicit way out).
- Other machines on your network using the anisette server: it must be published on 127.0.0.1 only
  (`icp doctor` warns when it listens on 0.0.0.0; see `packaging/anisette/`).
- Hammering Apple: one HTTP layer with per-host spacing, no retries on 401/403, and a circuit
  breaker that stops unattended calls after repeated errors.

## What it does NOT defend against

- Malware or any process running as you while the keyring is unlocked. It can read the vault key,
  the mirrored keyring items, and ptrace-less memory scraping of other user processes is limited
  only by `ptrace_scope`.
- A malicious or compromised browser extension with host permissions, or a compromised browser.
- Memory remnants: Python cannot reliably zeroize or mlock secrets. A Rust agent would help.
- Clipboard snooping: password copies set `x-kde-passwordManagerHint` and clear after 30 s, but
  GNOME offers no equivalent guarantee.
- Apple-side changes: this is an unofficial, reverse-engineered client.

## Operational rules

- Never commit `extension.pem` (the extension signing key) or anything under `~/.config/icp`.
- The README warns that ~10 wrong passcode entries permanently lock keychain recovery; nothing
  here retries escrow/passcode attempts automatically.
- Failed sign-ins back off exponentially (15 min doubling, 24 h cap) instead of hammering Apple.

## Apple-extension host (`com.apple.passwordmanager`)

- **Pairing PIN**: a fresh random 6-digit PIN per pairing attempt, from the OS CSPRNG, shown only in a
  desktop notification. It is never logged or written to disk by the host. It is the SRP password, so
  it never crosses the pipe; a wrong PIN fails the AES-GCM check.
- **Guessing**: after 3 wrong PINs the host refuses new pairings for 10 minutes (per host process).
  A 6-digit PIN is guessable offline only by someone who can already read the browser<->host pipe,
  i.e. code running as you; the same attacker could ask the agent directly.
- **Sessions**: keys live only in the host process memory, are dropped on `Hello`/cancel/failure, expire
  after 8 hours and are not persisted, so every browser start re-pairs.
- **Scope**: read-only. Save/update/TOTP requests are ignored. Lookups reuse the agent, so they obey
  its lock state and idle lock.
- **Getting past Apple's OS gate**: Apple's extension refuses to start on Linux. `icp setup` edits
  one function (`checkForValidOS`) in the extension copy your own browser installed, in place. The
  original `background.js` is saved under `~/.local/share/icp/apple-extension-orig/` and
  `icp apple-extension restore` puts it back. A systemd user path unit re-applies the edit when the
  browser updates the extension. The edit is not signed by Apple and only touches your local copy;
  Apple's code is never shipped in this repo. `--apple-extension unpacked` instead builds a separate
  copy for Developer mode -> Load unpacked.

## Threat model and red-team review

**Who we defend against.** (1) A malicious *website* trying to be offered, or to read, passwords
that belong to another site. (2) A malicious or compromised *anisette server* or network
attacker. (3) Another *local user* on the machine. (4) Corrupt or tampered *files* in the config
folder. **Out of scope:** code already running as you. It can read the vault through the agent
socket exactly as the browser host does (the socket is owner-only and checks the caller's uid), so
no host-side check can stop it.

**Review (Nov 2026).** Every item below was reproduced first, fixed, and is covered by a test.

| Finding | Impact | Fix |
|---|---|---|
| A bare-name login (`amazon`) matched `amazon.evil.com`, `evil.localhost`: any hostname *label* counted (Python **and** the Rust agent the browser actually uses) | a page on an attacker-chosen subdomain was offered your Amazon password | only the site's own name (the label left of the public suffix) can match |
| `https://evil.com\@example.com/` and `https://evil.com#@example.com/` were read as host `example.com`; IPv6 and NUL hosts parsed to junk | credentials for `example.com` offered to `evil.com` if a full URL reached the matcher | URLs are parsed as browsers do (`\`, `/`, `?`, `#` end the authority); anything that is not a plain ASCII hostname never matches |
| A non-ASCII stored domain normalised to "" and was then treated as a label-only entry | a name inside it matched any site | label-only matching needs a missing or one-word domain, never an unusable one |
| Pairing PIN was passed to `notify-send` on its command line | any local user could read it from `/proc/<pid>/cmdline` | sent over D-Bus from the host process; `notify-send` only as a fallback |
| The Apple host crashed on any JSON message that was not an object or had a wrong-typed field | one bad message killed the host | every shape is survivable; the stdio loop skips bad frames |
| Anisette server replies were trusted: `null`/list crashed the client, CR/LF in header values was accepted, no size limit, provisioning URLs were not checked | header injection, crashes, our identity sent to a non-Apple address | replies are size-bounded and validated; provisioning endpoints must be `https://*.apple.com`; every malformed reply is an `AnisetteError` |
| Debug transcripts ("safe to share") contained the Apple ID e-mail and account id inside free text | identity disclosure when sharing a log | identifiers are scrubbed from values and from every log line; only the newest 3 transcripts are kept |
| `~/.local/share/icp` (launchers and command files the browser/app execute) was mode 775; lock files 664 | a member of your group could replace a launcher and run code as you | data dir 0700, launchers 0700, command files 0600; older installs are tightened on the next `icp setup` |
| A corrupt `state.json`, `choices.json`, `anisette-v3.json` or `config.toml` crashed the app and the background timer | a reliability bug, not a leak | tolerant reader: such files read as empty; a damaged `device.json` is an explained error (never a silent new Apple device) |
| Rust agent: a panic in one request would poison its state lock and break every later request | denial of service until restart | poison-tolerant lock plus `catch_unwind` per request |
| `icp sync` used `os` without importing it (found while hardening) | `icp sync` would have crashed | fixed; a static test now finds undefined names in every module |

**Hardening kept as-is (checked):** the agent socket is 0600 in a 0700 directory, checks
`SO_PEERCRED` and refuses other uids, caps frames at 1 MiB and disables core dumps; the vault and
session are encrypted with a key held in the Secret Service; passwords are only released for an
explicit single-login request after a PIN-authenticated pairing (lists carry `Not Included`); the
systemd units use seccomp-only sandboxing (`NoNewPrivileges`, restricted address families; the
extension patcher has no network); in-place extension patching never follows a symlink out of the
extension folder and keeps the original file.

**Known limits.** The anisette server (a third party unless you run your own) sees anisette
requests, not your Apple ID or password. Apple can change its rules at any time. Pairing is read-only
by design. Autofill matching is deliberately *broader* than exact-host in two cases that mirror Apple's
own behaviour: a credential saved for `accounts.example.com` is offered on `example.com`, and curated
related sites (google.com / youtube.com) share logins.
