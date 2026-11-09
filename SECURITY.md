# Security notes and threat model

`icp` holds a decrypted copy of your iCloud Keychain logins on your computer and hands them to a
browser extension. This file says what that does and does not protect against.

## Where secrets live

| What | Where | Protection |
|---|---|---|
| Apple session tokens, saved Apple ID password | `~/.config/icp/session.enc` | libsodium secretbox; key in the login keyring |
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
- A dismissed keyring prompt wiping your vault: it now raises instead of minting a new key.

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
- **Patched extension copy**: required on Linux because Apple's extension refuses to start (OS gate).
  The copy is built locally from your own installed extension and is not auto-updated; re-run
  `python -m icp.applehost_install patch-extension` after an update. Only the OS check is changed.
