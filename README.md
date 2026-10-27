# iCloud Keychain for Linux

**Unofficial** client for iCloud Keychain. Sign in with your Apple ID and
`icp` registers this computer as one of your Apple devices, then downloads your passwords into a
private, encrypted store on your machine. A browser extension fills them in for you, just like the
Passwords app on a Mac or iPhone. Your Hide My Email addresses show up too. This project is a 
reverse engineering attempt and **is not affiliated with Apple in any way**.

> **Note:** Most of this project was written with AI assistance (and reviewed by a human).
> It works with my own Apple account, but that's no guarantee it will work with yours.
> Your passwords never leave your computer, and by default nothing is changed in your Apple
> account - `icp` only reads. The one exception is the experimental `icp edit` (see
> [Editing logins](#editing-logins-experimental)), which writes only when you add `--apply`.

> This is also **untested** with Advanced Data Protection enabled. Any help with this will be appreciated -
> let me know if you have any issues with ADP enabled (also lmk if it works). Please don't spam escrow attempts!

## What you'll need

An **anisette server** running on your machine. Apple's sign-in needs a small piece of data that
only Apple's own software can produce; the anisette server provides it locally. Start one with
Docker (or Podman) - it keeps running in the background:

```
docker run -d --restart=always -p 6969:6969 dadoum/anisette-v3-server:latest
```

You only have to do this once. (If you run it somewhere other than the default
`http://localhost:6969`, set `ICP_ANISETTE_URL` to its address.)

You will also need this repo. Clone it / download it as you wish.

## Install

From the project folder:

```
python3 -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate
```

## Sign in

```
icp login
```

This will walk you through the login: enter your Apple ID, password, and the 2FA code Apple
sends to your other devices. `icp` then asks for a **device passcode or iCloud Security Code** so
it can join your keychain.

- You're only asked for your password and 2FA code **once**. `icp` should stay signed in for a year after this.
- The passcode step is **important and can't be undone**: entering the wrong passcode too many
  times (about 10) will permanently lock your keychain recovery. One correct entry is
  perfectly safe.
- Your 2FA code and passcode are used immediately and **never saved**. Your password is kept
  **encrypted on your computer** (in your login keyring) so `icp` can stay signed in without
  asking you again - it never leaves your machine. Your access tokens and passwords are stored
  the same way.

## Browse your passwords

```
icp show
```

Opens a full-screen list - start typing to filter, **Enter** to reveal a password,
**Ctrl+P** / **Ctrl+U** to copy the password / username to the clipboard, **Esc** to quit. Add a word to search directly, or `--plain` for plain text:

```
icp show github
```

## Verification codes

If a login has an authenticator code set up in the Passwords app, `icp` picks it up too. `icp show`
lists the current 6-digit code next to the login with the seconds left before it changes, counting
down live.

## Set up the browser extension

The `extension/` folder works in Chromium based browsers and Firefox.

### Chrome, Chromium, Helium, or Brave

1. Open your browser's extensions page (e.g. `chrome://extensions`, `helium://extensions`) and turn on **Developer
   mode**.
2. Click **Load unpacked** and choose the `extension/` folder. Copy the **Extension ID** it shows.
3. Connect the extension to `icp` by running:

   ```
   host/install.sh <EXTENSION_ID>
   ```

4. Reload the extension. Click its toolbar icon - you'll see the logins for the current site.

### Firefox

1. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on...**, and choose
   `extension/manifest.json`. (Firefox removes temporary add-ons when it restarts, so you'll need
   to re-load it after restarting.)
2. Connect it to `icp`:

   ```
   host/install.sh
   ```

3. Click the toolbar icon to see logins for the current site.

If you ever move this project to a different folder, just run `host/install.sh` again.

## Filling in passwords

- On a sign-in page, click the username or password box - an **iCloud Passwords** dropdown appears
  with matching logins. Click one to fill it in (it handles email-first pages like Google too).
- Start typing to narrow the list.
- Or click the extension's toolbar icon and pick a login there.
- On a **two-factor code** box, the dropdown offers the current code instead - click to fill it.
  Pages that split the code across six separate boxes are filled a digit at a time. The code is
  always regenerated at the moment you click, so it is never a stale one, and the toolbar popup
  shows the code next to each login (click it to copy).

## Keeping your passwords up to date

Your passwords are a snapshot, so new or changed ones need a refresh. This happens
**automatically** in the background whenever the snapshot is more than 6 hours old - you don't have
to do anything. To refresh right now:

```
icp sync
```

Syncs are paced so Apple is never hammered: at most one every 5 minutes (`--force` skips that),
and after a failure the next try waits longer (5 min, 10, 20 ... up to 6 h, or whatever Apple's
`Retry-After` asks for). Background syncs (`icp sync --background`, used by the browser helper and
timers) never sign in with your password and never trigger a verification code on your devices -
if your sign-in has expired they stop and wait for `icp login`. `icp status` shows the state.

Shared password groups you created in the Passwords app are synced too; groups someone else
shared with you are not yet.

## Editing logins (experimental)

`icp` can also change an existing login and save it back to iCloud Keychain, so the change shows
up on your iPhone and Mac. This is **opt-in per command**: every edit is a dry run that prints
what would change, and only `--apply` sends it. Treat it as experimental - it has been checked
against one real account, not many.

```
icp edit example.com anna --add-site shop.example.com              # dry run: shows the diff
icp edit example.com anna --add-site shop.example.com --apply      # saves it
icp edit example.com anna --password-stdin --apply                 # new password (prompted)
icp edit example.com anna --stdin-json --apply < changes.json      # {"notes": ..., "totp": ...}
icp edit example.com anna --site example.org --apply               # new primary website (rekey)
icp edit example.com anna --delete --apply                         # move to Recently Deleted
```

What can be changed: the password, the primary website (`--site`), the username
(`--new-username`), extra websites (`--add-site` / `--remove-site`), the title, the notes and the
verification code (`totp`: an `otpauth://totp` URI or a base32 setup key, `""` removes it).
`--delete` moves the login and its metadata to **Recently Deleted**, like the Passwords app does,
so it can be recovered on any device. When several logins share website and username (http vs
https, another port or path), pick one with `--uuid` (the `uuid` the vault stores per login).
Title, notes, extra websites and codes live in the login's Passwords-app metadata; a login that
has none yet must be edited once in the Passwords app first. Secrets (password, notes, code) are
best passed via `--password-stdin` or `--stdin-json`, never as arguments. Logins in shared groups
stay read-only, and new logins cannot be created.

**Safety model.** Each rule is enforced in `icp/keychain/write.py`, not by the caller:

- Dry run by default; `--apply` per command.
- Every update and delete carries the record's *etag* from a fetch moments before - if another
  device changed the login in between, Apple refuses the write instead of overwriting it.
- Only entries encrypted with the current class key are written; the re-encrypted record is
  decrypted again locally and compared with the edit before anything is sent.
- Each record is backed up (encrypted, in `~/.config/icp/backup/`) before it is changed or
  deleted. `icp restore <uuid> --apply` puts that version back; the uuids are printed after an
  edit (`backups` in `--json`).
- Writes are paced (10 s between edits, at most 30 writes an hour). Any failed write blocks all
  further writes until you have looked at it: `icp write-state` shows the state,
  `icp write-state --clear` lifts the block.
- Keys, zones and anything outside your own `Passwords`/`Manatee` logins are never touched.

**Why changing the website or username creates a new entry.** Website and username are part of a
keychain item's primary key. Apple devices apply an incoming change by primary key only
(`CKKSIncomingQueueOperation` -> `SecDbItemInsertOrReplace` in Apple's Security code), so an
in-place change of either leaves the old row next to the new one on the device (observed on
iOS 27). `icp` therefore *rekeys*: it inserts the login (and its metadata) under
new record ids, reads them back from iCloud, and only then deletes the old records. If anything
fails before the delete you get a duplicate, never a lost password. A rekey refuses a target
website/username that another login already uses.

**Risks.** This writes to your real keychain with a protocol Apple does not document. A bug or an
unexpected server change could corrupt or duplicate an entry on all your devices. Try it on a
throwaway login first, and keep `icp diag write` (record shapes, no values) handy if something
looks off. `icp restore` puts back one record at a time; after a rekey, restore both the login and
its metadata and delete the new entry on a device.

## All commands

```
login    sign in, join your iCloud Keychain, and download your passwords
show     browse and search your passwords and Hide My Email addresses
sync     refresh your passwords now (--background for unattended runs, --force)
status   last sync, next allowed sync, whether a login is needed (--json)
diag     read-only diagnostics: zones, groups, write (shapes/counts only, no secrets)
edit     change one login - dry run unless --apply (experimental, see above)
restore  put a backed-up record back after an edit (dry run unless --apply)
write-state  edit pacing and block state (--clear lifts a block after an error)
logout   sign out (use --wipe-device to also forget this device)
```

## Credits

The GrandSlam sign-in flow is adapted from [JJTech's reference](https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452).
The keychain decryption, Octagon trust join, and CloudKit transport follow
[OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush), cross-checked against
[Apple's open-source Security code](https://github.com/apple-oss-distributions/Security). Hide My
Email is ported from [dedoussis's browser extension](https://github.com/dedoussis/icloud-hide-my-email-browser-extension).
The record save/delete layout and the Passwords-metadata format used by `icp edit` follow
[Laky-64/appleservices](https://github.com/Laky-64/appleservices) (MIT).
Machine data is provided by the SideStore ecosystem's `anisette-v3-server`. See `RESEARCH.md` for
how it all works.
