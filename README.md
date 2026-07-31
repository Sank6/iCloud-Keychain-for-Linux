# iCloud Keychain for Linux

**Unofficial** client for iCloud Keychain. Sign in with your Apple ID and
`icp` registers this computer as one of your Apple devices, then downloads your passwords into a
private, encrypted store on your machine. A browser extension fills them in for you, just like the
Passwords app on a Mac or iPhone. Your Hide My Email addresses show up too. This project is a 
reverse engineering attempt and **is not affiliated with Apple in any way**.

> **Note:** Most of this project was written with AI assistance (and reviewed by a human).
> It works with my own Apple account, but that's no guarantee it will work with yours.
> Your passwords never leave your computer, and nothing is ever changed in your Apple
> account - `icp` only reads.

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

Install and initialise [`pass`](https://www.passwordstore.org/) first. It uses your existing GPG
key and works independently of GNOME, KDE, or any other desktop environment:

```
# Distribution package name is usually "pass" or "password-store"
pass init YOUR_GPG_KEY_ID
```

Then, from the project folder:

```
python3 -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate
```

The encryption master key is stored at `icloud-keychain-for-linux/master-key` in password-store.
Set `ICP_PASS_ENTRY` to use another entry name. An existing `~/.config/icp/master.key` from an
older installation is imported into `pass` automatically, preserving the encrypted vault.

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
- Your sign-in 2FA code and passcode are used immediately and **never saved**. Your password is
  kept **encrypted on your computer** so `icp` can stay signed in without asking you again. The
  random encryption key is protected by `pass`/GPG; no GNOME keyring or Secret Service is needed.

## Browse your passwords

```
icp show
```

Opens a full-screen list - start typing to filter, **Enter** to reveal a password,
**Esc** to quit. Add a word to search directly, or `--plain` for plain text:

```
icp show github
```

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

- On a sign-in page, click the username, password, or verification-code box - an **iCloud
  Passwords** dropdown appears with matching logins. Click one to fill the username, password,
  and current TOTP code where those fields are present (including email-first pages like Google).
- Start typing to narrow the list.
- Or click the extension's toolbar icon and pick a login there.

## Keeping your passwords up to date

Your passwords are a snapshot, so new or changed ones need a refresh. This happens
**automatically** in the background whenever the snapshot is more than 6 hours old - you don't have
to do anything. To refresh right now:

```
icp sync
```

## All commands

```
login    sign in, join your iCloud Keychain, and download your passwords
show     browse and search your passwords and Hide My Email addresses
sync     refresh your passwords now
logout   sign out (use --wipe-device to also forget this device)
```

## Credits

The GrandSlam sign-in flow is adapted from [JJTech's reference](https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452).
The keychain decryption, Octagon trust join, and CloudKit transport follow
[OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush), cross-checked against
[Apple's open-source Security code](https://github.com/apple-oss-distributions/Security). Hide My
Email is ported from [dedoussis's browser extension](https://github.com/dedoussis/icloud-hide-my-email-browser-extension).
Machine data is provided by the SideStore ecosystem's `anisette-v3-server`. See `RESEARCH.md` for
how it all works.
