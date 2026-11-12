"""The saved Apple ID (and, unless declined, its password) as a Secret Service item.

Why in the keyring and not only in session.enc: the item is visible and removable in Seahorse
("Passwords and Keys"), carries the standard NetworkPassword attributes so it is not a mystery
blob, and the GTK sign-in dialog can pre-fill the Apple ID without decrypting the whole session.
When there is no Secret Service the password stays inside the encrypted session blob instead
(see `icp.auth.session`), exactly as before. Only items with our own attributes are ever touched."""

from __future__ import annotations

from . import keyring

ATTRS = {"application": "icp", "type": "apple-account"}
SERVER = "appleid.apple.com"
LABEL = "iCloud Passwords: Apple ID"


def _items(coll):
    return keyring.find(coll, ATTRS)


def save(username: str, password: str | None, *, interactive: bool = True) -> None:
    """Store/replace the Apple ID item (empty secret when no password is kept). Raises
    KeyringError when the keyring is unavailable or locked; callers fall back to session.enc."""
    coll = keyring.open_collection(interactive=interactive)
    secret = (password or "").encode()
    keep = None
    for item in _items(coll):
        same = item.get_attributes().get("user") == username
        if same and keep is None and item.get_secret() == secret:
            keep = item
        elif not same or keep is not None or item.get_secret() != secret:
            item.delete()  # other account, duplicate or stale password
    if keep is None:
        attrs = {**ATTRS, "user": username, "server": SERVER, "protocol": "https",
                 "xdg:schema": "org.gnome.keyring.NetworkPassword"}
        coll.create_item(f"{LABEL} ({username})", attrs, secret, replace=True)


def load(*, interactive: bool = False) -> tuple[str | None, str | None]:
    """(apple_id, password) or (None, None); never raises (a missing keyring is just 'unknown')."""
    try:
        for item in _items(keyring.open_collection(interactive=interactive)):
            user = item.get_attributes().get("user")
            pw = item.get_secret().decode() or None
            if user:
                return user, pw
    except keyring.KeyringError:
        pass
    return None, None


def forget() -> int:
    """Remove every saved Apple ID item. Returns how many were removed."""
    coll = keyring.open_collection()
    n = 0
    for item in _items(coll):
        item.delete()
        n += 1
    return n
