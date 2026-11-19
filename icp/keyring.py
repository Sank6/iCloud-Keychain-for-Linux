"""The one place that talks to the Secret Service (gnome-keyring / KWallet via `secretstorage`).

Everything else (master key, saved Apple ID, logins mirror, doctor) goes through `open_collection`
so a locked keyring, a missing service and a dismissed unlock prompt are handled identically and
reported with the same typed errors. Nothing here ever invents or replaces key material."""

from __future__ import annotations


from .errors import SessionError


class KeyringError(SessionError):
    """Base for keyring access problems."""


class KeyringUnavailable(KeyringError):
    """No Secret Service (no session bus, no daemon, library missing, or collection not found)."""


class KeyringLocked(KeyringError):
    """The keyring is locked and was not (or could not be) unlocked. Deliberately NOT a reason to
    fall back to a key file: that would mint a new key and orphan every stored file."""


def _pick(ss, conn, name: str | None):
    if not name:
        return ss.get_default_collection(conn)
    for coll in ss.get_all_collections(conn):
        label = ""
        try:
            label = coll.get_label()
        except Exception:  # noqa: BLE001 - a broken collection must not hide the others
            pass
        path = str(getattr(coll, "collection_path", ""))
        if name in (label, path.rsplit("/", 1)[-1]):
            return coll
    raise KeyringUnavailable(f"keyring collection {name!r} not found")


def open_collection(name: str | None = None, *, interactive: bool = True):
    """An unlocked collection: the default one, or `name` (label or D-Bus id).

    `interactive=False` never shows an unlock prompt (background runs): a locked keyring raises
    KeyringLocked instead. A dismissed prompt raises KeyringLocked too."""
    try:
        import secretstorage
    except Exception as e:  # noqa: BLE001
        raise KeyringUnavailable(f"secretstorage not importable ({e})") from e
    try:
        conn = secretstorage.dbus_init()
        coll = _pick(secretstorage, conn, name)
        locked = coll.is_locked()
    except KeyringError:
        raise
    except Exception as e:  # noqa: BLE001 - no bus, no daemon, ...
        raise KeyringUnavailable(f"Secret Service unavailable ({e})") from e
    if locked:
        if not interactive:
            raise KeyringLocked("the keyring is locked (unlock it in a desktop session)")
        try:
            dismissed = coll.unlock()  # secretstorage: True means the prompt was dismissed
        except Exception as e:  # noqa: BLE001
            raise KeyringUnavailable(f"could not unlock the keyring ({e})") from e
        if dismissed:
            raise KeyringLocked("the keyring is locked - unlock it (login keyring) and try again")
    return coll


def find(coll, attrs: dict):
    return list(coll.search_items(attrs))
