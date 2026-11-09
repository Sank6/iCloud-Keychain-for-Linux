"""Terminal output and prompt helpers. Normal output goes to stdout; progress/warnings/errors
go to stderr so `icp ... > file` captures only the result.

Every function here can be swapped for the duration of a block with `patched(...)`; the GTK sign-in
window uses that to turn the same flow into dialogs."""
import contextlib
import getpass
import sys


class Cancelled(Exception):
    """The user backed out of a prompt (cancelled a dialog, closed the window)."""


def out(msg: str = "") -> None:
    print(msg)


def step(msg: str) -> None:
    print(msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


last_error: str | None = None  # most recent err() text, read by `icp sync` for its status file
last_kind: str = ""            # its machine-readable kind ("credentials", "blocked", ...)


def err(msg: str, kind: str = "") -> None:
    global last_error, last_kind
    last_error, last_kind = msg, kind
    print(f"error: {msg}", file=sys.stderr)


def ask(msg: str) -> str:
    return input(msg).strip()


def secret(msg: str) -> str:
    return getpass.getpass(msg)


def confirm_yn(msg: str) -> bool:
    """Yes/No prompt that defaults to No (empty or anything but y/yes)."""
    return input(msg).strip().lower() in ("y", "yes")


def interactive() -> bool:
    """Can we ask the user things? (a terminal, or a GUI that patched this to True)"""
    return sys.stdin.isatty()


@contextlib.contextmanager
def patched(**replacements):
    """Temporarily replace functions in this module (restored even on error)."""
    g = globals()
    old = {k: g[k] for k in replacements}
    g.update(replacements)
    try:
        yield
    finally:
        g.update(old)
