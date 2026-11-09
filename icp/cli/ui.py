"""Terminal output and prompt helpers. Normal output goes to stdout; progress/warnings/errors
go to stderr so `icp ... > file` captures only the result."""
import getpass
import sys


def out(msg: str = "") -> None:
    print(msg)


def step(msg: str) -> None:
    print(msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


last_error: str | None = None  # most recent err() text, read by `icp sync` for its status file


def err(msg: str) -> None:
    global last_error
    last_error = msg
    print(f"error: {msg}", file=sys.stderr)


def ask(msg: str) -> str:
    return input(msg).strip()


def secret(msg: str) -> str:
    return getpass.getpass(msg)


def confirm_yn(msg: str) -> bool:
    """Yes/No prompt that defaults to No (empty or anything but y/yes)."""
    return input(msg).strip().lower() in ("y", "yes")
