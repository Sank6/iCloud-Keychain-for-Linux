"""The sign-in flow without any toolkit: run `cmd_login` on a worker thread with the terminal
prompts swapped for callbacks, support cancelling, and turn the outcome into something a window can
show. `login.py` is the GTK front end; everything testable lives here (no `gi` import)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from ..cli import ui

MAX_PASSWORD_TRIES = 2   # then warn: Apple locks accounts after repeated bad passwords


@dataclass
class Outcome:
    ok: bool
    cancelled: bool = False
    title: str = ""
    detail: str = ""
    retry: bool = True          # offering "Try again" makes sense
    credentials_wrong: bool = False


def describe(rc: int, error: str | None, kind: str) -> Outcome:
    """Map the CLI result to window text. `kind` comes from the failing layer (icp.ui.last_kind)."""
    if rc == 0:
        return Outcome(True, title="Signed in", detail="You can close this window.", retry=False)
    if kind == "credentials":
        return Outcome(False, title="Wrong Apple ID or password",
                       detail="Check them and try again. Apple locks an account after repeated "
                              "wrong passwords.", credentials_wrong=True)
    if kind == "blocked":
        return Outcome(False, title="Apple is refusing the request",
                       detail=(error or "") + "\n\nWait a while before trying again; repeating "
                       "can extend the block.", retry=True)
    if kind in ("network", "circuit"):
        return Outcome(False, title="Can't reach Apple", detail=error or "Check your connection.")
    if kind == "code":
        return Outcome(False, title="Verification code not accepted",
                       detail="Start again to get a new code.")
    return Outcome(False, title="Sign-in did not finish",
                   detail=error or "See the messages below, then try again.")


class LoginFlow:
    """One sign-in attempt. Callbacks run on the worker thread; the front end must marshal them
    onto its own thread. `ask_text/ask_secret` return a string or raise `ui.Cancelled`;
    `ask_confirm` returns bool."""

    def __init__(self, args, *, progress: Callable[[str], None],
                 ask_text: Callable[[str], str], ask_secret: Callable[[str], str],
                 ask_confirm: Callable[[str], bool], done: Callable[[Outcome], None],
                 run_login: Callable | None = None):
        self.args = args
        self.progress, self.ask_text, self.ask_secret = progress, ask_text, ask_secret
        self.ask_confirm, self.done = ask_confirm, done
        self._run_login = run_login
        self.cancelled = threading.Event()
        self._password_given = False
        self.password: str | None = None   # first "Password:" prompt is answered from the form

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._work, daemon=True)
        t.start()
        return t

    def cancel(self) -> None:
        self.cancelled.set()

    # ---- prompt plumbing ------------------------------------------------------------------
    def _guard(self, fn, msg):
        if self.cancelled.is_set():
            raise ui.Cancelled()
        return fn(msg)

    def _secret(self, msg: str) -> str:
        if not self._password_given and msg.lower().startswith("password") and self.password:
            self._password_given = True
            return self.password
        return self._guard(self.ask_secret, msg)

    def _work(self) -> None:
        from ..cli.app import cmd_login
        run = self._run_login or cmd_login
        ui.last_error, ui.last_kind = None, ""
        patches = dict(
            out=lambda m="": self.progress(m),
            step=lambda m: self.progress(m),
            warn=lambda m: self.progress(f"warning: {m}"),
            err=self._err,
            ask=lambda m: self._guard(self.ask_text, m),
            secret=self._secret,
            confirm_yn=lambda m: self._guard(self.ask_confirm, m),
            interactive=lambda: True,
        )
        try:
            with ui.patched(**patches):
                rc = run(self.args)
            outcome = describe(rc, ui.last_error, ui.last_kind)
        except ui.Cancelled:
            outcome = Outcome(False, cancelled=True, title="Cancelled",
                              detail="Nothing was changed on your account.")
        except Exception as e:  # noqa: BLE001 - shown in the window, never swallowed silently
            outcome = Outcome(False, title="Sign-in did not finish",
                              detail=f"{type(e).__name__}: {e}")
        finally:
            self.password = None   # don't keep the typed password around
        self.done(outcome)

    def _err(self, msg: str, kind: str = "") -> None:
        ui.last_error, ui.last_kind = msg, kind
        self.progress(f"error: {msg}")
