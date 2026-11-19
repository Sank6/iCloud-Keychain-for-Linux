"""Toolkit-free GUI logic: search/sort, sync & sign-in state, and the login flow controller
(dialog answers faked; cmd_login replaced). No display needed."""
import threading
import unittest

from icp.cli import ui
from icp.gui import loginflow, model
from icp.vault.host import Credential


def c(domain, user="", title=""):
    return Credential(domain=domain, username=user, password="pw", title=title)


class SearchTests(unittest.TestCase):
    creds = [c("github.com", "Me@x.com", "GitHub"), c("apple.com", "tim", "Apple"),
             c("gitlab.com", "me", "")]

    def test_words_anded_case_insensitive_fields_only(self):
        ids = lambda q: [x.domain for x in model.visible(self.creds, q)]  # noqa: E731
        self.assertEqual(ids(""), ["apple.com", "github.com", "gitlab.com"])   # sorted by title
        self.assertEqual(ids("GIT"), ["github.com", "gitlab.com"])
        self.assertEqual(ids("git me"), ["github.com", "gitlab.com"])
        self.assertEqual(ids("hub me@"), ["github.com"])
        self.assertEqual(ids("pw"), [])        # passwords are never searched
        self.assertEqual(ids("nothing"), [])


class SyncStateTests(unittest.TestCase):
    NOW = 1_000_000.0

    def st(self, status, signed_in=True):
        return model.sync_state(status, 12, signed_in=signed_in, now=self.NOW)

    def test_needs_sign_in_has_login_action(self):
        s = self.st({"needs_login": True, "last_error": "iCloud login needed"})
        self.assertEqual((s.kind, s.action), ("signin", "login"))
        self.assertIn("iCloud login needed", s.banner)
        self.assertEqual(self.st({}, signed_in=False).action, "login")

    def test_failing_stale_ok_never(self):
        self.assertEqual(self.st({"failures": 2, "hint": "wait"}).kind, "failing")
        self.assertEqual(self.st({"last_success": self.NOW - 5 * 86400}).kind, "stale")
        ok = self.st({"last_success": self.NOW - 7200})
        self.assertEqual((ok.kind, ok.banner), ("ok", ""))
        self.assertIn("2 hours ago", ok.text)
        self.assertEqual(self.st({}).kind, "never")

    def test_ago(self):
        self.assertEqual(model.ago(0, 30), "just now")
        self.assertEqual(model.ago(0, 60), "1 minute ago")
        self.assertEqual(model.ago(0, 86400 * 3), "3 days ago")


class OutcomeTests(unittest.TestCase):
    def test_describe(self):
        self.assertTrue(loginflow.describe(0, None, "").ok)
        self.assertTrue(loginflow.describe(1, "x", "credentials").credentials_wrong)
        self.assertIn("refusing", loginflow.describe(1, "403", "blocked").title)
        self.assertIn("reach", loginflow.describe(1, "x", "network").title)
        self.assertIn("did not finish", loginflow.describe(1, None, "").title)


class FlowTests(unittest.TestCase):
    def run_flow(self, login, **answers):
        done, lines = threading.Event(), []
        box = {}
        flow = loginflow.LoginFlow(
            object(), progress=lines.append,
            ask_text=answers.get("text", lambda m: "123456"),
            ask_secret=answers.get("secret", lambda m: "passcode"),
            ask_confirm=answers.get("confirm", lambda m: True),
            done=lambda o: (box.update(o=o), done.set()), run_login=login)
        flow.password = "form-password"
        self.flow = flow
        flow.start()
        self.assertTrue(done.wait(5))
        return box["o"], lines, flow

    def test_success_uses_form_password_once_then_prompts(self):
        seen = []

        def login(args):
            seen.append(ui.secret("Password: "))       # answered from the form, no dialog
            seen.append(ui.ask("6-digit code: "))      # asked in a dialog
            seen.append(ui.secret("Password: "))       # a second one is a real prompt
            ui.out("Signed in as x")
            return 0
        o, lines, flow = self.run_flow(login)
        self.assertEqual(seen, ["form-password", "123456", "passcode"])
        self.assertTrue(o.ok)
        self.assertIsNone(flow.password)               # not kept around
        self.assertIn("Signed in as x", lines)

    def test_cancelled_prompt_aborts_without_submitting(self):
        submitted = []

        def cancel(_m):
            raise ui.Cancelled()

        def login(args):
            code = ui.ask("6-digit code: ")
            submitted.append(code)
            return 0
        o, _, _ = self.run_flow(login, text=cancel)
        self.assertTrue(o.cancelled)
        self.assertEqual(submitted, [])                # an empty code is never sent to Apple

    def test_wrong_password_reports_kind_and_allows_retry(self):
        def login(args):
            ui.err("sign-in failed: Apple says the Apple ID or password is incorrect",
                   kind="credentials")
            return 1
        o, lines, _ = self.run_flow(login)
        self.assertTrue(o.credentials_wrong)
        self.assertTrue(o.retry)
        self.assertTrue(any(l.startswith("error:") for l in lines))

    def test_cancel_flag_stops_the_next_prompt(self):
        def login(args):
            self.flow.cancel()
            ui.ask("6-digit code: ")
            return 0
        o, _, flow = self.run_flow(login)
        self.assertTrue(o.cancelled)

    def test_exception_is_shown_not_swallowed(self):
        def login(args):
            raise RuntimeError("boom")
        o, _, _ = self.run_flow(login)
        self.assertFalse(o.ok)
        self.assertIn("boom", o.detail)

    def test_ui_functions_are_restored_afterwards(self):
        original = ui.ask
        self.run_flow(lambda a: 0)
        self.assertIs(ui.ask, original)


if __name__ == "__main__":
    unittest.main()
