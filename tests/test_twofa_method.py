"""Apple's `au: secondaryAuth` accepts either factor: we default to the code on trusted devices."""

import pytest

from icp.auth import grandslam


class FakeGSA:
    def __init__(self, au):
        self.au, self.calls, self.n = au, [], 0

    def authenticate(self, user, pw, label):
        self.n += 1
        status = {"au": self.au, "hsc": 409} if self.n == 1 else {}
        return {"Status": status}, {"adsid": "d", "GsIdmsToken": "t"}

    def trigger_trusted_factor(self, *a): self.calls.append("trigger-trusted")
    def submit_trusted_factor(self, code, *a): self.calls.append(f"submit-trusted-{code}")
    def trigger_sms_factor(self, *a): self.calls.append("trigger-sms")
    def submit_sms_factor(self, code, *a): self.calls.append(f"submit-sms-{code}")


@pytest.fixture(autouse=True)
def clean(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("ICP_2FA_METHOD", raising=False)


def run(au):
    gsa, asked = FakeGSA(au), []
    grandslam.authenticate(gsa, "u", "p", lambda kind: asked.append(kind) or "123456")
    return gsa.calls, asked


def test_secondary_auth_uses_trusted_device_by_default():
    calls, asked = run("secondaryAuth")
    assert calls == ["trigger-trusted", "submit-trusted-123456"] and asked == ["trusted"]


def test_sms_only_when_asked(monkeypatch):
    monkeypatch.setenv("ICP_2FA_METHOD", "sms")
    calls, asked = run("secondaryAuth")
    assert calls == ["trigger-sms", "submit-sms-123456"] and asked == ["sms"]


def test_trusted_device_mode_is_unchanged():
    calls, _ = run("trustedDeviceSecondaryAuth")
    assert calls == ["trigger-trusted", "submit-trusted-123456"]
