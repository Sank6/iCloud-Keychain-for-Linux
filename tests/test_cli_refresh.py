"""Silent token auto-refresh in the sync path (icp.cli.app._ensure_fresh_tokens)."""

import pytest

from icp.auth.gsa import GSAError
from icp.auth.icloud import ICloudAuthExpired
from icp.cli import app


def test_fresh_token_no_reauth(monkeypatch):
    """If the mmeAuthToken is still valid, refresh succeeds and we never re-authenticate."""
    calls = []
    monkeypatch.setattr(app, "_refresh_webservices", lambda *a, **k: calls.append("refresh"))
    monkeypatch.setattr(app, "_mint_tokens",
                        lambda *a, **k: pytest.fail("must not re-auth when token is valid"))
    app._ensure_fresh_tokens({"username": "u", "password": "p"}, None, None, interactive=False)
    assert calls == ["refresh"]


def test_expired_token_reauths_with_saved_password(monkeypatch):
    """An expired mmeAuthToken triggers a silent re-auth with the stored password, then retry."""
    seq = []

    def fake_refresh(s, *a, **k):
        seq.append("refresh")
        if seq.count("refresh") == 1:      # first attempt: token expired
            raise ICloudAuthExpired("iCloud credentials expired")
        # second attempt (after re-auth) succeeds

    def fake_mint(record, username, password, *a, **k):
        seq.append(f"mint:{username}:{password}")

    monkeypatch.setattr(app, "_refresh_webservices", fake_refresh)
    monkeypatch.setattr(app, "_mint_tokens", fake_mint)

    app._ensure_fresh_tokens({"username": "alice", "password": "secret"}, None, None,
                             interactive=True)
    assert seq == ["refresh", "mint:alice:secret", "refresh"]


def test_expired_token_without_saved_password_raises(monkeypatch):
    """No stored password -> surface the expiry so the user runs `icp login`."""
    monkeypatch.setattr(app, "_refresh_webservices",
                        lambda *a, **k: (_ for _ in ()).throw(ICloudAuthExpired("expired")))
    monkeypatch.setattr(app, "_mint_tokens",
                        lambda *a, **k: pytest.fail("cannot re-auth without a password"))
    with pytest.raises(ICloudAuthExpired):
        app._ensure_fresh_tokens({"username": "u"}, None, None, interactive=False)


def test_noninteractive_2fa_fails_cleanly():
    """The unattended 2FA callback raises instead of blocking on stdin."""
    with pytest.raises(GSAError):
        app._noninteractive_twofa("trusted")
