"""The escrow step reuses the PET of the sign-in (icp.cli.app._mint_pet).

Every extra SRP exchange is another chance for Apple to rate-limit the account, and the
PET of the sign-in is still valid for about five minutes - long enough for the escrow step.
"""

import time

from icp.cli import app


def _record(expiry_ms):
    return {"pet": "a-pet", "pet_expiry": expiry_ms}


def test_valid_pet_is_reused(monkeypatch):
    record = _record(int(time.time() * 1000) + 5 * 60 * 1000)
    assert app._pet_is_usable(record) is True


def test_expired_pet_is_not_reused():
    assert app._pet_is_usable(_record(int(time.time() * 1000) - 1000)) is False


def test_pet_expiring_soon_is_not_reused():
    expiry = int(time.time() * 1000) + app.PET_MARGIN_MS - 1000
    assert app._pet_is_usable(_record(expiry)) is False


def test_expiry_in_seconds_is_understood():
    expiry = int(time.time()) + 5 * 60
    assert app._pet_is_usable(_record(expiry)) is True


def test_missing_pet_is_not_reused():
    assert app._pet_is_usable({}) is False
    assert app._pet_is_usable(None) is False
    assert app._pet_is_usable({"pet": "p"}) is False
    assert app._pet_is_usable({"pet_expiry": 1}) is False


def test_mint_pet_does_not_authenticate_when_the_pet_is_valid(monkeypatch):
    """A usable PET means no SRP exchange at all."""

    def must_not_authenticate(*args, **kwargs):
        raise AssertionError("must not authenticate")

    monkeypatch.setattr(app.GSAClient, "__init__", must_not_authenticate)
    record = _record(int(time.time() * 1000) + 5 * 60 * 1000)

    assert app._mint_pet(None, None, "u", "p", record=record) == "a-pet"
