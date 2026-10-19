"""High-level authentication flow: SRP login + 2FA + PET extraction."""

import logging
from typing import Callable

from .gsa import GSAClient, GSAError

logger = logging.getLogger(__name__)

# Called with the factor kind ("trusted" | "sms"); must return the 6-digit code.
TwoFactorCallback = Callable[[str], str]


class TwoFactorUnavailable(GSAError):
    """2FA is required but nobody can type a code (unattended run) - nothing was triggered."""


def authenticate(gsa: GSAClient, username: str, password: str,
                 twofa: TwoFactorCallback, *, interactive: bool = True) -> dict:
    """Return the decrypted server provisioning data (spd), handling 2FA transparently.
    `interactive=False`: if Apple wants 2FA, stop BEFORE triggering a push/SMS - otherwise an
    unattended sync would buzz the user's phone and then fail anyway."""
    r, spd = gsa.authenticate(username, password, "sign-in")
    status = r.get("Status", {})
    au = status.get("au")

    if au in ("trustedDeviceSecondaryAuth", "secondaryAuth") and not interactive:
        raise TwoFactorUnavailable("Apple wants a 2FA code - run `icp login` interactively")
    if au in ("trustedDeviceSecondaryAuth", "secondaryAuth"):
        dsid = spd.get("adsid") or spd.get("DsPrsId")
        idms = spd.get("GsIdmsToken") or spd.get("GsIdMS")
        if not dsid or not idms:
            raise GSAError(f"2FA required but missing dsid/GsIdMS in spd: keys={list(spd)}")

        if au == "trustedDeviceSecondaryAuth":
            gsa.trigger_trusted_factor(dsid, idms)
            gsa.submit_trusted_factor(twofa("trusted"), dsid, idms)
        else:
            gsa.trigger_sms_factor(dsid, idms)
            gsa.submit_sms_factor(twofa("sms"), dsid, idms)

        # Re-authenticate: the device is now trusted, so this should NOT prompt again.
        r, spd = gsa.authenticate(
            username, password, "re-auth after 2FA (password already verified)")
        if r.get("Status", {}).get("au"):
            raise GSAError("still being asked for 2FA after submitting a code")

    return spd


def extract_pet(spd: dict) -> tuple[str, str, int | None]:
    """Return (dsid, pet, expiry_ms) from spd. The PET is a password-equivalent token."""
    dsid = spd.get("adsid") or spd.get("DsPrsId")
    tokens = spd.get("t", {})
    pet_entry = tokens.get("com.apple.gs.idms.pet", {})
    pet = pet_entry.get("token")
    if not dsid or not pet:
        raise GSAError(f"no PET in spd (keys={list(spd)}, token keys={list(tokens)})")
    return dsid, pet, pet_entry.get("expiry")
