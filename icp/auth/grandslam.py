"""High-level authentication flow: SRP login + 2FA + PET extraction."""

from typing import Callable

from .gsa import GSAClient, GSAError

# Called with the factor kind ("trusted" | "sms"); must return the 6-digit code.
TwoFactorCallback = Callable[[str], str]


class TwoFactorUnavailable(GSAError):
    """2FA is required in an unattended run; no additional code was requested."""


def authenticate(gsa: GSAClient, username: str, password: str,
                 twofa: TwoFactorCallback, *, interactive: bool = True) -> dict:
    """Return the decrypted server provisioning data (spd), handling 2FA transparently.
    `interactive=False` stops before requesting or prompting for a code. Apple can
    send a trusted-device code during the SRP exchange itself."""
    r, spd = gsa.authenticate(username, password, "sign-in")
    status = r["Status"]
    au = status.get("au")
    # A 409 without an auth mode means Apple has already sent a trusted-device code.
    code_sent = status.get("hsc") == 409 and not au
    if not code_sent and au not in ("trustedDeviceSecondaryAuth", "secondaryAuth"):
        return spd

    if not interactive:
        raise TwoFactorUnavailable("Apple wants a 2FA code - run `icp login` interactively")

    dsid, idms = spd["adsid"], spd["GsIdmsToken"]
    if au == "secondaryAuth":
        gsa.trigger_sms_factor(dsid, idms)
        gsa.submit_sms_factor(twofa("sms"), dsid, idms)
    else:
        # Requesting another code would invalidate the one Apple already sent.
        if not code_sent:
            gsa.trigger_trusted_factor(dsid, idms)
        gsa.submit_trusted_factor(twofa("trusted"), dsid, idms)

    # Re-authenticate to obtain a PET for the now-trusted device.
    r, spd = gsa.authenticate(username, password, "re-auth after 2FA")
    status = r["Status"]
    if status.get("au") or status.get("hsc") == 409:
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
