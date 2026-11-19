"""Persistent local device identity - generated once, reused forever, so a stable
X-Mme-Device-Id lets Apple remember the 2FA approval and stop re-prompting. Anisette supplies
the volatile X-Apple-I-MD* machine data and may override these values."""

import base64
import json

import locale
import uuid
from datetime import datetime, timezone

from .. import paths
from .. import jsonfile
from ..errors import AppleError


class DeviceError(AppleError):
    """device.json exists but cannot be used."""


class Device:
    def __init__(self, device_id: str, serial: str, local_user_uuid: str):
        self.device_id = device_id
        self.serial = serial
        self.local_user_uuid = local_user_uuid

    @classmethod
    def load_or_create(cls) -> "Device":
        f = paths.device_file()
        if f.exists():
            data = jsonfile.read_object(f)
            try:
                values = [data[k] for k in ("device_id", "serial", "local_user_uuid")]
                if all(isinstance(v, str) and v for v in values):
                    return cls(*values)
            except KeyError:
                pass
            # Regenerating silently would make Apple see a new device and ask to trust it again.
            raise DeviceError(
                f"{f} is damaged. Move it aside (mv {f} {f}.bad) to create a new device "
                "identity; you will have to sign in and approve this device again.")
        dev = cls(
            device_id=str(uuid.uuid4()).upper(),
            # Mac-like 12-char serial; replaced by anisette's if it provides one.
            serial="C02" + uuid.uuid4().hex[:9].upper(),
            local_user_uuid=str(uuid.uuid4()).upper(),
        )
        dev.save()
        return dev

    def save(self) -> None:
        f = paths.device_file()
        f.write_text(
            json.dumps(
                {
                    "device_id": self.device_id,
                    "serial": self.serial,
                    "local_user_uuid": self.local_user_uuid,
                },
                indent=2,
            )
        )
        f.chmod(0o600)

    def meta_headers(self) -> dict:
        """Fallback identity headers; anisette values override the X-Apple-I-MD* ones."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        loc = (locale.getdefaultlocale()[0] or "en_US")
        return {
            "X-Apple-I-Client-Time": now.isoformat().replace("+00:00", "Z"),
            "X-Apple-I-TimeZone": "UTC",
            "loc": loc,
            "X-Apple-Locale": loc,
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(
                self.local_user_uuid.upper().encode()
            ).decode(),
            "X-Mme-Device-Id": self.device_id.upper(),
            "X-Apple-I-SRL-NO": self.serial,
        }
