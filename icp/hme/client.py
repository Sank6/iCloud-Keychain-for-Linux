"""Hide My Email (iCloud+ alias) client - a thin read-only JSON REST layer authed purely by
the web session's cookies. See RESEARCH.md "Hide My Email"."""

from __future__ import annotations

import dataclasses

import requests

from .. import net
from ..errors import AppleError


class HmeError(AppleError):
    pass


# Origin/Referer of the icloud.com page that normally makes this XHR call.
_HEADERS = {"Accept": "application/json", "Origin": "https://www.icloud.com",
           "Referer": "https://www.icloud.com/"}


def _error_detail(data: dict) -> str:
    """Apple's `error` field shape varies (dict, bare int, or absent); fall back to the raw body."""
    err = data.get("error")
    if isinstance(err, dict):
        return err.get("errorMessage") or err.get("message") or str(err)
    if err is not None:
        return str(err)
    return data.get("errorMessage") or data.get("message") or str(data)


@dataclasses.dataclass(frozen=True)
class HmeAlias:
    anonymous_id: str
    address: str
    label: str
    note: str
    forward_to: str
    is_active: bool
    domain: str
    created_at: float  # unix epoch seconds

    def public_dict(self) -> dict:
        return {"address": self.address, "label": self.label, "domain": self.domain}


class HmeClient:
    def __init__(self, base_url: str, http: requests.Session):
        self._v2 = base_url.rstrip("/") + "/v2"
        self.http = http

    def list(self) -> list[HmeAlias]:
        try:
            resp = net.request("get", f"{self._v2}/hme/list", session=self.http,
                               headers=_HEADERS, timeout=(5, 20))
        except net.AppleNetError as e:
            raise HmeError(str(e)) from e
        try:
            data = resp.json()
        except ValueError as e:
            raise HmeError(f"non-JSON response from hme/list (HTTP {resp.status_code})") from e
        if not resp.ok or not data.get("success"):
            raise HmeError(f"hme/list failed (HTTP {resp.status_code}): {_error_detail(data)}")
        result = data.get("result") or {}
        return [_parse(e) for e in result.get("hmeEmails", [])]


def _parse(e: dict) -> HmeAlias:
    return HmeAlias(
        anonymous_id=e.get("anonymousId", ""),
        address=e.get("hme", ""),
        label=e.get("label", ""),
        note=e.get("note", ""),
        forward_to=e.get("forwardToEmail", ""),
        is_active=bool(e.get("isActive")),
        domain=e.get("domain", ""),
        created_at=(e.get("createTimestamp") or 0) / 1000,
    )
