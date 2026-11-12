"""Anisette client - the "machine validation data" (X-Apple-I-MD / X-Apple-I-MD-M) GrandSlam needs.

This is the v1 flow: the server owns the device identity and answers `GET /`. Use it for a server
on this machine. For a remote server use `anisette_v3.AnisetteV3` (own identity, no sharing); the
`open_anisette()` factory there picks between them.

The identity this client reports (`client_info`, `user_agent`, `platform`) is what every Apple
service call claims. Apple rejects a claim that contradicts where the data came from."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import requests

from .. import config, const
from ..errors import AppleError

logger = logging.getLogger(__name__)


class AnisetteError(AppleError):
    pass


class Anisette:
    # Header keys an anisette server may return; we forward exactly these.
    _KEYS = (
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Apple-I-SRL-NO",
        "X-Mme-Device-Id",
        "X-Apple-I-Client-Time",
        "X-Apple-I-TimeZone",
        "X-Apple-Locale",
    )

    def __init__(self, url: str | None = None, *, timeout: int = 20):
        configured = config.anisette_url(url)
        if not configured:
            raise AnisetteError(
                "no anisette server URL configured; pass --anisette URL, set ICP_ANISETTE_URL or "
                "put anisette_url = \"...\" in ~/.config/icp/config.toml (see the README for "
                "which servers Apple accepts)")
        self.url = configured
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise AnisetteError(f"invalid anisette server URL: {self.url}")
        self.timeout = timeout
        self._reported: dict[str, str] | None = None
        if not config.is_loopback(self.url):
            logger.warning("anisette server %s is not on this machine; it sees your device "
                           "identity. Prefer a loopback-only local server.", self.url)

    # ---- identity ----------------------------------------------------------------------------
    def _identity(self) -> dict[str, str]:
        """What the server says its data was generated for (`/v3/client_info`)."""
        if self._reported is None:
            url = f"{self.url}/v3/client_info"
            try:
                r = requests.get(url, timeout=self.timeout)
                r.raise_for_status()
                data = r.json()
            except (requests.RequestException, ValueError) as e:
                raise AnisetteError(
                    f"could not fetch anisette client info from {url}: {e}") from e
            if not isinstance(data, dict) or any(
                    not isinstance(data.get(k), str) or not data[k]
                    for k in ("client_info", "user_agent")):
                raise AnisetteError(f"anisette server at {url} returned invalid client info")
            self._reported = {"client_info": data["client_info"],
                              "user_agent": data["user_agent"]}
        return self._reported

    @property
    def client_info(self) -> str:
        """The X-Mme-Client-Info claimed to Apple: the user's override, else Android for a
        loopback server (our Docker image runs Apple's Android libraries but reports a Mac),
        else whatever the server reports."""
        return config.client_info() or (
            const.ANDROID_CLIENT_INFO if config.is_loopback(self.url)
            else self._identity()["client_info"])

    @property
    def user_agent(self) -> str:
        return self._identity()["user_agent"]

    @property
    def platform(self) -> str:
        """The "<model> <os>" part of client_info; service identities are appended to it."""
        platform, marker, _ = self.client_info.partition(" <com.apple.")
        if not marker:
            raise AnisetteError("anisette client info has no service identity")
        return platform

    # ---- machine data ------------------------------------------------------------------------
    def headers(self) -> dict:
        try:
            resp = requests.get(self.url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            raise AnisetteError(
                f"Could not reach anisette server at {self.url}: {e}\n"
                "Start one bound to loopback (see `icp doctor`), or set ICP_ANISETTE_URL / "
                "anisette_url in ~/.config/icp/config.toml."
            ) from e

        if not isinstance(data, dict):
            raise AnisetteError(f"anisette server at {self.url} returned invalid JSON")
        out = {k: data[k] for k in self._KEYS if k in data}
        if any(not isinstance(v, str) or not v for v in out.values()):
            raise AnisetteError(f"anisette server at {self.url} returned invalid header values")
        if "X-Apple-I-MD" not in out or "X-Apple-I-MD-M" not in out:
            raise AnisetteError(
                f"Anisette server at {self.url} did not return machine data "
                "(X-Apple-I-MD / X-Apple-I-MD-M). Is it a real anisette server?"
            )
        return out
