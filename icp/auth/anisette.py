"""Anisette client."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import requests

from ..errors import AppleError


class AnisetteError(AppleError):
    pass


class Anisette:
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
        configured = (url or os.environ.get("ICP_ANISETTE_URL") or "").strip().rstrip("/")
        if not configured:
            raise AnisetteError(
                "no anisette server URL configured; pass --anisette URL or set "
                "ICP_ANISETTE_URL"
            )
        parts = urlsplit(configured)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise AnisetteError(f"invalid anisette server URL: {configured}")
        self.url = configured
        self.timeout = timeout
        self._client_info: dict[str, str] | None = None

    def _url(self, path: str) -> str:
        """Build an endpoint URL, keeping the query string of the configured URL.

        Servers can be told which backend to use through a query parameter
        (for example ``?backend=macos``), so it has to survive the path.
        """
        base, _, query = self.url.partition("?")
        url = f"{base.rstrip('/')}{path}" if path else base
        return f"{url}?{query}" if query else url

    @property
    def client_info(self) -> str:
        return self._identity()["client_info"]

    @property
    def user_agent(self) -> str:
        return self._identity()["user_agent"]

    @property
    def platform(self) -> str:
        platform, marker, _ = self.client_info.partition(" <com.apple.")
        if not marker:
            raise AnisetteError("anisette client info has no service identity")
        return platform

    def _identity(self) -> dict[str, str]:
        if self._client_info is not None:
            return self._client_info
        url = self._url("/v3/client_info")
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            raise AnisetteError(f"could not fetch anisette client info from {url}: {e}") from e
        if not isinstance(data, dict) or any(
            not isinstance(data.get(key), str) or not data[key]
            for key in ("client_info", "user_agent")
        ):
            raise AnisetteError(f"anisette server at {url} returned invalid client info")
        self._client_info = {
            "client_info": data["client_info"],
            "user_agent": data["user_agent"],
        }
        return self._client_info

    def headers(self) -> dict:
        url = self._url("")
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            raise AnisetteError(f"could not fetch anisette data from {self.url}: {e}") from e

        if not isinstance(data, dict):
            raise AnisetteError(f"anisette server at {self.url} returned invalid JSON")
        headers = {key: data[key] for key in self._KEYS if key in data}
        if any(not isinstance(value, str) or not value for value in headers.values()):
            raise AnisetteError(f"anisette server at {self.url} returned invalid header values")
        if "X-Apple-I-MD" not in headers or "X-Apple-I-MD-M" not in headers:
            raise AnisetteError(
                f"anisette server at {self.url} did not return X-Apple-I-MD / X-Apple-I-MD-M"
            )
        return headers
