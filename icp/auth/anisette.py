"""Anisette client - fetches the "machine validation data" (X-Apple-I-MD / X-Apple-I-MD-M) that
GrandSlam auth requires from an external anisette server run locally."""

import logging

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

    def __init__(self, url: str | None = None):
        self.url = config.anisette_url(url)
        # Identity (X-MMe-Client-Info) of the machine that generated the anisette data. Apple
        # rejects data whose claimed client does not match its source, so GSA must send this one.
        self.client_info: str | None = None
        self.user_agent: str | None = None   # the matching GrandSlam User-Agent, if reported
        if not config.is_loopback(self.url):
            logger.warning("anisette server %s is not on this machine; it sees your device "
                           "identity. Prefer a loopback-only local server.", self.url)

    def headers(self) -> dict:
        try:
            resp = requests.get(self.url, timeout=5)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            raise AnisetteError(
                f"Could not reach anisette server at {self.url}: {e}\n"
                "Start one bound to loopback (see `icp doctor`), or set ICP_ANISETTE_URL / "
                "anisette_url in ~/.config/icp/config.toml."
            ) from e

        reported = data.get("X-MMe-Client-Info") or data.get("X-Mme-Client-Info")
        self.client_info = reported
        self._fetch_user_agent()
        # A loopback server is our dadoum container (Android libraries) which reports a Mac.
        self.client_info = config.client_info() or (
            const.ANDROID_CLIENT_INFO if config.is_loopback(self.url) else self.client_info)
        out = {k: data[k] for k in self._KEYS if k in data}
        if "X-Apple-I-MD" not in out or "X-Apple-I-MD-M" not in out:
            raise AnisetteError(
                f"Anisette server at {self.url} did not return machine data "
                "(X-Apple-I-MD / X-Apple-I-MD-M). Is it a real anisette server?"
            )
        return out

    def _fetch_user_agent(self) -> None:
        """v3 servers publish the client_info + user_agent pair their data was generated for."""
        try:
            info = requests.get(self.url.rstrip("/") + "/v3/client_info", timeout=5).json()
            self.user_agent = info.get("user_agent") or self.user_agent
            self.client_info = info.get("client_info") or self.client_info
        except (requests.RequestException, ValueError, AttributeError):
            pass  # optional endpoint: keep what the plain reply gave us
