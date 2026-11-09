"""Anisette client - fetches the "machine validation data" (X-Apple-I-MD / X-Apple-I-MD-M) that
GrandSlam auth requires from an external anisette server run locally."""

import logging

import requests

from .. import config
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

        out = {k: data[k] for k in self._KEYS if k in data}
        if "X-Apple-I-MD" not in out or "X-Apple-I-MD-M" not in out:
            raise AnisetteError(
                f"Anisette server at {self.url} did not return machine data "
                "(X-Apple-I-MD / X-Apple-I-MD-M). Is it a real anisette server?"
            )
        return out
