"""Public Suffix List lookups, so `co.uk`, `github.io` and similar shared suffixes are never
treated as one site. Data: icp/data/public_suffix_list.dat (Mozilla Public Suffix List, MPL-2.0,
https://publicsuffix.org). Private-section rules are included on purpose: `a.github.io` and
`b.github.io` are different sites for password purposes."""

from __future__ import annotations

import functools
import re
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "public_suffix_list.dat"
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|:")


@functools.lru_cache(maxsize=1)
def _rules() -> tuple[frozenset, frozenset, frozenset]:
    plain, wild, exc = set(), set(), set()
    try:
        lines = _DATA.read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset(), frozenset(), frozenset()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exc.add(line[1:])
        elif line.startswith("*."):
            wild.add(line[2:])
        else:
            plain.add(line)
    return frozenset(plain), frozenset(wild), frozenset(exc)


def is_ip(host: str) -> bool:
    return bool(_IP.search(host))


def suffix_len(host: str) -> int:
    """Number of labels in the host's public suffix (1 when the list is unavailable)."""
    plain, wild, exc = _rules()
    labels = host.lower().strip(".").split(".")
    best = 1
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        n = len(labels) - i
        if cand in exc:
            return n - 1
        if cand in plain:
            best = max(best, n)
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wild:
            best = max(best, n)
    return best


def is_public_suffix(host: str) -> bool:
    host = host.lower().strip(".")
    return bool(host) and not is_ip(host) and suffix_len(host) >= len(host.split("."))


def registrable_domain(host: str) -> str:
    """`login.example.co.uk` -> `example.co.uk`; the host itself if it is a suffix/IP/single label."""
    host = host.lower().strip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    n = suffix_len(host)
    return host if n >= len(labels) else ".".join(labels[-(n + 1):])
