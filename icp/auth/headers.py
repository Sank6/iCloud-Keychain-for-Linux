"""Merged device + anisette request headers, shared by every Apple call.

Device identity first, anisette machine-data second so anisette wins on the volatile
X-Apple-I-MD* fields - the order GSA, loginDelegates and account-settings all rely on.
"""
from __future__ import annotations

from .anisette import Anisette
from .device import Device


def identity_headers(device: Device, anisette: Anisette) -> dict:
    headers = dict(device.meta_headers())
    headers.update(anisette.headers())
    return headers


def service_client_info(anisette: Anisette, service_identity: str) -> str:
    return f"{anisette.platform} <{service_identity}>"
