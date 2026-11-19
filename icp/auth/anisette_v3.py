"""Anisette v3 client: our own device identity, provisioned from this machine.

A shared anisette server (v1: "GET /") hands every user the same device identity, and Apple blocks
such identities (mac-ani.jkcoxson.com, 2026-11-05). In v3 the server only runs Apple's ADI code;
*we* generate a random identifier, call Apple's provisioning endpoints ourselves, and keep the
resulting `adi_pb` blob. The server never sees anything but that blob and the identifier.

Protocol (same as SideStore's omnisette / Dadoum's anisette-v3-server):
  GET  /v3/client_info                         -> {client_info, user_agent}
  WS   /v3/provisioning_session                -> GiveIdentifier / GiveStartProvisioningData /
                                                   GiveEndProvisioningData / ProvisioningSuccess
  POST /v3/get_headers {identifier, adi_pb}    -> {result: Headers, X-Apple-I-MD, -MD-M, -MD-RINFO}
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import plistlib
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .. import config, const, jsonfile, net, paths
from . import apple_tls
from .anisette import (MAX_REPLY, Anisette, AnisetteError, header_value, read_json)

logger = logging.getLogger(__name__)

LOOKUP_URL = "https://gsa.apple.com/grandslam/GsService2/lookup"
NOT_PROVISIONED = "-45061"          # get_headers error meaning "adi_pb is not valid any more"
CONTENT_TYPE = "text/xml"           # see const.GSA_CONTENT_TYPE: Apple's firewall rejects others
TIMEOUT = 20


def state_file():
    return paths.config_dir() / "anisette-v3.json"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class _State:
    """identifier (16 random bytes, ours alone) + the adi_pb the server's ADI produced for it."""

    def __init__(self, identifier: bytes, adi_pb: bytes | None, server: str, claim: str = ""):
        # `claim` is the client identity Apple was told at provisioning; a different claim means
        # a new provisioning (Apple ties the registration to what the device said it was).
        self.identifier, self.adi_pb, self.server, self.claim = identifier, adi_pb, server, claim

    @classmethod
    def load(cls, server: str) -> "_State":
        d = jsonfile.read_object(state_file())
        try:
            ident = base64.b64decode(d["identifier"], validate=True)
            adi = base64.b64decode(d["adi_pb"], validate=True) if d.get("adi_pb") else None
        except (KeyError, TypeError, ValueError):
            return cls(os.urandom(16), None, server)       # nothing usable saved: a new identity
        if len(ident) != 16:
            return cls(os.urandom(16), None, server)
        claim = d.get("claim")
        # adi_pb belongs to the server (and claimed identity) that generated it
        return cls(ident, adi if d.get("server") == server else None, server,
                   claim if isinstance(claim, str) else "")

    def save(self) -> None:
        f = state_file()
        tmp = f.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"identifier": _b64(self.identifier),
                       "adi_pb": _b64(self.adi_pb) if self.adi_pb else None,
                       "server": self.server, "claim": self.claim}, fh)
        os.replace(tmp, f)

    @property
    def device_id(self) -> str:
        return str(uuid.UUID(bytes=self.identifier)).upper()

    @property
    def local_user(self) -> str:
        return hashlib.sha256(self.identifier).hexdigest().upper()


def _apple_url(url) -> str:
    """Provisioning endpoints come from Apple's lookup reply; we send our identity headers to
    them, so they must be https and on apple.com."""
    host = urlparse(url).hostname if isinstance(url, str) else None
    if not url.startswith("https://") or not host or not (
            host == "apple.com" or host.endswith(".apple.com")):
        raise AnisetteError("Apple's provisioning reply pointed at an unexpected address")
    return url


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AnisetteV3(Anisette):
    def __init__(self, url: str | None = None):
        super().__init__(url)
        self.state = _State.load(self.url)

    # ---- identity ----------------------------------------------------------------------------
    @property
    def client_info(self) -> str:
        """Real-Mac v3 servers report a 2016 MacBook on macOS 10.12.6, which Apple refuses for
        Advanced Data Protection accounts; claim a recent Mac instead (const.MAC_CLIENT_INFO)."""
        return config.client_info() or const.MAC_CLIENT_INFO

    def _identity(self) -> dict[str, str]:
        if self._reported is None:
            try:
                r = requests.get(self.url + "/v3/client_info", timeout=TIMEOUT, stream=True)
                r.raise_for_status()
                info = read_json(r, "client info")
                if not isinstance(info, dict):
                    raise AnisetteError("client info is not an object")
                self._reported = {k: header_value(info.get(k), "client info", 512)
                                  for k in ("client_info", "user_agent")}
            except requests.RequestException as e:
                raise AnisetteError(f"{self.url} is not an anisette v3 server ({e})") from e
        return self._reported

    # ---- provisioning ------------------------------------------------------------------------
    def _apple_headers(self) -> dict:
        return {
            "X-Mme-Client-Info": self.client_info, "User-Agent": self.user_agent,
            "Content-Type": CONTENT_TYPE,
            "X-Apple-I-MD-LU": self.state.local_user, "X-Mme-Device-Id": self.state.device_id,
            "X-Apple-I-Client-Time": _now(), "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
        }

    def _apple(self, what: str, method: str, url: str, body: dict | None = None) -> dict:
        kw = {"data": plistlib.dumps(body)} if body is not None else {}
        resp = net.request(method, url, headers=self._apple_headers(),
                           session=apple_tls.session(), **kw)
        if (ne := net.auth_error(resp, what)):
            raise AnisetteError(str(ne))
        if not resp.ok:
            raise AnisetteError(f"{what}: Apple answered HTTP {resp.status_code}")
        try:
            return plistlib.loads(resp.content)
        except Exception:
            raise AnisetteError(f"{what}: Apple's reply was not a property list") from None

    def provision(self, connect=None) -> None:
        """Register this identity with Apple through the server's ADI. `connect` is for tests.
        Everything that comes back is untrusted input: a malformed or hostile reply from the
        server or from the network ends in an AnisetteError, never a crash."""
        try:
            self._provision(connect)
        except AnisetteError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise AnisetteError(f"unexpected reply while provisioning ({type(e).__name__})") from None
        except (OSError, TimeoutError) as e:
            raise AnisetteError(f"could not reach the provisioning server: {e}") from e

    def _provision(self, connect) -> None:
        if connect is None:
            from websockets.exceptions import WebSocketException
            from websockets.sync.client import connect
        else:
            WebSocketException = OSError
        ws_url = self.url.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
        urls = self._apple("provisioning lookup", "get", LOOKUP_URL)["urls"]
        start = _apple_url(urls["midStartProvisioning"])
        finish = _apple_url(urls["midFinishProvisioning"])
        logger.info("provisioning a new anisette identity with %s", self.url)
        try:
            with connect(ws_url + "/v3/provisioning_session", open_timeout=TIMEOUT) as ws:
                while True:
                    msg = json.loads(ws.recv(timeout=60))
                    if not isinstance(msg, dict):
                        raise AnisetteError("the provisioning server sent a malformed message")
                    result = msg.get("result")
                    if result == "GiveIdentifier":
                        ws.send(json.dumps({"identifier": _b64(self.state.identifier)}))
                    elif result == "GiveStartProvisioningData":
                        r = self._apple("start provisioning", "post", start,
                                        {"Header": {}, "Request": {}})
                        ws.send(json.dumps({"spim": r["Response"]["spim"]}))
                    elif result == "GiveEndProvisioningData":
                        r = self._apple("finish provisioning", "post", finish,
                                        {"Header": {}, "Request": {"cpim": msg["cpim"]}})
                        ws.send(json.dumps({"ptm": r["Response"]["ptm"],
                                            "tk": r["Response"]["tk"]}))
                    elif result == "ProvisioningSuccess":
                        blob = base64.b64decode(msg["adi_pb"], validate=True)
                        if not blob or len(blob) > MAX_REPLY:
                            raise AnisetteError("the provisioning server returned an invalid blob")
                        self.state.adi_pb = blob
                        self.state.claim = self.client_info
                        self.state.save()
                        return
                    else:
                        raise AnisetteError(
                            f"anisette provisioning failed at {self.url}: "
                            f"{str(msg.get('message') or result)[:200]}")
        except WebSocketException as e:
            raise AnisetteError(f"provisioning connection to {self.url} failed: {e}") from e

    # ---- headers -----------------------------------------------------------------------------
    def headers(self) -> dict:
        self._identity()                       # fail early if this is not a v3 server
        if self.state.claim != self.client_info:
            self.state.adi_pb = None          # registered under another identity: redo it
        for attempt in (0, 1):
            if not self.state.adi_pb:
                self.provision()
            try:
                r = requests.post(self.url + "/v3/get_headers", timeout=TIMEOUT, stream=True, json={
                    "identifier": _b64(self.state.identifier),
                    "adi_pb": _b64(self.state.adi_pb)})
                data = read_json(r, "headers")
            except requests.RequestException as e:
                raise AnisetteError(f"Could not reach anisette server at {self.url}: {e}") from e
            if not isinstance(data, dict):
                raise AnisetteError(f"anisette server {self.url} returned invalid headers")
            if data.get("result") == "Headers":
                break
            if NOT_PROVISIONED in str(data.get("message", "")) and attempt == 0:
                self.state.adi_pb = None           # ADI forgot us: provision again, once
                continue
            raise AnisetteError(f"anisette server {self.url}: "
                                f"{str(data.get('message') or data.get('result'))[:200]}")
        return {
            "X-Apple-I-MD": header_value(data.get("X-Apple-I-MD"), "X-Apple-I-MD"),
            "X-Apple-I-MD-M": header_value(data.get("X-Apple-I-MD-M"), "X-Apple-I-MD-M"),
            "X-Apple-I-MD-RINFO": header_value(data.get("X-Apple-I-MD-RINFO"), "X-Apple-I-MD-RINFO",
                                         allow_int=True),
            "X-Apple-I-MD-LU": self.state.local_user,
            "X-Apple-I-SRL-NO": "0",
            "X-Mme-Device-Id": self.state.device_id,
            "X-Apple-I-Client-Time": _now(),
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
        }


def open_anisette(url: str | None = None, protocol: str | None = None) -> Anisette:
    """v1 for a loopback server (it holds its own identity), v3 for anything else, unless the
    `anisette_protocol` setting (env ICP_ANISETTE_PROTOCOL) says otherwise."""
    proto = config.get("anisette_protocol", env="ICP_ANISETTE_PROTOCOL", explicit=protocol,
                       default="auto")
    if proto == "auto":
        configured = config.anisette_url(url)
        if not configured:
            return Anisette(url)               # raises the "no server configured" error
        proto = "v1" if config.is_loopback(configured) else "v3"
    return AnisetteV3(url) if proto == "v3" else Anisette(url)
