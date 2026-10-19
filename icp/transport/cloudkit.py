"""CloudKit CKCode transport: carries each Cuttlefish RPC as a gzipped, length-delimited
function-invoke RequestOperation, authed with the cloudKitToken. See RESEARCH.md
"transport/cloudkit.py" for endpoint, container/bundle ids, headers, and the gzip gotcha."""

from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import os
import uuid as _uuid

import requests

from ..proto import codec as _proto
from ..proto.codec import Writer, decode_fields, first, first_str
from ..proto.cuttlefish import encode_function_invoke_request
from . import ckks
from ..errors import AppleError

# These requests carry the cloudKitToken; only set False for a debugging proxy.
VERIFY_TLS = True

CKCODE_INVOKE_URL = "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"
CKDATABASE_SYNC_URL = "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
CKDATABASE_ZONE_SYNC_URL = "https://gateway.icloud.com/ckdatabase/api/client/zone/sync"
CK_APP_INIT_URL = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"
CK_MME_CLIENT_INFO = ("<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
                      "<com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>")
CUTTLEFISH_CONTAINER = "com.apple.security.keychain"
CUTTLEFISH_BUNDLE = "com.apple.security.cuttlefish"   # CKCode (Cuttlefish) requests
SECURITYD_BUNDLE = "com.apple.securityd"              # CKKS record fetches
CUTTLEFISH_SERVICE = "Cuttlefish"

KCSHARING_CONTAINER = "com.apple.security.shared.keychain"
KCSHARING_BUNDLE = "com.apple.security.kcsharing"

ENV_PRODUCTION = 1
DB_PRIVATE = 1
DB_SHARED = 2
ISOLATION_ZONE = 1
IDENTIFIER_TYPE_DEVICE = 2
OP_TYPE_FUNCTION_INVOKE = 1101
OP_TYPE_ZONE_RETRIEVE_CHANGES = 203
FIELD_ZONE_RETRIEVE_CHANGES = 203
RESULT_SUCCESS = 1


def maybe_gunzip(payload: bytes) -> bytes:
    """Decompress if the body is gzip"""
    if payload[:2] == b"\x1f\x8b":
        return gzip.decompress(payload)
    return payload


def delimit(message: bytes) -> bytes:
    """CloudKit `delimited=true` framing: a uleb128 length prefix + the message."""
    return _proto.encode_varint(len(message)) + message


def undelimit(buf: bytes) -> list[bytes]:
    """Split a stream of length-delimited messages (the response body)."""
    out, pos, n = [], 0, len(buf)
    while pos < n:
        shift = val = 0
        while True:
            b = buf[pos]; pos += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        out.append(buf[pos:pos + val]); pos += val
    return out


def _identifier(name: str, type_: int) -> bytes:
    return Writer().string(1, name).uint64(2, type_).finish()


@dataclasses.dataclass
class DeviceConfig:
    """The device fields CloudKit's RequestOperation.Header wants."""
    device_uuid: str            # deviceIdentifier.name + deviceHardwareID (udid)
    serial: str                 # deviceSerial
    name: str = "Mac"           # deviceAssignedName
    software_version: str = "Mac OS X;13.4.1;22F8"
    hardware_version: str = "MacBookPro18,3"


def build_header(config: DeviceConfig, *, container: str = CUTTLEFISH_CONTAINER,
                 bundle: str = CUTTLEFISH_BUNDLE, env: int = ENV_PRODUCTION,
                 database: int = DB_PRIVATE, isolation: int = ISOLATION_ZONE) -> bytes:
    """RequestOperation.Header. userToken stays empty here - the cloudKitToken goes in the
    `x-cloudkit-authtoken` HTTP header, not this body field."""
    return (Writer()
            .string(2, container)
            .string(3, bundle)
            .message(7, _identifier(config.device_uuid, IDENTIFIER_TYPE_DEVICE))
            .string(8, config.software_version)
            .string(9, config.hardware_version)
            .string(10, "com.apple.cloudkit.CloudKitDaemon")
            .string(11, "1970")
            .string(18, "5.0")              # mmcsProtocolVersion
            .uint64(19, env)                # applicationContainerEnvironment
            .string(21, config.name)        # deviceAssignedName
            .string(22, config.device_uuid)  # deviceHardwareID
            .uint64(23, database)           # targetDatabase
            .uint64(25, isolation)          # isolationLevel
            .uint64(29, 0)                  # unk1
            .string(32, hashlib.sha1(config.device_uuid.encode()).hexdigest())  # unk2
            .string(33, config.serial)      # deviceSerial
            .uint64(34, 0)                  # unk3
            .uint64(35, 1)                  # unk4
            .finish())


def build_request_operation_generic(header: bytes, op_type: int, request_field: int,
                                    request_bytes: bytes, op_uuid: str | None = None) -> bytes:
    """The op-specific request rides in its own high field number (functionInvokeRequest=1101,
    retrieveChangesRequest=213, ...) and Operation.type names it."""
    op_uuid = op_uuid or str(_uuid.uuid4()).upper()
    operation = Writer().string(1, op_uuid).uint64(2, op_type).bool(4, True).finish()
    return (Writer().message(1, header).message(2, operation)
            .message(request_field, request_bytes).finish())


def _operation_id() -> str:
    return os.urandom(8).hex().upper()


def _container_headers(*, bundle: str, container: str, database_scope: str = "Private",
                       mme_client_info: str = CK_MME_CLIENT_INFO) -> dict:
    """Shared header block for ckAppInit and every CKCode/record op. Caller adds
    auth / userid / authtoken / routing-hint / anisette on top."""
    return {
        "accept": "application/x-protobuf",
        "accept-encoding": "gzip",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-transform",
        "content-encoding": "gzip",
        "content-type": ('application/x-protobuf; desc="https://gateway.icloud.com:443'
                         '/static/protobuf/CloudDB/CloudDBClient.desc"; '
                         'messageType=RequestOperation; delimited=true'),
        "user-agent": "CloudKit/1970 (19H384)",
        "x-apple-c2-metric-triggers": "0",
        "x-apple-operation-group-id": _operation_id(),
        "x-apple-operation-id": _operation_id(),
        "x-apple-request-uuid": str(_uuid.uuid4()).upper(),
        "x-cloudkit-bundleid": bundle,
        "x-cloudkit-containerid": container,
        "x-cloudkit-databasescope": database_scope,
        "x-cloudkit-duetpreclearedmode": "None",
        "x-cloudkit-environment": "Production",
        "x-mme-client-info": mme_client_info,
    }


def ck_app_init(container: str, bundle: str, dsid: str, mme_token: str, anisette,
                *, timeout: int = 30) -> str:
    """ckAppInit handshake -> the per-container `cloudKitUserId` CloudKit wants in
    `x-cloudkit-userid` (it is NOT the dsid). Authed with Basic(dsid, mmeAuthToken)."""
    headers = _container_headers(bundle=bundle, container=container)
    headers["Authorization"] = "Basic " + base64.b64encode(
        f"{dsid}:{mme_token}".encode()).decode()
    headers.update(anisette.headers())
    try:
        resp = requests.post(CK_APP_INIT_URL, params={"container": container}, headers=headers,
                             data="", verify=VERIFY_TLS, timeout=timeout)
    except requests.RequestException as e:
        raise CloudKitError(f"network error talking to ckAppInit: {e}") from e
    _raise_for_throttle(resp, "ckAppInit")
    if resp.status_code == 401:
        raise CloudKitError("ckAppInit rejected the mmeAuthToken (HTTP 401) - re-run "
                            "`icp login` to refresh it", http_status=401)
    return resp.json()["cloudKitUserId"]


def _raise_for_throttle(resp, what: str) -> None:
    """429 / 5xx -> CloudKitError carrying Retry-After, so the caller backs off (ratelimit.py)."""
    if resp.status_code == 429 or resp.status_code >= 500:
        from ..ratelimit import retry_after_seconds
        raise CloudKitError(f"{what}: HTTP {resp.status_code} (throttled or unavailable)",
                            http_status=resp.status_code, retry_after=retry_after_seconds(resp))


class CloudKitError(AppleError):
    """A CloudKit transport/operation failure (network, HTTP, or a non-success result code)."""

    def __init__(self, message: str, *, code: int | None = None,
                 description: str | None = None, http_status: int | None = None,
                 retry_after: float | None = None):
        super().__init__(message)
        self.code = code
        self.description = description
        self.http_status = http_status
        self.retry_after = retry_after


@dataclasses.dataclass
class CloudKitResult:
    code: int
    error_description: str | None
    fields: dict                       # decoded ResponseOperation top-level fields

    @property
    def ok(self) -> bool:
        return self.code == RESULT_SUCCESS

    @property
    def serialized_result(self) -> bytes:
        """functionInvokeResponse(1101).serializedResult(1) - the CKCode op's response proto."""
        fir = first(self.fields, 1101)
        return first(decode_fields(fir), 1, b"") if fir is not None else b""

    def field(self, num: int) -> bytes | None:
        """Raw bytes of an operation-specific response field (e.g. retrieveChangesResponse=213)."""
        return first(self.fields, num)


def parse_response_operation(raw: bytes) -> CloudKitResult:
    f = decode_fields(raw)
    code, err = RESULT_SUCCESS, None
    result_blob = first(f, 3)
    if result_blob is not None:
        rf = decode_fields(result_blob)
        code = first(rf, 1, RESULT_SUCCESS)
        err_blob = first(rf, 2)
        if err_blob is not None:
            err = first_str(decode_fields(err_blob), 4)
    return CloudKitResult(code=code, error_description=err, fields=f)


class CloudKitTransport:
    """Performs CloudKit operations for the keychain containers: CKCode function invokes
    (Cuttlefish) and record fetches. Every invoke/fetch_records call makes a LIVE HTTPS request."""

    def __init__(self, ck_token: str, user_id: str, device: DeviceConfig, anisette,
                 *, mme_client_info: str | None = None,
                 container: str = CUTTLEFISH_CONTAINER, timeout: int = 30):
        self.ck_token = ck_token
        self.user_id = user_id
        self.device = device
        self.anisette = anisette
        self.container = container
        self.mme_client_info = mme_client_info
        self.timeout = timeout

    def _headers(self, bundle: str, routing_hint: str | None = None,
                 database_scope: str = "Private") -> dict:
        """Shared container headers plus the two CKCode-invoke headers: x-cloudkit-userid
        (cloudKitUserId) and x-cloudkit-authtoken (cloudKitToken - never in the protobuf body)."""
        h = _container_headers(
            bundle=bundle, container=self.container, database_scope=database_scope,
            mme_client_info=self.mme_client_info or CK_MME_CLIENT_INFO)
        h["x-cloudkit-userid"] = self.user_id
        h["x-cloudkit-authtoken"] = self.ck_token
        if routing_hint:
            h["x-cloudkit-functionroutinghint"] = routing_hint
        h.update(self.anisette.headers())
        return h

    def _perform(self, url: str, op_type: int, request_field: int, request_bytes: bytes,
                 *, bundle: str, routing_hint: str | None = None,
                 database_scope: str = "Private", database: int = DB_PRIVATE) -> CloudKitResult:
        """LIVE. Build + gzip + POST a RequestOperation, parse + check the ResponseOperation."""
        header = build_header(self.device, container=self.container, bundle=bundle,
                              database=database)
        req = build_request_operation_generic(header, op_type, request_field, request_bytes)
        body = gzip.compress(delimit(req))
        try:
            resp = requests.post(url, headers=self._headers(bundle, routing_hint, database_scope),
                                 data=body, verify=VERIFY_TLS, timeout=self.timeout)
        except requests.RequestException as e:
            raise CloudKitError(f"network error talking to {url}: {e}") from e
        _raise_for_throttle(resp, url)
        try:
            messages = undelimit(maybe_gunzip(resp.content))
            result = parse_response_operation(messages[0])
        except Exception as e:   # HTML error page, truncated body ...
            raise CloudKitError(f"unreadable CloudKit response (HTTP {resp.status_code})",
                                http_status=resp.status_code) from e
        if not result.ok:
            raise CloudKitError(
                f"CloudKit operation failed: {result.error_description or 'unknown'}",
                code=result.code, description=result.error_description,
                http_status=resp.status_code)
        return result

    def invoke(self, op_name: str, parameters: bytes) -> CloudKitResult:
        """LIVE CKCode function invoke (Cuttlefish RPC). Returns the success result."""
        fir = encode_function_invoke_request(CUTTLEFISH_SERVICE, op_name, parameters)
        return self._perform(CKCODE_INVOKE_URL, OP_TYPE_FUNCTION_INVOKE, 1101, fir,
                             bundle=CUTTLEFISH_BUNDLE,
                             routing_hint=f"{CUTTLEFISH_SERVICE}/{op_name}")

    def fetch_records(self, zone_request_bytes: bytes, *, bundle: str = SECURITYD_BUNDLE,
                      database_scope: str = "Private", database: int = DB_PRIVATE) -> bytes:
        """LIVE. Fetch changed records from a CloudKit database."""
        result = self._perform(
            CKDATABASE_SYNC_URL, ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES,
            ckks.FIELD_RETRIEVE_CHANGES, zone_request_bytes, bundle=bundle,
            database_scope=database_scope, database=database)
        return result.field(ckks.FIELD_RETRIEVE_CHANGES) or b""

    def fetch_zone_changes(self, continuation: bytes | None = None, *, bundle: str,
                           database_scope: str = "Private", database: int = DB_PRIVATE) -> bytes:
        """LIVE. Enumerate changed zones in a CloudKit database."""
        req = (Writer().bytes(1, continuation).finish())
        result = self._perform(
            CKDATABASE_ZONE_SYNC_URL, OP_TYPE_ZONE_RETRIEVE_CHANGES,
            FIELD_ZONE_RETRIEVE_CHANGES, req, bundle=bundle,
            database_scope=database_scope, database=database)
        return result.field(FIELD_ZONE_RETRIEVE_CHANGES) or b""
