"""Native-messaging framing shared by the Python host and agent (the Rust shim/agent speak the same):
a 4-byte little-endian length, then that many bytes of UTF-8 JSON."""

from __future__ import annotations

import json
import struct

MAX_FRAME = 1 << 20


def pack(message: dict) -> bytes:
    body = json.dumps(message).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def read(stream) -> dict | None:
    """Blocking read from a binary file-like object; None on EOF, a short read or an oversized
    frame."""
    head = stream.read(4)
    if len(head) < 4:
        return None
    (n,) = struct.unpack("<I", head)
    if n > MAX_FRAME:
        return None
    data = stream.read(n)
    return json.loads(data.decode("utf-8")) if len(data) == n else None


async def aread(reader) -> dict | None:
    """asyncio StreamReader variant; raises asyncio.IncompleteReadError at EOF."""
    (n,) = struct.unpack("<I", await reader.readexactly(4))
    if n > MAX_FRAME:
        return None
    return json.loads((await reader.readexactly(n)).decode())
