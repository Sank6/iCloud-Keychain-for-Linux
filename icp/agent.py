"""icp-agent: a long-running per-user process that holds the decrypted vault in memory and answers
the native-messaging shim over a Unix socket. This replaces "spawn Python and decrypt the vault for
every message from the browser".

- Socket: $XDG_RUNTIME_DIR/icp/agent.sock, mode 0600 in a 0700 dir; peers must be the same uid.
- Wire format: the browser's native-messaging framing (4-byte LE length + JSON), so the shim is a
  plain byte forwarder and `vault.host.handle` is reused unchanged.
- Locking: after IDLE_LOCK seconds with no requests the vault is dropped from memory. Locked
  `match`/`search`/`totp` requests answer {"ok": false, "locked": true}; `unlock` reloads the vault
  (which may show the keyring prompt). `lock` locks immediately.
"""

from __future__ import annotations

import asyncio
import gc
import os
import socket
import struct
import sys
import time
from pathlib import Path

from . import framing, paths
from .vault import host

IDLE_LOCK = int(os.environ.get("ICP_IDLE_LOCK", str(15 * 60)))
NEEDS_UNLOCK = {"match", "search", "totp"}


def socket_path() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/icp-{os.getuid()}"
    d = Path(base) / "icp"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d / "agent.sock"


class Agent:
    def __init__(self):
        self.store = None
        self.aliases: list = []
        self.vault_mtime = 0.0
        self.last_used = time.time()

    @property
    def locked(self) -> bool:
        return self.store is None

    def load(self) -> None:
        from .hme.store import load_aliases
        from .vault.store import load_vault
        self.store = load_vault()
        try:
            self.aliases = load_aliases()
        except Exception:
            self.aliases = []
        vf = paths.vault_file()
        self.vault_mtime = vf.stat().st_mtime if vf.exists() else 0.0

    def lock(self) -> None:
        self.store, self.aliases = None, []
        gc.collect()

    def _fresh(self) -> None:
        """Pick up a vault rewritten by a sync without a restart."""
        vf = paths.vault_file()
        if not self.locked and vf.exists() and vf.stat().st_mtime != self.vault_mtime:
            self.load()

    async def handle(self, req: dict) -> dict:
        cmd = req.get("cmd")
        self.last_used = time.time()
        if cmd == "lock":
            self.lock()
            return {"ok": True, "locked": True}
        if cmd == "unlock":
            if self.locked:
                try:
                    await asyncio.get_running_loop().run_in_executor(None, self.load)
                except Exception as e:  # keyring dismissed, etc.
                    return {"ok": False, "locked": True, "error": str(e)}
            return {"ok": True, "locked": False}
        if cmd == "ping":
            base = {"ok": True, "locked": self.locked}
            return {**base, "count": 0 if self.locked else len(self.store)}
        if cmd == "status":
            from . import status
            return {"ok": True, "locked": self.locked, "sync": status.read(),
                    "signed_in": paths.session_file().exists(),
                    "count": 0 if self.locked else len(self.store)}
        if cmd in NEEDS_UNLOCK and self.locked:
            return {"ok": False, "locked": True, "error": "locked"}
        if not self.locked:
            self._fresh()
        return host.handle(req, self.store if not self.locked else host.CredentialStore([]),
                           self.aliases)


async def _client(agent: Agent, reader, writer) -> None:
    sock = writer.get_extra_info("socket")
    try:
        pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                            struct.calcsize("3i")))
        if uid != os.getuid():
            return
        while True:
            try:
                req = await framing.aread(reader)
            except (asyncio.IncompleteReadError, ValueError):
                return
            if req is None:
                return
            try:
                resp = await agent.handle(req)
            except Exception as e:  # never kill the agent on one bad request
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            writer.write(framing.pack(resp))
            await writer.drain()
    finally:
        writer.close()


async def _idle_lock(agent: Agent) -> None:
    while True:
        await asyncio.sleep(30)
        if not agent.locked and IDLE_LOCK > 0 and time.time() - agent.last_used > IDLE_LOCK:
            agent.lock()


async def _serve() -> None:
    agent = Agent()
    try:
        agent.load()
    except Exception:
        pass  # start locked; the first `unlock` retries
    sp = socket_path()
    if sp.exists():
        try:  # a live agent already owns it -> exit quietly
            c = socket.socket(socket.AF_UNIX)
            c.settimeout(1)
            c.connect(str(sp))
            c.close()
            return
        except OSError:
            sp.unlink()
    old = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(lambda r, w: _client(agent, r, w), path=str(sp))
    finally:
        os.umask(old)
    os.chmod(sp, 0o600)
    host._maybe_trigger_sync()
    asyncio.get_running_loop().create_task(_idle_lock(agent))
    async with server:
        await server.serve_forever()


def main() -> int:
    try:
        import ctypes
        ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0: no ptrace/core dump of secrets
    except Exception:
        pass
    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
