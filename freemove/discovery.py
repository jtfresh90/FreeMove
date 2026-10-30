"""LAN peer discovery over UDP broadcast.

Receivers announce themselves (hostname, transfer port, protocol
version, certificate fingerprint) and answer discovery queries.
Senders broadcast a query and collect announcements for a few
seconds.  Discovery is a convenience only — it carries no secrets,
and the user can always type an IP address by hand instead.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass, field

from . import __version__

DISCOVERY_PORT = 40119
TRANSFER_PORT = 40120
_MAGIC = "freemove-discovery-v1"


@dataclass
class Peer:
    name: str
    host: str
    port: int
    version: str = ""
    fingerprint: str = ""
    last_seen: float = field(default_factory=time.time)

    def label(self) -> str:
        return f"{self.name}  ({self.host}:{self.port})"


class DiscoveryService:
    """Announces this receiver and answers queries until stopped."""

    def __init__(self, transfer_port: int = TRANSFER_PORT,
                 fingerprint: str = "", name: str | None = None,
                 port: int = DISCOVERY_PORT):
        self.transfer_port = transfer_port
        self.fingerprint = fingerprint
        self.name = name or socket.gethostname()
        self.port = port
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def _announcement(self) -> bytes:
        return json.dumps({
            "magic": _MAGIC,
            "type": "announce",
            "name": self.name,
            "port": self.transfer_port,
            "version": __version__,
            "fingerprint": self.fingerprint,
        }).encode("utf-8")

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self._sock.bind(("", self.port))
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="freemove-discovery")
        self._thread.start()

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if msg.get("magic") != _MAGIC:
                continue
            if msg.get("type") == "query":
                try:
                    self._sock.sendto(self._announcement(), addr)
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)


def discover(timeout: float = 3.0,
             targets: list[tuple[str, int]] | None = None,
             port: int = DISCOVERY_PORT) -> list[Peer]:
    """Find FreeMove receivers.

    By default broadcasts a query on the LAN.  ``targets`` may give
    explicit ``(host, port)`` pairs to query by unicast (used by the
    tests, and handy on networks where broadcast is filtered).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    destinations = targets if targets is not None else [("255.255.255.255", port)]
    # Only request broadcast permission when actually broadcasting —
    # some sandboxed networks refuse broadcast-capable sockets even
    # for plain unicast sends.
    if any(dest[0] == "255.255.255.255" for dest in destinations):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.4)
    query = json.dumps({"magic": _MAGIC, "type": "query"}).encode("utf-8")
    peers: dict[str, Peer] = {}
    deadline = time.time() + timeout
    try:
        for dest in destinations:
            try:
                sock.sendto(query, dest)
            except OSError:
                # Discovery is best-effort: on networks/sandboxes that
                # forbid UDP sends, report "no peers" instead of dying.
                return []
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if msg.get("magic") != _MAGIC or msg.get("type") != "announce":
                continue
            key = f"{addr[0]}:{msg.get('port')}"
            peers[key] = Peer(
                name=msg.get("name", addr[0]),
                host=addr[0],
                port=int(msg.get("port", TRANSFER_PORT)),
                version=msg.get("version", ""),
                fingerprint=msg.get("fingerprint", ""),
            )
    finally:
        sock.close()
    return sorted(peers.values(), key=lambda p: p.name.lower())
