"""Sender side: pair with a receiver and stream a manifest of files.

The sender never sends a byte of file data before (a) the PIN proof
has authenticated the receiver's certificate fingerprint and (b) the
TLS connection has presented exactly that certificate.
"""

from __future__ import annotations

import socket
from pathlib import Path

from . import protocol, security


class Sender:
    def __init__(self, on_event=None):
        self.on_event = on_event or (lambda kind, data: None)
        self.bytes_sent = 0  # file-data bytes sent by the last send()

    def connect_pairing(self, host: str, port: int, pin: str):
        """Run the pairing handshake; returns the pinned fingerprint."""
        conn = socket.create_connection((host, port), timeout=30)
        try:
            _key, fingerprint = security.sender_pairing(conn, pin)
        finally:
            conn.close()
        return fingerprint

    def send(self, host: str, port: int, pin: str,
             entries: list[protocol.FileEntry],
             simulate_drop_after_bytes: int | None = None) -> dict:
        """Transfer ``entries`` to the receiver at ``host:port``.

        ``simulate_drop_after_bytes`` exists for the resume test: it
        aborts the connection abruptly after that many file-data
        bytes, like a crashed sender or a dropped Wi-Fi link.
        """
        self.bytes_sent = 0
        fingerprint = self.connect_pairing(host, port, pin)
        raw = socket.create_connection((host, port), timeout=30)
        conn = security.wrap_client_socket(raw, fingerprint)
        try:
            return self._send_over(conn, entries, simulate_drop_after_bytes)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _send_over(self, conn, entries, drop_after) -> dict:
        protocol.send_msg(conn, protocol.build_manifest(entries))
        resume = protocol.recv_msg(conn)
        if resume.get("type") != "resume_info":
            raise protocol.ProtocolError("expected resume_info")
        offsets: dict[str, int] = resume.get("offsets", {})

        for entry in entries:
            if entry.source is None:
                raise ValueError(f"entry has no source file: {entry.path}")
            offset = int(offsets.get(entry.path, 0))
            if not 0 <= offset <= entry.size:
                offset = 0
            protocol.send_msg(conn, {"type": "file_start",
                                     "path": entry.path,
                                     "offset": offset})
            self.on_event("file_start", {"path": entry.path,
                                         "size": entry.size,
                                         "offset": offset})
            remaining = entry.size - offset
            with open(entry.source, "rb") as fh:
                fh.seek(offset)
                left = remaining
                while left > 0:
                    chunk = fh.read(min(left, protocol.CHUNK_SIZE))
                    if not chunk:
                        raise protocol.ProtocolError(
                            f"source file shrank during send: {entry.path}")
                    conn.sendall(chunk)
                    self.bytes_sent += len(chunk)
                    left -= len(chunk)
                    self.on_event("progress", {
                        "path": entry.path,
                        "sent": entry.size - left,
                        "size": entry.size,
                    })
                    if drop_after is not None and \
                            self.bytes_sent >= drop_after:
                        # Abrupt drop: no close_notify, no goodbye —
                        # exactly what a dead connection looks like.
                        conn.close()
                        raise ConnectionError(
                            "simulated connection drop (test hook)")
            result = protocol.recv_msg(conn)
            if result.get("type") != "file_result" or not result.get("ok"):
                raise protocol.VerificationError(
                    f"receiver rejected {entry.path}: "
                    f"{result.get('error', 'unknown error')}")
            self.on_event("file_done", {"path": entry.path})

        final = protocol.recv_msg(conn)
        if final.get("type") != "report":
            raise protocol.ProtocolError("expected final report")
        return final


def send_paths(host: str, port: int, pin: str,
               items: list[tuple[Path, str]], on_event=None) -> dict:
    """Convenience: expand ``(path, prefix)`` items and send them."""
    from . import collector
    entries = collector.expand_selection(items)
    return Sender(on_event=on_event).send(host, port, pin, entries)
