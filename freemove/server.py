"""Receiver side: listen, pair, receive, verify, place, report.

One ``serve_once()`` handles one sender session:

1. A plain pairing connection authenticates the certificate
   fingerprint with the PIN proof (see :mod:`freemove.security`).
2. A TLS connection (fingerprint-pinned by the sender) carries the
   manifest, the resume negotiation and the file data.
3. Each file lands in ``<dest>/.freemove-partial/`` first.  Only
   after its SHA-256 matches the manifest is it moved into place —
   a corrupt or tampered transfer never appears at the destination.
4. A JSON transfer report is written into the destination folder.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import discovery, protocol, security

PARTIAL_DIRNAME = ".freemove-partial"


class Receiver:
    def __init__(self, dest_dir, host: str = "0.0.0.0",
                 port: int = discovery.TRANSFER_PORT,
                 pin: str | None = None, announce: bool = False,
                 on_event=None):
        self.dest_dir = Path(dest_dir)
        self.host = host
        self.port = port
        self.pin = pin or security.generate_pin()
        self.announce = announce
        self.on_event = on_event or (lambda kind, data: None)
        self.identity: security.Identity | None = None
        self.fingerprint: str = ""
        self.report: dict | None = None
        self.error: BaseException | None = None
        self._listener: socket.socket | None = None
        self._discovery: discovery.DiscoveryService | None = None

    # -- lifecycle ----------------------------------------------------

    def prepare(self) -> "Receiver":
        """Generate the identity and bind the listener (call first)."""
        self.identity = security.generate_identity()
        self.fingerprint = self.identity.fingerprint
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(4)
        self.port = listener.getsockname()[1]
        self._listener = listener
        return self

    def serve_in_thread(self) -> threading.Thread:
        if self._listener is None:
            self.prepare()
        thread = threading.Thread(target=self.serve_once, daemon=True,
                                  name="freemove-receiver")
        thread.start()
        return thread

    def close(self) -> None:
        if self._discovery is not None:
            self._discovery.stop()
            self._discovery = None
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None

    # -- internals -----------------------------------------------------

    def _partial_path(self, entry: protocol.FileEntry) -> Path:
        rel = protocol.sanitize_relpath(entry.path)
        return self.dest_dir / PARTIAL_DIRNAME / (str(rel) + ".part")

    def _existing_offset(self, entry: protocol.FileEntry) -> int:
        partial = self._partial_path(entry)
        if partial.is_file():
            size = partial.stat().st_size
            if 0 <= size <= entry.size:
                return size
            partial.unlink()  # oversized/corrupt stub: start over
        return 0

    def _receive_file(self, conn, entry: protocol.FileEntry,
                      offset: int) -> None:
        partial = self._partial_path(entry)
        partial.parent.mkdir(parents=True, exist_ok=True)
        remaining = entry.size - offset
        mode = "r+b" if offset else "wb"
        with open(partial, mode) as fh:
            if offset:
                fh.seek(offset)
            left = remaining
            while left > 0:
                chunk = conn.recv(min(left, protocol.CHUNK_SIZE))
                if not chunk:
                    raise ConnectionError(
                        f"connection dropped mid-file: {entry.path}")
                fh.write(chunk)
                left -= len(chunk)
                self.on_event("progress", {
                    "path": entry.path,
                    "received": entry.size - left,
                    "size": entry.size,
                })
        # Verify *before* placing: the destination only ever sees
        # files whose hash matches the manifest.
        actual = protocol.sha256_file(partial)
        if actual != entry.sha256:
            partial.unlink(missing_ok=True)
            raise protocol.VerificationError(
                f"SHA-256 mismatch for {entry.path} "
                f"(expected {entry.sha256}, got {actual}); "
                "file was NOT placed")
        target = self.dest_dir / protocol.sanitize_relpath(entry.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        partial.replace(target)

    def serve_once(self) -> dict:
        """Run one full session.  Returns (and stores) the report."""
        if self._listener is None:
            self.prepare()
        assert self.identity is not None and self._listener is not None
        self.dest_dir.mkdir(parents=True, exist_ok=True)
        if self.announce:
            self._discovery = discovery.DiscoveryService(
                transfer_port=self.port, fingerprint=self.fingerprint)
            self._discovery.start()
        report: dict = {
            "started": datetime.now(timezone.utc).isoformat(),
            "destination": str(self.dest_dir),
            "received": [], "failed": [], "bytes": 0, "verified": False,
        }
        try:
            self.on_event("listening", {
                "port": self.port, "pin": self.pin,
                "fingerprint": self.fingerprint,
            })
            pairing_conn, _ = self._listener.accept()
            with pairing_conn:
                security.receiver_pairing(pairing_conn, self.pin,
                                          self.fingerprint)
            self.on_event("paired", {})
            raw_conn, _ = self._listener.accept()
            ctx = security.server_context(self.identity)
            with ctx.wrap_socket(raw_conn, server_side=True) as conn:
                manifest = protocol.recv_msg(conn)
                entries = protocol.manifest_entries(manifest)
                offsets = {e.path: self._existing_offset(e) for e in entries}
                protocol.send_msg(conn, {"type": "resume_info",
                                         "offsets": offsets})
                for entry in entries:
                    start = protocol.recv_msg(conn)
                    if start.get("type") != "file_start" or \
                            start.get("path") != entry.path:
                        raise protocol.ProtocolError(
                            "expected file_start for " + entry.path)
                    offset = int(start.get("offset", 0))
                    if offset != offsets[entry.path]:
                        raise protocol.ProtocolError(
                            "sender/receiver offset disagreement for "
                            + entry.path)
                    self.on_event("file_start", {
                        "path": entry.path, "size": entry.size,
                        "offset": offset,
                    })
                    self._receive_file(conn, entry, offset)
                    report["received"].append(entry.path)
                    report["bytes"] += entry.size - offset
                    protocol.send_msg(conn, {"type": "file_result",
                                             "path": entry.path,
                                             "ok": True})
                    self.on_event("file_done", {"path": entry.path})
                report["verified"] = True
                protocol.send_msg(conn, {"type": "report", **report})
        except BaseException as exc:  # stored for the caller/thread
            self.error = exc
            report["failed"].append(str(exc))
            self.on_event("error", {"error": str(exc)})
        finally:
            report["finished"] = datetime.now(timezone.utc).isoformat()
            self.report = report
            try:
                report_path = self.dest_dir / \
                    f"freemove-report-{datetime.now():%Y%m%d-%H%M%S}.json"
                report_path.write_text(json.dumps(report, indent=2),
                                       encoding="utf-8")
            except OSError:
                pass
            self.close()
        if self.error is not None:
            raise self.error
        return report
