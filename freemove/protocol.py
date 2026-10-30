"""Wire protocol for FreeMove.

Framing is deliberately simple and auditable:

* Control messages are JSON objects, each prefixed with a 4-byte
  big-endian length.
* File data is *not* framed: after a ``file_start`` control message the
  sender streams exactly ``size - offset`` raw bytes, then moves on to
  the next control message.  The receiver knows the byte count from the
  manifest, so no escaping or chunk headers are needed.

Every transfer starts with a MANIFEST: a list of
``{path, size, sha256}`` entries.  The receiver replies with the byte
offset it already holds for each file (resume), and after a file is
fully received its SHA-256 is checked against the manifest before the
file is moved into place.  A file that fails verification is never
placed at its destination.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_CONTROL_BYTES = 32 * 1024 * 1024
CHUNK_SIZE = 256 * 1024
PROTOCOL_VERSION = 1


class ProtocolError(Exception):
    """Raised when a peer sends something the protocol forbids."""


class VerificationError(Exception):
    """Raised when received data does not match its manifest hash."""


# --------------------------------------------------------------------------
# Framing helpers
# --------------------------------------------------------------------------

def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    if len(data) > MAX_CONTROL_BYTES:
        raise ProtocolError("control message too large")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock) -> dict:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_CONTROL_BYTES:
        raise ProtocolError(f"control message too large: {length}")
    data = _recv_exact(sock, length)
    msg = json.loads(data.decode("utf-8"))
    if not isinstance(msg, dict) or "type" not in msg:
        raise ProtocolError("malformed control message")
    return msg


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def sha256_file(path, _bufsize: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(_bufsize)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------

@dataclass
class FileEntry:
    """One file in a transfer.

    ``path`` is the destination-relative path, always written with
    forward slashes so manifests are portable between machines.
    ``source`` is the local path to read from (sender side only; never
    serialised into the manifest).
    """

    path: str
    size: int
    sha256: str
    source: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, d: dict) -> "FileEntry":
        return cls(path=d["path"], size=int(d["size"]), sha256=d["sha256"])


def make_entry(source_path, relpath: str) -> FileEntry:
    source_path = os.fspath(source_path)
    return FileEntry(
        path=relpath.replace("\\", "/"),
        size=os.path.getsize(source_path),
        sha256=sha256_file(source_path),
        source=source_path,
    )


def build_manifest(entries: list[FileEntry]) -> dict:
    return {
        "type": "manifest",
        "version": PROTOCOL_VERSION,
        "files": [e.to_dict() for e in entries],
        "total_bytes": sum(e.size for e in entries),
        "file_count": len(entries),
    }


def manifest_entries(manifest: dict) -> list[FileEntry]:
    if manifest.get("type") != "manifest":
        raise ProtocolError("expected a manifest message")
    return [FileEntry.from_dict(d) for d in manifest["files"]]


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------

def sanitize_relpath(relpath: str) -> Path:
    """Turn a manifest path into a safe relative :class:`Path`.

    Rejects absolute paths, drive letters and ``..`` components so a
    malicious or buggy sender cannot write outside the destination
    folder.
    """
    pure = PurePosixPath(relpath.replace("\\", "/"))
    if pure.is_absolute() or (pure.parts and ":" in pure.parts[0]):
        raise ProtocolError(f"unsafe path in manifest: {relpath!r}")
    parts = [p for p in pure.parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise ProtocolError(f"unsafe path in manifest: {relpath!r}")
    return Path(*parts)
