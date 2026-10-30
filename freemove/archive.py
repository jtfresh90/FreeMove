"""Image-file mode: a selection packed into one ``.fmimg`` file.

For offline moves and data rescue: export on (or from) the old PC —
including a slaved drive from a dead machine — carry the file over
on external media, and import it on the new PC.  The image is a ZIP
container plus a ``manifest.json`` with a SHA-256 per file; import
verifies every hash and refuses to place tampered files.

Encryption is optional and is *only* done with the vetted
``cryptography`` package (AES-256-GCM, key from PBKDF2-HMAC-SHA256).
If a passphrase is requested but that package is not installed,
FreeMove warns loudly and writes an UNENCRYPTED image rather than
pretending — or falls over, per the caller's ``on_missing_crypto``.
FreeMove never hand-rolls encryption.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import secrets
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import protocol

log = logging.getLogger("freemove.archive")

MAGIC = b"FMIMG1"          # prefix of an encrypted image
_PBKDF2_ITERATIONS = 200_000
_SALT_LEN = 16
_NONCE_LEN = 12

try:  # optional dependency — the only non-stdlib one FreeMove uses
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover - depends on environment
    AESGCM = None  # type: ignore
    _HAS_CRYPTO = False


def crypto_available() -> bool:
    return _HAS_CRYPTO


class EncryptionUnavailable(Exception):
    """A passphrase was requested but `cryptography` is not installed."""


@dataclass
class ImageReport:
    image: str
    files: int
    total_bytes: int
    encrypted: bool
    placed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Encryption helpers
# --------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                               salt, _PBKDF2_ITERATIONS, dklen=32)


def _encrypt_blob(data: bytes, passphrase: str) -> bytes:
    salt = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, data, None)


def _decrypt_blob(data: bytes, passphrase: str) -> bytes:
    salt = data[len(MAGIC):len(MAGIC) + _SALT_LEN]
    nonce = data[len(MAGIC) + _SALT_LEN:len(MAGIC) + _SALT_LEN + _NONCE_LEN]
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, data[len(MAGIC) + _SALT_LEN + _NONCE_LEN:], None)


# --------------------------------------------------------------------------
# Export / import
# --------------------------------------------------------------------------

def export_image(entries: list[protocol.FileEntry], out_path,
                 passphrase: str | None = None,
                 on_missing_crypto: str = "warn") -> ImageReport:
    """Pack ``entries`` into a ``.fmimg`` at ``out_path``."""
    out_path = Path(out_path)
    manifest = {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "files": [e.to_dict() for e in entries],
        "total_bytes": sum(e.size for e in entries),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        for entry in entries:
            if entry.source is None:
                raise ValueError(f"entry has no source file: {entry.path}")
            zf.write(entry.source, f"files/{entry.path}")
    payload = buffer.getvalue()

    encrypted = False
    if passphrase:
        if _HAS_CRYPTO:
            payload = _encrypt_blob(payload, passphrase)
            encrypted = True
        elif on_missing_crypto == "error":
            raise EncryptionUnavailable(
                "passphrase given but the 'cryptography' package is not "
                "installed; refusing to write an unencrypted image")
        else:
            log.warning(
                "WARNING: 'cryptography' is not installed, so this image "
                "is being written UNENCRYPTED despite the passphrase. "
                "Install 'cryptography' for AES-256-GCM image encryption.")
    out_path.write_bytes(payload)
    return ImageReport(image=str(out_path), files=len(entries),
                       total_bytes=manifest["total_bytes"],
                       encrypted=encrypted)


def import_image(image_path, dest_dir, passphrase: str | None = None) -> ImageReport:
    """Extract a ``.fmimg`` into ``dest_dir``, verifying every hash.

    Raises :class:`~freemove.protocol.VerificationError` if any file
    does not match the manifest — nothing tampered is placed.
    """
    image_path = Path(image_path)
    dest_dir = Path(dest_dir)
    raw = image_path.read_bytes()
    encrypted = raw.startswith(MAGIC)
    if encrypted:
        if not _HAS_CRYPTO:
            raise EncryptionUnavailable(
                "this image is encrypted but the 'cryptography' package "
                "is not installed")
        if not passphrase:
            raise EncryptionUnavailable(
                "this image is encrypted; a passphrase is required")
        raw = _decrypt_blob(raw, passphrase)

    report = ImageReport(image=str(image_path), files=0, total_bytes=0,
                         encrypted=encrypted)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        entries = [protocol.FileEntry.from_dict(d) for d in manifest["files"]]
        report.files = len(entries)
        report.total_bytes = int(manifest.get("total_bytes", 0))
        for entry in entries:
            arcname = f"files/{entry.path}"
            try:
                data = zf.read(arcname)
            except KeyError:
                raise protocol.VerificationError(
                    f"image is missing a manifest file: {entry.path}")
            if len(data) != entry.size or \
                    protocol.sha256_bytes(data) != entry.sha256:
                raise protocol.VerificationError(
                    f"hash mismatch for {entry.path} — image is corrupt "
                    "or has been tampered with; nothing was placed for it")
            target = dest_dir / protocol.sanitize_relpath(entry.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            report.placed.append(entry.path)
    return report
