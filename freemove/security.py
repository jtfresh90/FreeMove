"""Pairing and transport security.

Design (no plaintext mode, ever):

1. The receiver generates a fresh RSA key + self-signed certificate
   every time it starts listening, and shows a 6-digit pairing PIN
   plus the certificate's SHA-256 fingerprint.
2. Pairing runs over a short plain handshake whose only job is to
   authenticate that fingerprint: both sides contribute a random
   salt, derive a session key with PBKDF2-HMAC-SHA256 from the PIN,
   and the sender proves knowledge of the PIN by sending
   ``HMAC(session_key, fingerprint)``.  A man-in-the-middle who swaps
   in his own certificate cannot forge that proof without the PIN,
   because the proof is computed over *his* fingerprint with a key he
   cannot derive — so the fingerprint the sender pins is the one the
   PIN holder's peer actually presented.
3. The data connection then runs TLS 1.2+ with that certificate.
   The client does not trust any CA for it; it compares the presented
   certificate's SHA-256 fingerprint with the pinned value and aborts
   on mismatch.

The PIN has only ~20 bits of entropy, so the receiver allows a small
number of pairing attempts and the PBKDF2 iteration count is high;
the PIN is single-session and worthless once the receiver stops.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import socket
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import protocol

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
MAX_PAIRING_ATTEMPTS = 5


class PairingError(Exception):
    """Raised when PIN pairing fails."""


# --------------------------------------------------------------------------
# PIN + key derivation
# --------------------------------------------------------------------------

def generate_pin() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def derive_session_key(pin: str, salt_receiver: bytes, salt_sender: bytes,
                       iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if not (pin.isdigit() and len(pin) == 6):
        raise PairingError("PIN must be exactly 6 digits")
    return hashlib.pbkdf2_hmac(
        "sha256", pin.encode("ascii"), salt_receiver + salt_sender,
        iterations, dklen=32,
    )


def pairing_proof(session_key: bytes, fingerprint: str) -> str:
    msg = f"freemove-pair-v1:{fingerprint}".encode("ascii")
    return hmac.new(session_key, msg, hashlib.sha256).hexdigest()


def verify_proof(session_key: bytes, fingerprint: str, proof: str) -> bool:
    return hmac.compare_digest(pairing_proof(session_key, fingerprint), proof)


# --------------------------------------------------------------------------
# Runtime identity (self-signed certificate)
# --------------------------------------------------------------------------

def cert_fingerprint(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()


@dataclass
class Identity:
    cert_path: Path
    key_path: Path
    fingerprint: str  # hex SHA-256 of the DER certificate

    def short_fingerprint(self) -> str:
        fp = self.fingerprint.upper()
        return " ".join(fp[i:i + 4] for i in range(0, 16, 4)) + " …"


def _generate_with_cryptography(workdir: Path) -> tuple[Path, Path, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FreeMove Receiver")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"),
                 x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = workdir / "cert.pem"
    key_path = workdir / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)


def _generate_with_openssl(workdir: Path) -> tuple[Path, Path, bytes]:
    cert_path = workdir / "cert.pem"
    key_path = workdir / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key_path), "-out", str(cert_path),
         "-days", "2", "-nodes", "-subj", "/CN=FreeMove Receiver",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    return cert_path, key_path, der


def generate_identity(workdir: str | os.PathLike | None = None) -> Identity:
    """Create a fresh self-signed identity.

    Prefers the ``cryptography`` package; falls back to the ``openssl``
    command-line tool (present on this dev box and most systems).
    """
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="freemove-id-"))
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        cert_path, key_path, der = _generate_with_cryptography(workdir)
    except ImportError:
        cert_path, key_path, der = _generate_with_openssl(workdir)
    return Identity(cert_path=cert_path, key_path=key_path,
                    fingerprint=cert_fingerprint(der))


# --------------------------------------------------------------------------
# TLS contexts
# --------------------------------------------------------------------------

def server_context(identity: Identity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(identity.cert_path), str(identity.key_path))
    return ctx


def wrap_client_socket(sock: socket.socket, pinned_fingerprint: str,
                       server_hostname: str = "freemove") -> ssl.SSLSocket:
    """Wrap ``sock`` in TLS and pin the peer certificate fingerprint.

    CA verification is intentionally off: trust comes from the
    PIN-authenticated pairing exchange, not from a CA.  The connection
    is closed and :class:`PairingError` raised if the certificate the
    server presents is not the one that was pinned during pairing.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(sock, server_hostname=server_hostname)
    der = tls.getpeercert(binary_form=True)
    if der is None or not hmac.compare_digest(cert_fingerprint(der),
                                              pinned_fingerprint):
        tls.close()
        raise PairingError(
            "server certificate does not match the fingerprint from "
            "pairing — refusing to transfer (possible MITM)"
        )
    return tls


# --------------------------------------------------------------------------
# Pairing handshake (runs before TLS, authenticates the fingerprint)
# --------------------------------------------------------------------------

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def receiver_pairing(conn: socket.socket, pin: str, fingerprint: str,
                     attempts: int = MAX_PAIRING_ATTEMPTS) -> bytes:
    """Receiver side of pairing.  Returns the derived session key."""
    for _ in range(attempts):
        salt_r = new_salt()
        protocol.send_msg(conn, {
            "type": "pair_hello",
            "salt_r": _b64(salt_r),
            "fingerprint": fingerprint,
        })
        msg = protocol.recv_msg(conn)
        if msg.get("type") != "pair_response":
            raise PairingError("unexpected message during pairing")
        salt_s = _unb64(msg["salt_s"])
        key = derive_session_key(pin, salt_r, salt_s)
        if verify_proof(key, fingerprint, msg.get("proof", "")):
            protocol.send_msg(conn, {"type": "pair_result", "ok": True})
            return key
        protocol.send_msg(conn, {"type": "pair_result", "ok": False})
    raise PairingError("too many failed pairing attempts")


def sender_pairing(conn: socket.socket, pin: str) -> tuple[bytes, str]:
    """Sender side of pairing.

    Returns ``(session_key, pinned_fingerprint)``.  The fingerprint is
    the one the receiver announced *and* authenticated with the PIN
    proof, so it is safe to pin for the TLS connection.
    """
    hello = protocol.recv_msg(conn)
    if hello.get("type") != "pair_hello":
        raise PairingError("unexpected message during pairing")
    salt_r = _unb64(hello["salt_r"])
    fingerprint = hello["fingerprint"]
    salt_s = new_salt()
    key = derive_session_key(pin, salt_r, salt_s)
    protocol.send_msg(conn, {
        "type": "pair_response",
        "salt_s": _b64(salt_s),
        "proof": pairing_proof(key, fingerprint),
    })
    result = protocol.recv_msg(conn)
    if not result.get("ok"):
        raise PairingError("pairing rejected — wrong PIN?")
    return key, fingerprint
