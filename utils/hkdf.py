"""Key derivation helpers."""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional


def hkdf_sha256(ikm: bytes, *, salt: Optional[bytes] = None, info: bytes = b"", length: int = 32) -> bytes:
    """HKDF-Extract-and-Expand with SHA-256 (RFC 5869)."""
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


__all__ = ["hkdf_sha256"]
