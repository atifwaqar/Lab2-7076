from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def gcm_with_aad_demo(
    *,
    key: bytes | None = None,
    nonce: bytes | None = None,
    aad: bytes | None = None,
):
    """Run a short AES-GCM example that highlights the role of AAD.

    Parameters are optional so tests can supply deterministic inputs.  The
    function returns the cryptographic artefacts instead of only printing so
    the caller can make assertions on the behaviour.
    """

    if key is None:
        key = get_random_bytes(16)
    if len(key) != 16:
        raise ValueError("AES-128 demo expects a 16-byte key")

    if nonce is None:
        nonce = get_random_bytes(12)
    if len(nonce) != 12:
        raise ValueError("AES-GCM demo expects a 12-byte nonce")

    if aad is None:
        aad = b"hdr:v1;type=demo"

    pt = b"hello gcm with aad"
    enc = AES.new(key, AES.MODE_GCM, nonce=nonce)
    enc.update(aad)
    ct, tag = enc.encrypt_and_digest(pt)

    # Verify with correct AAD
    dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    dec.update(aad)
    dec.decrypt_and_verify(ct, tag)  # should pass

    # Verify with tampered AAD -> should raise ValueError
    bad = AES.new(key, AES.MODE_GCM, nonce=nonce)
    bad.update(aad[:-1] + bytes([aad[-1] ^ 1]))
    try:
        bad.decrypt_and_verify(ct, tag)
        tamper_fails = False
        tamper_error = None
    except ValueError as exc:
        tamper_fails = True
        tamper_error = type(exc).__name__

    # AAD tamper ⇒ verification failure.
    return {
        "key": key.hex(),
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "tag": tag.hex(),
        "aad_hex": aad.hex(),
        "aad_ok": True,
        "aad_tamper_fails": tamper_fails,
        "aad_tamper_error": tamper_error,
    }


if __name__ == "__main__":
    print(gcm_with_aad_demo())
