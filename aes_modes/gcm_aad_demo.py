import secrets

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def gcm_with_aad_demo():
    key = secrets.token_bytes(16)
    nonce = get_random_bytes(12)
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
        ok = False
    except ValueError:
        ok = True

    # AAD tamper ⇒ verification failure.
    return {
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "tag": tag.hex(),
        "aad_ok": True,
        "aad_tamper_fails": ok,
    }


if __name__ == "__main__":
    print(gcm_with_aad_demo())
