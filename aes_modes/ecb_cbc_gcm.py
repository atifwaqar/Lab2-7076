from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

BLOCK = 16

def pkcs7_pad(b: bytes, block: int = BLOCK) -> bytes:
    pad = block - (len(b) % block)
    return b + bytes([pad]) * pad

def pkcs7_unpad(b: bytes, block: int = BLOCK) -> bytes:
    if not b or len(b) % block != 0:
        raise ValueError("Invalid padded data length")
    pad = b[-1]
    if pad < 1 or pad > block or b[-pad:] != bytes([pad]) * pad:
        raise ValueError("Bad PKCS#7 padding")
    return b[:-pad]

def aes_ecb_encrypt(key: bytes, pt: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(pt))

def aes_ecb_decrypt(key: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(ct))

def aes_cbc_encrypt(key: bytes, pt: bytes, iv: bytes | None = None) -> bytes:
    iv = iv or get_random_bytes(BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pkcs7_pad(pt))

def aes_cbc_decrypt(key: bytes, iv_ct: bytes) -> bytes:
    iv, ct = iv_ct[:BLOCK], iv_ct[BLOCK:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return pkcs7_unpad(cipher.decrypt(ct))

def aes_gcm_encrypt(key: bytes, pt: bytes, aad: bytes = b"", nonce: bytes | None = None):
    nonce = nonce or get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return nonce, ct, tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)

def demo_ecb_pattern_leakage():
    key = get_random_bytes(16)
    block = b"A" * 16
    pt = block * 4 + b"B" * 16 + block * 3
    ct = aes_ecb_encrypt(key, pt)
    blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    unique_blocks = len(set(blocks))
    print(f"[ECB] blocks={len(blocks)}, unique_blocks={unique_blocks} (lower is worse)")

def demo_cbc_iv_reuse():
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    p1 = b"Message One starts here..." + os.urandom(5)
    p2 = b"Message Two starts here..." + os.urandom(5)
    c1 = aes_cbc_encrypt(key, p1, iv=iv)
    c2 = aes_cbc_encrypt(key, p2, iv=iv)
    c1_first = c1[:16]
    c2_first = c2[:16]
    print(f"[CBC] IV reused -> first blocks equal? {c1_first == c2_first}")
    diff = int.from_bytes(c1_first, "big") ^ int.from_bytes(c2_first, "big")
    print(f"[CBC] C1^C1' (hex): {diff:032x}")

def demo_gcm_nonce_reuse():
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    aad = b"hdr"
    p1 = b"GCM message one"
    p2 = b"GCM message two"
    n1, c1, t1 = aes_gcm_encrypt(key, p1, aad=aad, nonce=nonce)
    n2, c2, t2 = aes_gcm_encrypt(key, p2, aad=aad, nonce=nonce)
    print(f"[GCM] Nonce reused -> tags equal? {t1 == t2}")
    try:
        _ = aes_gcm_decrypt(key, n1, c1, t2, aad=aad)
        print("[GCM] Unexpectedly verified with wrong tag (should not happen).")
    except Exception as e:
        print(f"[GCM] Verification with wrong tag failed as expected: {type(e).__name__}")

def roundtrip_checks():
    key = get_random_bytes(16)
    msg = b"hello world! " * 5
    cte = aes_ecb_encrypt(key, msg)
    assert aes_ecb_decrypt(key, cte) == msg
    ctc = aes_cbc_encrypt(key, msg)
    assert aes_cbc_decrypt(key, ctc) == msg
    nonce, ctg, tag = aes_gcm_encrypt(key, msg, aad=b"meta")
    assert aes_gcm_decrypt(key, nonce, ctg, tag, aad=b"meta") == msg
    print("[Roundtrip] ECB, CBC, GCM all OK")

if __name__ == "__main__":
    print("== AES Demos ==")
    roundtrip_checks()
    demo_ecb_pattern_leakage()
    demo_cbc_iv_reuse()
    demo_gcm_nonce_reuse()
    print("Done.")
