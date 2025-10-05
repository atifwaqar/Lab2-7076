import base64
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK = 16


def xor_hex(a: bytes, b: bytes) -> str:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n])).hex()

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
    print("[ECB] Key:", key.hex())
    print(f"[ECB] Total blocks: {len(blocks)}, unique blocks: {unique_blocks} (lower is worse)")
    print("[ECB] Ciphertext block pattern:")
    for idx, block_bytes in enumerate(blocks, start=1):
        marker = "*" if blocks.count(block_bytes) > 1 else " "
        print(f"    Block {idx:02d}{marker}: {block_bytes.hex()}")
    print("[ECB] Repeated blocks (marked with * ) reveal the repeated plaintext pattern.")

def demo_cbc_iv_reuse():
    key = get_random_bytes(16)
    iv = get_random_bytes(BLOCK)

    # Two plaintexts that share the same first block but diverge afterwards.
    shared_block = b"shared prefix bl"
    assert len(shared_block) == BLOCK
    p1 = shared_block + b"ock -> amount=100" + os.urandom(5)
    p2 = shared_block + b"ock -> amount=900" + os.urandom(5)

    c1 = aes_cbc_encrypt(key, p1, iv=iv)
    c2 = aes_cbc_encrypt(key, p2, iv=iv)

    c1_iv, c1_body = c1[:BLOCK], c1[BLOCK:]
    c2_iv, c2_body = c2[:BLOCK], c2[BLOCK:]
    c1_first_block = c1_body[:BLOCK]
    c2_first_block = c2_body[:BLOCK]

    print("[CBC] Key:", key.hex())
    print("[CBC] Reused IV:", iv.hex())
    print(f"[CBC] Reused IV -> identical IV blocks? {c1_iv == c2_iv}")
    print(f"[CBC] Reused IV -> identical first ciphertext blocks? {c1_first_block == c2_first_block}")
    print("[CBC] Ciphertext #1 blocks:")
    for i in range(0, len(c1_body), BLOCK):
        print(f"    C1[{i//BLOCK:02d}]: {c1_body[i:i+BLOCK].hex()}")
    print("[CBC] Ciphertext #2 blocks:")
    for i in range(0, len(c2_body), BLOCK):
        print(f"    C2[{i//BLOCK:02d}]: {c2_body[i:i+BLOCK].hex()}")
    print("[CBC] Second ciphertext block differs?", c1_body[BLOCK:2*BLOCK] != c2_body[BLOCK:2*BLOCK])

    # Show the classic leakage equation for CBC with reused IV:
    # C1[0] ^ C2[0] == P1[0] ^ P2[0]
    p1_first = p1[:BLOCK]
    p2_first = p2[:BLOCK]
    x_c = bytes(a ^ b for a, b in zip(c1_first_block, c2_first_block))
    x_p = bytes(a ^ b for a, b in zip(p1_first, p2_first))
    print("[CBC] XOR(C1[0], C2[0]) == XOR(P1[0], P2[0]) ?", x_c == x_p)
    print("[CBC] XOR(C1[0], C2[0]):", x_c.hex())
    print("[CBC] XOR(P1[0], P2[0]):", x_p.hex())

    # Demonstrate bit-flipping attack on CBC first block via IV tampering
    # Flip a bit in IV and decrypt c2 under the tampered IV;
    # the corresponding bit in P2'[0] will flip.
    from Crypto.Cipher import AES as _AES

    tampered_iv = bytearray(c2_iv)
    tampered_iv[0] ^= 0x20  # flip one bit
    dec = _AES.new(key, _AES.MODE_CBC, iv=bytes(tampered_iv)).decrypt(c2_body)
    tampered_first_block = dec[:BLOCK]
    print("[CBC] Bit-flip demo: P2'[0] differs from original P2[0]?", tampered_first_block != p2_first)
    print("[CBC] Tampered first plaintext block:", tampered_first_block.hex())
    print("[CBC] Original first plaintext block:", p2_first.hex())

def demo_gcm_nonce_reuse():
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    aad = b"hdr"
    p1 = b"GCM message one"
    p2 = b"GCM message two"
    n1, c1, t1 = aes_gcm_encrypt(key, p1, aad=aad, nonce=nonce)
    n2, c2, t2 = aes_gcm_encrypt(key, p2, aad=aad, nonce=nonce)
    print("[GCM] Key:", key.hex())
    print("[GCM] Nonce (reused):", nonce.hex())
    print(f"[GCM] Tag #1: {t1.hex()} | Tag #2: {t2.hex()} | tags equal? {t1 == t2}")
    print("[GCM] Ciphertext #1:", c1.hex())
    print("[GCM] Ciphertext #2:", c2.hex())
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
    print("[Roundtrip] AES-128 key:", key.hex())
    print("[Roundtrip] Plaintext length:", len(msg), "bytes")
    print("[Roundtrip] ECB ciphertext (first 32 hex):", cte[:16].hex())
    print("[Roundtrip] CBC IV:", ctc[:BLOCK].hex())
    print("[Roundtrip] GCM nonce:", nonce.hex(), "tag:", tag.hex())
    print("[Roundtrip] All modes decrypted back to the original message.")


def demo_gcm_keystream_reuse_xor_leak():
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)  # BAD: reused nonce
    # Construct messages: identical except a middle slice differs
    prefix = b"A" * 32
    mid1 = b"TOPSECRET"
    mid2 = b"REDACTED!"
    suffix = b"A" * 32
    p1 = prefix + mid1 + suffix
    p2 = prefix + mid2 + suffix

    # Same key + SAME nonce (this is the vulnerability)
    n1, c1, t1 = aes_gcm_encrypt(key, p1, nonce=nonce)
    n2, c2, t2 = aes_gcm_encrypt(key, p2, nonce=nonce)

    # Emulate reading ciphertext bundles from JSON files
    bundle1 = {"ciphertext_b64": base64.b64encode(c1).decode("ascii")}
    bundle2 = {"ciphertext_b64": base64.b64encode(c2).decode("ascii")}
    ct1 = base64.b64decode(bundle1["ciphertext_b64"])
    ct2 = base64.b64decode(bundle2["ciphertext_b64"])

    # Keystream reuse property in CTR/GCM: C1 ^ C2 = P1 ^ P2
    leak_hex = xor_hex(ct1, ct2)
    expected_hex = xor_hex(p1, p2)
    print("[GCM] Key:", key.hex())
    print("[GCM] Nonce reused:", nonce.hex())
    print("[GCM] Keystream reuse: XOR(c1,c2) == XOR(p1,p2)?", leak_hex == expected_hex)
    print("[GCM] XOR(ct1, ct2):", leak_hex)
    print("[GCM] XOR(pt1, pt2):", expected_hex)

    # Show recovery of p2's differing middle when p1's middle is known
    start = len(prefix)
    end = start + len(mid1)
    c1_mid = c1[start:end]
    c2_mid = c2[start:end]
    recovered_p2_mid = bytes(a ^ b ^ c for (a, b, c) in zip(c1_mid, c2_mid, mid1))
    print("[GCM] Recover p2's middle given p1's middle:", recovered_p2_mid)
    print("[GCM] p2 middle (expected):", mid2)


if __name__ == "__main__":
    print("== AES Demos ==")
    roundtrip_checks()
    demo_ecb_pattern_leakage()
    demo_cbc_iv_reuse()
    demo_gcm_nonce_reuse()
    demo_gcm_keystream_reuse_xor_leak()
    print("Done.")
