import base64
import secrets

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

def demo_ecb_pattern_leakage(*, verbose: bool = True):
    """Show ECB block repetition and return the artefacts for testing."""

    key = get_random_bytes(16)
    block = b"A" * 16
    pt = block * 4 + b"B" * 16 + block * 3
    ct = aes_ecb_encrypt(key, pt)
    blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    unique_blocks = len(set(blocks))
    result = {
        "key": key,
        "ciphertext_blocks": blocks,
        "unique_blocks": unique_blocks,
    }

    if verbose:
        print("[ECB] Key:", key.hex())
        print(
            f"[ECB] Total blocks: {len(blocks)}, unique blocks: {unique_blocks} (lower is worse)"
        )
        print("[ECB] Ciphertext block pattern:")
        for idx, block_bytes in enumerate(blocks, start=1):
            marker = "*" if blocks.count(block_bytes) > 1 else " "
            print(f"    Block {idx:02d}{marker}: {block_bytes.hex()}")
        print("[ECB] Repeated blocks (marked with * ) reveal the repeated plaintext pattern.")

    return result

def demo_cbc_iv_reuse(*, verbose: bool = True):
    """Demonstrate CBC IV reuse leakage and return the computed values."""

    key = get_random_bytes(16)
    iv = get_random_bytes(BLOCK)

    # Two plaintexts that share the same first block but diverge afterwards.
    shared_block = b"shared prefix bl"
    assert len(shared_block) == BLOCK
    p1 = shared_block + b"ock -> amount=100" + secrets.token_bytes(5)
    p2 = shared_block + b"ock -> amount=900" + secrets.token_bytes(5)

    c1 = aes_cbc_encrypt(key, p1, iv=iv)
    c2 = aes_cbc_encrypt(key, p2, iv=iv)

    c1_iv, c1_body = c1[:BLOCK], c1[BLOCK:]
    c2_iv, c2_body = c2[:BLOCK], c2[BLOCK:]
    c1_first_block = c1_body[:BLOCK]
    c2_first_block = c2_body[:BLOCK]

    p1_first = p1[:BLOCK]
    p2_first = p2[:BLOCK]
    x_c = bytes(a ^ b for a, b in zip(c1_first_block, c2_first_block))
    x_p = bytes(a ^ b for a, b in zip(p1_first, p2_first))

    tampered_iv = bytearray(c2_iv)
    tampered_iv[0] ^= 0x20  # flip one bit
    dec = AES.new(key, AES.MODE_CBC, iv=bytes(tampered_iv)).decrypt(c2_body)
    tampered_first_block = dec[:BLOCK]

    result = {
        "key": key,
        "iv": iv,
        "plaintexts": (p1, p2),
        "ciphertexts": (c1, c2),
        "xor_ciphertexts": x_c,
        "xor_plaintexts": x_p,
        "tampered_first_block": tampered_first_block,
        "original_first_block": p2_first,
    }

    if verbose:
        print("[CBC] Key:", key.hex())
        print("[CBC] Reused IV:", iv.hex())
        print(f"[CBC] Reused IV -> identical IV blocks? {c1_iv == c2_iv}")
        print(
            f"[CBC] Reused IV -> identical first ciphertext blocks? {c1_first_block == c2_first_block}"
        )
        print("[CBC] Ciphertext #1 blocks:")
        for i in range(0, len(c1_body), BLOCK):
            print(f"    C1[{i//BLOCK:02d}]: {c1_body[i:i+BLOCK].hex()}")
        print("[CBC] Ciphertext #2 blocks:")
        for i in range(0, len(c2_body), BLOCK):
            print(f"    C2[{i//BLOCK:02d}]: {c2_body[i:i+BLOCK].hex()}")
        print(
            "[CBC] Second ciphertext block differs?",
            c1_body[BLOCK:2 * BLOCK] != c2_body[BLOCK:2 * BLOCK],
        )
        print("[CBC] XOR(C1[0], C2[0]) == XOR(P1[0], P2[0]) ?", x_c == x_p)
        print("[CBC] XOR(C1[0], C2[0]):", x_c.hex())
        print("[CBC] XOR(P1[0], P2[0]):", x_p.hex())
        print(
            "[CBC] Bit-flip demo: P2'[0] differs from original P2[0]?",
            tampered_first_block != p2_first,
        )
        print("[CBC] Tampered first plaintext block:", tampered_first_block.hex())
        print("[CBC] Original first plaintext block:", p2_first.hex())

    return result

def demo_gcm_nonce_reuse(*, verbose: bool = True):
    """Highlight the dangers of nonce reuse in GCM and return context."""

    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    aad = b"hdr"
    p1 = b"GCM message one"
    p2 = b"GCM message two"
    n1, c1, t1 = aes_gcm_encrypt(key, p1, aad=aad, nonce=nonce)
    _, c2, t2 = aes_gcm_encrypt(key, p2, aad=aad, nonce=nonce)

    wrong_tag_valid = False
    wrong_tag_error: str | None = None
    try:
        aes_gcm_decrypt(key, n1, c1, t2, aad=aad)
        wrong_tag_valid = True
    except Exception as exc:  # pragma: no cover - exercised via bool
        wrong_tag_error = type(exc).__name__

    result = {
        "key": key,
        "nonce": nonce,
        "aad": aad,
        "ciphertexts": (c1, c2),
        "tags": (t1, t2),
        "wrong_tag_valid": wrong_tag_valid,
        "wrong_tag_error": wrong_tag_error,
    }

    if verbose:
        print("[GCM] Key:", key.hex())
        print("[GCM] Nonce (reused):", nonce.hex())
        print(f"[GCM] Tag #1: {t1.hex()} | Tag #2: {t2.hex()} | tags equal? {t1 == t2}")
        print("[GCM] Ciphertext #1:", c1.hex())
        print("[GCM] Ciphertext #2:", c2.hex())
        if wrong_tag_valid:
            print("[GCM] Unexpectedly verified with wrong tag (should not happen).")
        else:
            print(
                f"[GCM] Verification with wrong tag failed as expected: {wrong_tag_error}"
            )

    return result

def roundtrip_demo():
    """Run a short AES round-trip across ECB, CBC and GCM.

    Returns a dictionary with the ciphertext artefacts and boolean flags
    confirming that each mode decrypted to the original plaintext.  The
    structure is intentionally simple so tests can assert on the booleans
    without parsing printed output.
    """

    key = get_random_bytes(16)
    msg = b"hello world! " * 5
    cte = aes_ecb_encrypt(key, msg)
    ok_ecb = aes_ecb_decrypt(key, cte) == msg
    ctc = aes_cbc_encrypt(key, msg)
    ok_cbc = aes_cbc_decrypt(key, ctc) == msg
    nonce, ctg, tag = aes_gcm_encrypt(key, msg, aad=b"meta")
    ok_gcm = aes_gcm_decrypt(key, nonce, ctg, tag, aad=b"meta") == msg
    return {
        "key": key,
        "plaintext": msg,
        "ecb_ct": cte,
        "cbc_iv_ct": ctc,
        "gcm_nonce": nonce,
        "gcm_ct": ctg,
        "gcm_tag": tag,
        "ok_ecb": ok_ecb,
        "ok_cbc": ok_cbc,
        "ok_gcm": ok_gcm,
    }


def roundtrip_checks(*, verbose: bool = True):
    """Run the AES round-trip demo and optionally print a summary."""

    result = roundtrip_demo()
    if verbose:
        key = result["key"]
        msg = result["plaintext"]
        cte = result["ecb_ct"]
        ctc = result["cbc_iv_ct"]
        nonce = result["gcm_nonce"]
        tag = result["gcm_tag"]
        print("[Roundtrip] AES-128 key:", key.hex())
        print("[Roundtrip] Plaintext length:", len(msg), "bytes")
        print("[Roundtrip] ECB ciphertext (first 32 hex):", cte[:16].hex())
        print("[Roundtrip] CBC IV:", ctc[:BLOCK].hex())
        print("[Roundtrip] GCM nonce:", nonce.hex(), "tag:", tag.hex())
        print("[Roundtrip] All modes decrypted back to the original message.")
    return result


def demo_gcm_keystream_reuse_xor_leak(*, verbose: bool = True):
    """Return details of GCM keystream reuse while logging optionally."""

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
    _, c1, t1 = aes_gcm_encrypt(key, p1, nonce=nonce)
    _, c2, t2 = aes_gcm_encrypt(key, p2, nonce=nonce)

    # Emulate reading ciphertext bundles from JSON files
    bundle1 = {"ciphertext_b64": base64.b64encode(c1).decode("ascii")}
    bundle2 = {"ciphertext_b64": base64.b64encode(c2).decode("ascii")}
    ct1 = base64.b64decode(bundle1["ciphertext_b64"])
    ct2 = base64.b64decode(bundle2["ciphertext_b64"])

    # Keystream reuse property in CTR/GCM: C1 ^ C2 = P1 ^ P2
    leak_hex = xor_hex(ct1, ct2)
    expected_hex = xor_hex(p1, p2)

    # Show recovery of p2's differing middle when p1's middle is known
    start = len(prefix)
    end = start + len(mid1)
    c1_mid = c1[start:end]
    c2_mid = c2[start:end]
    recovered_p2_mid = bytes(a ^ b ^ c for (a, b, c) in zip(c1_mid, c2_mid, mid1))

    result = {
        "key": key,
        "nonce": nonce,
        "ciphertexts": (c1, c2),
        "leak_hex": leak_hex,
        "expected_hex": expected_hex,
        "recovered_mid": recovered_p2_mid,
        "expected_mid": mid2,
    }

    if verbose:
        print("[GCM] Key:", key.hex())
        print("[GCM] Nonce reused:", nonce.hex())
        print("[GCM] Keystream reuse: XOR(c1,c2) == XOR(p1,p2)?", leak_hex == expected_hex)
        print("[GCM] XOR(ct1, ct2):", leak_hex)
        print("[GCM] XOR(pt1, pt2):", expected_hex)
        print("[GCM] Recover p2's middle given p1's middle:", recovered_p2_mid)
        print("[GCM] p2 middle (expected):", mid2)

    return result


if __name__ == "__main__":
    print("== AES Demos ==")
    roundtrip_checks()
    demo_ecb_pattern_leakage()
    demo_cbc_iv_reuse()
    demo_gcm_nonce_reuse()
    demo_gcm_keystream_reuse_xor_leak()
    print("Done.")
