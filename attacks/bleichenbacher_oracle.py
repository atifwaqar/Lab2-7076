"""
Minimal scaffold for Bleichenbacher's padding oracle attack (PKCS#1 v1.5).

This file is OPTIONAL for higher grades. It provides:

* A toy RSA key
* A padding/validation oracle that ONLY reveals padding-valid/invalid
* A placeholder for the adaptive attack loop (TODO)

It runs and demonstrates the oracle behavior, but the full attack is left as TODOs.
"""

import secrets
from rsa.rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int

def pkcs1v15_pad(msg: bytes, k: int) -> bytes:
    """
    Encodes: 0x00 0x02 PS 0x00 M
    k = length of modulus in bytes
    """
    if len(msg) > k - 11:
        raise ValueError("message too long")
    ps_len = k - len(msg) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b
    return b"\x00\x02" + bytes(ps) + b"\x00" + msg

def pkcs1v15_unpad(em: bytes) -> bytes:
    if len(em) < 11 or not em.startswith(b"\x00\x02"):
        raise ValueError("Invalid padding")
    try:
        sep = em.index(b"\x00", 2)
    except ValueError as exc:
        raise ValueError("Invalid padding") from exc
    if sep < 10:
        raise ValueError("Invalid padding")
    return em[sep + 1:]

def oracle_padding_valid(c: int, d: int, n: int, k: int) -> bool:
    m = decrypt_int(c, d, n)
    em = os2ip(m, length=k)
    try:
        _ = pkcs1v15_unpad(em)
        return True
    except ValueError:
        return False

def demo_oracle():
    n, e, d = generate_key(512)
    k = (n.bit_length() + 7) // 8
    pt = b"secret"
    em = pkcs1v15_pad(pt, k)
    c = encrypt_int(i2osp(em), e, n)
    valid = oracle_padding_valid(c, d, n, k)
    print(f"Oracle says padding valid? {valid} (expected True)")
    c_bad = (c ^ 2) % n
    print(f"Oracle says padding valid (tampered)? {oracle_padding_valid(c_bad, d, n, k)}")
    # TODO: Implement the adaptive attack (interval narrowing with s multipliers)
    # Steps outline:
    # 1) Find s1 such that (c * s1^e mod n) decrypts to a valid padded block.
    # 2) Maintain [a,b] interval and iterate to narrow down to the plaintext.
    # 3) Stop when a == b.

if __name__ == "__main__":
    demo_oracle()
