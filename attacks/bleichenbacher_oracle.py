"""
Minimal scaffold for Bleichenbacher's padding oracle attack (PKCS#1 v1.5).

This file is OPTIONAL for higher grades. It provides:

* A toy RSA key
* A padding/validation oracle that ONLY reveals padding-valid/invalid
* A placeholder for the adaptive attack loop (TODO)

It runs and demonstrates the oracle behavior, but the full attack is left as TODOs.
"""

import math
import secrets
import sys
from pathlib import Path

try:
    from rsa.rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int
except ModuleNotFoundError:  # pragma: no cover - convenience for direct execution
    sys.path.append(str(Path(__file__).resolve().parents[1] / "rsa"))
    from rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int


def bleichenbacher_attack(c0: int, e: int, n: int, k: int, oracle) -> bytes:
    """Recover the padded message using Bleichenbacher's adaptive attack."""

    B = 1 << (8 * (k - 2))
    two_B = 2 * B
    three_B = 3 * B

    # Initial state
    M = [(two_B, three_B - 1)]
    s = None
    i = 1

    def query(s_candidate: int) -> bool:
        c_test = (c0 * pow(s_candidate, e, n)) % n
        return oracle(c_test)

    while True:
        if i == 1:
            # Step 2.a: search for the first valid s
            base = math.ceil(n / three_B)
            s = base
            while s < base + 5000:
                if query(s):
                    break
                s += 1
            else:
                while True:
                    s = secrets.randbelow(n)
                    if s < base:
                        continue
                    if query(s):
                        break
        elif len(M) >= 2:
            # Step 2.b: when there are multiple intervals, incrementally search
            s += 1
            while not query(s):
                s += 1
        else:
            # Step 2.c: single interval, use focused search on r
            a, b = M[0]
            r = math.ceil((2 * (b * s - two_B)) / n)
            while True:
                s_low = math.ceil((two_B + r * n) / b)
                s_high = math.floor((three_B - 1 + r * n) / a)
                if s_low > s_high:
                    r += 1
                    continue
                for s_candidate in range(s_low, s_high + 1):
                    if query(s_candidate):
                        s = s_candidate
                        break
                else:
                    r += 1
                    continue
                break

        # Step 3: Narrow the set of intervals
        new_M = []
        for a, b in M:
            r_min = math.ceil((a * s - three_B + 1) / n)
            r_max = math.floor((b * s - two_B) / n)
            if r_min > r_max:
                continue
            for r in range(r_min, r_max + 1):
                new_a = max(a, math.ceil((two_B + r * n) / s))
                new_b = min(b, math.floor((three_B - 1 + r * n) / s))
                if new_a <= new_b:
                    new_M.append((new_a, new_b))
        M = new_M

        # Step 4: check if the interval collapsed
        if len(M) == 1:
            a, b = M[0]
            if a == b:
                m = a
                padded = os2ip(m, length=k)
                return pkcs1v15_unpad(padded)

        i += 1


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
    while True:
        try:
            n, e, d = generate_key(96, e=3)
            break
        except ValueError:
            continue
    k = (n.bit_length() + 7) // 8
    pt = b"A"
    em = pkcs1v15_pad(pt, k)
    c = encrypt_int(i2osp(em), e, n)
    valid = oracle_padding_valid(c, d, n, k)
    print(f"Oracle says padding valid? {valid} (expected True)")
    c_bad = (c ^ 2) % n
    print(f"Oracle says padding valid (tampered)? {oracle_padding_valid(c_bad, d, n, k)}")
    recovered = bleichenbacher_attack(
        c,
        e,
        n,
        k,
        lambda ct: oracle_padding_valid(ct, d, n, k),
    )
    print(f"Recovered plaintext: {recovered!r}")
    print(f"Success? {recovered == pt}")

if __name__ == "__main__":
    demo_oracle()
