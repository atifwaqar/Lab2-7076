"""
Minimal scaffold for Bleichenbacher's padding oracle attack (PKCS#1 v1.5).

This file provides:

* A toy RSA key
* A padding/validation oracle that ONLY reveals padding-valid/invalid
* A placeholder for the adaptive attack loop

It runs and demonstrates the oracle behavior.
"""

import logging
import secrets
import sys
import time
from math import gcd
from pathlib import Path

try:
    from rsa.rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int
except ModuleNotFoundError:  # pragma: no cover - convenience for direct execution
    sys.path.append(str(Path(__file__).resolve().parents[1] / "rsa"))
    from rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int


logger = logging.getLogger(__name__)


def bleichenbacher_attack(
    c0: int,
    e: int,
    n: int,
    k: int,
    oracle,
    fast_oracle=None,
) -> bytes:
    """Recover the padded message using Bleichenbacher's adaptive attack."""

    def ceil_div(num: int, den: int) -> int:
        return -(-num // den)

    def floor_div(num: int, den: int) -> int:
        return num // den

    B = 1 << (8 * (k - 2))
    two_B = 2 * B
    three_B = 3 * B

    # Initial state
    M = [(two_B, three_B - 1)]
    s = None
    i = 1
    rounds = 0
    MAX_ROUNDS = 200_000  # safety guard for demos

    fast_mode = fast_oracle is not None

    def query(s_candidate: int, *, fast: bool = False) -> bool:
        # ensure s is invertible mod n (s ∈ Z*_n)
        if gcd(s_candidate, n) != 1:
            return False
        c_test = (c0 * pow(s_candidate, e, n)) % n
        if fast and fast_mode:
            return fast_oracle(c_test)
        return oracle(c_test)

    if fast_mode:
        logger.info(
            "Fast oracle enabled: Step 2 uses prefix-only padding checks before"
            " switching back to the strict oracle."
        )

    while True:
        rounds += 1
        if rounds > MAX_ROUNDS:
            raise RuntimeError("Attack did not converge within MAX_ROUNDS")

        logger.info("Iteration %d: %d interval(s) remaining", i, len(M))
        if i == 1:
            # Step 2.a: search for the first valid s
            base = ceil_div(n, three_B)
            s = base
            limit = base + 40000
            logger.info(
                "Step 2a: searching for initial s starting at %d (limit %d)",
                base,
                limit,
            )
            attempts = 0
            start = time.perf_counter()
            while s < limit:
                attempts += 1
                if query(s, fast=True):
                    logger.info(
                        "Step 2a: found s=%d after %d attempts in %.3fs",
                        s,
                        attempts,
                        time.perf_counter() - start,
                    )
                    break
                s += 1
            else:
                # Deterministic fallback: continue linear search from current s
                logger.info(
                    "Step 2a fallback: switching to deterministic linear search from s=%d",
                    s,
                )
                start = time.perf_counter()
                more = 0
                last_log = start
                while not query(s, fast=True):
                    s += 1
                    more += 1
                    now = time.perf_counter()
                    if more % 5000 == 0 or now - last_log >= 1.0:
                        logger.info(
                            "Step 2a fallback: searching... +%d candidates (s=%d, elapsed=%.3fs)",
                            more,
                            s,
                            now - start,
                        )
                        last_log = now
                logger.info(
                    "Step 2a fallback: found s=%d after total %d attempts in %.3fs",
                    s,
                    attempts + more,
                    time.perf_counter() - start,
                )
        elif len(M) >= 2:
            # Step 2.b: when there are multiple intervals, incrementally search
            start = time.perf_counter()
            attempts = 0
            s += 1
            last_log = start
            while not query(s, fast=True):
                attempts += 1
                s += 1
                now = time.perf_counter()
                if attempts % 5000 == 0 or now - last_log >= 1.0:
                    logger.info(
                        "Step 2b: searching... attempts=%d elapsed=%.3fs",
                        attempts,
                        now - start,
                    )
                    last_log = now
            logger.info(
                "Step 2b: found s=%d after %d increments in %.3fs",
                s,
                attempts,
                time.perf_counter() - start,
            )
        else:
            # Step 2.c: single interval, use focused search on r
            a, b = M[0]
            r = ceil_div(2 * (b * s - two_B), n)
            logger.info(
                "Step 2c: focused search with initial r=%d for interval [%d, %d]",
                r,
                a,
                b,
            )
            while True:
                s_low = ceil_div(two_B + r * n, b)
                s_high = floor_div(three_B - 1 + r * n, a)
                if s_low > s_high:
                    r += 1
                    continue
                start = time.perf_counter()
                attempts = 0
                last_log = start
                for s_candidate in range(s_low, s_high + 1):
                    attempts += 1
                    if query(s_candidate):
                        s = s_candidate
                        logger.info(
                            "Step 2c: found s=%d within range [%d, %d] after %d attempts in %.3fs",
                            s,
                            s_low,
                            s_high,
                            attempts,
                            time.perf_counter() - start,
                        )
                        break
                    now = time.perf_counter()
                    if attempts % 2000 == 0 or now - last_log >= 1.0:
                        logger.info(
                            "Step 2c: searching range [%d, %d] (attempts=%d elapsed=%.3fs)",
                            s_low,
                            s_high,
                            attempts,
                            now - start,
                        )
                        last_log = now
                else:
                    r += 1
                    continue
                break

        # Step 3: Narrow the set of intervals
        new_M = []
        for a, b in M:
            r_min = ceil_div(a * s - three_B + 1, n)
            r_max = floor_div(b * s - two_B, n)
            if r_min > r_max:
                continue
            # guard against runaway ranges (prevents MemoryError)
            if r_max - r_min > 2_000_000:
                raise RuntimeError("r-range too large; check k/B/oracle correctness.")
            for r in range(r_min, r_max + 1):
                new_a = max(a, ceil_div(two_B + r * n, s))
                new_b = min(b, floor_div(three_B - 1 + r * n, s))
                if new_a <= new_b:
                    new_M.append((new_a, new_b))

        if not new_M:
            raise RuntimeError("Interval refinement failed – no candidates remain")

        # Merge overlapping intervals to avoid an explosion in the candidate list.
        new_M.sort()
        merged: list[tuple[int, int]] = []
        for start, end in new_M:
            if not merged:
                merged.append((start, end))
                continue
            prev_start, prev_end = merged[-1]
            # merge overlapping OR adjacent intervals
            if start <= prev_end + 1:
                merged[-1] = (prev_start, max(prev_end, end))
            else:
                merged.append((start, end))

        M = merged
        logger.info(
            "Step 3: refined to %d interval(s); smallest width=%d", 
            len(M),
            min((b - a) for a, b in M),
        )

        # Step 4: check if the interval collapsed
        if len(M) == 1:
            a, b = M[0]
            if a == b:
                m = a
                em = os2ip(m, length=k)
                logger.info("Step 4: interval collapsed; recovered message.")
                return pkcs1v15_unpad(em)

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

def oracle_padding_valid_prefix(c: int, d: int, n: int, k: int) -> bool:
    """
    Fast/loose oracle: only checks that EM begins with 0x00 0x02.
    This is NON-COMPLIANT and only for demo speed-ups.
    """
    m = decrypt_int(c, d, n)
    em = os2ip(m, length=k)
    return len(em) >= 2 and em.startswith(b"\x00\x02")

def demo_oracle(use_fast: bool = False, bits: int = 96, e: int = 3):
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logger.info("Starting Bleichenbacher oracle demo")
    while True:
        try:
            n, e, d = generate_key(bits, e=e)
            break
        except ValueError:
            continue
    logger.info("Generated RSA modulus n with %d bits", n.bit_length())
    k = (n.bit_length() + 7) // 8

    pt = b"A"
    em = pkcs1v15_pad(pt, k)
    c = encrypt_int(i2osp(em), e, n)

    print(f"Oracle says padding valid? {oracle_padding_valid(c, d, n, k)} (expected True)")
    c_bad = (c ^ 2) % n
    print(f"Oracle says padding valid (tampered)? {oracle_padding_valid(c_bad, d, n, k)}")

    fast_cb = (lambda ct: oracle_padding_valid_prefix(ct, d, n, k)) if use_fast else None
    recovered = bleichenbacher_attack(
        c,
        e,
        n,
        k,
        oracle=lambda ct: oracle_padding_valid(ct, d, n, k),
        fast_oracle=fast_cb,
    )
    logger.info("Attack completed")
    print(f"Recovered plaintext: {recovered!r}")
    print(f"Success? {recovered == pt}")

if __name__ == "__main__":
    demo_oracle()
