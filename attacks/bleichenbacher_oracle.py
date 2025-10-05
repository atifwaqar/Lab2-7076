"""
Bleichenbacher PKCS#1 v1.5 padding-oracle (demo)
Implements:
  Step 1: Blinding                      (RFC-style numbering)
  Step 2a: Search for initial s         (padding-valid c' = c * s^e mod n)
  Step 2b: If multiple intervals, increase s linearly
  Step 2c: Focused search using r       (ceil((2B + rn)/M_max) .. (3B + rn - 1)/M_min)
  Step 3: Narrow M intervals
  Step 4: Recover m when |M|=1 and bounds meet
Logging lines like "Step 2c: found s=..." correspond to these phases.
"""

import logging
import secrets
import sys
import time
from dataclasses import dataclass
from math import gcd
from pathlib import Path
from typing import List, Sequence

try:
    from rsa.rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int
except ModuleNotFoundError:  # pragma: no cover - convenience for direct execution
    sys.path.append(str(Path(__file__).resolve().parents[1] / "rsa"))
    from rsa_from_scratch import generate_key, i2osp, os2ip, encrypt_int, decrypt_int


logger = logging.getLogger(__name__)


@dataclass
class IterationStats:
    """Telemetry for a single Bleichenbacher iteration."""

    iteration: int
    intervals: int
    min_width: int
    s: int
    queries_this_iter: int
    total_queries: int


def bleichenbacher_attack(
    c0: int,
    e: int,
    n: int,
    k: int,
    oracle,
    fast_oracle=None,
    *,
    return_trace: bool = False,
) -> bytes | tuple[bytes, Sequence[IterationStats]]:
    """Recover the padded message using Bleichenbacher's adaptive attack.

    When ``return_trace`` is ``True`` the function also returns the
    per-iteration telemetry that can be graphed to visualise convergence.
    """

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

    telemetry: List[IterationStats] = []
    query_count = 0

    def query(s_candidate: int, *, fast: bool = False) -> bool:
        nonlocal query_count
        # ensure s is invertible mod n (s ∈ Z*_n)
        if gcd(s_candidate, n) != 1:
            return False
        c_test = (c0 * pow(s_candidate, e, n)) % n
        if fast and fast_mode:
            result = fast_oracle(c_test)
        else:
            result = oracle(c_test)
        query_count += 1
        return result

    if fast_mode:
        logger.info(
            "Fast oracle enabled: Step 2 uses prefix-only padding checks before"
            " switching back to the strict oracle."
        )

    while True:
        rounds += 1
        if rounds > MAX_ROUNDS:
            raise RuntimeError("Attack did not converge within MAX_ROUNDS")

        queries_before = query_count
        logger.info("Iteration %d: %d interval(s) remaining", i, len(M))
        if i == 1:
            # -- Step 2a: initial s search
            base = ceil_div(n, three_B)
            s = base
            # About 1 in 2^16 s candidates will decrypt to a value that begins
            # with 0x0002, so the initial successful query typically appears
            # after tens of thousands of tries for toy moduli.
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
            # -- Step 2b: linear search when multiple intervals remain
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
            # -- Step 2c: focused search with r and bounds
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

        # -- Step 3: intervals narrowing (M update)
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
        min_width = min((b - a) for a, b in M)
        if return_trace:
            telemetry.append(
                IterationStats(
                    iteration=i,
                    intervals=len(M),
                    min_width=min_width,
                    s=s if s is not None else 0,
                    queries_this_iter=query_count - queries_before,
                    total_queries=query_count,
                )
            )
        logger.info(
            "Step 3: refined to %d interval(s); smallest width=%d",
            len(M),
            min_width,
        )

        # -- Step 4: recover m when interval collapses
        if len(M) == 1:
            a, b = M[0]
            if a == b:
                m = a
                em = os2ip(m, length=k)
                logger.info("Step 4: interval collapsed; recovered message.")
                plaintext = pkcs1v15_unpad(em)
                logger.info(
                    "Attack summary: %d oracle queries across %d iterations.",
                    query_count,
                    i,
                )
                if return_trace:
                    return plaintext, telemetry
                return plaintext

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

def oracle_padding_valid(
    c: int,
    d: int,
    n: int,
    e: int,
    k: int,
    *,
    use_blinding: bool = False,
) -> bool:
    m = decrypt_int(c, d, n, e=e, use_blinding=use_blinding)
    em = os2ip(m, length=k)
    try:
        _ = pkcs1v15_unpad(em)
        return True
    except ValueError:
        return False

def oracle_padding_valid_prefix(
    c: int,
    d: int,
    n: int,
    e: int,
    k: int,
    *,
    use_blinding: bool = False,
) -> bool:
    """
    Fast/loose oracle: only checks that EM begins with 0x00 0x02.
    This is NON-COMPLIANT and only for demo speed-ups.
    """
    m = decrypt_int(c, d, n, e=e, use_blinding=use_blinding)
    em = os2ip(m, length=k)
    return len(em) >= 2 and em.startswith(b"\x00\x02")

def plot_interval_convergence(
    stats: Sequence[IterationStats], destination: str | Path
) -> Path:
    """Plot the minimum interval width per iteration on a log scale."""

    if not stats:
        raise ValueError("No iteration telemetry to plot")

    import matplotlib.pyplot as plt

    iterations = [entry.iteration for entry in stats]
    min_widths = [entry.min_width for entry in stats]

    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    ax.plot(iterations, min_widths, marker="o", linewidth=1.5)
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Minimum interval width |b - a|")
    ax.set_yscale("log")
    ax.set_title("Bleichenbacher interval convergence")
    ax.grid(True, which="both", linestyle="--", linewidth=0.5, alpha=0.6)

    destination = Path(destination)
    fig.tight_layout()
    fig.savefig(destination, bbox_inches="tight")
    plt.close(fig)
    return destination


def demo_oracle(
    use_fast: bool = False,
    bits: int = 96,
    e: int = 3,
    *,
    plot_path: str | Path | None = None,
    log_level: int | str = logging.INFO,
):
    if isinstance(log_level, str):
        level_value = getattr(logging, log_level.upper(), logging.INFO)
    else:
        level_value = log_level

    logging.basicConfig(
        level=level_value,
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
    print(f"n ({n.bit_length()} bits): 0x{n:x}")
    print(f"Public exponent e: {e}")
    print(f"Private exponent d: 0x{d:x}")
    print(f"Modulus length k: {k} bytes")

    pt = b"A"
    em = pkcs1v15_pad(pt, k)
    c = encrypt_int(i2osp(em), e, n)
    print(f"Padded plaintext EM: {em.hex()}")
    print(f"Ciphertext c: 0x{c:x}")

    print(
        "Oracle says padding valid? "
        f"{oracle_padding_valid(c, d, n, e, k, use_blinding=False)} (expected True)"
    )
    c_bad = (c ^ 2) % n
    print(f"Tampered ciphertext c_bad: 0x{c_bad:x}")
    print(
        "Oracle says padding valid (tampered)? "
        f"{oracle_padding_valid(c_bad, d, n, e, k, use_blinding=False)}"
    )

    fast_cb = (
        (lambda ct: oracle_padding_valid_prefix(ct, d, n, e, k, use_blinding=False))
        if use_fast
        else None
    )
    want_trace = plot_path is not None
    result = bleichenbacher_attack(
        c,
        e,
        n,
        k,
        oracle=lambda ct: oracle_padding_valid(ct, d, n, e, k, use_blinding=False),
        fast_oracle=fast_cb,
        return_trace=want_trace,
    )
    if want_trace:
        recovered, stats = result
    else:
        recovered = result
        stats = None
    logger.info("Attack completed")
    print(f"Recovered plaintext: {recovered!r}")
    print(f"Success? {recovered == pt}")

    if plot_path and stats is not None:
        out_path = plot_interval_convergence(stats, plot_path)
        print(f"Saved interval convergence plot to {out_path}")


def demo_fast_oracle(bits: int = 96, e: int = 3):
    """Run the oracle demo with the fast prefix check and return stats."""

    while True:
        try:
            n, e_pub, d = generate_key(bits, e=e)
            break
        except ValueError:
            continue
    k = (n.bit_length() + 7) // 8
    pt = b"A"
    em = pkcs1v15_pad(pt, k)
    c = encrypt_int(i2osp(em), e_pub, n)

    queries = 0

    def counting_oracle(ct: int) -> bool:
        nonlocal queries
        queries += 1
        return oracle_padding_valid(ct, d, n, e_pub, k, use_blinding=False)

    fast_cb = lambda ct: oracle_padding_valid_prefix(
        ct, d, n, e_pub, k, use_blinding=False
    )

    recovered = bleichenbacher_attack(
        c,
        e_pub,
        n,
        k,
        oracle=counting_oracle,
        fast_oracle=fast_cb,
    )
    return recovered == pt, queries


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Demonstrate a Bleichenbacher padding-oracle attack",
    )
    parser.add_argument("--fast", action="store_true", help="Use the loose prefix oracle")
    parser.add_argument("--bits", type=int, default=96, help="RSA modulus size in bits")
    parser.add_argument(
        "--exponent",
        type=int,
        default=3,
        help="Public exponent e (must be odd and >= 3)",
    )
    parser.add_argument(
        "--plot",
        type=Path,
        help="Write a convergence plot to this path (requires matplotlib)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging verbosity (DEBUG, INFO, WARNING, ...)",
    )
    args = parser.parse_args()

    demo_oracle(
        use_fast=args.fast,
        bits=args.bits,
        e=args.exponent,
        plot_path=args.plot,
        log_level=args.log_level,
    )
