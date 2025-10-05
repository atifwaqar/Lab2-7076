from __future__ import annotations

import os
from statistics import mean

from utils.entropy import shannon_entropy


def run_entropy_demo() -> dict:
    """Generate random samples, compute entropy, and print a brief summary."""
    keys = [os.urandom(16) for _ in range(10)]
    nonces = [os.urandom(12) for _ in range(10)]
    low_zero = bytes(16)
    low_pattern = b"\xaa" * 16

    key_entropies = [shannon_entropy(key) for key in keys]
    nonce_entropies = [shannon_entropy(nonce) for nonce in nonces]
    low_zero_entropy = shannon_entropy(low_zero)
    low_pattern_entropy = shannon_entropy(low_pattern)

    key_warn = any(entropy < 7.5 for entropy in key_entropies)
    nonce_warn = any(entropy < 6.0 for entropy in nonce_entropies)

    print("== Entropy sanity checks ==")
    print(
        "  Keys  : min={:.2f} max={:.2f} avg={:.2f} warn={}".format(
            min(key_entropies), max(key_entropies), mean(key_entropies), key_warn
        )
    )
    print(
        "  Nonces: min={:.2f} max={:.2f} avg={:.2f} warn={}".format(
            min(nonce_entropies), max(nonce_entropies), mean(nonce_entropies), nonce_warn
        )
    )
    print(
        "  Low samples entropy -> zeros: {:.2f}, pattern: {:.2f}".format(
            low_zero_entropy, low_pattern_entropy
        )
    )

    return {
        "keys_entropy": key_entropies,
        "nonces_entropy": nonce_entropies,
        "low_zero_entropy": low_zero_entropy,
        "low_pattern_entropy": low_pattern_entropy,
        "flags": {"key_warn": key_warn, "nonce_warn": nonce_warn},
    }


if __name__ == "__main__":  # pragma: no cover
    run_entropy_demo()
