from __future__ import annotations

import random
from collections import deque
from pathlib import Path
from typing import Iterable

from attacks.bleichenbacher_oracle import estimate_bleich_calls
from utils.entropy import shannon_entropy
from utils.plotting import HAS_MPL, nice_axes, save, wide_grid


def _years_to_crack(bits: int, guesses_per_second: float) -> float:
    seconds_per_year = 60 * 60 * 24 * 365.25
    guesses = 2 ** bits
    return guesses / (guesses_per_second * seconds_per_year)


def _simulate_entropy_series(rng: random.Random, *, samples: int, window: int, bias: float) -> list[float]:
    window_values: deque[int] = deque(maxlen=window)
    entropies: list[float] = []
    for _ in range(samples):
        if rng.random() < bias:
            value = rng.randrange(0, 64)
        else:
            value = rng.randrange(0, 256)
        window_values.append(value)
        entropies.append(shannon_entropy(bytes(window_values)))
    return entropies


def _simulate_uniform_entropy_series(rng: random.Random, *, samples: int, window: int) -> list[float]:
    window_values: deque[int] = deque(maxlen=window)
    entropies: list[float] = []
    for _ in range(samples):
        window_values.append(rng.randrange(0, 256))
        entropies.append(shannon_entropy(bytes(window_values)))
    return entropies


def _prepare_bleich_ranges(sizes: Iterable[int]) -> tuple[list[int], list[int], list[int]]:
    xs: list[int] = []
    mins: list[int] = []
    maxes: list[int] = []
    for bits in sizes:
        lower, upper = estimate_bleich_calls(bits)
        xs.append(bits)
        mins.append(float(lower))
        maxes.append(float(upper))
    return xs, mins, maxes


def make_attack_complexity_dashboard(save_path: str | Path) -> Path:
    if not HAS_MPL:  # pragma: no cover - matplotlib optional dependency guard
        raise RuntimeError("matplotlib is required to generate dashboards")

    fig, axes = wide_grid(2, 2)
    (ax_a, ax_b), (ax_c, ax_d) = axes

    # Subplot A: Brute force complexity
    key_sizes = [64, 80, 96, 112, 128, 192, 256, 512]
    guesses_per_second = 1e12
    years = [_years_to_crack(bits, guesses_per_second) for bits in key_sizes]
    ax_a = nice_axes(
        ax_a,
        "Brute Force Attack Complexity",
        xlabel="Key Size (bits)",
        ylabel="Years to Crack @ 10¹² guesses/s",
    )
    ax_a.plot(key_sizes, years, marker="o", label="Estimated time")
    ax_a.axhline(1.38e10, linestyle="--", color="tab:red", label="Age of Universe (≈1.38e10 years)")
    ax_a.set_yscale("log")
    ax_a.legend()

    # Subplot B: Bleichenbacher oracle complexity
    rsa_sizes = [512, 1024, 1536, 2048, 3072, 4096]
    xs, mins, maxes = _prepare_bleich_ranges(rsa_sizes)
    ax_b = nice_axes(
        ax_b,
        "Bleichenbacher Padding-Oracle Complexity",
        xlabel="RSA Modulus (bits)",
        ylabel="Estimated Oracle Calls",
    )
    ax_b.fill_between(xs, mins, maxes, alpha=0.2, color="tab:blue", label="Toy range")
    ax_b.plot(xs, mins, marker="o", linestyle="--", color="tab:blue", label="Min estimate")
    ax_b.plot(xs, maxes, marker="o", linestyle="--", color="tab:orange", label="Max estimate")
    ax_b.set_yscale("log")
    ax_b.legend()

    # Subplot C: Security levels
    algorithms = [
        "DES (56)",
        "AES-128",
        "AES-256",
        "RSA-1024",
        "RSA-2048",
        "ECC-256",
    ]
    security_bits = [56, 128, 256, 80, 112, 128]
    ax_c = nice_axes(
        ax_c,
        "Illustrative Security Levels",
        xlabel="Algorithm",
        ylabel="Security Bits",
    )
    positions = list(range(len(algorithms)))
    ax_c.bar(positions, security_bits, color="tab:green")
    ax_c.axhline(128, linestyle="--", color="tab:red", label="128-bit target")
    ax_c.axhline(256, linestyle="--", color="tab:purple", label="256-bit target")
    ax_c.set_ylim(0, 300)
    ax_c.set_xticks(positions, algorithms, rotation=20, ha="right")
    ax_c.legend()

    # Subplot D: Entropy comparison
    samples = 1000
    window = 64
    weak_rng = random.Random(1337)
    strong_rng = random.Random(4242)
    weak_entropy = _simulate_entropy_series(weak_rng, samples=samples, window=window, bias=0.7)
    strong_entropy = _simulate_uniform_entropy_series(strong_rng, samples=samples, window=window)
    ax_d = nice_axes(
        ax_d,
        "PRNG vs CSPRNG Entropy",
        xlabel="Sample Index",
        ylabel="Shannon Entropy (bits/byte)",
    )
    ax_d.plot(range(samples), weak_entropy, label="Weak PRNG (biased)", color="tab:orange")
    ax_d.plot(range(samples), strong_entropy, label="CSPRNG (uniform)", color="tab:blue")
    ax_d.axhline(7.0, linestyle="--", color="tab:red", label="7 bits/byte threshold")
    ax_d.set_ylim(0, 8.2)
    ax_d.legend()

    fig.suptitle("Attack Complexity Dashboard (Illustrative Models)")
    fig.tight_layout(rect=(0, 0, 1, 0.97))

    target = save(fig, save_path)
    return target


__all__ = ["make_attack_complexity_dashboard"]
