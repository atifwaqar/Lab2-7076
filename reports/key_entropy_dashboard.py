from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Tuple

from utils.entropy import shannon_entropy
from utils.plotting import HAS_MPL, nice_axes, save, wide_grid

_TITLE = "Key Entropy and Quality Analysis"
_MAX_ENTROPY = 8.0

_SAMPLES: Dict[str, bytes] = {
    "Weak (Sequential)": bytes(range(16)) * 2,
    "Patterned (0xAA)": b"\xaa" * 32,
    "Password Derived": hashlib.sha256(b"correct horse battery staple").digest(),
    "Secure Random": os.urandom(32),
}


def _entropy_percentages(values: Iterable[float]) -> Tuple[float, ...]:
    return tuple(max(0.0, min(value / _MAX_ENTROPY, 1.0)) for value in values)


def _normalized_histogram(sample: bytes) -> Tuple[float, ...]:
    length = len(sample)
    if length == 0:
        return (0.0,) * 256
    counts = Counter(sample)
    return tuple(counts.get(i, 0) / length for i in range(256))


def _collision_probability(key_bits: int, count: float) -> float:
    # p \approx 1 - exp(-n(n-1)/(2*2^k))
    n = float(count)
    numerator = n * (n - 1.0)
    denominator = 2.0 * (2.0 ** key_bits)
    exponent = -numerator / denominator
    if exponent < -700.0:  # guard for underflow in exp
        return 1.0
    return 1.0 - math.exp(exponent)


def make_key_entropy_dashboard(save_path: str | Path) -> Path:
    """Render the key entropy dashboard to *save_path* and return the file path."""
    target = Path(save_path)
    if not HAS_MPL:
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    fig, axes = wide_grid(2, 2)
    fig.suptitle(_TITLE, fontsize=16)

    labels = list(_SAMPLES.keys())
    samples = list(_SAMPLES.values())
    entropies = [shannon_entropy(sample) for sample in samples]

    # Top-left: entropy comparison bar chart
    ax_entropy = nice_axes(axes[0][0], "Key Entropy Comparison", ylabel="Entropy (bits/byte)")
    bar_colors = ["#c44e52", "#dd8452", "#55a868", "#4c72b0"]
    x_positions = list(range(len(labels)))
    ax_entropy.bar(x_positions, entropies, color=bar_colors)
    ax_entropy.axhline(7.0, color="black", linestyle="--", linewidth=1, label="Recommended (7)")
    ax_entropy.axhline(8.0, color="gray", linestyle="--", linewidth=1, label="Maximum (8)")
    ax_entropy.set_ylim(0, 8.5)
    ax_entropy.set_xticks(x_positions)
    ax_entropy.set_xticklabels(labels, rotation=20, ha="right")
    ax_entropy.legend()

    # Top-right: byte value distribution histograms
    ax_hist = nice_axes(
        axes[0][1],
        "Byte Value Distribution",
        xlabel="Byte Value",
        ylabel="Frequency",
    )
    x_values = range(256)
    for label, sample, color in zip(labels, samples, bar_colors):
        hist = _normalized_histogram(sample)
        ax_hist.plot(x_values, hist, label=label, color=color, linewidth=1.5)
    ax_hist.set_xlim(0, 255)
    ax_hist.legend()

    # Bottom-left: key quality distribution pie chart
    ax_pie = axes[1][0]
    percentages = _entropy_percentages(entropies)
    pie_labels = labels

    def _pie_autopct(pct: float, *, values: Tuple[float, ...] = percentages) -> str:
        actual = (pct / 100.0) * sum(values)
        return f"{actual * 100:.1f}%"

    ax_pie.set_title("Key Quality Distribution")
    ax_pie.pie(
        percentages,
        labels=pie_labels,
        autopct=_pie_autopct,
        colors=["#f28e2b", "#e15759", "#59a14f", "#4e79a7"],
    )

    # Bottom-right: birthday paradox collision probabilities
    ax_birthday = nice_axes(
        axes[1][1],
        "Birthday Paradox: Key Collision Probability",
        xlabel="Key Size (bits)",
        ylabel="Collision Probability",
    )
    key_sizes = [64, 96, 128, 160, 256]
    key_counts = [1e6, 1e9, 1e12, 1e15]
    for count in key_counts:
        probabilities = [_collision_probability(bits, count) for bits in key_sizes]
        ax_birthday.plot(key_sizes, probabilities, marker="o", label=f"n = {int(count):,}")
    ax_birthday.set_yscale("log")
    ax_birthday.set_ylim(1e-20, 1.0)
    ax_birthday.legend(title="Key Count")

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    return save(fig, target)
