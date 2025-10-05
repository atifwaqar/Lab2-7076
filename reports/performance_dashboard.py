"""Illustrative cryptographic performance and security dashboard."""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from utils.plotting import HAS_MPL, nice_axes, save, wide_grid


def _ensure_path(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def make_performance_dashboard(save_path: str | Path) -> Path:
    """Generate the performance trade-off dashboard and save to PNG."""
    target = _ensure_path(save_path)

    if not HAS_MPL:
        return target

    fig, axes = wide_grid(2, 2)
    fig.suptitle("Cryptographic Performance and Security Trade-offs (illustrative)")

    # Top-left: AES mode throughput comparison (illustrative numbers).
    aes_modes: Sequence[str] = ("ECB", "CBC", "GCM", "CTR", "CFB")
    aes_throughput = [1200, 1100, 950, 1150, 900]
    ax = axes[0][0]
    nice_axes(ax, "AES Mode Performance Comparison (illustrative)", ylabel="Throughput (MB/s)")
    ax.bar(aes_modes, aes_throughput, color="#3b82f6")

    # Top-right: KDF performance vs iteration count (simple power-law models).
    iterations = [1_000, 10_000, 100_000, 1_000_000]
    pbkdf2 = [0.4 * (i ** 0.8) for i in iterations]
    scrypt = [0.6 * (i ** 0.85) for i in iterations]
    argon2 = [0.5 * (i ** 0.75) for i in iterations]
    ax = axes[0][1]
    nice_axes(
        ax,
        "KDF Performance (illustrative)",
        xlabel="Iterations",
        ylabel="Relative time (ms)",
    )
    for label, values, marker in (
        ("PBKDF2", pbkdf2, "o"),
        ("scrypt", scrypt, "s"),
        ("Argon2", argon2, "^"),
    ):
        ax.loglog(iterations, values, marker=marker, label=label)
    ax.legend()

    # Bottom-left: RSA vs ECC key size comparison.
    # Data inspired by NIST SP 800-57 Part 1 recommendations.
    security_bits = [80, 112, 128, 192, 256]
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]
    ecc_sizes = [160, 224, 256, 384, 512]
    positions = range(len(security_bits))
    width = 0.35
    ax = axes[1][0]
    nice_axes(
        ax,
        "RSA vs ECC Key Size Comparison (illustrative)",
        xlabel="Security level (bits)",
        ylabel="Key size (bits)",
    )
    ax.bar([p - width / 2 for p in positions], rsa_sizes, width=width, label="RSA", color="#f97316")
    ax.bar([p + width / 2 for p in positions], ecc_sizes, width=width, label="ECC", color="#10b981")
    ax.set_xticks(list(positions))
    ax.set_xticklabels([str(bits) for bits in security_bits])
    ax.legend()

    # Bottom-right: Effect of IV/nonce handling on effective security.
    scenarios = [
        "ECB",
        "CBC\nIV reuse",
        "CTR\nnonce reuse",
        "GCM\nnonce reuse",
        "CBC\nrandom IV",
        "GCM\nunique nonce",
    ]
    statuses = ["BROKEN", "BROKEN", "WEAK", "BROKEN", "SECURE", "SECURE"]
    security_levels = [0, 0, 50, 0, 100, 100]
    ax = axes[1][1]
    nice_axes(
        ax,
        "Impact of IV/Nonce Reuse on Security",
        ylabel="Relative security level (%)",
    )
    bars = ax.bar(range(len(scenarios)), security_levels, color="#6366f1")
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels([f"{scenario}\n[{status}]" for scenario, status in zip(scenarios, statuses)])
    ax.set_ylim(0, 110)
    for bar, status in zip(bars, statuses):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 3, status, ha="center", va="bottom")

    fig.text(0.5, 0.01, "Illustrative scaling only; not a benchmark.", ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    return save(fig, target)


__all__ = ["make_performance_dashboard"]
