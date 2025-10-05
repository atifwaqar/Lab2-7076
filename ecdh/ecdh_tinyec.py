"""ECDH demonstration using tinyec with visualisations of key steps."""

import atexit
import hashlib
import os
import secrets
from typing import Iterable, Tuple

import matplotlib.pyplot as plt
from tinyec import ec, registry

__all__ = ["validate_public_point", "ecdh_demo"]


# Close any open matplotlib figures before the interpreter exits to avoid
# Tkinter "can't delete Tcl command" warnings on some platforms (notably
# Windows with the TkAgg backend) when running the demos non-interactively.
atexit.register(lambda: plt.close("all"))


# -------- helpers --------

def _normalise_point(point, modulus: int) -> Tuple[float, float]:
    """Project a point in the finite field onto [0, 1] for plotting."""
    if point is None or isinstance(point, ec.Inf):
        raise ValueError("Cannot normalise the point at infinity.")
    return float(point.x) / modulus, float(point.y) / modulus

def _set_axes(ax):
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_aspect("equal", adjustable="box")
    ax.grid(True, linestyle=":", linewidth=0.6, alpha=0.5)

def _plot_curve_samples(curve, samples: Iterable) -> None:
    """Plot a handful of multiples of the generator as a curve preview."""
    modulus = curve.field.p
    xs, ys = zip(*(_normalise_point(point, modulus) for point in samples))

    fig, ax = plt.subplots()
    ax.plot(xs, ys, linestyle="dashed", linewidth=1, color="#4c72b0", alpha=0.6)
    scatter = ax.scatter(
        xs, ys, c=range(1, len(xs) + 1), cmap="viridis", s=60, label="k·G (sampled)"
    )
    for idx, (x, y) in enumerate(zip(xs, ys), start=1):
        ax.annotate(f"{idx}G", (x, y), textcoords="offset points", xytext=(0, 6), ha="center")

    ax.scatter(*_normalise_point(curve.g, modulus), color="black", marker="x", s=100, label="Generator G")
    ax.set_title(f"Sample multiples of G on {curve.name} (normalised)")
    ax.set_xlabel("x / p")
    ax.set_ylabel("y / p")
    _set_axes(ax)
    ax.legend()
    fig.colorbar(scatter, ax=ax, label="Multiplier k")
    fig.tight_layout()

def _plot_key_exchange(curve, qa, qb, shared_point) -> None:
    """Highlight Alice and Bob's public keys alongside the shared secret."""
    modulus = curve.field.p
    qa_point = _normalise_point(qa, modulus)
    qb_point = _normalise_point(qb, modulus)
    shared = _normalise_point(shared_point, modulus)

    fig, ax = plt.subplots()
    ax.scatter(*qa_point, color="#dd8452", s=80, label="QA = dA·G")
    ax.scatter(*qb_point, color="#55a868", s=80, label="QB = dB·G")
    ax.scatter(*shared, color="#c44e52", s=120, marker="*", label="Shared secret")

    ax.annotate("Alice", qa_point, textcoords="offset points", xytext=(8, 6))
    ax.annotate("Bob", qb_point, textcoords="offset points", xytext=(8, 6))
    ax.annotate(f"x(S)={hex(int(shared_point.x))[2:10]}…", shared, textcoords="offset points", xytext=(8, 6))

    ax.set_title(f"ECDH shared point on {curve.name} (normalised)")
    ax.set_xlabel("x / p")
    ax.set_ylabel("y / p")
    _set_axes(ax)
    ax.legend()
    fig.tight_layout()

def _x_bytes(curve, P):
    coord_size = (curve.field.p.bit_length() + 7) // 8
    return int(P.x).to_bytes(coord_size, "big")


# -------- validation --------

def validate_public_point(point, curve) -> None:
    """Validate a peer's public point before using it in ECDH."""
    if point is None or isinstance(point, ec.Inf):
        raise ValueError("Peer public point must not be the point at infinity.")
    if not isinstance(point, ec.Point):
        raise TypeError("Peer public point must be a tinyec Point instance.")
    if point.curve is not curve:
        raise ValueError("Peer public point is not defined over the expected curve.")

    # tinyec exposes a boolean flag on the point itself
    if not getattr(point, "on_curve", False):
        raise ValueError("Peer public point is not on the curve.")

    # Subgroup membership: n * P should be infinity for curves like P-256
    n = getattr(curve.field, "n", None)
    if isinstance(n, int) and not isinstance(n * point, ec.Inf):
        raise ValueError("Peer public point failed the subgroup membership check.")

def _sanity_checks(curve, dA, dB, QA, QB, S1, S2):
    """Extra math checks so the visuals are trustworthy."""
    p = curve.field.p
    n = curve.field.n

    # Points are on curve and coordinates in range
    for name, P in [("G", curve.g), ("QA", QA), ("QB", QB), ("S1", S1), ("S2", S2)]:
        assert getattr(P, "on_curve", False), f"{name} not on curve"
        assert 0 <= int(P.x) < p and 0 <= int(P.y) < p, f"{name} coord out of range"

    # Private scalars in range
    assert 1 <= dA < n and 1 <= dB < n, "private scalar out of range"

    # Order checks
    assert isinstance(n * curve.g, ec.Inf), "n*G must be infinity"
    assert isinstance(n * QA, ec.Inf) and isinstance(n * QB, ec.Inf), "n*Q must be infinity"

    # Shared points must match and derived keys must match
    assert S1.x == S2.x and S1.y == S2.y, "shared point mismatch"
    kA = hashlib.sha256(_x_bytes(curve, S1)).hexdigest()
    kB = hashlib.sha256(_x_bytes(curve, S2)).hexdigest()
    assert kA == kB, "derived keys differ"
    print("[ECDH] Sanity checks passed.")
    print(f"[ECDH] Derived shared secret SHA-256: {kA}")


# -------- demo --------

def _demo_keys():
    curve = registry.get_curve("secp256r1")
    n = curve.field.n

    # Optional: stable picture while debugging
    use_fixed = os.environ.get("ECDH_FIXED") == "1"
    if use_fixed:
        dA = 0x12345
        dB = 0x23456
    else:
        dA = secrets.randbelow(n - 1) + 1
        dB = secrets.randbelow(n - 1) + 1

    QA = dA * curve.g
    QB = dB * curve.g
    validate_public_point(QA, curve)
    validate_public_point(QB, curve)

    S1 = dA * QB
    S2 = dB * QA
    return curve, dA, dB, QA, QB, S1, S2


def ecdh_demo() -> str:
    """Return the SHA-256 digest of the ECDH shared point's x-coordinate."""

    curve, dA, dB, QA, QB, S1, S2 = _demo_keys()
    _sanity_checks(curve, dA, dB, QA, QB, S1, S2)
    digest = hashlib.sha256(_x_bytes(curve, S1)).hexdigest()
    return digest


def demo():
    curve, dA, dB, QA, QB, S1, S2 = _demo_keys()
    _sanity_checks(curve, dA, dB, QA, QB, S1, S2)
    modulus_bits = curve.field.p.bit_length()
    print(f"[ECDH] Curve: {curve.name} (p={modulus_bits} bits)")
    print(f"[ECDH] Generator G.x: 0x{int(curve.g.x):x}")
    print(f"[ECDH] Alice private dA: 0x{dA:x}")
    print(f"[ECDH] Bob private dB: 0x{dB:x}")
    print(f"[ECDH] Alice public QA: (x=0x{int(QA.x):x}, y=0x{int(QA.y):x})")
    print(f"[ECDH] Bob public QB: (x=0x{int(QB.x):x}, y=0x{int(QB.y):x})")
    print(f"[ECDH] Shared point S: (x=0x{int(S1.x):x}, y=0x{int(S1.y):x})")

    samples = [k * curve.g for k in range(1, 11)]
    _plot_curve_samples(curve, samples)
    _plot_key_exchange(curve, QA, QB, S1)
    # Use a non-blocking show so the CLI regains control even if figures stay open.
    plt.show(block=False)
    # Give matplotlib a moment to render the figures before returning to the caller.
    plt.pause(0.001)


if __name__ == "__main__":
    demo()
