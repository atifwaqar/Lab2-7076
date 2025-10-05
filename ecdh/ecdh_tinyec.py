"""ECDH demonstration using tinyec with visualisations of key steps."""

import secrets
from typing import Iterable, Tuple

import matplotlib.pyplot as plt
from tinyec import registry


def _normalise_point(point, modulus: int) -> Tuple[float, float]:
    """Project a point in the finite field onto [0, 1] for plotting."""

    if point is None:
        raise ValueError("Cannot normalise the point at infinity.")

    return point.x / modulus, point.y / modulus


def _plot_curve_samples(curve, samples: Iterable) -> None:
    """Plot a handful of multiples of the generator as a curve preview."""

    modulus = curve.field.p
    xs, ys = zip(*(_normalise_point(point, modulus) for point in samples))

    fig, ax = plt.subplots()
    ax.plot(xs, ys, linestyle="dashed", linewidth=1, color="#4c72b0", alpha=0.6)
    scatter = ax.scatter(
        xs,
        ys,
        c=range(1, len(xs) + 1),
        cmap="viridis",
        s=60,
        label="k·G (sampled)",
    )
    for idx, (x, y) in enumerate(zip(xs, ys), start=1):
        ax.annotate(f"{idx}G", (x, y), textcoords="offset points", xytext=(0, 6), ha="center")

    ax.scatter(*_normalise_point(curve.g, modulus), color="black", marker="x", s=100, label="Generator G")
    ax.set_title(f"Sample multiples of G on {curve.name} (normalised)")
    ax.set_xlabel("x / p")
    ax.set_ylabel("y / p")
    ax.legend()
    fig.colorbar(scatter, ax=ax, label="Multiplier k")


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
    ax.annotate("S", shared, textcoords="offset points", xytext=(8, 6))

    ax.set_title(f"ECDH shared point on {curve.name} (normalised)")
    ax.set_xlabel("x / p")
    ax.set_ylabel("y / p")
    ax.legend()


def demo():
    curve = registry.get_curve("secp256r1")
    n = curve.field.n
    dA = secrets.randbelow(n - 1) + 1
    dB = secrets.randbelow(n - 1) + 1
    QA = dA * curve.g
    QB = dB * curve.g
    S1 = dA * QB
    S2 = dB * QA
    assert S1.x == S2.x and S1.y == S2.y
    print(f"ECDH on {curve.name}: shared point established (x agrees).")

    samples = [k * curve.g for k in range(1, 11)]
    _plot_curve_samples(curve, samples)
    _plot_key_exchange(curve, QA, QB, S1)
    plt.show()


if __name__ == "__main__":
    demo()
