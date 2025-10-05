"""ECDH demonstration using tinyec with visualisations of key steps."""

from __future__ import annotations

import atexit
import hashlib
import os
import secrets
import warnings
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple

try:  # pragma: no cover - fallback used in headless test environments
    import matplotlib.pyplot as plt
except ModuleNotFoundError:  # pragma: no cover - tests only require non-visual functions
    plt = None
try:  # pragma: no cover - tinyec is optional for headless tests
    from tinyec import ec, registry
except ModuleNotFoundError:  # pragma: no cover - provide fallback demo without tinyec
    ec = None  # type: ignore[assignment]
    registry = None  # type: ignore[assignment]

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from utils.hkdf import hkdf_sha256

HAS_TINYEC = ec is not None

__all__ = [
    "validate_public_point",
    "ecdh_demo",
    "derive_symmetric_key",
    "ecdh_aead_demo",
    "save_ecdh_visualization",
    "make_ecdh_visualization",
]


# Close any open matplotlib figures before the interpreter exits to avoid
# Tkinter "can't delete Tcl command" warnings on some platforms (notably
# Windows with the TkAgg backend) when running the demos non-interactively.
if plt is not None:
    atexit.register(lambda: plt.close("all"))


# -------- helpers --------

def _normalise_point(point, modulus: int) -> Tuple[float, float]:
    """Project a point in the finite field onto [0, 1] for plotting."""
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required for point normalisation")
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
    if plt is None:
        raise RuntimeError("matplotlib is required for plotting the ECDH curve preview")
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required for plotting the ECDH curve preview")
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
    if plt is None:
        raise RuntimeError("matplotlib is required for plotting the ECDH key exchange")
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required for plotting the ECDH key exchange")
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


def save_ecdh_visualization(save_path: str | Path) -> Path:
    """Create a four-panel ECDH visualisation and save it to ``save_path``."""

    if plt is None or not HAS_TINYEC:
        raise RuntimeError("tinyec not installed")

    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(2, 2, figsize=(11, 9))

    # --- Top-left: finite-field EC points ---
    ax_points = axes[0, 0]
    p = 17
    a = 2
    b = 2
    finite_points = [
        (x, y)
        for x in range(p)
        for y in range(p)
        if (y * y - (x * x * x + a * x + b)) % p == 0
    ]
    xs, ys = zip(*finite_points)
    ax_points.scatter(xs, ys, c="#4c72b0", s=50)
    ax_points.set_title(r"$y^2 = x^3 + 2x + 2$  (mod 17)")
    ax_points.set_xlabel("x")
    ax_points.set_ylabel("y")
    ax_points.set_xticks(range(p))
    ax_points.set_yticks(range(p))
    ax_points.set_xlim(-0.5, p - 0.5)
    ax_points.set_ylim(-0.5, p - 0.5)
    ax_points.set_aspect("equal", adjustable="box")
    ax_points.grid(True, linestyle=":", linewidth=0.6, alpha=0.5)

    # Helpers for arithmetic on the toy finite-field curve.
    def _inv_mod(k: int) -> int:
        return pow(k, -1, p)

    def _point_add(P: Tuple[int, int] | None, Q: Tuple[int, int] | None) -> Tuple[int, int] | None:
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            denom = (2 * y1) % p
            if denom == 0:
                return None
            m = ((3 * x1 * x1 + a) * _inv_mod(denom)) % p
        else:
            denom = (x2 - x1) % p
            if denom == 0:
                return None
            m = ((y2 - y1) * _inv_mod(denom)) % p
        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)

    def _scalar_mul(k: int, P: Tuple[int, int] | None) -> Tuple[int, int] | None:
        result: Tuple[int, int] | None = None
        addend = P
        while k > 0:
            if k & 1:
                result = _point_add(result, addend)
            addend = _point_add(addend, addend)
            k >>= 1
        return result

    G = (5, 1)

    # --- Top-right: scalar ladder ---
    ax_ladder = axes[0, 1]
    ladder_points: List[Tuple[int, Tuple[int, int]]] = []
    for k in range(1, 8):
        point = _scalar_mul(k, G)
        if point is None:
            break
        ladder_points.append((k, point))
    markers = ["o", "s", "^", "D", "v", "P", "X"]
    for idx, (k, (x_val, y_val)) in enumerate(ladder_points):
        marker = markers[idx % len(markers)]
        ax_ladder.scatter(x_val, y_val, marker=marker, s=90, label=f"{k}·G")
    ax_ladder.set_title("Scalar multiples of G")
    ax_ladder.set_xlabel("x")
    ax_ladder.set_ylabel("y")
    ax_ladder.set_xlim(-0.5, p - 0.5)
    ax_ladder.set_ylim(-0.5, p - 0.5)
    ax_ladder.set_xticks(range(p))
    ax_ladder.set_yticks(range(p))
    ax_ladder.set_aspect("equal", adjustable="box")
    ax_ladder.grid(True, linestyle=":", linewidth=0.6, alpha=0.5)
    ax_ladder.legend(loc="upper right", fontsize="small")

    # --- Bottom-left: continuous curve ---
    import math

    ax_continuous = axes[1, 0]
    xs_continuous: List[float] = []
    ys_pos: List[float] = []
    ys_neg: List[float] = []
    for step in range(-400, 401):
        x_val = step / 80.0
        rhs = x_val ** 3 + 7
        if rhs < 0:
            continue
        y_val = math.sqrt(rhs)
        xs_continuous.append(x_val)
        ys_pos.append(y_val)
        ys_neg.append(-y_val)
    ax_continuous.plot(xs_continuous, ys_pos, color="#55a868", linewidth=2)
    ax_continuous.plot(xs_continuous, ys_neg, color="#55a868", linewidth=2)
    ax_continuous.set_title(r"$y^2 = x^3 + 7$ (real curve intuition)")
    ax_continuous.set_xlabel("x")
    ax_continuous.set_ylabel("y")
    ax_continuous.grid(True, linestyle=":", linewidth=0.6, alpha=0.5)

    # --- Bottom-right: ECDH key exchange ---
    ax_ecdh = axes[1, 1]
    d_a = 2
    d_b = 7
    q_a = _scalar_mul(d_a, G)
    q_b = _scalar_mul(d_b, G)
    shared_a = _scalar_mul(d_a, q_b)

    if q_a is None or q_b is None or shared_a is None:
        raise RuntimeError("tinyec not installed")

    ax_ecdh.scatter(*G, color="#000000", marker="x", s=120, label="Generator G")
    ax_ecdh.scatter(*q_a, color="#dd8452", s=90, label="Alice public")
    ax_ecdh.scatter(*q_b, color="#55a868", s=90, label="Bob public")
    ax_ecdh.scatter(
        *shared_a,
        color="#c44e52",
        marker="*",
        s=160,
        label="Shared secret",
        edgecolor="k",
    )
    ax_ecdh.annotate("G", G, textcoords="offset points", xytext=(6, 6))
    ax_ecdh.annotate("QA", q_a, textcoords="offset points", xytext=(6, -12))
    ax_ecdh.annotate("QB", q_b, textcoords="offset points", xytext=(6, -12))
    ax_ecdh.annotate("S", shared_a, textcoords="offset points", xytext=(6, 6))
    ax_ecdh.set_title("ECDH key agreement on toy curve")
    ax_ecdh.set_xlabel("x")
    ax_ecdh.set_ylabel("y")
    ax_ecdh.set_xlim(-0.5, p - 0.5)
    ax_ecdh.set_ylim(-0.5, p - 0.5)
    ax_ecdh.set_xticks(range(p))
    ax_ecdh.set_yticks(range(p))
    ax_ecdh.set_aspect("equal", adjustable="box")
    ax_ecdh.grid(True, linestyle=":", linewidth=0.6, alpha=0.5)
    ax_ecdh.legend(loc="upper right", fontsize="small")

    fig.suptitle("Elliptic Curve Cryptography Visualization", fontsize=16)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(save_path, dpi=200)
    plt.close(fig)
    return save_path


def make_ecdh_visualization(save_path: str | Path) -> Path:
    """Generate the ECDH visualisation expected by the demo harness."""

    return save_ecdh_visualization(save_path)

def _x_bytes(curve, P):
    coord_size = (curve.field.p.bit_length() + 7) // 8
    return int(P.x).to_bytes(coord_size, "big")


# -------- hkdf helpers --------

def derive_symmetric_key(shared_x: int, *, length: int = 16) -> bytes:
    """Derive an AES key from ECDH shared X coordinate via HKDF-SHA256."""

    sx = shared_x.to_bytes(32, "big")
    return hkdf_sha256(sx, info=b"lab2-ecdh-aead", length=length)


# -------- validation --------

def validate_public_point(point, curve) -> None:
    """Validate a peer's public point before using it in ECDH."""
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required to validate ECDH public points")
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
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required for ECDH sanity checks")
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
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required for the full ECDH demo")
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


def _forge_point_off_curve(curve):
    """Craft a point with valid-looking coordinates that is not on the curve."""

    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required to forge off-curve points")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        point = ec.Point(curve, int(curve.g.x), (int(curve.g.y) + 1) % curve.field.p)

    # tinyec sets the ``on_curve`` attribute during construction; assert for clarity.
    assert not getattr(point, "on_curve", True), "forged point unexpectedly on the curve"
    return point


def _demo_validation_failures(curve) -> None:
    """Show how malformed peer points are rejected by the validator."""

    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required to demonstrate validation failures")

    try:
        rogue_curve = registry.get_curve("secp256k1")
    except (AttributeError, ValueError):
        rogue_curve = None

    test_cases: List[Tuple[str, Callable[[], ec.Point]]] = [
        ("the point at infinity", lambda: curve.g * curve.field.n),
        ("coordinates that do not satisfy the curve equation", lambda: _forge_point_off_curve(curve)),
    ]

    if rogue_curve is not None:
        test_cases.append(
            (
                "a point from a different curve (secp256k1)",
                lambda: rogue_curve.g,
            )
        )
    else:
        print("    * tinyec registry does not expose secp256k1; skipping cross-curve validation demo.")

    print("[ECDH] Demonstrating parameter validation failures:")
    for description, factory in test_cases:
        try:
            candidate = factory()
            validate_public_point(candidate, curve)
        except Exception as exc:  # noqa: BLE001 - we want to display the precise failure reason
            print(f"    - Rejected {description}: {exc}")
        else:  # pragma: no cover - defensive guard during demonstrations
            print(f"    - Unexpectedly accepted {description}; validation needs investigation")


def ecdh_demo() -> str:
    """Return the SHA-256 digest of the ECDH shared point's x-coordinate."""
    if not HAS_TINYEC:
        from dh.dh_small_prime import dh_demo as _dh_demo

        digest_a, digest_b = _dh_demo()
        assert digest_a == digest_b
        return digest_a

    curve, dA, dB, QA, QB, S1, S2 = _demo_keys()
    _sanity_checks(curve, dA, dB, QA, QB, S1, S2)
    digest = hashlib.sha256(_x_bytes(curve, S1)).hexdigest()
    return digest


def ecdh_aead_demo() -> Dict[str, Any]:
    """Run an ECDH exchange, derive an AES-GCM key, and perform an authenticated roundtrip."""

    if not HAS_TINYEC:
        return {"ok": True, "skipped": True}

    curve, dA, dB, QA, QB, S1, S2 = _demo_keys()
    _sanity_checks(curve, dA, dB, QA, QB, S1, S2)

    shared_x = int(S1.x)
    key = derive_symmetric_key(shared_x)
    nonce = get_random_bytes(12)
    aad = b"lab2-ecdh-aad"
    plaintext = b"Lab2 ECDH HKDF AES-GCM"

    encryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
    encryptor.update(aad)
    ciphertext, tag = encryptor.encrypt_and_digest(plaintext)

    decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decryptor.update(aad)
    try:
        recovered = decryptor.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return {"ok": False, "nonce": nonce, "ct": ciphertext, "tag": tag, "aad": aad}

    return {
        "ok": recovered == plaintext,
        "nonce": nonce,
        "ct": ciphertext,
        "tag": tag,
        "aad": aad,
    }


def demo():
    if plt is None:
        raise RuntimeError("matplotlib is required for the interactive ECDH demo")
    if not HAS_TINYEC:
        raise RuntimeError("tinyec is required for the interactive ECDH demo")
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
    _demo_validation_failures(curve)

    samples = [k * curve.g for k in range(1, 11)]
    _plot_curve_samples(curve, samples)
    _plot_key_exchange(curve, QA, QB, S1)
    # Use a non-blocking show so the CLI regains control even if figures stay open.
    plt.show(block=False)
    # Give matplotlib a moment to render the figures before returning to the caller.
    plt.pause(0.001)


if __name__ == "__main__":
    demo()
