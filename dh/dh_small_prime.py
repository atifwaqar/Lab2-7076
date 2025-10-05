import hashlib
import secrets

p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
g = 2

__all__ = [
    "p",
    "g",
    "validate_public_component",
    "derive_shared_secret",
]


def validate_public_component(component: int, modulus: int) -> None:
    """Basic peer validation before Diffie–Hellman exponentiation."""

    if not isinstance(component, int):
        raise TypeError("Public component must be an integer.")

    if not (1 < component < modulus - 1):
        raise ValueError("Peer public component is out of the valid range (1, p-1).")


def derive_shared_secret(private_key: int, peer_public: int, modulus: int) -> int:
    """Derive the shared secret after validating the peer's public contribution."""

    validate_public_component(peer_public, modulus)
    return pow(peer_public, private_key, modulus)


def _demo_exchange():
    a = secrets.randbelow(p - 2) + 1
    b = secrets.randbelow(p - 2) + 1
    A = pow(g, a, p)
    B = pow(g, b, p)
    validate_public_component(A, p)
    validate_public_component(B, p)
    s1 = derive_shared_secret(a, B, p)
    s2 = derive_shared_secret(b, A, p)
    return {
        "a": a,
        "b": b,
        "A": A,
        "B": B,
        "shared_a": s1,
        "shared_b": s2,
    }


def dh_demo():
    """Return matching SHA-256 digests of the DH shared secret."""

    values = _demo_exchange()
    shared_a = values["shared_a"]
    shared_b = values["shared_b"]
    assert shared_a == shared_b
    k = (p.bit_length() + 7) // 8
    digest_a = hashlib.sha256(shared_a.to_bytes(k, "big")).hexdigest()
    digest_b = hashlib.sha256(shared_b.to_bytes(k, "big")).hexdigest()
    return digest_a, digest_b


def demo():
    values = _demo_exchange()
    shared_a = values["shared_a"]
    shared_b = values["shared_b"]
    assert shared_a == shared_b
    print(f"p (modulus) bits: {p.bit_length()} | generator g: {g}")
    print(f"Alice private a: 0x{values['a']:x}")
    print(f"Bob private b: 0x{values['b']:x}")
    print(f"Alice public A = g^a mod p: 0x{values['A']:x}")
    print(f"Bob public B = g^b mod p: 0x{values['B']:x}")
    shared_hex = hex(shared_a)[2:66] + ("…" if shared_a.bit_length() > 256 else "")
    print(f"Shared secret (head): 0x{shared_hex}")
    print("DH shared secret established with peer input validation.")

if __name__ == "__main__":
    demo()
