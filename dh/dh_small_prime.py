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


def demo():
    a = secrets.randbelow(p - 2) + 1
    b = secrets.randbelow(p - 2) + 1
    A = pow(g, a, p)
    B = pow(g, b, p)
    validate_public_component(A, p)
    validate_public_component(B, p)
    s1 = derive_shared_secret(a, B, p)
    s2 = derive_shared_secret(b, A, p)
    assert s1 == s2
    print("DH shared secret established with peer input validation.")

if __name__ == "__main__":
    demo()
