from tinyec import registry
import secrets

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

if __name__ == "__main__":
    demo()
