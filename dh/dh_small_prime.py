import secrets

p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
g = 2

def demo():
    a = secrets.randbelow(p - 2) + 1
    b = secrets.randbelow(p - 2) + 1
    A = pow(g, a, p)
    B = pow(g, b, p)
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)
    assert s1 == s2
    print("DH shared secret established. (Only equality checked; do not print secrets.)")

if __name__ == "__main__":
    demo()
