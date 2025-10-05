import secrets

def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def inv_mod(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def miller_rabin(n: int, k: int = 40) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits)
        cand |= (1 << (bits - 1)) | 1
        if miller_rabin(cand):
            return cand

def generate_key(bits: int = 1024, e: int = 65537):
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while q == p:
        q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inv_mod(e, phi)
    return n, e, d

def i2osp(b: bytes) -> int:
    return int.from_bytes(b, "big")

def os2ip(i: int, length: int | None = None) -> bytes:
    length = length or (i.bit_length() + 7) // 8
    return i.to_bytes(length, "big")

def encrypt_int(m: int, e: int, n: int) -> int:
    if not (0 <= m < n):
        raise ValueError("Message representative out of range")
    return pow(m, e, n)

def decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

if __name__ == "__main__":
    print("== RSA from scratch ==")
    n, e, d = generate_key(1024)
    msg = b"hi rsa"
    m = i2osp(msg)
    c = encrypt_int(m, e, n)
    dec = decrypt_int(c, d, n)
    out = os2ip(dec)
    assert out == msg, "Roundtrip failed"
    print(f"n bits: {n.bit_length()}, e: {e}, ok = {out == msg}")
