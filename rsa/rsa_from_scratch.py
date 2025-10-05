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
    """Return ``True`` when ``n`` is probably prime using Miller–Rabin."""

    if n < 2:
        return False

    # Trial-divide by a few small primes first – this quickly rejects
    # obviously composite numbers and handles the small-prime cases.
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    if n % 2 == 0:
        return False

    # Write n-1 as (2**r) * d with d odd.
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Perform ``k`` rounds with independently sampled bases.  The witnesses
    # are chosen with ``secrets`` to guarantee cryptographic randomness.
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # 2 <= a <= n-2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    """Generate a random probable prime with ``bits`` bits."""

    if bits < 2:
        raise ValueError("Prime size must be at least 2 bits")

    while True:
        cand = secrets.randbits(bits)
        # Ensure the number has the requested size and is odd.
        cand |= (1 << (bits - 1)) | 1
        if miller_rabin(cand):
            return cand


def generate_key(bits: int = 1024, e: int = 65537):
    """Generate an RSA modulus ``n`` together with the public/secret exponents."""

    if e % 2 == 0:
        raise ValueError("Public exponent must be odd")

    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = gen_prime(p_bits)
        q = gen_prime(q_bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if egcd(e, phi)[0] == 1:
            break

    n = p * q
    d = inv_mod(e, phi)
    return n, e, d


def i2osp(data: bytes) -> int:
    """Convert a byte-string into its non-negative integer representation."""

    return int.from_bytes(data, "big", signed=False)


def os2ip(value: int, length: int | None = None) -> bytes:
    """Convert an integer into a big-endian byte-string."""

    if value < 0:
        raise ValueError("Cannot convert negative integers")

    if length is None:
        length = (value.bit_length() + 7) // 8

    if value.bit_length() > length * 8:
        raise ValueError("Integer too large for the requested length")

    return value.to_bytes(length, "big") if length > 0 else b""


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
