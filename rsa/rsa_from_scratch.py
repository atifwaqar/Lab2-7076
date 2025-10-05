import secrets
from typing import Tuple

def egcd(a: int, b: int):
    """Extended Euclidean algorithm without recursion.

    The original recursive implementation could exceed Python's recursion
    depth when working with very large integers (such as the RSA blinding
    factor ``r`` and modulus ``n``).  By rewriting the routine iteratively we
    avoid hitting the recursion limit while computing the Bézout coefficients.
    """

    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t

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


def generate_key(bits: int = 2048, e: int = 65537):
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

def decrypt_int(
    c: int,
    d: int,
    n: int,
    *,
    e: int | None = None,
    use_blinding: bool = True,
) -> int:
    """Compute ``c**d mod n`` with optional RSA blinding to reduce timing leakage."""

    if not (0 <= c < n):
        raise ValueError("Ciphertext representative out of range")

    if use_blinding and e is not None:
        # Randomize the ciphertext before the private exponentiation.  The
        # blinding factor must be invertible modulo n so we resample until the
        # greatest common divisor is 1.  This prevents timing side channels
        # that would otherwise leak information about ``d``.
        while True:
            r = secrets.randbelow(n - 1) + 1  # 1 <= r < n
            if egcd(r, n)[0] == 1:
                break
        blinded = (c * pow(r, e, n)) % n
        m_blinded = pow(blinded, d, n)
        r_inv = inv_mod(r, n)
        return (m_blinded * r_inv) % n

    return pow(c, d, n)


def rsa_roundtrip(bits: int = 512) -> Tuple[int, int, int, bool]:
    """Generate a small RSA key and perform an encrypt/decrypt round-trip.

    Returns the key parameters together with a boolean indicating whether the
    decrypted plaintext matches the original message.  The helper keeps the
    key size modest so smoke tests run quickly while still exercising the
    number-theory utilities.
    """

    n, e, d = generate_key(bits)
    msg = b"hi rsa"
    m = i2osp(msg)
    c = encrypt_int(m, e, n)
    dec = decrypt_int(c, d, n, e=e)
    out = os2ip(dec)
    return n, e, d, out == msg

if __name__ == "__main__":
    print("== RSA from scratch ==")
    n, e, d, ok = rsa_roundtrip(2048)
    msg = b"hi rsa"
    m = i2osp(msg)
    c = encrypt_int(m, e, n)
    dec = decrypt_int(c, d, n, e=e)
    out = os2ip(dec)
    assert ok and out == msg, "Roundtrip failed"
    print(f"n bits: {n.bit_length()}, e: {e}, ok = {out == msg}")
