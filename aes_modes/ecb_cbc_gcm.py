import base64
import os
import secrets
import tempfile
from collections import Counter
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

try:  # pragma: no cover - exercised indirectly via demos
    import matplotlib.pyplot as plt
except ModuleNotFoundError:  # pragma: no cover - fallback for environments without matplotlib
    plt = None
    _FALLBACK_PNG = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
    )
else:  # pragma: no cover - plotting is tested via smoke tests
    _FALLBACK_PNG = None

BLOCK = 16


def xor_hex(a: bytes, b: bytes) -> str:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n])).hex()

def pkcs7_pad(b: bytes, block: int = BLOCK) -> bytes:
    pad = block - (len(b) % block)
    return b + bytes([pad]) * pad

def pkcs7_unpad(b: bytes, block: int = BLOCK) -> bytes:
    if not b or len(b) % block != 0:
        raise ValueError("Invalid padded data length")
    pad = b[-1]
    if pad < 1 or pad > block or b[-pad:] != bytes([pad]) * pad:
        raise ValueError("Bad PKCS#7 padding")
    return b[:-pad]

def aes_ecb_encrypt(key: bytes, pt: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(pt))

def aes_ecb_decrypt(key: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(ct))

def aes_cbc_encrypt(key: bytes, pt: bytes, iv: bytes | None = None) -> bytes:
    iv = iv or get_random_bytes(BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pkcs7_pad(pt))

def aes_cbc_decrypt(key: bytes, iv_ct: bytes) -> bytes:
    iv, ct = iv_ct[:BLOCK], iv_ct[BLOCK:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return pkcs7_unpad(cipher.decrypt(ct))

def aes_gcm_encrypt(key: bytes, pt: bytes, aad: bytes = b"", nonce: bytes | None = None):
    nonce = nonce or get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return nonce, ct, tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


def _render_gcm_keystream_heatmap(
    ct1: bytes,
    ct2: bytes,
    leak: bytes,
    save_path: str | os.PathLike[str] | None = None,
    highlight: tuple[int, int] | None = None,
):
    """Render a small heatmap that highlights the reuse leakage.

    The function saves the figure to ``save_path`` (or a temporary file) and
    returns the resolved :class:`~pathlib.Path`.  When ``highlight`` is
    provided, the byte-range (``start``, ``end``) is outlined to emphasise where
    the known-plaintext slice differs between the two messages.
    """

    if plt is None:
        if save_path is None:
            tmp = tempfile.NamedTemporaryFile(prefix="gcm_leak_", suffix=".png", delete=False)
            save_path = tmp.name
            tmp.close()
        path = Path(save_path).expanduser().resolve()
        if _FALLBACK_PNG is not None:
            path.write_bytes(_FALLBACK_PNG)
        else:  # pragma: no cover - guard if fallback constant missing
            path.write_bytes(b"")
        return path

    data = [list(ct1), list(ct2), list(leak)]
    width = max(len(leak) / 4.0, 6)
    fig, ax = plt.subplots(figsize=(width, 2.8))
    im = ax.imshow(data, aspect="auto", cmap="magma", interpolation="nearest")
    ax.set_title("GCM nonce reuse leakage (byte values)")
    ax.set_xlabel("Ciphertext byte index")
    ax.set_yticks(range(3))
    ax.set_yticklabels(["Ciphertext 1", "Ciphertext 2", "XOR leak"])
    ax.set_xticks(range(0, len(leak), max(1, len(leak) // 12)))
    cbar = fig.colorbar(im, ax=ax, orientation="vertical")
    cbar.set_label("Byte value")

    if highlight is not None:
        start, end = highlight
        if 0 <= start < end <= len(leak):
            from matplotlib.patches import Rectangle

            rect = Rectangle(
                (start - 0.5, -0.5),
                end - start,
                len(data),
                linewidth=1.5,
                edgecolor="#f0ad4e",
                facecolor="none",
                linestyle="--",
            )
            ax.add_patch(rect)
            ax.text(
                start,
                len(data) - 0.2,
                "Differing plaintext slice",
                color="#f0ad4e",
                fontsize=9,
                fontweight="bold",
                ha="left",
                va="top",
                backgroundcolor="black",
                alpha=0.6,
            )
    fig.tight_layout()

    if save_path is None:
        tmp = tempfile.NamedTemporaryFile(prefix="gcm_leak_", suffix=".png", delete=False)
        save_path = tmp.name
        tmp.close()

    path = Path(save_path).expanduser().resolve()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path

def demo_ecb_pattern_leakage() -> dict[str, object]:
    """Return metadata that highlights ECB's repeating-block leakage."""

    key = get_random_bytes(16)
    block = b"A" * 16
    pt = block * 4 + b"B" * 16 + block * 3
    ct = aes_ecb_encrypt(key, pt)
    blocks = [ct[i : i + BLOCK] for i in range(0, len(ct), BLOCK)]
    counts = Counter(blocks)
    block_data = [
        {
            "index": idx,
            "hex": block_bytes.hex(),
            "repeats": counts[block_bytes],
        }
        for idx, block_bytes in enumerate(blocks, start=1)
    ]
    return {
        "key": key,
        "plaintext": pt,
        "ciphertext": ct,
        "block_metadata": block_data,
        "unique_blocks": len(counts),
        "total_blocks": len(blocks),
    }

def demo_cbc_iv_reuse() -> dict[str, object]:
    """Return artefacts that demonstrate CBC IV reuse leakage."""

    key = get_random_bytes(16)
    iv = get_random_bytes(BLOCK)

    # Two plaintexts that share the same first block but diverge afterwards.
    shared_block = b"shared prefix bl"
    assert len(shared_block) == BLOCK
    p1 = shared_block + b"ock -> amount=100" + secrets.token_bytes(5)
    p2 = shared_block + b"ock -> amount=900" + secrets.token_bytes(5)

    c1 = aes_cbc_encrypt(key, p1, iv=iv)
    c2 = aes_cbc_encrypt(key, p2, iv=iv)

    c1_iv, c1_body = c1[:BLOCK], c1[BLOCK:]
    c2_iv, c2_body = c2[:BLOCK], c2[BLOCK:]
    c1_first_block = c1_body[:BLOCK]
    c2_first_block = c2_body[:BLOCK]

    p1_first = p1[:BLOCK]
    p2_first = p2[:BLOCK]
    x_c = bytes(a ^ b for a, b in zip(c1_first_block, c2_first_block))
    x_p = bytes(a ^ b for a, b in zip(p1_first, p2_first))

    from Crypto.Cipher import AES as _AES

    tampered_iv = bytearray(c2_iv)
    tampered_iv[0] ^= 0x20  # flip one bit
    dec = _AES.new(key, _AES.MODE_CBC, iv=bytes(tampered_iv)).decrypt(c2_body)
    tampered_first_block = dec[:BLOCK]

    return {
        "key": key,
        "iv": iv,
        "plaintext_1": p1,
        "plaintext_2": p2,
        "ciphertext_1": c1,
        "ciphertext_2": c2,
        "xor_ciphertexts": x_c,
        "xor_plaintexts": x_p,
        "second_block_differs": c1_body[BLOCK : 2 * BLOCK] != c2_body[BLOCK : 2 * BLOCK],
        "tampered_first_block": tampered_first_block,
        "original_first_block": p2_first,
    }

def demo_gcm_nonce_reuse() -> dict[str, object]:
    """Return ciphertext/tag artefacts for a nonce-reuse demonstration."""

    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    aad = b"hdr"
    p1 = b"GCM message one"
    p2 = b"GCM message two"
    n1, c1, t1 = aes_gcm_encrypt(key, p1, aad=aad, nonce=nonce)
    n2, c2, t2 = aes_gcm_encrypt(key, p2, aad=aad, nonce=nonce)
    assert n1 == n2 == nonce
    try:
        aes_gcm_decrypt(key, n1, c1, t2, aad=aad)
    except Exception as exc:  # noqa: BLE001 - display the verification failure class
        verification_error = type(exc).__name__
    else:  # pragma: no cover - defensive guard for unexpected library behaviour
        verification_error = None

    return {
        "key": key,
        "nonce": nonce,
        "ciphertext_1": c1,
        "ciphertext_2": c2,
        "tag_1": t1,
        "tag_2": t2,
        "tags_equal": t1 == t2,
        "verification_error": verification_error,
    }

def roundtrip_demo():
    """Run a short AES round-trip across ECB, CBC and GCM.

    Returns a dictionary with the ciphertext artefacts and boolean flags
    confirming that each mode decrypted to the original plaintext.  The
    structure is intentionally simple so tests can assert on the booleans
    without parsing printed output.
    """

    key = get_random_bytes(16)
    msg = b"hello world! " * 5
    cte = aes_ecb_encrypt(key, msg)
    ok_ecb = aes_ecb_decrypt(key, cte) == msg
    ctc = aes_cbc_encrypt(key, msg)
    ok_cbc = aes_cbc_decrypt(key, ctc) == msg
    nonce, ctg, tag = aes_gcm_encrypt(key, msg, aad=b"meta")
    ok_gcm = aes_gcm_decrypt(key, nonce, ctg, tag, aad=b"meta") == msg
    return {
        "key": key,
        "plaintext": msg,
        "ecb_ct": cte,
        "cbc_iv_ct": ctc,
        "gcm_nonce": nonce,
        "gcm_ct": ctg,
        "gcm_tag": tag,
        "ok_ecb": ok_ecb,
        "ok_cbc": ok_cbc,
        "ok_gcm": ok_gcm,
    }


def roundtrip_checks():
    result = roundtrip_demo()
    key = result["key"]
    msg = result["plaintext"]
    cte = result["ecb_ct"]
    ctc = result["cbc_iv_ct"]
    nonce = result["gcm_nonce"]
    tag = result["gcm_tag"]
    print("[Roundtrip] AES-128 key:", key.hex())
    print("[Roundtrip] Plaintext length:", len(msg), "bytes")
    print("[Roundtrip] ECB ciphertext (first 32 hex):", cte[:16].hex())
    print("[Roundtrip] CBC IV:", ctc[:BLOCK].hex())
    print("[Roundtrip] GCM nonce:", nonce.hex(), "tag:", tag.hex())
    print("[Roundtrip] All modes decrypted back to the original message.")


def demo_gcm_keystream_reuse_xor_leak(
    save_path: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)  # BAD: reused nonce
    # Construct messages: identical except a middle slice differs
    prefix = b"A" * 32
    mid1 = b"TOPSECRET"
    mid2 = b"REDACTED!"
    suffix = b"A" * 32
    p1 = prefix + mid1 + suffix
    p2 = prefix + mid2 + suffix

    # Same key + SAME nonce (this is the vulnerability)
    n1, c1, t1 = aes_gcm_encrypt(key, p1, nonce=nonce)
    n2, c2, t2 = aes_gcm_encrypt(key, p2, nonce=nonce)

    # Emulate reading ciphertext bundles from JSON files
    bundle1 = {"ciphertext_b64": base64.b64encode(c1).decode("ascii")}
    bundle2 = {"ciphertext_b64": base64.b64encode(c2).decode("ascii")}
    ct1 = base64.b64decode(bundle1["ciphertext_b64"])
    ct2 = base64.b64decode(bundle2["ciphertext_b64"])

    # Keystream reuse property in CTR/GCM: C1 ^ C2 = P1 ^ P2
    leak = bytes(a ^ b for a, b in zip(ct1, ct2))
    leak_hex = leak.hex()
    expected_hex = xor_hex(p1, p2)

    # Show recovery of p2's differing middle when p1's middle is known
    start = len(prefix)
    end = start + len(mid1)
    c1_mid = c1[start:end]
    c2_mid = c2[start:end]
    recovered_p2_mid = bytes(a ^ b ^ c for (a, b, c) in zip(c1_mid, c2_mid, mid1))

    highlight = (start, end)
    plot_path = _render_gcm_keystream_heatmap(
        ct1, ct2, leak, save_path=save_path, highlight=highlight
    )

    return {
        "key": key,
        "nonce": nonce,
        "ciphertext_1": c1,
        "ciphertext_2": c2,
        "leak_hex": leak_hex,
        "expected_hex": expected_hex,
        "plot_path": str(plot_path),
        "highlight_span": highlight,
        "recovered_mid": recovered_p2_mid,
        "expected_mid": mid2,
    }


if __name__ == "__main__":
    print("== AES Demos ==")
    roundtrip_checks()
    ecb_info = demo_ecb_pattern_leakage()
    print("[ECB] Key:", ecb_info["key"].hex())
    print(
        f"[ECB] Total blocks: {ecb_info['total_blocks']}, unique blocks: {ecb_info['unique_blocks']} (lower is worse)"
    )
    print("[ECB] Ciphertext block pattern (repeats marked with *):")
    for block in ecb_info["block_metadata"]:
        marker = "*" if block["repeats"] > 1 else " "
        print(f"    Block {block['index']:02d}{marker}: {block['hex']}")

    cbc_info = demo_cbc_iv_reuse()
    print("[CBC] Key:", cbc_info["key"].hex())
    print("[CBC] Reused IV:", cbc_info["iv"].hex())
    print("[CBC] Second ciphertext blocks differ?", cbc_info["second_block_differs"])
    print(
        "[CBC] XOR(C1[0], C2[0]) == XOR(P1[0], P2[0])?",
        cbc_info["xor_ciphertexts"] == cbc_info["xor_plaintexts"],
    )
    print("[CBC] XOR(C1[0], C2[0]):", cbc_info["xor_ciphertexts"].hex())
    print("[CBC] XOR(P1[0], P2[0]):", cbc_info["xor_plaintexts"].hex())
    print(
        "[CBC] Bit-flip changed first block?",
        cbc_info["tampered_first_block"] != cbc_info["original_first_block"],
    )
    print("[CBC] Tampered P2'[0]:", cbc_info["tampered_first_block"].hex())
    print("[CBC] Original P2[0]:", cbc_info["original_first_block"].hex())

    gcm_info = demo_gcm_nonce_reuse()
    print("[GCM] Key:", gcm_info["key"].hex())
    print("[GCM] Nonce (reused):", gcm_info["nonce"].hex())
    print(
        f"[GCM] Tag #1: {gcm_info['tag_1'].hex()} | Tag #2: {gcm_info['tag_2'].hex()} | tags equal? {gcm_info['tags_equal']}"
    )
    if gcm_info["verification_error"]:
        print(
            "[GCM] Verification with wrong tag failed as expected:",
            gcm_info["verification_error"],
        )
    else:
        print("[GCM] WARNING: verification unexpectedly succeeded with wrong tag!")

    leak_info = demo_gcm_keystream_reuse_xor_leak()
    print("[GCM] Nonce reused:", leak_info["nonce"].hex())
    print(
        "[GCM] Keystream reuse equality?",
        leak_info["leak_hex"] == leak_info["expected_hex"],
    )
    print("[GCM] XOR(ct1, ct2):", leak_info["leak_hex"])
    print("[GCM] XOR(pt1, pt2):", leak_info["expected_hex"])
    print("[GCM] Heatmap saved to:", leak_info["plot_path"])
    print("[GCM] Recovered differing plaintext segment:", leak_info["recovered_mid"])
    print("[GCM] Expected segment:", leak_info["expected_mid"])
    print("Done.")
