import os
import pathlib
import sys

# Ensure matplotlib uses a non-interactive backend for headless test runs.
os.environ.setdefault("MPLBACKEND", "Agg")

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_aes_roundtrip():
    from aes_modes.ecb_cbc_gcm import roundtrip_demo

    res = roundtrip_demo()
    assert res["ok_ecb"] and res["ok_cbc"] and res["ok_gcm"]


def test_cbc_bitflip_corrupts_first_block():
    from aes_modes.ecb_cbc_gcm import aes_cbc_decrypt, aes_cbc_encrypt, BLOCK

    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    pt = b"A" * BLOCK + b"B" * BLOCK

    iv_ct = aes_cbc_encrypt(key, pt)
    assert aes_cbc_decrypt(key, iv_ct) == pt

    original_iv = iv_ct[:BLOCK]
    ciphertext_body = iv_ct[BLOCK:]

    tampered_iv = bytearray(original_iv)
    tampered_iv[0] ^= 0x01

    tampered_plaintext = aes_cbc_decrypt(key, bytes(tampered_iv) + ciphertext_body)

    assert tampered_plaintext[:BLOCK] != pt[:BLOCK]
    assert tampered_plaintext[BLOCK:] == pt[BLOCK:]


def test_gcm_keystream_visualization(tmp_path):
    from aes_modes.ecb_cbc_gcm import demo_gcm_keystream_reuse_xor_leak

    out = demo_gcm_keystream_reuse_xor_leak(save_path=tmp_path / "reuse.png")

    assert out["leak_hex"] == out["expected_hex"]
    assert out["recovered_mid"] == out["expected_mid"]
    assert (tmp_path / "reuse.png").exists()


def test_dh_shared_secret():
    from dh.dh_small_prime import dh_demo

    sha_a, sha_b = dh_demo()
    assert sha_a == sha_b


def test_ecdh_shared_secret():
    from ecdh.ecdh_tinyec import ecdh_demo

    digest = ecdh_demo()
    assert isinstance(digest, str) and len(digest) == 64


def test_rsa_roundtrip():
    from rsa.rsa_from_scratch import rsa_roundtrip

    n, e, d, ok = rsa_roundtrip()
    assert ok and all(isinstance(value, int) for value in (n, e, d))


def test_bleichenbacher_fast_oracle():
    from attacks.bleichenbacher_oracle import demo_fast_oracle

    ok, iters = demo_fast_oracle()
    assert ok and iters > 0


def test_dh_hkdf_aead():
    from dh.dh_small_prime import dh_aead_demo

    out = dh_aead_demo()
    assert out["ok"] and isinstance(out["nonce"], bytes) and isinstance(out["tag"], bytes)


def test_ecdh_hkdf_aead():
    from ecdh.ecdh_tinyec import ecdh_aead_demo

    out = ecdh_aead_demo()
    assert out.get("ok", False)
