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
