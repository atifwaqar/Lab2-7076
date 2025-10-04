#!/usr/bin/env python3
"""
Lab 2 CLI – one entry point to run all demos.

Usage:
  Interactive menu:
    python lab2_cli.py

  Non-interactive:
    python lab2_cli.py --run aes
    python lab2_cli.py --run rsa
    python lab2_cli.py --run dh
    python lab2_cli.py --run ecdh
    python lab2_cli.py --run bleichenbacher
    python lab2_cli.py --run all
"""

from __future__ import annotations
import argparse
import textwrap

# --- Imports from your repo modules (ensure you run from repo root) ---
# AES demos (functions already exist in aes_modes/ecb_cbc_gcm.py)
from aes_modes.ecb_cbc_gcm import (
    roundtrip_checks as aes_roundtrip,
    demo_ecb_pattern_leakage,
    demo_cbc_iv_reuse,
    demo_gcm_nonce_reuse,
    demo_gcm_keystream_reuse_xor_leak,
)
from aes_modes.aes_file_io import run_encrypt_console, run_decrypt_console

# RSA: build a small roundtrip using the provided primitives
from rsa.rsa_from_scratch import (
    generate_key,
    i2osp, os2ip,
    encrypt_int, decrypt_int,
)
from rsa.rsa_file_io import (
    run_encrypt_console as run_rsa_encrypt_console,
    run_decrypt_console as run_rsa_decrypt_console,
)

# DH / ECDH have demo() functions
from dh.dh_small_prime import demo as dh_demo
from dh.dh_file_io import (
    run_encrypt_console as run_dh_encrypt_console,
    run_decrypt_console as run_dh_decrypt_console,
)

try:
    from ecdh.ecdh_tinyec import demo as ecdh_demo
    from ecdh.ecdh_file_io import (
        run_encrypt_console as run_ecdh_encrypt_console,
        run_decrypt_console as run_ecdh_decrypt_console,
    )
except Exception as e:
    ecdh_demo = None
    run_ecdh_encrypt_console = None
    run_ecdh_decrypt_console = None
    _ecdh_import_error = e

# Bleichenbacher oracle scaffold (optional)
try:
    from attacks.bleichenbacher_oracle import demo_oracle as bleichenbacher_demo
except Exception:
    bleichenbacher_demo = None

BANNER = r"""
  _          _        __     ___  
 | |        | |       \ \   / / | 
 | |     ___| |__   ___\ \_/ /| | 
 | |    / __| '_ \ / _ \\   / | | 
 | |____\__ \ | | |  __/ | |  | | 
 |______|___/_| |_|\___| |_|  |_|   Lab 2 — Crypto Demos

"""

def line():
    print("-" * 70)

def menu():
    print(BANNER)
    print("Choose a demo/task to run:")
    print("  1) AES demos (ECB/CBC/GCM + misuse)")
    print("  2) RSA round-trip test (generate key, encrypt/decrypt)")
    print("  3) Diffie–Hellman (finite field) demo")
    print("  4) Elliptic-Curve DH (tinyec) demo")
    print("  5) Bleichenbacher padding-oracle scaffold (optional)")
    print("  6) Run ALL (in order)")
    print("  0) Exit")
    return input("\nEnter choice: ").strip()

def _run_aes_demos():
    line()
    print("== AES Demos ==")
    aes_roundtrip()
    demo_ecb_pattern_leakage()
    demo_cbc_iv_reuse()
    demo_gcm_nonce_reuse()
    print("[GCM] Demonstrating keystream reuse XOR leakage...")
    demo_gcm_keystream_reuse_xor_leak()
    print("AES demos done.")
    line()


def run_aes(run_default: bool = False):
    if run_default:
        _run_aes_demos()
        return

    while True:
        line()
        print("== AES Menu ==")
        print("  1) Run AES demos")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _run_aes_demos()
        elif choice == "2":
            run_encrypt_console()
        elif choice == "3":
            run_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            print("Invalid option. Choose 0-3.")

def _run_rsa_demo():
    line()
    print("== RSA Round-trip ==")
    # small demo using existing functions
    n, e, d = generate_key(1024)
    msg = b"hi rsa from CLI"
    m = i2osp(msg)
    c = encrypt_int(m, e, n)
    dec = decrypt_int(c, d, n)
    out = os2ip(dec)
    ok = (out == msg)
    print(f"Key size: {n.bit_length()} bits | round-trip OK? {ok}")
    if not ok:
        print("ERROR: RSA round-trip failed.")
    line()

def run_rsa(run_default: bool = False):
    if run_default:
        _run_rsa_demo()
        return

    while True:
        line()
        print("== RSA Menu ==")
        print("  1) Run RSA round-trip demo")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _run_rsa_demo()
        elif choice == "2":
            run_rsa_encrypt_console()
        elif choice == "3":
            run_rsa_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            print("Invalid option. Choose 0-3.")


def _run_dh_demo():
    line()
    print("== Diffie–Hellman (finite field) ==")
    dh_demo()
    line()

def run_dh(run_default: bool = False):
    if run_default:
        _run_dh_demo()
        return

    while True:
        line()
        print("== DH Menu ==")
        print("  1) Run DH demo")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _run_dh_demo()
        elif choice == "2":
            run_dh_encrypt_console()
        elif choice == "3":
            run_dh_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            print("Invalid option. Choose 0-3.")


def _run_ecdh_demo():
    line()
    print("== ECDH (tinyec) ==")
    if ecdh_demo is None:
        print("ECDH demo unavailable. Import failed.")
        print("Detail:", repr(_ecdh_import_error))
        print("Hint: Did you run `pip install -r requirements.txt`?")
    else:
        ecdh_demo()
    line()


def run_ecdh(run_default: bool = False):
    if run_default:
        _run_ecdh_demo()
        return

    while True:
        line()
        print("== ECDH Menu ==")
        print("  1) Run ECDH demo")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _run_ecdh_demo()
        elif choice == "2":
            if run_ecdh_encrypt_console is None:
                print("ECDH file helpers unavailable. Import failed.")
            else:
                run_ecdh_encrypt_console()
        elif choice == "3":
            if run_ecdh_decrypt_console is None:
                print("ECDH file helpers unavailable. Import failed.")
            else:
                run_ecdh_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            print("Invalid option. Choose 0-3.")

def run_bleichenbacher():
    line()
    print("== Bleichenbacher Padding-Oracle (scaffold) ==")
    if bleichenbacher_demo is None:
        print("Bleichenbacher demo not available (scaffold missing or import failed).")
        print("If you plan to implement it, run: python attacks/bleichenbacher_oracle.py")
    else:
        bleichenbacher_demo()
    line()

def run_all():
    run_aes(run_default=True)
    run_rsa(run_default=True)
    run_dh(run_default=True)
    run_ecdh(run_default=True)
    run_bleichenbacher()
    print("All demos completed.")

def parse_args():
    ap = argparse.ArgumentParser(
        description="Lab 2 CLI — run crypto demos from a single entry point.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python lab2_cli.py
          python lab2_cli.py --run aes
          python lab2_cli.py --run all
        """),
    )
    ap.add_argument("--run",
        choices=["aes","rsa","dh","ecdh","bleichenbacher","all"],
        help="Run a specific demo non-interactively.")
    return ap.parse_args()

def main():
    args = parse_args()
    if args.run:
        mapping = {
            "aes": lambda: run_aes(run_default=True),
            "rsa": run_rsa,
            "dh": run_dh,
            "ecdh": run_ecdh,
            "bleichenbacher": run_bleichenbacher,
            "all": run_all,
        }
        mapping[args.run]()
        return

    # interactive loop
    while True:
        choice = menu()
        if choice == "1":
            run_aes()
        elif choice == "2":
            run_rsa()
        elif choice == "3":
            run_dh()
        elif choice == "4":
            run_ecdh()
        elif choice == "5":
            run_bleichenbacher()
        elif choice == "6":
            run_all()
        elif choice == "0" or choice.lower() in {"q", "quit", "exit"}:
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 0–6.")

if __name__ == "__main__":
    main()
