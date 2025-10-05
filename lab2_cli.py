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
import os
import pathlib
import sys
import textwrap
import pyfiglet
# Ensure relative repo imports work even if executed from another directory.
sys.path.insert(0, str(pathlib.Path(__file__).parent.resolve()))

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

BANNER = pyfiglet.figlet_format("Lab2 - Crypto Demos")


def clear_screen() -> None:
    """Clear the terminal screen in a cross-platform way."""
    command = "cls" if os.name == "nt" else "clear"
    try:
        os.system(command)
    except Exception:
        # Ignore failures so the CLI still works even if the command is missing.
        pass


def line():
    print("-" * 70)

def menu():
    clear_screen()
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
    print("[AES] Round-trip correctness across ECB/CBC/GCM:")
    aes_roundtrip()
    print()
    print("[AES] ECB pattern leakage demo:")
    ecb_data = demo_ecb_pattern_leakage()
    print(f"    Key: {ecb_data['key'].hex()}")
    print(
        f"    Total blocks: {ecb_data['total_blocks']}, unique blocks: {ecb_data['unique_blocks']} (lower is worse)"
    )
    print("    Ciphertext block pattern (repeats marked with *):")
    for block in ecb_data["block_metadata"]:
        marker = "*" if block["repeats"] > 1 else " "
        print(f"      Block {block['index']:02d}{marker}: {block['hex']}")
    print()
    print("[AES] CBC IV reuse demo:")
    cbc_data = demo_cbc_iv_reuse()
    print(f"    Key: {cbc_data['key'].hex()}")
    print(f"    Reused IV: {cbc_data['iv'].hex()}")
    print(f"    Second ciphertext blocks differ? {cbc_data['second_block_differs']}")
    print(
        "    XOR(C1[0], C2[0]) == XOR(P1[0], P2[0])?",
        cbc_data["xor_ciphertexts"] == cbc_data["xor_plaintexts"],
    )
    print(f"    XOR(C1[0], C2[0]): {cbc_data['xor_ciphertexts'].hex()}")
    print(f"    XOR(P1[0], P2[0]): {cbc_data['xor_plaintexts'].hex()}")
    print(
        "    Bit-flip changed first block?",
        cbc_data["tampered_first_block"] != cbc_data["original_first_block"],
    )
    print(f"    Tampered P2'[0]: {cbc_data['tampered_first_block'].hex()}")
    print(f"    Original P2[0]: {cbc_data['original_first_block'].hex()}")
    print()
    print("[AES] GCM nonce reuse demo:")
    gcm_data = demo_gcm_nonce_reuse()
    print(f"    Key: {gcm_data['key'].hex()}")
    print(f"    Nonce (reused): {gcm_data['nonce'].hex()}")
    print(
        f"    Tags equal? {gcm_data['tags_equal']} | Tag #1: {gcm_data['tag_1'].hex()} | Tag #2: {gcm_data['tag_2'].hex()}"
    )
    print(f"    Ciphertext #1: {gcm_data['ciphertext_1'].hex()}")
    print(f"    Ciphertext #2: {gcm_data['ciphertext_2'].hex()}")
    if gcm_data["verification_error"]:
        print(
            "    Verification with wrong tag failed as expected:",
            gcm_data["verification_error"],
        )
    else:
        print("    Warning: verification unexpectedly succeeded with wrong tag!")
    print()
    print("[AES] Demonstrating keystream reuse XOR leakage in GCM:")
    leak_data = demo_gcm_keystream_reuse_xor_leak()
    print(f"    Key: {leak_data['key'].hex()}")
    print(f"    Nonce reused: {leak_data['nonce'].hex()}")
    print(
        "    Keystream reuse equality?",
        leak_data["leak_hex"] == leak_data["expected_hex"],
    )
    print(f"    XOR(ct1, ct2): {leak_data['leak_hex']}")
    print(f"    XOR(pt1, pt2): {leak_data['expected_hex']}")
    print(f"    Heatmap saved to: {leak_data['plot_path']}")
    highlight = leak_data.get("highlight_span")
    if highlight is not None:
        start, end = highlight
        print(
            f"    Highlighted columns: [{start}, {end}) mark the differing plaintext segment."
        )
    print(
        "    Recovered differing plaintext segment:",
        leak_data["recovered_mid"],
    )
    print(f"    Expected segment: {leak_data['expected_mid']}")
    print("\nAES demos done.")
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
    n, e, d = generate_key(2048)
    msg = b"hi rsa from CLI"
    m = i2osp(msg)
    c = encrypt_int(m, e, n)
    dec = decrypt_int(c, d, n, e=e)
    out = os2ip(dec)
    ok = (out == msg)
    modulus_preview = hex(n)[2:66] + ("…" if n.bit_length() > 256 else "")
    priv_preview = hex(d)[2:66] + ("…" if d.bit_length() > 256 else "")
    print(f"Modulus n size: {n.bit_length()} bits")
    print(f"Modulus n (head): 0x{modulus_preview}")
    print(f"Public exponent e: {e}")
    print(f"Private exponent d (head): 0x{priv_preview}")
    print(f"Plaintext bytes: {msg!r}")
    print(f"Plaintext as integer: 0x{m:x}")
    print(f"Ciphertext: 0x{c:x}")
    print(f"Decryption recovered: {out!r}")
    print(f"Round-trip OK? {ok}")
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

def run_bleichenbacher(
    run_default: bool = False,
    fast_default: bool = True,
    *,
    wait_for_key: bool | None = None,
):
    line()
    print("== Bleichenbacher Padding-Oracle (scaffold) ==")

    if wait_for_key is None:
        wait_for_key = not run_default

    if bleichenbacher_demo is None:
        print("This demo is optional or missing dependencies.")
        print("If you want to try it, make sure 'attacks/bleichenbacher_oracle.py' is present.")
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        line()
        return

    if run_default:
        mode = "FAST" if fast_default else "SLOW"
        print(f"[Auto] Running in {mode} mode...")
        bleichenbacher_demo(use_fast=fast_default)
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        line()
        return

    while True:
        print("Choose a mode:")
        print("  1) Slow (strict PKCS#1 v1.5 oracle)")
        print("  2) Fast (prefix-only oracle)")
        print("  0) Back")
        choice = input("\nEnter choice: ").strip()
        if choice == "1":
            print()
            bleichenbacher_demo(use_fast=False)
            if wait_for_key:
                input("\nPress Enter to return to the main menu...")
            line()
            break
        elif choice == "2":
            print()
            bleichenbacher_demo(use_fast=True)
            if wait_for_key:
                input("\nPress Enter to return to the main menu...")
            line()
            break
        elif choice == "0":
            line()
            return
        else:
            print("Invalid choice. Please try again.\n")

def run_all(wait_for_key: bool = False):
    run_aes(run_default=True)
    run_rsa(run_default=True)
    run_dh(run_default=True)
    run_ecdh(run_default=True)
    run_bleichenbacher(run_default=True, fast_default=True)
    print("All demos completed.")
    if wait_for_key:
        input("\nPress Enter to return to the main menu...")

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
    ap.add_argument(
        "--run",
        choices=["aes", "rsa", "dh", "ecdh", "bleichenbacher", "all"],
        help="Run a specific demo non-interactively.",
    )
    return ap.parse_args()

def main():
    args = parse_args()
    if args.run:
        mapping = {
            "aes": lambda: run_aes(run_default=True),
            "rsa": lambda: run_rsa(run_default=True),
            "dh": lambda: run_dh(run_default=True),
            "ecdh": lambda: run_ecdh(run_default=True),
            "bleichenbacher": lambda: run_bleichenbacher(run_default=True, fast_default=True),
            # When running all demos non-interactively, still wait for the user before exiting.
            "all": lambda: run_all(wait_for_key=True),
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
            run_all(wait_for_key=True)
        elif choice == "0" or choice.lower() in {"q", "quit", "exit"}:
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 0–6.")

if __name__ == "__main__":
    main()
