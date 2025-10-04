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
import hashlib
import importlib
import os
import subprocess
import sys
import textwrap
from pathlib import Path


def _venv_python_path(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _requirements_marker_path(base_dir: Path, python_executable: Path) -> Path:
    # Use a short hash of the interpreter path to avoid collisions when users
    # run the CLI from multiple environments (e.g., system Python vs venv).
    digest = hashlib.sha256(str(python_executable).encode()).hexdigest()[:16]
    return base_dir / f".requirements_{digest}"


_REQUIREMENT_IMPORTS = {
    "pycryptodome": ["Crypto"],
    "tinyec": ["tinyec"],
    "matplotlib": ["matplotlib"],
}


def _requirements_already_available(requirements_path: Path) -> bool:
    """Return True if every requirement can already be imported."""

    for raw_line in requirements_path.read_text().splitlines():
        requirement = raw_line.strip()
        if not requirement or requirement.startswith("#"):
            continue

        modules = _REQUIREMENT_IMPORTS.get(requirement)
        if not modules:
            # Unknown requirement — we can't reliably check, so request install.
            return False

        for module_name in modules:
            try:
                importlib.import_module(module_name)
            except Exception:
                return False

    return True


def _ensure_requirements_installed(
    python_executable: Path,
    requirements_path: Path,
    marker_path: Path,
) -> None:
    """Install requirements if the hash has changed since the last run."""

    if not requirements_path.exists():
        return

    req_hash = hashlib.sha256(requirements_path.read_bytes()).hexdigest()
    if marker_path.exists() and marker_path.read_text().strip() == req_hash:
        return

    marker_path.parent.mkdir(parents=True, exist_ok=True)

    if _requirements_already_available(requirements_path):
        marker_path.write_text(req_hash)
        return

    subprocess.check_call([
        str(python_executable),
        "-m",
        "pip",
        "install",
        "-r",
        str(requirements_path),
    ])

    marker_path.write_text(req_hash)


def _running_in_any_virtualenv() -> bool:
    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    return sys.prefix != base_prefix


def _running_in_repo_venv(venv_dir: Path, python_in_venv: Path) -> bool:
    env_path = os.environ.get("VIRTUAL_ENV")
    if env_path and Path(env_path).resolve() == venv_dir.resolve():
        return True
    try:
        return Path(sys.executable).resolve() == python_in_venv.resolve()
    except FileNotFoundError:
        return False


def ensure_environment() -> None:
    """Ensure a virtual environment exists with all requirements installed."""

    repo_root = Path(__file__).resolve().parent
    venv_dir = repo_root / ".venv"
    python_in_venv = _venv_python_path(venv_dir)
    requirements_path = repo_root / "requirements.txt"

    if _running_in_repo_venv(venv_dir, python_in_venv):
        marker = venv_dir / ".requirements_hash"
        _ensure_requirements_installed(Path(sys.executable), requirements_path, marker)
        return

    if _running_in_any_virtualenv():
        marker = _requirements_marker_path(repo_root, Path(sys.executable))
        _ensure_requirements_installed(Path(sys.executable), requirements_path, marker)
        return

    if not venv_dir.exists():
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])

    marker = venv_dir / ".requirements_hash"
    _ensure_requirements_installed(python_in_venv, requirements_path, marker)

    os.execv(
        str(python_in_venv),
        [str(python_in_venv), str(repo_root / "lab2_cli.py"), *sys.argv[1:]],
    )


ensure_environment()


# --- Imports from your repo modules (after the environment is ready) ---
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

# DH / ECDH have demo() functions
from dh.dh_small_prime import demo as dh_demo

try:
    from ecdh.ecdh_tinyec import demo as ecdh_demo
except Exception as e:
    ecdh_demo = None
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
        print("  a) Encrypt to file")
        print("  b) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _run_aes_demos()
        elif choice == "a":
            run_encrypt_console()
        elif choice == "b":
            run_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            print("Invalid option. Choose 0, 1, a, or b.")

def run_rsa():
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

def run_dh():
    line()
    print("== Diffie–Hellman (finite field) ==")
    dh_demo()
    line()

def run_ecdh():
    line()
    print("== ECDH (tinyec) ==")
    if ecdh_demo is None:
        print("ECDH demo unavailable. Import failed.")
        print("Detail:", repr(_ecdh_import_error))
        print("Hint: Did you run `pip install -r requirements.txt`?")
    else:
        ecdh_demo()
    line()

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
    run_rsa()
    run_dh()
    run_ecdh()
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
