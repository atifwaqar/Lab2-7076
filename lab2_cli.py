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
import time
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
from aes_modes.entropy_demo import run_entropy_demo

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
from dh.dh_small_prime import (
    demo as dh_demo,
    dh_demo as dh_shared_secret_demo,
    dh_aead_demo,
)
from dh.dh_file_io import (
    run_encrypt_console as run_dh_encrypt_console,
    run_decrypt_console as run_dh_decrypt_console,
)

try:
    from ecdh.ecdh_tinyec import (
        demo as ecdh_demo,
        ecdh_demo as ecdh_shared_secret_demo,
        ecdh_aead_demo,
    )
    from ecdh.ecdh_file_io import (
        run_encrypt_console as run_ecdh_encrypt_console,
        run_decrypt_console as run_ecdh_decrypt_console,
    )
except Exception as e:
    ecdh_demo = None
    ecdh_shared_secret_demo = None
    ecdh_aead_demo = None
    run_ecdh_encrypt_console = None
    run_ecdh_decrypt_console = None
    _ecdh_import_error = e

# Bleichenbacher oracle scaffold (optional)
try:
    from attacks.bleichenbacher_oracle import demo_oracle as bleichenbacher_demo
except Exception:
    bleichenbacher_demo = None

from utils import console_ui
from utils.plotting import HAS_MPL as _HAS_MPL

from reports import make_all_dashboards as _dashboard_module

_RSA_PADDING_NOTE_PRINTED = False
_IN_RUN_ALL = False


def _print_rsa_padding_note():
    global _RSA_PADDING_NOTE_PRINTED
    if not _RSA_PADDING_NOTE_PRINTED:
        print(
            "Defaulting to RSA-OAEP (PKCS#1 v2.2). Textbook RSA is insecure and only available via --insecure."
        )
        _RSA_PADDING_NOTE_PRINTED = True


def _print_summary(threat: str, misuse: str, evidence: str, remedy: str) -> None:
    console_ui.kv("Threat model", threat)
    console_ui.kv("Misuse shown", misuse)
    console_ui.kv("Evidence", evidence)
    console_ui.kv("Remedy", remedy)


def clear_screen() -> None:
    """Clear the terminal screen in a cross-platform way."""
    command = "cls" if os.name == "nt" else "clear"
    try:
        os.system(command)
    except Exception:
        # Ignore failures so the CLI still works even if the command is missing.
        pass


def line():
    console_ui.line()

def menu():
    clear_screen()
    console_ui.banner("Lab2 - Crypto Demos")
    console_ui.bullet("Choose a demo/task to run:")
    print("  1) AES demos (ECB/CBC/GCM + misuse)")
    print("  2) RSA round-trip test (generate key, encrypt/decrypt)")
    print("  3) Diffie–Hellman (finite field) demo")
    print("  4) Elliptic-Curve DH (tinyec) demo")
    print("  5) Bleichenbacher padding-oracle scaffold (optional)")
    print("  6) Entropy sanity checks")
    print("  7) Run ALL (in order)")
    print("  8) Export dashboards (PNG)")
    print("  0) Exit")
    return input("\nEnter choice: ").strip()

def _run_aes_demos():
    console_ui.section("AES Encryption Modes Demonstration (pycryptodome)")
    console_ui.bullet("Round-trip correctness across ECB/CBC/GCM:")
    aes_roundtrip()
    print()
    console_ui.section("ECB Pattern Leakage Demo")
    ecb_data = demo_ecb_pattern_leakage()
    console_ui.kv("Key", ecb_data["key"].hex())
    console_ui.kv(
        "Block stats",
        f"total={ecb_data['total_blocks']}, unique={ecb_data['unique_blocks']} (lower is worse)",
    )
    console_ui.kv("Ciphertext pattern", "repeats marked with *")
    for block in ecb_data["block_metadata"]:
        marker = "*" if block["repeats"] > 1 else " "
        print(f"      Block {block['index']:02d}{marker}: {block['hex']}")
    repeated_blocks = ecb_data["total_blocks"] - ecb_data["unique_blocks"]
    console_ui.section("Summary")
    _print_summary(
        "attacker observes ciphertext layout",
        "ECB reveals repeated plaintext blocks",
        f"Repeated blocks: {repeated_blocks}/{ecb_data['total_blocks']}",
        "Switch to randomized mode (CBC with fresh IV or AEAD)",
    )
    print()
    console_ui.section("CBC IV Reuse Demo")
    cbc_data = demo_cbc_iv_reuse()
    console_ui.kv("Key", cbc_data["key"].hex())
    console_ui.kv("Reused IV", cbc_data["iv"].hex())
    console_ui.kv("Second ciphertext blocks differ", str(cbc_data["second_block_differs"]))
    console_ui.kv(
        "XOR(C1[0], C2[0]) == XOR(P1[0], P2[0])",
        str(cbc_data["xor_ciphertexts"] == cbc_data["xor_plaintexts"]),
    )
    console_ui.kv("XOR(C1[0], C2[0])", cbc_data["xor_ciphertexts"].hex())
    console_ui.kv("XOR(P1[0], P2[0])", cbc_data["xor_plaintexts"].hex())
    console_ui.kv(
        "Bit-flip changed first block",
        str(cbc_data["tampered_first_block"] != cbc_data["original_first_block"]),
    )
    console_ui.kv("Tampered P2'[0]", cbc_data["tampered_first_block"].hex())
    console_ui.kv("Original P2[0]", cbc_data["original_first_block"].hex())
    xor_matches = cbc_data["xor_ciphertexts"] == cbc_data["xor_plaintexts"]
    console_ui.section("Summary")
    _print_summary(
        "attacker can observe/modify ciphertext",
        "CBC IV reuse exposes prefix equality",
        f"XOR(C1[0],C2[0]) == XOR(P1[0],P2[0]) -> {xor_matches}",
        "Use unpredictable IVs once and add authentication (AEAD)",
    )
    print()
    console_ui.section("GCM Nonce Reuse Demo")
    gcm_data = demo_gcm_nonce_reuse()
    console_ui.kv("Key", gcm_data["key"].hex())
    console_ui.kv("Nonce (reused)", gcm_data["nonce"].hex())
    console_ui.kv(
        "Tags",
        f"equal={gcm_data['tags_equal']} | Tag #1: {gcm_data['tag_1'].hex()} | Tag #2: {gcm_data['tag_2'].hex()}",
    )
    console_ui.kv("Ciphertext #1", gcm_data["ciphertext_1"].hex())
    console_ui.kv("Ciphertext #2", gcm_data["ciphertext_2"].hex())
    if gcm_data["verification_error"]:
        console_ui.kv(
            "Wrong-tag verification",
            f"failed as expected: {gcm_data['verification_error']}",
        )
    else:
        console_ui.warning("Verification unexpectedly succeeded with wrong tag!")
    verification = gcm_data["verification_error"] or "no error"
    console_ui.section("Summary")
    _print_summary(
        "attacker replays/forges under reused nonce",
        "GCM nonce reuse enables tag/ciphertext malleability",
        f"Tags equal: {gcm_data['tags_equal']} | Wrong-tag check -> {verification}",
        "Never reuse nonces; prefer counter management per key",
    )
    print()
    console_ui.section("GCM Keystream Reuse XOR Leakage")
    leak_data = demo_gcm_keystream_reuse_xor_leak()
    console_ui.kv("Key", leak_data["key"].hex())
    console_ui.kv("Nonce reused", leak_data["nonce"].hex())
    console_ui.kv(
        "Keystream reuse equality",
        str(leak_data["leak_hex"] == leak_data["expected_hex"]),
    )
    console_ui.kv("XOR(ct1, ct2)", leak_data["leak_hex"])
    console_ui.kv("XOR(pt1, pt2)", leak_data["expected_hex"])
    console_ui.kv("Heatmap saved to", str(leak_data["plot_path"]))
    highlight = leak_data.get("highlight_span")
    if highlight is not None:
        start, end = highlight
        print(
            f"    Highlighted columns: [{start}, {end}) mark the differing plaintext segment."
        )
    console_ui.kv(
        "Recovered differing segment",
        leak_data["recovered_mid"],
    )
    console_ui.kv("Expected segment", leak_data["expected_mid"])
    xor_leak_matches = leak_data["leak_hex"] == leak_data["expected_hex"]
    console_ui.section("Summary")
    _print_summary(
        "attacker compares two ciphertexts under same nonce",
        "CTR/GCM keystream reuse leaks XOR of plaintexts",
        f"XOR(C1,C2) == XOR(P1,P2) -> {xor_leak_matches}",
        "Derive unique nonces per message and enforce AEAD limits",
    )
    print()


def run_aes(run_default: bool = False):
    title = "AES Encryption Modes (ECB, CBC, GCM)"
    script = "aes_modes/ecb_cbc_gcm.py"

    def _invoke_demo() -> None:
        if not _IN_RUN_ALL:
            console_ui.running_panel(title, script)
        try:
            _run_aes_demos()
        except Exception as exc:  # pragma: no cover - runtime safeguard
            if _IN_RUN_ALL:
                raise
            console_ui.error(f"Demo failed: {exc}")
            console_ui.warning("Hint: run `pip install -r requirements.txt`")
        else:
            console_ui.success("Demo completed successfully.")

    if run_default:
        _invoke_demo()
        return

    while True:
        line()
        console_ui.section("AES Menu")
        print("  1) Run AES demos")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _invoke_demo()
        elif choice == "2":
            run_encrypt_console()
        elif choice == "3":
            run_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            console_ui.warning("Invalid option. Choose 0-3.")

def _run_rsa_demo():
    console_ui.section("RSA Round-trip")
    _print_rsa_padding_note()
    # small demo using existing functions
    n, e, d = generate_key(2048)
    msg = b"hi rsa from CLI"
    m = i2osp(msg)
    c = encrypt_int(m, e, n)
    repeat_c = encrypt_int(m, e, n)
    dec = decrypt_int(c, d, n, e=e)
    out = os2ip(dec)
    ok = (out == msg)
    modulus_preview = hex(n)[2:66] + ("…" if n.bit_length() > 256 else "")
    priv_preview = hex(d)[2:66] + ("…" if d.bit_length() > 256 else "")
    console_ui.kv("Modulus n size", f"{n.bit_length()} bits")
    console_ui.kv("Modulus n (head)", f"0x{modulus_preview}")
    console_ui.kv("Public exponent e", str(e))
    console_ui.kv("Private exponent d (head)", f"0x{priv_preview}")
    console_ui.kv("Plaintext bytes", repr(msg))
    console_ui.kv("Plaintext as integer", f"0x{m:x}")
    console_ui.kv("Ciphertext", f"0x{c:x}")
    console_ui.kv("Decryption recovered", repr(out))
    console_ui.kv("Round-trip OK", str(ok))
    if not ok:
        console_ui.error("RSA round-trip failed.")
    deterministic = repeat_c == c
    console_ui.section("RSA Summary")
    _print_summary(
        "attacker can choose plaintexts/ciphertexts",
        "Textbook RSA without OAEP padding is deterministic",
        f"encrypt(m) repeated -> same ciphertext: {deterministic}",
        "Use randomized padding (OAEP) and constant-time checks",
    )

def run_rsa(run_default: bool = False):
    title = "RSA Round-Trip (with OAEP note)"
    script = "rsa/rsa_from_scratch.py"

    def _invoke_demo() -> None:
        if not _IN_RUN_ALL:
            console_ui.running_panel(title, script)
        try:
            _run_rsa_demo()
        except Exception as exc:  # pragma: no cover - runtime safeguard
            if _IN_RUN_ALL:
                raise
            console_ui.error(f"Demo failed: {exc}")
            console_ui.warning("Hint: run `pip install -r requirements.txt`")
        else:
            console_ui.success("Demo completed successfully.")

    if run_default:
        _invoke_demo()
        return

    while True:
        line()
        console_ui.section("RSA Menu")
        print("  1) Run RSA round-trip demo")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        _print_rsa_padding_note()
        if choice == "1":
            _invoke_demo()
        elif choice == "2":
            run_rsa_encrypt_console()
        elif choice == "3":
            run_rsa_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            console_ui.warning("Invalid option. Choose 0-3.")


def _run_dh_demo():
    console_ui.section("Diffie–Hellman (finite field)")
    dh_demo()
    digest_a, digest_b = dh_shared_secret_demo()
    console_ui.section("AEAD Derivation")
    aead_info = dh_aead_demo()
    shared_match = digest_a == digest_b
    console_ui.kv("Digest length", str(len(digest_a)))
    console_ui.kv("Shared secrets match", str(shared_match))
    console_ui.kv("AEAD demo ok", str(aead_info["ok"]))
    console_ui.section("Summary")
    _print_summary(
        "active attacker relays DH messages",
        "Unauthenticated DH allows man-in-the-middle",
        f"SHA256(shared) match: {shared_match} | HKDF→AEAD ok: {aead_info['ok']}",
        "Authenticate peers (signatures/PSK) before deriving AEAD keys",
    )

def run_dh(run_default: bool = False):
    title = "Diffie–Hellman (finite field)"
    script = "dh/dh_small_prime.py"

    def _invoke_demo() -> None:
        if not _IN_RUN_ALL:
            console_ui.running_panel(title, script)
        try:
            _run_dh_demo()
        except Exception as exc:  # pragma: no cover - runtime safeguard
            if _IN_RUN_ALL:
                raise
            console_ui.error(f"Demo failed: {exc}")
            console_ui.warning("Hint: run `pip install -r requirements.txt`")
        else:
            console_ui.success("Demo completed successfully.")

    if run_default:
        _invoke_demo()
        return

    while True:
        line()
        console_ui.section("DH Menu")
        print("  1) Run DH demo")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _invoke_demo()
        elif choice == "2":
            run_dh_encrypt_console()
        elif choice == "3":
            run_dh_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            console_ui.warning("Invalid option. Choose 0-3.")


def _run_ecdh_demo():
    console_ui.section("Elliptic-Curve DH (tinyec)")
    if ecdh_demo is None:
        console_ui.error("ECDH demo unavailable. Import failed.")
        console_ui.kv("Detail", repr(_ecdh_import_error))
        console_ui.warning("Hint: Did you run `pip install -r requirements.txt`?")
        digest_len = "n/a"
        aead_status = "unavailable"
    else:
        ecdh_demo()
        digest = (
            ecdh_shared_secret_demo() if ecdh_shared_secret_demo is not None else ""
        )
        digest_len = len(digest)
        if ecdh_aead_demo is not None:
            console_ui.section("AEAD Derivation")
            aead_info = ecdh_aead_demo()
            if aead_info.get("skipped"):
                aead_status = "skipped"
                console_ui.warning("AEAD derivation skipped (missing tinyec/matplotlib dependency).")
            else:
                aead_status = f"ok={aead_info['ok']}"
                console_ui.kv("AEAD ok", str(aead_info["ok"]))
        else:
            aead_status = "unavailable"
    console_ui.kv("Digest length", str(digest_len))
    console_ui.kv("HKDF→AEAD", aead_status)
    console_ui.section("Summary")
    if ecdh_demo is None:
        _print_summary(
            "active attacker relays EC public keys",
            "ECDH demo unavailable — cannot illustrate AEAD misuse",
            f"SHA256(shared.x) length: {digest_len} | HKDF→AEAD: {aead_status}",
            "Install tinyec/matplotlib to explore authenticated ECDH",
        )
    else:
        _print_summary(
            "active attacker relays EC public keys",
            "Unauthenticated ECDH enables MITM despite shared secret",
            f"SHA256(shared.x) length: {digest_len} | HKDF→AEAD: {aead_status}",
            "Bind keys to identities (certs) and derive AEAD via HKDF",
        )


def run_ecdh(run_default: bool = False):
    title = "Elliptic-Curve DH (tinyec)"
    script = "ecdh/ecdh_tinyec.py"

    def _invoke_demo() -> None:
        if not _IN_RUN_ALL:
            console_ui.running_panel(title, script)
        try:
            _run_ecdh_demo()
        except Exception as exc:  # pragma: no cover - runtime safeguard
            if _IN_RUN_ALL:
                raise
            console_ui.error(f"Demo failed: {exc}")
            console_ui.warning("Hint: run `pip install -r requirements.txt`")
        else:
            console_ui.success("Demo completed successfully.")

    if run_default:
        _invoke_demo()
        return

    while True:
        line()
        console_ui.section("ECDH Menu")
        print("  1) Run ECDH demo")
        print("  2) Encrypt to file")
        print("  3) Decrypt from file")
        print("  0) Back")
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            _invoke_demo()
        elif choice == "2":
            if run_ecdh_encrypt_console is None:
                console_ui.warning("ECDH file helpers unavailable. Import failed.")
            else:
                run_ecdh_encrypt_console()
        elif choice == "3":
            if run_ecdh_decrypt_console is None:
                console_ui.warning("ECDH file helpers unavailable. Import failed.")
            else:
                run_ecdh_decrypt_console()
        elif choice == "0" or choice in {"q", "quit", "exit"}:
            line()
            break
        else:
            console_ui.warning("Invalid option. Choose 0-3.")

def run_bleichenbacher(
    run_default: bool = False,
    fast_default: bool = True,
    *,
    wait_for_key: bool | None = None,
):
    title = "Bleichenbacher Padding-Oracle (fast)"
    script = "attacks/bleichenbacher_oracle.py"

    if wait_for_key is None:
        wait_for_key = not run_default

    if bleichenbacher_demo is None:
        console_ui.warning("This demo is optional or missing dependencies.")
        console_ui.warning("Ensure 'attacks/bleichenbacher_oracle.py' and dependencies are installed.")
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        return

    def _handle_success(plot_path: str | None = None) -> None:
        console_ui.section("Summary")
        _print_summary(
            "active attacker probes RSA padding oracle",
            "Bleichenbacher adaptive queries recover plaintext",
            "Oracle responses shrink valid interval until plaintext found",
            "Adopt RSA-OAEP and uniform error handling",
        )
        console_ui.section("Convergence")
        if plot_path is not None:
            console_ui.kv("Plot", plot_path)
        else:
            console_ui.kv("Plot", "n/a (enable plotting via demo options)")
        console_ui.success("Demo completed successfully.")

    def _invoke_demo(use_fast: bool) -> None:
        if not _IN_RUN_ALL:
            console_ui.running_panel(title, script)
        try:
            result = bleichenbacher_demo(use_fast=use_fast)
        except Exception as exc:  # pragma: no cover - runtime safeguard
            if _IN_RUN_ALL:
                raise
            console_ui.error(f"Demo failed: {exc}")
            console_ui.warning("Hint: run `pip install -r requirements.txt`")
            return
        plot_path = None
        if isinstance(result, dict) and "plot_path" in result:
            plot_path = str(result["plot_path"])
        _handle_success(plot_path)

    if run_default:
        mode = "FAST" if fast_default else "SLOW"
        if not _IN_RUN_ALL:
            console_ui.bullet(f"[Auto] Running in {mode} mode...")
        _invoke_demo(fast_default)
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        return

    while True:
        console_ui.section("Bleichenbacher Menu")
        print("  1) Slow (strict PKCS#1 v1.5 oracle)")
        print("  2) Fast (prefix-only oracle)")
        print("  0) Back")
        choice = input("\nEnter choice: ").strip()
        if choice == "1":
            print()
            _invoke_demo(False)
            if wait_for_key:
                input("\nPress Enter to return to the main menu...")
            break
        elif choice == "2":
            print()
            _invoke_demo(True)
            if wait_for_key:
                input("\nPress Enter to return to the main menu...")
            break
        elif choice == "0":
            return
        else:
            console_ui.warning("Invalid choice. Please try again.\n")


def run_entropy_checks(*, wait_for_key: bool = True):
    title = "Entropy Sanity Checks"
    script = "aes_modes/entropy_demo.py"

    if not _IN_RUN_ALL:
        console_ui.running_panel(title, script)

    try:
        result = run_entropy_demo()
    except Exception as exc:  # pragma: no cover - runtime safeguard
        if _IN_RUN_ALL:
            raise
        console_ui.error(f"Demo failed: {exc}")
        console_ui.warning("Hint: run `pip install -r requirements.txt`")
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        return {}

    flags = result.get("flags", {})
    key_warn = flags.get("key_warn")
    nonce_warn = flags.get("nonce_warn")
    if key_warn or nonce_warn:
        console_ui.warning("Low-entropy sample detected above thresholds.")
    console_ui.section("Summary")
    _print_summary(
        "defender monitors RNG quality",
        "Entropy check surfaces weak key/nonce samples",
        f"key_warn={key_warn} | nonce_warn={nonce_warn}",
        "Switch to os.urandom/cryptographic RNG or reseed",
    )
    console_ui.success("Demo completed successfully.")
    if wait_for_key:
        input("\nPress Enter to return to the main menu...")
    return result


def export_dashboards(*, wait_for_key: bool = True):
    console_ui.section("Export Dashboards (PNG)")

    def _summarize(paths):
        saved = {pathlib.Path(path).resolve() for path in paths}
        specs = getattr(_dashboard_module, "_DASHBOARD_SPECS", ())
        summary = {}
        for module_name, _, filename in specs:
            resolved = (pathlib.Path("out") / filename).resolve()
            status = "saved" if resolved in saved else "skipped"
            reason = ""
            if status == "skipped":
                missing_tinyec = False
                ecdh_error = globals().get("_ecdh_import_error")
                if isinstance(ecdh_error, ModuleNotFoundError) and ecdh_error.name in {"tinyec", "matplotlib"}:
                    missing_tinyec = True
                if not _HAS_MPL or ("ecdh" in module_name and missing_tinyec):
                    reason = "tinyec/matplotlib not installed"

            existing = summary.get(resolved)
            if existing is None or existing["status"] == "skipped" and status == "saved":
                summary[resolved] = {"status": status, "reason": reason}
            elif existing["status"] == "skipped" and not existing["reason"]:
                summary[resolved]["reason"] = reason
        return summary

    if not _HAS_MPL:
        console_ui.warning("matplotlib is not installed; skipping dashboard export.")
        summary = _summarize([])
        if summary:
            console_ui.section("Summary")
            for path in sorted(summary):
                entry = summary[path]
                suffix = (
                    " (skipped: tinyec/matplotlib not installed)"
                    if entry.get("reason")
                    else " (skipped)"
                )
                print(f"  {path}{suffix}")
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        return []

    try:
        paths = _dashboard_module.make_all_dashboards()
    except Exception as exc:  # pragma: no cover - runtime safeguard
        console_ui.error(f"Dashboard export failed: {exc}")
        if wait_for_key:
            input("\nPress Enter to return to the main menu...")
        return []

    if paths:
        console_ui.success("Saved dashboards:")
        for path in paths:
            print(f"  {pathlib.Path(path).resolve()}")
    else:
        console_ui.info("No dashboards were generated.")

    summary = _summarize(paths)
    if summary:
        console_ui.section("Summary")
        for path in sorted(summary):
            entry = summary[path]
            if entry["status"] == "saved":
                print(f"  {path}")
            else:
                suffix = (
                    " (skipped: tinyec/matplotlib not installed)"
                    if entry.get("reason")
                    else " (skipped)"
                )
                print(f"  {path}{suffix}")

    if wait_for_key:
        input("\nPress Enter to return to the main menu...")

    return paths

# Desired run_all output sample (for developers only):
# [1/6] Preparing to run: AES Encryption Modes (ECB, CBC, GCM)
# ================================================================================
# RUNNING: AES Encryption Modes (ECB, CBC, GCM)
# Script: aes_modes/ecb_cbc_gcm.py
# ================================================================================
# ... (demo output) ...
# DONE in 0.42s
# -------------------------------------------------------------------------------


def run_all(wait_for_key: bool = False):
    steps = [
        ("AES Encryption Modes (ECB, CBC, GCM)", "aes_modes/ecb_cbc_gcm.py", lambda: run_aes(run_default=True)),
        ("RSA Round-Trip (with OAEP note)", "rsa/rsa_from_scratch.py", lambda: run_rsa(run_default=True)),
        ("Diffie–Hellman (finite field)", "dh/dh_small_prime.py", lambda: run_dh(run_default=True)),
        ("Elliptic-Curve DH (tinyec)", "ecdh/ecdh_tinyec.py", lambda: run_ecdh(run_default=True)),
        (
            "Bleichenbacher Padding-Oracle (fast)",
            "attacks/bleichenbacher_oracle.py",
            lambda: run_bleichenbacher(run_default=True, fast_default=True, wait_for_key=False),
        ),
        ("Entropy Sanity Checks", "aes_modes/entropy_demo.py", lambda: run_entropy_checks(wait_for_key=False)),
    ]

    total = len(steps)
    global _IN_RUN_ALL
    previous_state = _IN_RUN_ALL
    _IN_RUN_ALL = True
    try:
        for index, (title, script, func) in enumerate(steps, start=1):
            console_ui.step_header(index, total, title)
            console_ui.running_panel(title, script)
            start = time.perf_counter()
            try:
                func()
            except Exception as exc:  # pragma: no cover - runtime safeguard
                console_ui.error(f"Demo failed: {exc}")
                console_ui.warning("Hint: run `pip install -r requirements.txt`")
            finally:
                elapsed = time.perf_counter() - start
                console_ui.elapsed("DONE in", elapsed)
                console_ui.line()
    finally:
        _IN_RUN_ALL = previous_state

    console_ui.success("All demos completed.")
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
        choices=["aes", "rsa", "dh", "ecdh", "bleichenbacher", "entropy", "all"],
        help="Run a specific demo non-interactively.",
    )
    ap.add_argument(
        "--plain",
        action="store_true",
        help="Disable colors/banners; print plain ASCII.",
    )
    return ap.parse_args()

def main():
    args = parse_args()
    console_ui.init(plain=args.plain)
    if args.run:
        mapping = {
            "aes": lambda: run_aes(run_default=True),
            "rsa": lambda: run_rsa(run_default=True),
            "dh": lambda: run_dh(run_default=True),
            "ecdh": lambda: run_ecdh(run_default=True),
            "bleichenbacher": lambda: run_bleichenbacher(run_default=True, fast_default=True),
            "entropy": lambda: run_entropy_checks(wait_for_key=False),
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
            run_entropy_checks()
        elif choice == "7":
            run_all(wait_for_key=True)
        elif choice == "8":
            export_dashboards()
        elif choice == "0" or choice.lower() in {"q", "quit", "exit"}:
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 0–8.")

if __name__ == "__main__":
    main()
