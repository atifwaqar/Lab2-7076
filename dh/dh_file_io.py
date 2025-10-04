"""Helper utilities for Diffie–Hellman-based file encryption using AES-GCM."""
from __future__ import annotations

import base64
import json
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from dh.dh_small_prime import p as GROUP_P, g as GROUP_G


@dataclass(frozen=True)
class DhPrivate:
    value: int


class MissingSecretError(ValueError):
    """Raised when the DH private value is required but missing."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, *, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError(f"Invalid base64 value for '{field}'") from exc


def _derive_key(shared_secret: int) -> bytes:
    secret_bytes = shared_secret.to_bytes((GROUP_P.bit_length() + 7) // 8, "big")
    return hashlib.sha256(secret_bytes).digest()


def encrypt_to_file(
    plaintext: bytes | bytearray | memoryview,
    out_path: str | Path,
    *,
    store_private: bool = False,
) -> tuple[DhPrivate, int, int]:
    """Encrypt *plaintext* using DH-derived AES-GCM key and persist to JSON."""

    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    message = bytes(plaintext)

    from secrets import randbelow

    a = randbelow(GROUP_P - 2) + 1
    b = randbelow(GROUP_P - 2) + 1
    A = pow(GROUP_G, a, GROUP_P)
    B = pow(GROUP_G, b, GROUP_P)
    shared = pow(B, a, GROUP_P)

    key = _derive_key(shared)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    bundle: dict[str, Any] = {
        "alg": "DH",
        "v": 1,
        "group": {
            "p": str(GROUP_P),
            "g": GROUP_G,
        },
        "public": {
            "A": str(A),
            "B": str(B),
        },
        "ciphertext_b64": _b64encode(ciphertext),
        "nonce_b64": _b64encode(nonce),
        "tag_b64": _b64encode(tag),
        "plaintext_len": len(message),
    }

    if store_private:
        bundle["private"] = {"a": format(a, "x")}

    stored = DhPrivate(value=a)

    output_path = Path(out_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")

    return stored, A, B


def decrypt_from_file(
    in_path: str | Path,
    *,
    private_value: DhPrivate | None = None,
) -> bytes:
    """Decrypt a DH AES-GCM JSON bundle and return the plaintext."""

    path = Path(in_path)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Input file is not valid JSON") from exc

    if data.get("alg") != "DH":
        raise ValueError("Input file does not contain Diffie–Hellman data")

    public = data.get("public") or {}
    try:
        A = int(public["A"])
        B = int(public["B"])
        plaintext_len = int(data["plaintext_len"])
    except KeyError as exc:
        raise ValueError(f"Missing required DH field: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ValueError("DH metadata contains invalid integers") from exc

    priv_in_file = data.get("private", {}).get("a")
    if private_value is None:
        if priv_in_file is None:
            raise MissingSecretError(
                "DH private value required but not provided and not stored in file."
            )
        private_value = DhPrivate(value=int(priv_in_file, 16))

    shared = pow(B, private_value.value, GROUP_P)

    key = _derive_key(shared)

    ciphertext_b64 = data.get("ciphertext_b64")
    nonce_b64 = data.get("nonce_b64")
    tag_b64 = data.get("tag_b64")
    if not ciphertext_b64 or not nonce_b64 or not tag_b64:
        raise ValueError("Missing ciphertext, nonce, or tag for DH bundle")

    ciphertext = _b64decode(ciphertext_b64, field="ciphertext_b64")
    nonce = _b64decode(nonce_b64, field="nonce_b64")
    tag = _b64decode(tag_b64, field="tag_b64")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError("GCM authentication failed. Secret or ciphertext incorrect.") from exc

    if plaintext_len != len(plaintext):
        plaintext = plaintext[:plaintext_len]
    return plaintext


def run_encrypt_console() -> None:
    """Interactive prompt for DH encryption to a JSON file."""

    print("-- DH Encrypt to File --")
    plaintext = input("Enter plaintext: ").encode("utf-8")

    store_private_answer = input("Store private value in file? (y/N): ").strip().lower()
    store_private = store_private_answer in {"y", "yes"}

    output_dir = Path("EncryptedFiles") / "DH"
    output_dir.mkdir(parents=True, exist_ok=True)

    name_hint = input("Name for output file (optional): ").strip()
    if not name_hint:
        name_hint = "dh"
    sanitized = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in name_hint)
    if not sanitized:
        sanitized = "dh"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = output_dir / f"{sanitized}_{timestamp}.json"

    try:
        private_value, A, B = encrypt_to_file(
            plaintext,
            out_file,
            store_private=store_private,
        )
    except Exception as exc:
        print(f"Encryption failed: {exc}")
        return

    print("DH encrypted data saved to:")
    print(f"  {out_file.resolve()}")
    print("Public values (hex):")
    print(f"  A = {A:#x}")
    print(f"  B = {B:#x}")

    if not store_private:
        print("Private value (hex) — keep this safe:")
        print(f"  a = {private_value.value:#x}")


def run_decrypt_console() -> None:
    """Interactive prompt for DH decryption from a JSON file."""

    print("-- DH Decrypt from File --")
    encrypted_dir = Path("EncryptedFiles") / "DH"
    if not encrypted_dir.exists():
        print("No DH encrypted files found.")
        return

    files = sorted(file for file in encrypted_dir.iterdir() if file.suffix == ".json")
    if not files:
        print("No DH JSON files available.")
        return

    print("Available DH files:")
    for idx, file in enumerate(files, start=1):
        print(f"  {idx}) {file.name}")

    while True:
        selection = input("Select a file number to decrypt (or 'q' to cancel): ").strip()
        if selection.lower() in {"q", "quit", "exit", "0"}:
            print("Decryption cancelled.")
            return
        try:
            choice = int(selection)
        except ValueError:
            print("Invalid selection. Enter a number or 'q'.")
            continue
        if not 1 <= choice <= len(files):
            print("Selection out of range. Try again.")
            continue
        in_file = files[choice - 1]
        break

    try:
        plaintext = decrypt_from_file(in_file)
    except MissingSecretError:
        key_input = input("Private value not in file. Enter a (decimal or 0x-hex): ").strip()
        if not key_input:
            print("No private value provided. Aborting.")
            return
        try:
            value = int(key_input, 0)
        except ValueError:
            print("Invalid private value.")
            return
        try:
            plaintext = decrypt_from_file(in_file, private_value=DhPrivate(value=value))
        except Exception as exc:
            print(f"Decryption failed: {exc}")
            return
    except Exception as exc:
        print(f"Decryption failed: {exc}")
        return

    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        decoded = plaintext.decode("utf-8", errors="replace")
    print("Recovered plaintext:")
    print(decoded)
