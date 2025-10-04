"""Helper utilities for RSA file-based encryption using raw textbook RSA."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Tuple

from rsa.rsa_from_scratch import (
    generate_key,
    encrypt_int,
    decrypt_int,
)


@dataclass(frozen=True)
class RsaPublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class RsaPrivateKey:
    n: int
    d: int


class MissingPrivateKeyError(ValueError):
    """Raised when the RSA private exponent is required but unavailable."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, *, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError(f"Invalid base64 value for '{field}'") from exc


def _ensure_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return bytes(data)


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _parse_int(value: str, *, field: str) -> int:
    text = value.strip().lower()
    if text.startswith("0x"):
        base = 16
        text = text[2:]
    else:
        base = 10
    try:
        return int(text, base)
    except ValueError as exc:
        raise ValueError(f"Invalid integer for {field}") from exc


def encrypt_to_file(
    plaintext: bytes | bytearray | memoryview,
    out_path: str | Path,
    *,
    public_key: RsaPublicKey | None = None,
    key_bits: int = 1024,
    store_private: bool = False,
) -> Tuple[RsaPublicKey, RsaPrivateKey | None]:
    """Encrypt *plaintext* with RSA and persist as JSON."""

    message = _ensure_bytes(plaintext)

    if public_key is None:
        n, e, d = generate_key(key_bits)
        public_key = RsaPublicKey(n=n, e=e)
        private_key = RsaPrivateKey(n=n, d=d)
    else:
        n = public_key.n
        e = public_key.e
        private_key = None
        if store_private:
            raise ValueError("store_private=True requires a generated key pair")

    modulus_bytes = (public_key.n.bit_length() + 7) // 8
    if len(message) >= modulus_bytes:
        raise ValueError("Plaintext too large for modulus (no padding used)")

    m_int = _bytes_to_int(message)
    c_int = encrypt_int(m_int, public_key.e, public_key.n)
    ciphertext_bytes = _int_to_bytes(c_int, modulus_bytes)

    bundle: dict[str, Any] = {
        "alg": "RSA",
        "v": 1,
        "n": str(public_key.n),
        "e": public_key.e,
        "modulus_bytes": modulus_bytes,
        "plaintext_len": len(message),
        "ciphertext_b64": _b64encode(ciphertext_bytes),
    }

    if store_private and private_key is not None:
        bundle["d"] = str(private_key.d)

    output_path = Path(out_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")

    return public_key, private_key


def decrypt_from_file(
    in_path: str | Path,
    *,
    private_key: RsaPrivateKey | None = None,
) -> bytes:
    """Decrypt a JSON RSA bundle and return the plaintext."""

    path = Path(in_path)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Input file is not valid JSON") from exc

    if data.get("alg") != "RSA":
        raise ValueError("Input file does not contain RSA data")

    try:
        n = int(data["n"])
        e = int(data["e"])
        modulus_bytes = int(data["modulus_bytes"])
        plaintext_len = int(data["plaintext_len"])
    except KeyError as exc:
        raise ValueError(f"Missing required RSA field: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ValueError("RSA metadata contains invalid integers") from exc

    key_in_file = data.get("d")
    if private_key is None:
        if key_in_file is None:
            raise MissingPrivateKeyError(
                "RSA private exponent required but not provided and not stored in file."
            )
        private_key = RsaPrivateKey(n=n, d=int(key_in_file))
    elif private_key.n == 0:
        private_key = RsaPrivateKey(n=n, d=private_key.d)
    elif private_key.n != n:
        raise ValueError("Provided private key does not match modulus in file")

    ciphertext_b64 = data.get("ciphertext_b64")
    if not ciphertext_b64:
        raise ValueError("Missing ciphertext in RSA file")
    ciphertext = _b64decode(ciphertext_b64, field="ciphertext_b64")
    if len(ciphertext) != modulus_bytes:
        raise ValueError("Ciphertext length does not match recorded modulus bytes")

    c_int = _bytes_to_int(ciphertext)
    m_int = decrypt_int(c_int, private_key.d, private_key.n)
    plaintext_padded = _int_to_bytes(m_int, modulus_bytes)
    if plaintext_len > len(plaintext_padded):
        raise ValueError("Recorded plaintext length larger than recovered data")
    return plaintext_padded[-plaintext_len:]


def run_encrypt_console() -> None:
    """Interactive prompt for RSA encryption to a JSON file."""

    print("-- RSA Encrypt to File --")
    plaintext_str = input("Enter plaintext: ")
    plaintext = plaintext_str.encode("utf-8")

    key_bits_str = input("Key size in bits (default 1024): ").strip()
    key_bits = 1024
    if key_bits_str:
        try:
            key_bits = int(key_bits_str)
        except ValueError:
            print("Invalid key size; using 1024 bits.")
            key_bits = 1024
        if key_bits < 256:
            print("Key size too small; using minimum 256 bits.")
            key_bits = max(256, key_bits)

    store_private_answer = input("Store private exponent in file? (y/N): ").strip().lower()
    store_private = store_private_answer in {"y", "yes"}

    output_dir = Path("EncryptedFiles") / "RSA"
    output_dir.mkdir(parents=True, exist_ok=True)

    name_hint = input("Name for output file (optional): ").strip()
    if not name_hint:
        name_hint = "rsa"
    sanitized = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in name_hint)
    if not sanitized:
        sanitized = "rsa"

    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = output_dir / f"{sanitized}_{timestamp}.json"

    try:
        public_key, private_key = encrypt_to_file(
            plaintext,
            out_file,
            key_bits=key_bits,
            store_private=store_private,
        )
    except Exception as exc:
        print(f"Encryption failed: {exc}")
        return

    print("RSA encrypted data saved to:")
    print(f"  {out_file.resolve()}")
    print("Public key (hex):")
    print(f"  n = {public_key.n:#x}")
    print(f"  e = {public_key.e:#x}")

    if not store_private and private_key is not None:
        print("Private exponent (hex) — keep this safe:")
        print(f"  d = {private_key.d:#x}")


def run_decrypt_console() -> None:
    """Interactive prompt for RSA decryption from a JSON file."""

    print("-- RSA Decrypt from File --")
    encrypted_dir = Path("EncryptedFiles") / "RSA"
    if not encrypted_dir.exists():
        print("No RSA encrypted files found.")
        return

    files = sorted(file for file in encrypted_dir.iterdir() if file.suffix == ".json")
    if not files:
        print("No RSA JSON files available.")
        return

    print("Available RSA files:")
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
    except MissingPrivateKeyError:
        key_input = input("Private exponent not in file. Enter d (decimal or 0x-hex): ").strip()
        if not key_input:
            print("No private key provided. Aborting.")
            return
        try:
            d_value = _parse_int(key_input, field="private exponent")
        except ValueError as exc:
            print(str(exc))
            return
        try:
            plaintext = decrypt_from_file(in_file, private_key=RsaPrivateKey(n=0, d=d_value))
        except ValueError as exc:
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
