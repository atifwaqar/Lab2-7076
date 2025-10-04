"""Helper utilities for ECDH-based file encryption using AES-GCM."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tinyec import registry


@dataclass(frozen=True)
class EcdhPrivate:
    value: int
    curve_name: str


class MissingScalarError(ValueError):
    """Raised when the ECDH private scalar is required but missing."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, *, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError(f"Invalid base64 value for '{field}'") from exc


def _derive_key(curve, shared_point) -> bytes:
    coord_size = (curve.field.p.bit_length() + 7) // 8
    x_bytes = int(shared_point.x).to_bytes(coord_size, "big")
    return hashlib.sha256(x_bytes).digest()


def encrypt_to_file(
    plaintext: bytes | bytearray | memoryview,
    out_path: str | Path,
    *,
    curve_name: str = "secp256r1",
    store_private: bool = False,
) -> tuple[EcdhPrivate, tuple[int, int], tuple[int, int]]:
    """Encrypt *plaintext* using an ECDH-derived AES key and persist to JSON."""

    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    message = bytes(plaintext)

    curve = registry.get_curve(curve_name)
    n = curve.field.n

    from secrets import randbelow

    dA = randbelow(n - 1) + 1
    dB = randbelow(n - 1) + 1
    QA = dA * curve.g
    QB = dB * curve.g
    shared = dA * QB

    key = _derive_key(curve, shared)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    bundle: dict[str, Any] = {
        "alg": "ECDH",
        "v": 1,
        "curve": curve.name,
        "public": {
            "QA": {"x": format(QA.x, "x"), "y": format(QA.y, "x")},
            "QB": {"x": format(QB.x, "x"), "y": format(QB.y, "x")},
        },
        "ciphertext_b64": _b64encode(ciphertext),
        "nonce_b64": _b64encode(nonce),
        "tag_b64": _b64encode(tag),
        "plaintext_len": len(message),
    }

    if store_private:
        bundle["private"] = {"dA": format(dA, "x")}

    output_path = Path(out_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")

    stored = EcdhPrivate(value=dA, curve_name=curve.name)
    return stored, (QA.x, QA.y), (QB.x, QB.y)


def decrypt_from_file(
    in_path: str | Path,
    *,
    private_scalar: EcdhPrivate | None = None,
) -> bytes:
    """Decrypt an ECDH AES-GCM JSON bundle and return the plaintext."""

    path = Path(in_path)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Input file is not valid JSON") from exc

    if data.get("alg") != "ECDH":
        raise ValueError("Input file does not contain ECDH data")

    curve_name = data.get("curve")
    if not curve_name:
        raise ValueError("Missing curve information in ECDH file")
    curve = registry.get_curve(curve_name)

    try:
        QA_data = data["public"]["QA"]
        QB_data = data["public"]["QB"]
        QA = (int(QA_data["x"], 16), int(QA_data["y"], 16))
        QB = (int(QB_data["x"], 16), int(QB_data["y"], 16))
        plaintext_len = int(data["plaintext_len"])
    except KeyError as exc:
        raise ValueError(f"Missing required ECDH field: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ValueError("ECDH metadata contains invalid integers") from exc

    priv_in_file = data.get("private", {}).get("dA")
    if private_scalar is None:
        if priv_in_file is None:
            raise MissingScalarError(
                "ECDH private scalar required but not provided and not stored in file."
            )
        private_scalar = EcdhPrivate(value=int(priv_in_file, 16), curve_name=curve_name)

    if private_scalar.curve_name != curve_name:
        raise ValueError("Provided private scalar does not match curve in file")

    # reconstruct points
    QA_point = curve.point(QA[0], QA[1])
    QB_point = curve.point(QB[0], QB[1])

    shared = private_scalar.value * QB_point
    key = _derive_key(curve, shared)

    ciphertext_b64 = data.get("ciphertext_b64")
    nonce_b64 = data.get("nonce_b64")
    tag_b64 = data.get("tag_b64")
    if not ciphertext_b64 or not nonce_b64 or not tag_b64:
        raise ValueError("Missing ciphertext, nonce, or tag for ECDH bundle")

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
    """Interactive prompt for ECDH encryption to a JSON file."""

    print("-- ECDH Encrypt to File --")
    plaintext = input("Enter plaintext: ").encode("utf-8")
    curve_name = input("Curve name (default secp256r1): ").strip() or "secp256r1"

    store_private_answer = input("Store private scalar in file? (y/N): ").strip().lower()
    store_private = store_private_answer in {"y", "yes"}

    output_dir = Path("EncryptedFiles") / "ECDH"
    output_dir.mkdir(parents=True, exist_ok=True)

    name_hint = input("Name for output file (optional): ").strip()
    if not name_hint:
        name_hint = "ecdh"
    sanitized = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in name_hint)
    if not sanitized:
        sanitized = "ecdh"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = output_dir / f"{sanitized}_{timestamp}.json"

    try:
        private_scalar, QA, QB = encrypt_to_file(
            plaintext,
            out_file,
            curve_name=curve_name,
            store_private=store_private,
        )
    except Exception as exc:
        print(f"Encryption failed: {exc}")
        return

    print("ECDH encrypted data saved to:")
    print(f"  {out_file.resolve()}")
    print(f"Curve: {curve_name}")
    print("Public points (hex):")
    print(f"  QA.x = {QA[0]:#x}")
    print(f"  QA.y = {QA[1]:#x}")
    print(f"  QB.x = {QB[0]:#x}")
    print(f"  QB.y = {QB[1]:#x}")

    if not store_private:
        print("Private scalar (hex) — keep this safe:")
        print(f"  dA = {private_scalar.value:#x}")


def run_decrypt_console() -> None:
    """Interactive prompt for ECDH decryption from a JSON file."""

    print("-- ECDH Decrypt from File --")
    encrypted_dir = Path("EncryptedFiles") / "ECDH"
    if not encrypted_dir.exists():
        print("No ECDH encrypted files found.")
        return

    files = sorted(file for file in encrypted_dir.iterdir() if file.suffix == ".json")
    if not files:
        print("No ECDH JSON files available.")
        return

    print("Available ECDH files:")
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
    except MissingScalarError:
        key_input = input("Private scalar not in file. Enter dA (decimal or 0x-hex): ").strip()
        if not key_input:
            print("No private scalar provided. Aborting.")
            return
        try:
            value = int(key_input, 0)
        except ValueError:
            print("Invalid private scalar.")
            return
        try:
            with open(in_file, "r", encoding="utf-8") as f:
                curve_name = json.load(f)["curve"]
        except Exception as exc:
            print(f"Unable to read curve from file: {exc}")
            return
        try:
            plaintext = decrypt_from_file(
                in_file,
                private_scalar=EcdhPrivate(value=value, curve_name=curve_name),
            )
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
