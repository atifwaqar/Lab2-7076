"""Helper utilities for AES file-based encryption and decryption."""
from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY_SIZE = 32
_GCM_NONCE_SIZE = 12


class MissingKeyError(ValueError):
    """Raised when the encryption key is required but unavailable."""


def _ensure_bytes(data: bytes | bytearray | memoryview | None, *, name: str) -> bytes | None:
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"{name} must be bytes-like or None")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, *, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError(f"Invalid base64 value for '{field}'") from exc


def _validate_mode(mode: str) -> str:
    if not isinstance(mode, str):
        raise TypeError("mode must be a string")
    normalized = mode.strip().upper()
    if normalized not in {"ECB", "CBC", "GCM"}:
        raise ValueError("mode must be one of: ECB, CBC, GCM")
    return normalized


def encrypt_to_file(
    plaintext: bytes,
    mode: str,
    out_path: str | Path,
    key: bytes | None = None,
    aad: bytes | None = None,
    store_key: bool = False,
    iv: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Encrypt *plaintext* under *mode* and persist the bundle as JSON."""

    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")

    mode_name = _validate_mode(mode)
    key_bytes = _ensure_bytes(key, name="key") or get_random_bytes(KEY_SIZE)
    if len(key_bytes) != KEY_SIZE:
        raise ValueError("key must be 32 bytes for AES-256")

    aad_bytes = _ensure_bytes(aad, name="aad") or b""

    bundle: dict[str, Any] = {
        "alg": "AES",
        "mode": mode_name,
        "v": 1,
        "key_size": KEY_SIZE,
    }

    if store_key:
        bundle["key_b64"] = _b64encode(key_bytes)

    if mode_name == "ECB":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(bytes(plaintext), BLOCK_SIZE))
        bundle["ciphertext_b64"] = _b64encode(ciphertext)

    elif mode_name == "CBC":
        iv = _ensure_bytes(iv, name="iv") or get_random_bytes(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("iv must be 16 bytes for CBC mode")
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(bytes(plaintext), BLOCK_SIZE))
        bundle["iv_b64"] = _b64encode(iv)
        bundle["ciphertext_b64"] = _b64encode(ciphertext)

    else:  # GCM
        nonce = _ensure_bytes(nonce, name="nonce") or get_random_bytes(_GCM_NONCE_SIZE)
        if len(nonce) != _GCM_NONCE_SIZE:
            raise ValueError("nonce must be 12 bytes for GCM mode")
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        if aad_bytes:
            cipher.update(aad_bytes)
        ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext))
        bundle["nonce_b64"] = _b64encode(nonce)
        bundle["tag_b64"] = _b64encode(tag)
        if aad_bytes:
            bundle["aad_b64"] = _b64encode(aad_bytes)
        bundle["ciphertext_b64"] = _b64encode(ciphertext)

    output_path = Path(out_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cipher_bytes = None
    if "ciphertext_b64" in bundle:
        cipher_bytes = base64.b64decode(bundle["ciphertext_b64"])
        bundle["ciphertext_len"] = len(cipher_bytes)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")

    if cipher_bytes is not None:
        bin_path = output_path.with_suffix(output_path.suffix + ".bin")
        bin_path.write_bytes(cipher_bytes)

    return key_bytes


def decrypt_from_file(
    in_path: str | Path,
    mode_hint: str | None = None,
    key: bytes | None = None,
) -> bytes:
    """Restore plaintext from an encrypted JSON bundle."""

    path = Path(in_path)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Input file is not valid JSON") from exc

    mode_in_file = data.get("mode")
    if mode_in_file is None:
        raise ValueError("Missing 'mode' in input file")
    mode_name = _validate_mode(mode_in_file)

    if mode_hint is not None and _validate_mode(mode_hint) != mode_name:
        raise ValueError("mode_hint does not match mode stored in file")

    key_bytes = _ensure_bytes(key, name="key")
    if key_bytes is None:
        key_b64 = data.get("key_b64")
        if not key_b64:
            raise MissingKeyError(
                "Encryption key required but not provided and not stored in file."
            )
        key_bytes = _b64decode(key_b64, field="key_b64")

    if len(key_bytes) != KEY_SIZE:
        raise ValueError("key must be 32 bytes for AES-256")

    ciphertext_b64 = data.get("ciphertext_b64")
    if not ciphertext_b64:
        raise ValueError("Missing 'ciphertext_b64' in input file")
    ciphertext = _b64decode(ciphertext_b64, field="ciphertext_b64")

    if mode_name == "ECB":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return plaintext

    if mode_name == "CBC":
        iv_b64 = data.get("iv_b64")
        if not iv_b64:
            raise ValueError("Missing 'iv_b64' for CBC mode")
        iv = _b64decode(iv_b64, field="iv_b64")
        if len(iv) != BLOCK_SIZE:
            raise ValueError("Invalid IV length for CBC mode")
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return plaintext

    # GCM
    nonce_b64 = data.get("nonce_b64")
    tag_b64 = data.get("tag_b64")
    if not nonce_b64 or not tag_b64:
        raise ValueError("Missing 'nonce_b64' or 'tag_b64' for GCM mode")
    nonce = _b64decode(nonce_b64, field="nonce_b64")
    tag = _b64decode(tag_b64, field="tag_b64")
    if len(nonce) != _GCM_NONCE_SIZE:
        raise ValueError("Invalid nonce length for GCM mode")
    aad_b64 = data.get("aad_b64")
    aad_bytes = _b64decode(aad_b64, field="aad_b64") if aad_b64 else b""

    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    if aad_bytes:
        cipher.update(aad_bytes)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError(
            "GCM authentication failed (wrong key/nonce/tag or ciphertext tampered)."
        ) from e
    return plaintext


def run_encrypt_console() -> None:
    """Interactive prompt for encrypting a message to a JSON file."""

    print("-- AES Encrypt to File --")
    mode_mapping = {"1": "ECB", "2": "CBC", "3": "GCM"}
    while True:
        print("Choose mode:")
        print("  1) ECB")
        print("  2) CBC")
        print("  3) GCM")
        selection = input("Select a mode: ").strip()
        mode = mode_mapping.get(selection, selection)
        try:
            mode_name = _validate_mode(mode)
            break
        except Exception as exc:
            print(f"Error: {exc}")

    plaintext_str = input("Enter plaintext: ")
    plaintext = plaintext_str.encode("utf-8")

    name_hint = input(
        "Name for encrypted output (optional, used in filename): "
    ).strip()
    if not name_hint:
        name_hint = mode_name.lower()
    sanitized_name = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in name_hint
    ).strip("_")
    if not sanitized_name:
        sanitized_name = "encryption"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("EncryptedFiles")
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"{sanitized_name}_{timestamp}.json"

    store_key_answer = input("Store key in file? (y/N): ").strip().lower()
    store_key = store_key_answer in {"y", "yes"}

    aad_bytes = None
    iv_bytes = None
    nonce_bytes = None
    if mode_name == "CBC":
        while True:
            iv_hex = input(
                "Initialization vector (hex, optional, blank for random): "
            ).strip()
            if not iv_hex:
                break
            try:
                iv_bytes = bytes.fromhex(iv_hex)
            except ValueError:
                print("Invalid hex string for IV. Please try again.")
                continue
            if len(iv_bytes) != BLOCK_SIZE:
                print("IV must be 16 bytes (32 hex characters).")
                iv_bytes = None
                continue
            break
    elif mode_name == "GCM":
        aad_str = input("Additional authenticated data (optional, press Enter to skip): ")
        if aad_str:
            aad_bytes = aad_str.encode("utf-8")
        while True:
            nonce_hex = input("Nonce (hex, optional, blank for random): ").strip()
            if not nonce_hex:
                break
            try:
                nonce_bytes = bytes.fromhex(nonce_hex)
            except ValueError:
                print("Invalid hex string for nonce. Please try again.")
                continue
            if len(nonce_bytes) != _GCM_NONCE_SIZE:
                print("Nonce must be 12 bytes (24 hex characters).")
                nonce_bytes = None
                continue
            break

    try:
        key = encrypt_to_file(
            plaintext=plaintext,
            mode=mode_name,
            out_path=out_file,
            aad=aad_bytes,
            store_key=store_key,
            iv=iv_bytes,
            nonce=nonce_bytes,
        )
    except Exception as exc:
        print(f"Encryption failed: {exc}")
        return

    json_path = out_file.resolve()
    bin_path = out_file.with_suffix(out_file.suffix + ".bin").resolve()
    print("Encrypted data saved.")
    print(f"  JSON metadata: {json_path}")
    if bin_path.exists():
        print(f"  Ciphertext bytes: {bin_path}")
    if not store_key:
        print("Encryption key (Base64) — keep this safe:")
        print(_b64encode(key))


def run_decrypt_console() -> None:
    """Interactive prompt for decrypting a message from a JSON file."""

    print("-- AES Decrypt from File --")
    in_file = input("Input file path: ").strip()

    try:
        plaintext = decrypt_from_file(in_file)
    except MissingKeyError:
        key_b64 = (
            input("Key not found in file. Enter Base64-encoded key: ")
            .strip()
            .replace(" ", "")
        )
        if not key_b64:
            print("No key provided. Aborting.")
            return
        try:
            key = _b64decode(key_b64, field="provided key")
        except Exception as exc:
            print(f"Invalid key: {exc}")
            return
        try:
            plaintext = decrypt_from_file(in_file, key=key)
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

