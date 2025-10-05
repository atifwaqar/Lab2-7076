# Lab 2: Symmetric & Asymmetric Cryptography

This repository contains reference implementations and demos for:

- **AES** (ECB, CBC, GCM) using PyCryptodome + misuse demonstrations (IV/nonce reuse)
- **RSA from scratch** (keygen, encrypt, decrypt) using Python big-ints
- **Diffie–Hellman** (finite field) demo
- **ECDH** using tinyec (with a quick visualization)
- **Bleichenbacher padding-oracle attack** (PKCS#1 v1.5) demo with an implemented adaptive loop

> **Important security notes**
> - File-based RSA here is **textbook RSA** (no OAEP) and **insecure in practice**. Use **RSA-OAEP** for real encryption.
> - **GCM nonces must be unique per key**. **CBC IVs must be random and unique**. Demos intentionally show what goes wrong if these are misused.

## Prerequisites

- **Python 3.10+** (tested on 3.10/3.11 across Linux, macOS, and Windows)
- `pip install -r requirements.txt`  
  (Installs: `pycryptodome`, `tinyec`, `matplotlib`, `pyfiglet`)

`pyfiglet` powers the CLI banner, and `tinyec` is required for the ECDH demo. The CLI will gracefully warn you if `tinyec` is missing.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
````

## How to run

### One entry point (interactive CLI)

```bash
python lab2_cli.py
```

### Non-interactive

```bash
python lab2_cli.py --run aes
python lab2_cli.py --run rsa
python lab2_cli.py --run dh
python lab2_cli.py --run ecdh
python lab2_cli.py --run bleichenbacher
python lab2_cli.py --run all
```

### Run modules directly (optional)

```bash
python aes_modes/ecb_cbc_gcm.py
python rsa/rsa_from_scratch.py
python dh/dh_small_prime.py
python ecdh/ecdh_tinyec.py
python attacks/bleichenbacher_oracle.py   # runs the oracle + attack demo
```

## File-based encryption helpers

The CLI provides helpers to encrypt/decrypt short messages to **JSON bundles**:

* **AES (ECB/CBC/GCM)** → `EncryptedFiles/`
* **RSA (textbook; no padding)** → `EncryptedFiles/RSA/`
* **Diffie–Hellman (finite field) → AES-GCM** → `EncryptedFiles/DH/`
* **Elliptic-Curve DH → AES-GCM** → `EncryptedFiles/ECDH/`

Each bundle records the algorithm, parameters (key size, IV/nonce, AAD, etc.), and Base64 ciphertext. When binary ciphertext is generated, a matching `.bin` file is written alongside the JSON. You may choose to **omit private values** from the bundle; the CLI prints them so you can store them securely.

## Repository layout

```
aes_modes/
  ├─ ecb_cbc_gcm.py        # AES demos + misuse demos
  └─ aes_file_io.py        # AES file-based helper (JSON I/O)
rsa/
  ├─ rsa_from_scratch.py   # RSA keygen/encrypt/decrypt using pow()
  └─ rsa_file_io.py        # RSA file-based helper (JSON I/O)
dh/
  ├─ dh_small_prime.py     # DH demo (FF)
  └─ dh_file_io.py         # DH→AES-GCM file helper
ecdh/
  ├─ ecdh_tinyec.py        # ECDH demo (+ optional visualization)
  └─ ecdh_file_io.py       # ECDH→AES-GCM file helper
attacks/
  └─ bleichenbacher_oracle.py  # PKCS#1 v1.5 oracle + adaptive attack
report/
  └─ lab2_report.md        # Your analysis/report
lab2_cli.py                # Interactive menu for all demos/helpers
requirements.txt
```

## Notes for graders / users

* **ECDH visualization** requires `matplotlib`. If `tinyec` is missing, the CLI will skip ECDH with a helpful message.
* **RSA helpers** reject plaintexts ≥ modulus length (because no padding is used); this is intentional to motivate OAEP in the report.

## Troubleshooting

* `ModuleNotFoundError`: run `pip install -r requirements.txt` (in the activated venv).
* Windows venv activation: `.\.venv\Scripts\activate`.
* If running from outside the repo root, the CLI injects the repo path; still, running from root is recommended.

## License

This project is provided for educational purposes as part of a cryptography lab. If you adapt it, credit the original authors/instructors as required by your course policies.
