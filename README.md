# Lab 2: Symmetric & Asymmetric Cryptography

This repository contains reference implementations for:
- AES (ECB, CBC, GCM) using PyCryptodome + IV/nonce misuse demos
- RSA from scratch (keygen, encrypt, decrypt) using only Python builtins
- Diffie–Hellman (finite field) demo
- ECDH using tinyec (with quick visualization)
- Bleichenbacher padding oracle attack scaffold

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
````

## How to run

## One entry point (interactive CLI)
```bash
python lab2_cli.py
```

## Non-interactive

```bash
python lab2_cli.py --run aes
python lab2_cli.py --run rsa
python lab2_cli.py --run dh
python lab2_cli.py --run ecdh
python lab2_cli.py --run bleichenbacher
python lab2_cli.py --run all
```

```bash
python aes_modes/ecb_cbc_gcm.py
python rsa/rsa_from_scratch.py
python dh/dh_small_prime.py
python ecdh/ecdh_tinyec.py
python attacks/bleichenbacher_oracle.py  # optional scaffold
```

### File-based encryption helpers

The interactive CLI now provides helper utilities to encrypt/decrypt short
messages to JSON bundles using several algorithms:

- **AES (ECB/CBC/GCM)** — original helpers retained under `EncryptedFiles/`.
- **RSA** — generates textbook RSA key pairs (no padding) and stores ciphertext
  bundles in `EncryptedFiles/RSA/`.
- **Diffie–Hellman (finite field)** — derives an AES-GCM key from the shared
  secret and stores metadata in `EncryptedFiles/DH/`.
- **Elliptic-Curve Diffie–Hellman** — derives an AES-GCM key on a TinyEC curve
  and stores metadata in `EncryptedFiles/ECDH/`.

Each helper offers the option to omit secret material from the JSON bundle, in
which case the CLI prints the necessary key so it can be recorded securely.

See `aes_modes/README.md` for AES-specific notes.

## Report

Write your analysis in `report/lab2_report.md`.
