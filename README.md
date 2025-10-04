# Lab 2: Symmetric & Asymmetric Cryptography

This repository contains reference implementations for:
- AES (ECB, CBC, GCM) using PyCryptodome + IV/nonce misuse demos
- RSA from scratch (keygen, encrypt, decrypt) using only Python builtins
- Diffie–Hellman (finite field) demo
- ECDH using tinyec (with optional quick visualization)
- (Optional) Bleichenbacher padding oracle attack scaffold

## Quickstart

Just run the CLI entry point – it now bootstraps a local virtual environment
and installs `requirements.txt` automatically on first use:

```bash
python lab2_cli.py
```

Prefer to manage the environment manually? You still can:

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

See `aes_modes/README.md` for AES-specific notes.

## Report

Write your analysis in `report/lab2_report.md`.
