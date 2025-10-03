# Lab 2: Symmetric & Asymmetric Cryptography

This repository contains reference implementations for:
- AES (ECB, CBC, GCM) using PyCryptodome + IV/nonce misuse demos
- RSA from scratch (keygen, encrypt, decrypt) using only Python builtins
- Diffie–Hellman (finite field) demo
- ECDH using tinyec (with optional quick visualization)
- (Optional) Bleichenbacher padding oracle attack scaffold

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
````

## How to run

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
