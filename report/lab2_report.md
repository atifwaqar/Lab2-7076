# Lab 2 Report — Symmetric & Asymmetric Cryptography

## Introduction

Briefly state goals: implement AES modes (ECB/CBC/GCM), RSA, DH, ECDH, and (optionally) simulate a Bleichenbacher padding oracle.

## Methods

* **AES**: PyCryptodome; PKCS#7 padding for ECB/CBC; random IV (CBC) and random nonce (GCM).
* **RSA**: Miller–Rabin primality, modular inverse (Extended Euclid), keygen, int-based encrypt/decrypt.
* **DH**: Safe prime p and generator g; verify shared secret equality.
* **ECDH**: `tinyec` on `secp256r1`; verify shared point equality.
* **Attack (optional)**: Oracle validates PKCS#1 v1.5 padding; adaptive chosen-ciphertext outline.

## Results & Analysis

* **ECB pattern leakage**: identical plaintext blocks produce identical ciphertext blocks.
* **CBC IV reuse**: first-block relation leaks structure; show C1 ⊕ C1'.
* **GCM nonce reuse**: tag/verification issues and keystream reuse risks.
* **RSA**: correctness checks, key sizes, performance notes.
* **(EC)DH**: successful shared secret equality and explicit rejection of invalid peer points (infinity, wrong curve, malformed coordinates).
* **Oracle**: demonstrates how a padding-only leak violates IND-CCA.

## Key Entropy & Best Practices

* Use CSPRNGs; 128–256-bit symmetric keys; RSA ≥ 2048 bits; standard NIST curves (P-256+).
* Unique IVs (CBC) and unique nonces (GCM) per message.
* Use OAEP for RSA encryption; avoid PKCS#1 v1.5 in new systems.

## How to Run

```
python aes_modes/ecb_cbc_gcm.py
python rsa/rsa_from_scratch.py
python dh/dh_small_prime.py
python ecdh/ecdh_tinyec.py
python attacks/bleichenbacher_oracle.py
```

## Conclusion

Summarize findings and recommendations.
