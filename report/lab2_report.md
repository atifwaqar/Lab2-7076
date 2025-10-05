# Lab 2 Report — Symmetric & Asymmetric Cryptography

## Introduction

Briefly state goals: implement AES modes (ECB/CBC/GCM), RSA, DH, ECDH, and (optionally) simulate a Bleichenbacher padding oracle.

## Methods

* **AES**: PyCryptodome; PKCS#7 padding for ECB/CBC; random IV (CBC) and random nonce (GCM).
* **RSA**: Miller–Rabin primality, modular inverse (Extended Euclid), keygen, int-based encrypt/decrypt; RSA blinding limits timing leakage.
* **DH**: Safe prime p and generator g; verify shared secret equality.
* **ECDH**: `tinyec` on `secp256r1`; verify shared point equality.
* **Attack (optional)**: Oracle validates PKCS#1 v1.5 padding; adaptive chosen-ciphertext outline.

## Results & Analysis

* **ECB pattern leakage**: identical plaintext blocks produce identical ciphertext blocks.
* **CBC IV reuse**: first-block relation leaks structure; show C1 ⊕ C1'.
* **GCM nonce reuse**: tag/verification issues and keystream reuse risks.
* **RSA**: correctness checks, 2048-bit default keys for demos, blinding protects private exponent during decryption.
* **(EC)DH**: successful shared secret equality.
* **Oracle**: demonstrates how a padding-only leak violates IND-CCA. The step-2
  search is effectively a Bernoulli process that succeeds once the blinded
  plaintext starts with `0x0002`. Because the padding oracle checks a 16-bit
  prefix, the hit probability is ≈ 2⁻¹⁶; therefore the expected number of
  ciphertext queries before the first success is about 65k even for our 96-bit
  toy modulus. This matches the observed hundred-thousand-candidate scans and aligns with
  the `≈ 1/p` behaviour highlighted in Bleichenbacher's original analysis.

## Key Entropy & Best Practices

* Use the `secrets` CSPRNG throughout; 128–256-bit symmetric keys; RSA ≥ 2048 bits (default in demos); standard NIST curves such as P-256 and beyond.
* Unique IVs (CBC) and unique nonces (GCM) per message.
* Use OAEP for RSA encryption; avoid PKCS#1 v1.5 in new systems.

## How to Run

```
python aes_modes/ecb_cbc_gcm.py
python rsa/rsa_from_scratch.py
python dh/dh_small_prime.py
python ecdh/ecdh_tinyec.py
python attacks/bleichenbacher_oracle.py --log-level WARNING --plot report/bleichenbacher_interval_convergence.png
```
The optional `--plot` flag writes a log-scale convergence figure that tracks
the minimum interval width per iteration, making the shrinkage of the search
space visually apparent.

## Conclusion

Summarize findings and recommendations.
