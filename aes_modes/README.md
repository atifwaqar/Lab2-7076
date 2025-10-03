# AES Modes (ECB, CBC, GCM)

* **ECB**: Shows block pattern leakage.
* **CBC**: Properly generates a random IV per message; demo of IV reuse leakage.
* **GCM**: AEAD mode; demo of nonce reuse failure and verification error.

Run:

```bash
python aes_modes/ecb_cbc_gcm.py
```

The script prints round-trip correctness and a short misuse demonstration for CBC (IV reuse) and GCM (nonce reuse).
