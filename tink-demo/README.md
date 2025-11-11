# Tink Python Quickstart for User Study

This repo sets up a minimal Python project using Google Tink for crypto primitives.

## Prerequisites

- macOS with Python 3.10+

## Setup

```zsh
# From the repo root
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run sanity check

This script demonstrates AEAD encrypt/decrypt and Signatures sign/verify.

```zsh
source .venv/bin/activate
python sanity_check.py
```

Expected output prints the decrypted message and verifies the signature.

AEAD = Authenticated Encryption with Associated Data

## Examples

- `aead_example.py` – Encrypt/Decrypt with AES-GCM through Tink AEAD.
- `signature_example.py` – ECDSA sign/verify.
- `key_rotate.py` – Template showing how you could integrate HashiCorp Vault transit for envelope encryption and rotate a local Tink keyset (dry-run capable).
- For rotate_key: Initial setup (dry-run: no files written, just logs)
```zsh python key_rotate.py --dry-run```
- Simulate a rotation (still dry-run)
```zsh python key_rotate.py --rotate --dry-run ```


**Signature example**
```zsh
source .venv/bin/activate
python aead_example.py
python signature_example.py
```

## Notes for user study

Security reminders (mention briefly to participants):

- These examples keep key material only in memory.
- AEAD is randomized; encrypting the same plaintext twice yields different ciphertexts (good for security).
- Signatures are deterministic for ECDSA in Tink (given same key/message) but you should still treat signatures as opaque bytes.

