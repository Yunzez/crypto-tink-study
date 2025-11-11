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

## For hashicorp
### in one terminal
```bash
vault server -config=crypto-tink-study/tink-demo/vault-dev.hcl
```

this starts the UI, for key creation, choose: 
```bash 
key share = 1
key threshold = 1
```

Copy and save the **Initial root token** and **Key 1**

then on first prompt (**Unseal Vault**): use key1
then on second prompt (**Sign in to Vault**): use method **token**, use **Initial root token**

# terminal 2
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

vault status
vault secrets enable transit
vault write -f transit/keys/tink-kek    # create a transit key named tink-kek