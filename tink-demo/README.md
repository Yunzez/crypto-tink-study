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


Copy and save the **Initial root token** and **Key 1**

then on first prompt (**Unseal Vault**): use key1
then on second prompt (**Sign in to Vault**): use method **token**, use **Initial root token**

# terminal 2
### better in your .venv in the project, you wil need the VAULT_TOKEN

```bash
vault server -config=vault-dev.hcl &
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_SKIP_VERIFY=1
export VAULT_TOKEN='root'

vault operator init -key-shares=1 -key-threshold=1

# save your keys! 
vault operator unseal <UNSEAL_KEY_FROM_OUTPUT>
export VAULT_TOKEN=<NEW_ROOT_TOKEN>

vault status
vault secrets enable transit
vault write -f transit/keys/tink-kek    # create a transit key named tink-kek
vault write -f transit/keys/test
vault list transit/keys
# you should see the keys
```

## Work with Tink: 
<!-- vault server -dev -dev-root-token-id=root -->
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_TOKEN=root
export VAULT_SKIP_VERIFY=1  # only for self-signed dev

# Generate encrypted keyset
python tink_with_vault.py \
  --mode=generate \
  --keyset_path=encrypted_keyset.json \
  --kek_uri=vault://transit/test \
  --vault_addr=$VAULT_ADDR \
  --vault_token=$VAULT_TOKEN \
  --vault_skip_verify

# Encrypt data
echo 'hello secret world' > plain.txt
python tink_with_vault.py \
  --mode=encrypt \
  --keyset_path=encrypted_keyset.json \
  --kek_uri=vault://transit/my-app-key \
  --input_path=plain.txt \
  --output_path=cipher.bin \
  --associated_data='file-v1' \
  --vault_addr=$VAULT_ADDR \
  --vault_token=$VAULT_TOKEN \
  --vault_skip_verify

# Decrypt
python tink_with_vault.py \
  --mode=decrypt \
  --keyset_path=encrypted_keyset.json \
  --kek_uri=vault://transit/my-app-key \
  --input_path=cipher.bin \
  --output_path=recovered.txt \
  --associated_data='file-v1' \
  --vault_addr=$VAULT_ADDR \
  --vault_token=$VAULT_TOKEN \
  --vault_skip_verify
diff plain.txt recovered.txt