#!/usr/bin/env python3
"""
Template: Demonstrate how key rotation & envelope encryption could work with HashiCorp Vault.

This is a teaching/illustrative script for a user study. It DOES NOT actually
connect to Vault. Instead, it shows the structure you might use.

Concepts:
- Envelope encryption: a 'master key' lives in Vault; local Tink keyset encrypted with it.
- Rotation: generate new keyset, promote new primary, keep old for reads (grace period), then retire.

Usage:
    python key_rotate.py --dry-run            # Show steps without persistence
    python key_rotate.py --rotate             # Pretend to perform rotation

In a real implementation you would:
1. Authenticate to Vault (token or AppRole).
2. Call Vault transit encryption API to encrypt Tink keyset JSON bytes.
3. Store encrypted blob in durable storage (file, DB, secret manager).
4. For decryption, call Vault transit decrypt API.

References:
- Vault Transit: https://developer.hashicorp.com/vault/docs/secrets/transit
- Tink Python Keyset docs
"""
from __future__ import annotations

import argparse
import pathlib
from dataclasses import dataclass
import tink
from tink import aead, tink_config

# Register Tink primitives we need.
tink_config.register(); aead.register()

# Placeholder paths (would be encrypted blobs in production)
STORAGE_DIR = pathlib.Path("./vault_demo_store")
CURRENT_KEYSET_FILE = STORAGE_DIR / "aead_keyset.enc.json"
PENDING_KEYSET_FILE = STORAGE_DIR / "aead_keyset_pending.enc.json"

# Simulated Vault transit key URI (if using official integrations you might have a different scheme)
VAULT_KEY_NAME = "vault-transit/master-aead"


@dataclass
class MockVaultAead:
    """A mock AEAD representing Vault transit endpoints.

    In reality you'd make HTTP calls to Vault's /transit/encrypt and /transit/decrypt
    endpoints. Here we just wrap an in-memory AEAD for demonstration.
    """
    _delegate: tink.aead.Aead

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:  # type: ignore[override]
        return self._delegate.encrypt(plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:  # type: ignore[override]
        return self._delegate.decrypt(ciphertext, associated_data)


def obtain_vault_aead(vault_key_name: str) -> MockVaultAead:
    """Pretend to fetch an AEAD primitive backed by Vault transit.

    For illustration we just generate a local Tink AEAD key and treat it as the master key.
    """
    master_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    return MockVaultAead(master_handle.primitive(aead.Aead))


def generate_local_data_key() -> tink.KeysetHandle:
    return tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)


def write_encrypted_keyset(handle: tink.KeysetHandle, path: pathlib.Path, kms_aead: MockVaultAead, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] Would write encrypted keyset to {path}")
        return
    with path.open("wt") as f:
        writer = tink.JsonKeysetWriter(f)
        # Envelope encryption: master (Vault) AEAD wraps the keyset
        handle.write(writer, kms_aead)
    print(f"Encrypted keyset written to {path}")


def read_encrypted_keyset(path: pathlib.Path, kms_aead: MockVaultAead) -> tink.KeysetHandle:
    with path.open("rt") as f:
        reader = tink.JsonKeysetReader(f.read())
    return tink.read_keyset_handle(reader, kms_aead)


def ensure_storage():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def initial_setup(dry_run: bool) -> None:
    kms_aead = obtain_vault_aead(VAULT_KEY_NAME)
    handle = generate_local_data_key()
    write_encrypted_keyset(handle, CURRENT_KEYSET_FILE, kms_aead, dry_run)
    print("Initial keyset generated and stored (encrypted).")


def rotate(dry_run: bool) -> None:
    kms_aead = obtain_vault_aead(VAULT_KEY_NAME)
    # Load current (simulate existing)
    if CURRENT_KEYSET_FILE.exists():
        current_handle = read_encrypted_keyset(CURRENT_KEYSET_FILE, kms_aead)
        current_aead = current_handle.primitive(aead.Aead)
        test_ct = current_aead.encrypt(b"pre-rotation", b"aad")
        _ = current_aead.decrypt(test_ct, b"aad")
        print("Verified existing keyset before rotation.")
    else:
        print("No existing keyset found. Performing initial setup first.")
        initial_setup(dry_run)

    # Generate new keyset
    new_handle = generate_local_data_key()
    write_encrypted_keyset(new_handle, PENDING_KEYSET_FILE, kms_aead, dry_run)
    print("New keyset staged as pending.")

    # Promotion step (in real life you might update a metadata pointer)
    if dry_run:
        print("[dry-run] Would promote pending keyset to current and schedule old for retirement.")
    else:
        # Archive old
        if CURRENT_KEYSET_FILE.exists():
            CURRENT_KEYSET_FILE.rename(CURRENT_KEYSET_FILE.with_suffix(".old.enc.json"))
        PENDING_KEYSET_FILE.rename(CURRENT_KEYSET_FILE)
        print("Promoted new keyset to current; old archived.")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Demonstrate Vault-like envelope encryption & rotation with Tink")
    p.add_argument("--dry-run", action="store_true", help="Do not persist any files; just log actions")
    p.add_argument("--rotate", action="store_true", help="Perform a rotation (stages and promotes new keyset)")
    return p.parse_args()


def main():
    args = parse_args()
    ensure_storage()
    if args.rotate:
        rotate(args.dry_run)
    else:
        initial_setup(args.dry_run)

    print("Done.")


if __name__ == "__main__":
    main()
