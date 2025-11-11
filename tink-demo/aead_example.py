#!/usr/bin/env python3
"""Demonstrate AEAD encryption/decryption with Tink."""
from __future__ import annotations

import tink
from tink import aead, tink_config


def main():
    tink_config.register()
    aead.register()

    key_template = aead.aead_key_templates.AES256_GCM
    handle = tink.new_keyset_handle(key_template)
    primitive = handle.primitive(aead.Aead)

    msg = b"confidential data for user study"
    aad = b"context-123"

    ciphertext = primitive.encrypt(msg, aad)
    recovered = primitive.decrypt(ciphertext, aad)

    print(f"Ciphertext length: {len(ciphertext)}")
    print("Recovered:", recovered.decode())


if __name__ == "__main__":
    main()
