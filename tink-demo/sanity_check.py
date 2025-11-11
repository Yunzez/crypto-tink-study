#!/usr/bin/env python3
"""
Quick sanity check for Tink: AEAD encrypt/decrypt and Signature sign/verify.
"""
from __future__ import annotations

import tink
from tink import aead, signature, tink_config


def setup():
    # Register all primitives we use
    tink_config.register()


def aead_demo() -> None:
    aead.register()
    # Generate a fresh AEAD keyset (AES256_GCM)
    key_template = aead.aead_key_templates.AES256_GCM
    handle = tink.new_keyset_handle(key_template)
    primitive = handle.primitive(aead.Aead)

    plaintext = b"hello tink"
    associated_data = b"study"

    ct = primitive.encrypt(plaintext, associated_data)
    pt = primitive.decrypt(ct, associated_data)

    assert pt == plaintext
    print("AEAD OK: decrypted:", pt.decode())


def signature_demo() -> None:
    signature.register()
    # Generate a fresh ECDSA P-256 keyset
    key_template = signature.signature_key_templates.ECDSA_P256
    private_handle = tink.new_keyset_handle(key_template)

    signer = private_handle.primitive(signature.PublicKeySign)
    public_handle = private_handle.public_keyset_handle()
    verifier = public_handle.primitive(signature.PublicKeyVerify)

    message = b"measure twice, cut once"
    sig = signer.sign(message)
    verifier.verify(sig, message)
    print("Signature OK: verify succeeded")


if __name__ == "__main__":
    setup()
    aead_demo()
    signature_demo()
