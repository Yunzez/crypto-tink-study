#!/usr/bin/env python3
"""Demonstrate ECDSA signing and verification with Tink."""
from __future__ import annotations

import tink
from tink import signature, tink_config


def main():
    tink_config.register()
    signature.register()

    key_template = signature.signature_key_templates.ECDSA_P256
    private_handle = tink.new_keyset_handle(key_template)

    signer = private_handle.primitive(signature.PublicKeySign)
    public_handle = private_handle.public_keyset_handle()
    verifier = public_handle.primitive(signature.PublicKeyVerify)

    message = b"hello from user study"
    sig = signer.sign(message)
    verifier.verify(sig, message)

    print(f"Signature length: {len(sig)} bytes")
    print("Verification succeeded")


if __name__ == "__main__":
    main()
