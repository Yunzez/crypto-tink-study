"""A command-line utility for generating, encrypting and storing keysets (Vault Transit edition)."""

from absl import app
from absl import flags
from absl import logging

import base64
import json
import os
import re
import requests
import tink
from tink import aead

FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['generate', 'encrypt', 'decrypt'], 'The operation to perform.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for encryption.')
flags.DEFINE_string('kek_uri', None,
                    'KEK URI. For Vault use: vault://transit/<key-name> or vault://transit/keys/<key-name>')
flags.DEFINE_string('input_path', None, 'Path to the input file.')
flags.DEFINE_string('output_path', None, 'Path to the output file.')
flags.DEFINE_string('associated_data', None,
                    'Optional associated data to use with the encryption operation.')

# Optional explicit Vault flags (else use env).
flags.DEFINE_string('vault_addr', None, 'Vault address (e.g., https://127.0.0.1:8200). Defaults to $VAULT_ADDR.')
flags.DEFINE_string('vault_token', None, 'Vault token. Defaults to $VAULT_TOKEN.')
flags.DEFINE_bool('vault_skip_verify', None, 'Skip TLS verification. Defaults to $VAULT_SKIP_VERIFY==1.')


class VaultTransitAead(aead.Aead):
  """ Minimal AEAD adapter backed by HashiCorp Vault Transit. We map Tink's AAD to Vault Transit 'context' (base64-encoded).
  """

  def __init__(self, addr: str, token: str, key_name: str, verify_tls: bool = True):
    self._addr = addr.rstrip('/')
    self._token = token
    self._key_name = key_name
    self._verify_tls = verify_tls
    self._session = requests.Session()
    self._session.headers.update({"X-Vault-Token": self._token})

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    url = f"{self._addr}/v1/transit/encrypt/{self._key_name}"
    payload = {
      "plaintext": base64.b64encode(plaintext).decode("ascii")
    }
    if associated_data:
      # use Vault 'context' for AAD; must be base64
      payload["context"] = base64.b64encode(associated_data).decode("ascii")

    r = self._session.post(url, json=payload, verify=self._verify_tls)
    r.raise_for_status()
    ct = r.json()["data"]["ciphertext"]
    # Return ciphertext as bytes (UTF-8)
    return ct.encode("utf-8")

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    url = f"{self._addr}/v1/transit/decrypt/{self._key_name}"
    payload = {
      "ciphertext": ciphertext.decode("utf-8")
    }
    if associated_data:
      payload["context"] = base64.b64encode(associated_data).decode("ascii")

    r = self._session.post(url, json=payload, verify=self._verify_tls)
    r.raise_for_status()
    pt_b64 = r.json()["data"]["plaintext"]
    return base64.b64decode(pt_b64)


def _parse_vault_kek_uri(kek_uri: str) -> str:
  """
  Accepts:
    vault://transit/<key-name>
    vault://transit/keys/<key-name>
  Returns: <key-name>
  """
  if not kek_uri.startswith("vault://"):
    raise ValueError("kek_uri must start with vault:// for Vault usage.")
  # remove scheme
  rest = kek_uri[len("vault://"):]
  # Allowed forms: transit/<key> or transit/keys/<key>
  m = re.match(r'^transit/(?:keys/)?([^/]+)$', rest)
  if not m:
    raise ValueError("Invalid Vault kek_uri. Use vault://transit/<key-name> or vault://transit/keys/<key-name>")
  return m.group(1)


def _vault_from_env_or_flags():
  addr = FLAGS.vault_addr or os.environ.get("VAULT_ADDR")
  token = FLAGS.vault_token or os.environ.get("VAULT_TOKEN")
  skip = os.environ.get("VAULT_SKIP_VERIFY")
  # precedence: explicit flag wins, else env
  if FLAGS.vault_skip_verify is not None:
    verify_tls = not FLAGS.vault_skip_verify
  else:
    verify_tls = not (skip == "1" or str(skip).lower() in ("true", "yes"))

  if not addr:
    raise ValueError("Vault address not provided. Set --vault_addr or $VAULT_ADDR")
  if not token:
    raise ValueError("Vault token not provided. Set --vault_token or $VAULT_TOKEN")
  return addr, token, verify_tls


def main(argv):
  del argv  # Unused.

  associated_data = b'' if not FLAGS.associated_data else FLAGS.associated_data.encode('utf-8')

  # Initialise Tink AEAD registry (for local key templates etc).
  aead.register()

  # Build a Vault-backed AEAD from the kek_uri.
  try:
    key_name = _parse_vault_kek_uri(FLAGS.kek_uri)
    vault_addr, vault_token, verify_tls = _vault_from_env_or_flags()
    remote_aead = VaultTransitAead(vault_addr, vault_token, key_name, verify_tls=verify_tls)
  except Exception as e:
    logging.exception('Error setting up Vault Transit AEAD: %s', e)
    return 1

  if FLAGS.mode == 'generate':
    # Generate a fresh data-encryption keyset (DEK) locally
    try:
      key_template = aead.aead_key_templates.AES128_GCM
      keyset_handle = tink.new_keyset_handle(key_template)
    except tink.TinkError as e:
      logging.exception('Error generating keyset: %s', e)
      return 1

    # Envelope-encrypt the keyset with Vault Transit (our "KEK") and write to file
    try:
      keyset_encryption_associated_data = b'encrypted keyset example'
      serialized_encrypted_keyset = tink.json_proto_keyset_format.serialize_encrypted(
          keyset_handle, remote_aead, keyset_encryption_associated_data)
      with open(FLAGS.keyset_path, 'wt') as f:
        f.write(serialized_encrypted_keyset)
    except tink.TinkError as e:
      logging.exception('Error writing encrypted keyset: %s', e)
      return 1

    return 0

  # For encrypt/decrypt: read encrypted keyset and unwrap via Vault Transit
  try:
    with open(FLAGS.keyset_path, 'rt') as f:
      serialized_encrypted_keyset = f.read()
    keyset_encryption_associated_data = b'encrypted keyset example'
    keyset_handle = tink.json_proto_keyset_format.parse_encrypted(
        serialized_encrypted_keyset, remote_aead, keyset_encryption_associated_data)
  except tink.TinkError as e:
    logging.exception('Error reading or parsing encrypted keyset: %s', e)
    return 1

  try:
    cipher = keyset_handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.exception('Error creating AEAD primitive: %s', e)
    return 1

  try:
    with open(FLAGS.input_path, 'rb') as fin:
      data = fin.read()
    if FLAGS.mode == 'encrypt':
      out = cipher.encrypt(data, associated_data)
    elif FLAGS.mode == 'decrypt':
      out = cipher.decrypt(data, associated_data)
    else:
      logging.error('Unsupported mode %s. Choose "generate", "encrypt", or "decrypt".', FLAGS.mode)
      return 1
    with open(FLAGS.output_path, 'wb') as fout:
      fout.write(out)
  except tink.TinkError as e:
    logging.exception('Error during %s: %s', FLAGS.mode, e)
    return 1

  return 0


if __name__ == '__main__':
  flags.mark_flags_as_required([
      'mode', 'keyset_path', 'kek_uri'
  ])
  app.run(main)
