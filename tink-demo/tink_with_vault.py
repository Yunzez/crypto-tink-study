"""Vault Transit envelope encryption CLI for Tink AEAD keysets.

Adapted from the GCP KMS sample; replaces GCP remote AEAD with a custom VaultTransitAead.
Workflow:
  generate: create local DEK keyset -> envelope encrypt with Vault transit key -> store encrypted keyset
  encrypt/decrypt: unwrap encrypted keyset via transit -> use local AEAD primitive on data
"""

from absl import app
from absl import flags
from absl import logging

import base64
import os
import re
import requests
import tink
from tink import aead

FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['generate', 'encrypt', 'decrypt'], 'Operation: generate keyset or encrypt/decrypt data.')
flags.DEFINE_string('keyset_path', None, 'File path for encrypted keyset (read/write).')
flags.DEFINE_string('kek_uri', None, 'Vault KEK URI: vault://transit/<key-name> or vault://transit/keys/<key-name>.')
flags.DEFINE_string('input_path', None, 'Input file for encrypt/decrypt modes.')
flags.DEFINE_string('output_path', None, 'Output file for encrypt/decrypt modes.')
flags.DEFINE_string('associated_data', None, 'Optional associated data for data encryption/decryption.')

# Vault connection flags (fallback to env VAULT_ADDR / VAULT_TOKEN / VAULT_SKIP_VERIFY)
flags.DEFINE_string('vault_addr', None, 'Vault address, e.g. https://127.0.0.1:8200')
flags.DEFINE_string('vault_token', None, 'Vault token value.')
flags.DEFINE_bool('vault_skip_verify', None, 'Skip TLS verification (dev/self-signed).')
flags.DEFINE_bool('auto_create_transit', True, 'Automatically enable transit engine and create key if missing.')


class VaultTransitAead(aead.Aead):
  """AEAD adapter using Vault Transit; Tink AAD mapped to Vault 'context' (base64)."""

  def __init__(self, addr: str, token: str, key_name: str, verify_tls: bool = True):
    self._addr = addr.rstrip('/')
    self._token = token
    self._key_name = key_name
    self._verify_tls = verify_tls
    self._session = requests.Session()
    self._session.headers.update({"X-Vault-Token": self._token})

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    url = f"{self._addr}/v1/transit/encrypt/{self._key_name}"
    payload = {"plaintext": base64.b64encode(plaintext).decode("ascii")}
    if associated_data:
      if isinstance(associated_data, str):
        associated_data = associated_data.encode('utf-8')
      payload['context'] = base64.b64encode(associated_data).decode('ascii')
    r = self._session.post(url, json=payload, verify=self._verify_tls)
    r.raise_for_status()
    return r.json()['data']['ciphertext'].encode('utf-8')

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    url = f"{self._addr}/v1/transit/decrypt/{self._key_name}"
    payload = {"ciphertext": ciphertext.decode('utf-8')}
    if associated_data:
      if isinstance(associated_data, str):
        associated_data = associated_data.encode('utf-8')
      payload['context'] = base64.b64encode(associated_data).decode('ascii')
    r = self._session.post(url, json=payload, verify=self._verify_tls)
    r.raise_for_status()
    pt_b64 = r.json()['data']['plaintext']
    return base64.b64decode(pt_b64)


def _parse_vault_kek_uri(kek_uri: str) -> str:
  if not kek_uri.startswith('vault://'):
    raise ValueError('kek_uri must start with vault://')
  rest = kek_uri[len('vault://'):]
  m = re.match(r'^transit/(?:keys/)?([^/]+)$', rest)
  if not m:
    raise ValueError('Use vault://transit/<key-name> or vault://transit/keys/<key-name>')
  return m.group(1)


def _vault_from_env_or_flags():
  addr = FLAGS.vault_addr or os.getenv('VAULT_ADDR')
  token = FLAGS.vault_token or os.getenv('VAULT_TOKEN')
  skip_env = os.getenv('VAULT_SKIP_VERIFY')
  if FLAGS.vault_skip_verify is not None:
    verify_tls = not FLAGS.vault_skip_verify
  else:
    verify_tls = not (skip_env and skip_env.lower() in ('1','true','yes'))
  if not addr:
    raise ValueError('Vault address missing (--vault_addr or VAULT_ADDR)')
  if not token:
    raise ValueError('Vault token missing (--vault_token or VAULT_TOKEN)')
  return addr, token, verify_tls


def _ensure_transit_key(vault_addr: str, token: str, key_name: str, verify_tls: bool):
  """Ensure transit engine mounted and key exists. Safe to call repeatedly.

  Steps:
    1. Check key existence via read endpoint; if 404, attempt creation.
    2. If creation fails due to missing mount, mount transit then retry key creation.
  """
  session = requests.Session()
  session.headers.update({"X-Vault-Token": token})
  base = vault_addr.rstrip('/')
  key_read_url = f"{base}/v1/transit/keys/{key_name}"  # reading key (GET) gives metadata
  try:
    resp = session.get(key_read_url, verify=verify_tls)
    if resp.status_code == 200:
      return  # key exists
  except requests.RequestException:
    pass  # proceed to creation attempts

  # Try create key
  key_create_url = key_read_url
  create_payload = {"type": "aes256-gcm"}
  resp = session.post(key_create_url, json=create_payload, verify=verify_tls)
  if resp.status_code in (200, 201, 204):
    return
  # If mount missing, enable transit then retry
  if resp.status_code == 404:
    mount_url = f"{base}/v1/sys/mounts/transit"
    mount_payload = {"type": "transit"}
    mresp = session.post(mount_url, json=mount_payload, verify=verify_tls)
    if mresp.status_code not in (200,201,204):
      raise RuntimeError(f"Failed to mount transit engine: {mresp.status_code} {mresp.text}")
    resp2 = session.post(key_create_url, json=create_payload, verify=verify_tls)
    if resp2.status_code not in (200,201,204):
      raise RuntimeError(f"Transit key creation failed after mount: {resp2.status_code} {resp2.text}")
    return
  # Other errors (403 etc.) indicate policy problems
  if resp.status_code == 403:
    raise RuntimeError("Vault token lacks permissions for transit key create/read (403).")
  raise RuntimeError(f"Unexpected response creating transit key: {resp.status_code} {resp.text}")


def main(argv):
  del argv
  aead.register()
  associated_data = b'' if not FLAGS.associated_data else FLAGS.associated_data.encode('utf-8')
  try:
    key_name = _parse_vault_kek_uri(FLAGS.kek_uri)
    vault_addr, vault_token, verify_tls = _vault_from_env_or_flags()
    if FLAGS.auto_create_transit:
      _ensure_transit_key(vault_addr, vault_token, key_name, verify_tls)
    remote_aead = VaultTransitAead(vault_addr, vault_token, key_name, verify_tls=verify_tls)
  except Exception as e:
    logging.exception('Vault Transit setup failed: %s', e)
    return 1

  keyset_envelope_ad = b'encrypted keyset example'

  if FLAGS.mode == 'generate':
    try:
      key_template = aead.aead_key_templates.AES128_GCM
      keyset_handle = tink.new_keyset_handle(key_template)
      serialized_encrypted_keyset = tink.json_proto_keyset_format.serialize_encrypted(
          keyset_handle, remote_aead, keyset_envelope_ad)
      with open(FLAGS.keyset_path, 'wt') as f:
        f.write(serialized_encrypted_keyset)
      logging.info('Encrypted keyset written to %s', FLAGS.keyset_path)
      return 0
    except tink.TinkError as e:
      logging.exception('Keyset generation/encryption error: %s', e)
      return 1

  # decrypt existing encrypted keyset
  try:
    with open(FLAGS.keyset_path, 'rt') as f:
      serialized_encrypted_keyset = f.read()
    keyset_handle = tink.json_proto_keyset_format.parse_encrypted(
        serialized_encrypted_keyset, remote_aead, keyset_envelope_ad)
  except tink.TinkError as e:
    logging.exception('Keyset parse error: %s', e)
    return 1

  try:
    cipher = keyset_handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.exception('Primitive creation error: %s', e)
    return 1

  try:
    with open(FLAGS.input_path, 'rb') as fin:
      data = fin.read()
    if FLAGS.mode == 'encrypt':
      out = cipher.encrypt(data, associated_data)
    elif FLAGS.mode == 'decrypt':
      out = cipher.decrypt(data, associated_data)
    else:
      logging.error('Unsupported mode %s', FLAGS.mode)
      return 1
    with open(FLAGS.output_path, 'wb') as fout:
      fout.write(out)
    logging.info('Wrote %d bytes to %s', len(out), FLAGS.output_path)
  except tink.TinkError as e:
    logging.exception('Data %s error: %s', FLAGS.mode, e)
    return 1
  return 0


if __name__ == '__main__':
  flags.mark_flags_as_required(['mode', 'keyset_path', 'kek_uri'])
  app.run(main)
