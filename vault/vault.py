"""ACV Vault: Encrypt-then-MAC file format.

On-disk layout (big-endian byte concatenation, no framing):

    [Salt 16 B] [Nonce 12 B] [Ciphertext N B] [HMAC-SHA-512 tag 64 B]

The HMAC is computed over (Salt || Nonce || Ciphertext) using the same key
derived from (password, salt). Decryption verifies the tag in constant time
*before* any plaintext is produced — a tampered or wrong-password file is
rejected without ever calling the AES-CTR decrypt path.
"""

import os
import sys

from hmac_kdf import derive_key, hmac_equal, hmac_sha512, new_salt


SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 64
HEADER_LEN = SALT_LEN + NONCE_LEN
MIN_BLOB_LEN = SALT_LEN + NONCE_LEN + TAG_LEN  # ciphertext may be empty


class VaultError(Exception):
    """Raised on any vault-format / authentication failure."""


def _ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes, backend: str) -> bytes:
    if backend == "v1":
        from aes import ctr_encrypt_with_nonce
        return ctr_encrypt_with_nonce(plaintext, key, nonce)
    if backend == "v2":
        from aes_v2 import ctr_encrypt as v2_ctr_encrypt
        return v2_ctr_encrypt(plaintext, key, nonce)
    raise ValueError(f"unknown backend: {backend!r} (expected 'v1' or 'v2')")


def _ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, backend: str) -> bytes:
    # CTR is symmetric: encryption and decryption share the same keystream.
    if backend == "v1":
        from aes import ctr_decrypt_with_nonce
        return ctr_decrypt_with_nonce(ciphertext, key, nonce)
    if backend == "v2":
        from aes_v2 import ctr_encrypt as v2_ctr_encrypt
        return v2_ctr_encrypt(ciphertext, key, nonce)
    raise ValueError(f"unknown backend: {backend!r} (expected 'v1' or 'v2')")


def vault_encrypt_bytes(plaintext: bytes, password: bytes, *, backend: str = "v1") -> bytes:
    """Encrypt `plaintext` under `password` and return the on-disk blob."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    salt = new_salt()
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(bytes(password), salt)
    ciphertext = _ctr_encrypt(bytes(plaintext), key, nonce, backend)
    tag = hmac_sha512(key, salt + nonce + ciphertext)
    return salt + nonce + ciphertext + tag


def vault_decrypt_bytes(blob: bytes, password: bytes, *, backend: str = "v1") -> bytes:
    """Authenticate and decrypt a vault blob. Raises VaultError on failure."""
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    if len(blob) < MIN_BLOB_LEN:
        raise VaultError("file too short")

    blob = bytes(blob)
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:HEADER_LEN]
    ciphertext = blob[HEADER_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    key = derive_key(bytes(password), salt)
    expected_tag = hmac_sha512(key, salt + nonce + ciphertext)
    if not hmac_equal(expected_tag, tag):
        raise VaultError(
            "HMAC verification failed - file is tampered or wrong password"
        )

    return _ctr_decrypt(ciphertext, key, nonce, backend)


def vault_encrypt_file(in_path, out_path, password: bytes, *, backend: str = "v1") -> None:
    """Encrypt the file at `in_path` and write the vault blob to `out_path`."""
    with open(in_path, "rb") as f:
        plaintext = f.read()
    blob = vault_encrypt_bytes(plaintext, password, backend=backend)
    # Write atomically-ish: write then rename. Keeps the output path absent
    # if the encrypt itself raises.
    tmp_path = f"{out_path}.acv-tmp"
    try:
        with open(tmp_path, "wb") as f:
            f.write(blob)
        os.replace(tmp_path, out_path)
    except Exception:
        # Best-effort cleanup of the temp file; never touch the final path.
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def vault_decrypt_file(in_path, out_path, password: bytes, *, backend: str = "v1") -> None:
    """Decrypt a vault file. On HMAC failure, prints a security warning to
    stderr, raises VaultError, and never creates `out_path`."""
    with open(in_path, "rb") as f:
        blob = f.read()
    try:
        plaintext = vault_decrypt_bytes(blob, password, backend=backend)
    except VaultError as e:
        sys.stderr.write(f"SECURITY WARNING: {e}\n")
        raise
    # Only on success do we write the output.
    tmp_path = f"{out_path}.acv-tmp"
    try:
        with open(tmp_path, "wb") as f:
            f.write(plaintext)
        os.replace(tmp_path, out_path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
