"""Authenticated Cryptographic Vault — file format + helpers."""

from .vault import (
    VaultError,
    vault_encrypt_bytes,
    vault_decrypt_bytes,
    vault_encrypt_file,
    vault_decrypt_file,
)

__all__ = [
    "VaultError",
    "vault_encrypt_bytes",
    "vault_decrypt_bytes",
    "vault_encrypt_file",
    "vault_decrypt_file",
]
