"""Key derivation for the ACV vault.

derive_key(password, salt) := SHA512(password || salt)[:16]

This is the simple SHA-512 truncation KDF specified by the project guidelines.
It is *not* a password-hashing function (no work factor, no memory hardness),
so it is only acceptable because the spec mandates this exact construction
for the demo. A production system should use Argon2id / scrypt / PBKDF2.
"""

import os

from sha512 import sha512


_SALT_LEN = 16
_KEY_LEN = 16


def new_salt() -> bytes:
    """Return a fresh 16-byte random salt from the OS CSPRNG."""
    return os.urandom(_SALT_LEN)


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 16-byte AES-128 key from `password` and a 16-byte `salt`."""
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if len(salt) != _SALT_LEN:
        raise ValueError(f"salt must be {_SALT_LEN} bytes, got {len(salt)}")
    return sha512(bytes(password) + bytes(salt))[:_KEY_LEN]
