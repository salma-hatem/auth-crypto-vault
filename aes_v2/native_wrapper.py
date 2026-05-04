"""ctypes wrapper for the V2 C extension."""

from __future__ import annotations

import ctypes
import os

_LIB_PATH = os.path.join(os.path.dirname(__file__), "native", "libaes_v2.so")
_lib = ctypes.CDLL(_LIB_PATH)
_lib.aes128_ctr_xor.argtypes = [
    ctypes.c_char_p,   # key (16)
    ctypes.c_char_p,   # nonce (12)
    ctypes.c_char_p,   # in
    ctypes.c_char_p,   # out
    ctypes.c_size_t,   # len
]
_lib.aes128_ctr_xor.restype = None


def ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    out = ctypes.create_string_buffer(len(plaintext))
    _lib.aes128_ctr_xor(key, nonce, plaintext, out, len(plaintext))
    return out.raw[: len(plaintext)]


ctr_decrypt = ctr_encrypt
