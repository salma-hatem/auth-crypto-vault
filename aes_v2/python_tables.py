"""Pure-Python T-table AES-128-CTR fallback for V2.

Self-contained: does not import anything from the V1 ``aes/`` package.
The S-box is reproduced here from FIPS 197 §5.1.1; T-tables are computed
at module import time using the same GF(2^8) reduction polynomial 0x11b
that the C extension uses, so the two backends are bit-identical.
"""

from __future__ import annotations


# FIPS 197 §5.1.1 substitution table.
_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

_MASK32 = 0xFFFFFFFF


def _xtime(b: int) -> int:
    """Multiply by {02} in GF(2^8) under polynomial 0x11b."""
    return ((b << 1) ^ (0x1B if (b & 0x80) else 0)) & 0xFF


def _build_tables():
    t0 = [0] * 256
    t1 = [0] * 256
    t2 = [0] * 256
    t3 = [0] * 256
    t4 = [0] * 256
    for a in range(256):
        s = _SBOX[a]
        s2 = _xtime(s)
        s3 = s2 ^ s
        word = ((s2 << 24) | (s << 16) | (s << 8) | s3) & _MASK32
        t0[a] = word
        t1[a] = ((word >> 8) | (word << 24)) & _MASK32
        t2[a] = ((word >> 16) | (word << 16)) & _MASK32
        t3[a] = ((word >> 24) | (word << 8)) & _MASK32
        t4[a] = ((s << 24) | (s << 16) | (s << 8) | s) & _MASK32
    return t0, t1, t2, t3, t4


_T0, _T1, _T2, _T3, _T4 = _build_tables()


def _key_expansion(key: bytes) -> list:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    rk = [0] * 44
    for i in range(4):
        rk[i] = (
            (key[4 * i] << 24)
            | (key[4 * i + 1] << 16)
            | (key[4 * i + 2] << 8)
            | key[4 * i + 3]
        )
    for i in range(4, 44):
        temp = rk[i - 1]
        if (i % 4) == 0:
            rot = ((temp << 8) | (temp >> 24)) & _MASK32
            b0 = _SBOX[(rot >> 24) & 0xFF]
            b1 = _SBOX[(rot >> 16) & 0xFF]
            b2 = _SBOX[(rot >> 8) & 0xFF]
            b3 = _SBOX[rot & 0xFF]
            sub = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            temp = sub ^ (_RCON[i // 4] << 24)
        rk[i] = (rk[i - 4] ^ temp) & _MASK32
    return rk


def _encrypt_block(rk: list, block: bytes) -> bytes:
    s0 = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]
    s1 = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]
    s2 = (block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]
    s3 = (block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]
    s0 ^= rk[0]
    s1 ^= rk[1]
    s2 ^= rk[2]
    s3 ^= rk[3]

    for r in range(1, 10):
        t0 = (
            _T0[(s0 >> 24) & 0xFF]
            ^ _T1[(s1 >> 16) & 0xFF]
            ^ _T2[(s2 >> 8) & 0xFF]
            ^ _T3[s3 & 0xFF]
            ^ rk[r * 4 + 0]
        ) & _MASK32
        t1 = (
            _T0[(s1 >> 24) & 0xFF]
            ^ _T1[(s2 >> 16) & 0xFF]
            ^ _T2[(s3 >> 8) & 0xFF]
            ^ _T3[s0 & 0xFF]
            ^ rk[r * 4 + 1]
        ) & _MASK32
        t2 = (
            _T0[(s2 >> 24) & 0xFF]
            ^ _T1[(s3 >> 16) & 0xFF]
            ^ _T2[(s0 >> 8) & 0xFF]
            ^ _T3[s1 & 0xFF]
            ^ rk[r * 4 + 2]
        ) & _MASK32
        t3 = (
            _T0[(s3 >> 24) & 0xFF]
            ^ _T1[(s0 >> 16) & 0xFF]
            ^ _T2[(s1 >> 8) & 0xFF]
            ^ _T3[s2 & 0xFF]
            ^ rk[r * 4 + 3]
        ) & _MASK32
        s0, s1, s2, s3 = t0, t1, t2, t3

    # Final round: SubBytes + ShiftRows + AddRoundKey via T4 with masking.
    t0 = (
        (_T4[(s0 >> 24) & 0xFF] & 0xFF000000)
        ^ (_T4[(s1 >> 16) & 0xFF] & 0x00FF0000)
        ^ (_T4[(s2 >> 8) & 0xFF] & 0x0000FF00)
        ^ (_T4[s3 & 0xFF] & 0x000000FF)
        ^ rk[40]
    ) & _MASK32
    t1 = (
        (_T4[(s1 >> 24) & 0xFF] & 0xFF000000)
        ^ (_T4[(s2 >> 16) & 0xFF] & 0x00FF0000)
        ^ (_T4[(s3 >> 8) & 0xFF] & 0x0000FF00)
        ^ (_T4[s0 & 0xFF] & 0x000000FF)
        ^ rk[41]
    ) & _MASK32
    t2 = (
        (_T4[(s2 >> 24) & 0xFF] & 0xFF000000)
        ^ (_T4[(s3 >> 16) & 0xFF] & 0x00FF0000)
        ^ (_T4[(s0 >> 8) & 0xFF] & 0x0000FF00)
        ^ (_T4[s1 & 0xFF] & 0x000000FF)
        ^ rk[42]
    ) & _MASK32
    t3 = (
        (_T4[(s3 >> 24) & 0xFF] & 0xFF000000)
        ^ (_T4[(s0 >> 16) & 0xFF] & 0x00FF0000)
        ^ (_T4[(s1 >> 8) & 0xFF] & 0x0000FF00)
        ^ (_T4[s2 & 0xFF] & 0x000000FF)
        ^ rk[43]
    ) & _MASK32

    return bytes(
        [
            (t0 >> 24) & 0xFF, (t0 >> 16) & 0xFF, (t0 >> 8) & 0xFF, t0 & 0xFF,
            (t1 >> 24) & 0xFF, (t1 >> 16) & 0xFF, (t1 >> 8) & 0xFF, t1 & 0xFF,
            (t2 >> 24) & 0xFF, (t2 >> 16) & 0xFF, (t2 >> 8) & 0xFF, t2 & 0xFF,
            (t3 >> 24) & 0xFF, (t3 >> 16) & 0xFF, (t3 >> 8) & 0xFF, t3 & 0xFF,
        ]
    )


def ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    rk = _key_expansion(key)
    out = bytearray(len(plaintext))
    counter = 0
    off = 0
    n = len(plaintext)
    while off < n:
        counter_block = nonce + counter.to_bytes(4, "big")
        keystream = _encrypt_block(rk, counter_block)
        chunk = min(16, n - off)
        for i in range(chunk):
            out[off + i] = plaintext[off + i] ^ keystream[i]
        off += chunk
        counter += 1
        if counter >= (1 << 32):
            raise OverflowError("CTR counter overflow")
    return bytes(out)


ctr_decrypt = ctr_encrypt
