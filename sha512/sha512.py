"""
Pure-Python SHA-512 (FIPS 180-4).

No hashlib, no third-party crypto. Uses struct only for byte packing of
the final digest and the 128-bit length field, never for the bitwise
crypto primitives.
"""

import struct

from .constants import H0, K

MASK64 = (1 << 64) - 1


# --- 64-bit logical primitives (all operate mod 2**64) ---

def ROTR(x: int, n: int) -> int:
    """Right rotation of a 64-bit word by n bits."""
    n &= 63
    return ((x >> n) | (x << (64 - n))) & MASK64


def SHR(x: int, n: int) -> int:
    """Logical right shift of a 64-bit word."""
    return (x & MASK64) >> n


def Ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (~x & z)) & MASK64


def Maj(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK64


def BigSigma0(x: int) -> int:
    return (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39)) & MASK64


def BigSigma1(x: int) -> int:
    return (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)) & MASK64


def smallSigma0(x: int) -> int:
    return (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7)) & MASK64


def smallSigma1(x: int) -> int:
    return (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6)) & MASK64


# --- Block compression ---

def _compress(state, block):
    """Compress one 1024-bit (128-byte) block into the eight-word state."""
    # Prepare message schedule W[0..79].
    W = list(struct.unpack(">16Q", block))
    for t in range(16, 80):
        w = (
            smallSigma1(W[t - 2])
            + W[t - 7]
            + smallSigma0(W[t - 15])
            + W[t - 16]
        ) & MASK64
        W.append(w)

    a, b, c, d, e, f, g, h = state

    for t in range(80):
        T1 = (h + BigSigma1(e) + Ch(e, f, g) + K[t] + W[t]) & MASK64
        T2 = (BigSigma0(a) + Maj(a, b, c)) & MASK64
        h = g
        g = f
        f = e
        e = (d + T1) & MASK64
        d = c
        c = b
        b = a
        a = (T1 + T2) & MASK64

    return (
        (state[0] + a) & MASK64,
        (state[1] + b) & MASK64,
        (state[2] + c) & MASK64,
        (state[3] + d) & MASK64,
        (state[4] + e) & MASK64,
        (state[5] + f) & MASK64,
        (state[6] + g) & MASK64,
        (state[7] + h) & MASK64,
    )


# --- Streaming class ---

class Sha512:
    """Streaming SHA-512.

    Usage:
        h = Sha512()
        h.update(b"abc")
        digest = h.digest()  # 64 bytes
    """

    block_size = 128
    digest_size = 64

    def __init__(self) -> None:
        self._state = tuple(H0)
        self._buffer = b""
        self._length = 0  # message length in bytes

    def update(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        data = bytes(data)
        self._length += len(data)
        buf = self._buffer + data
        # Process every full 128-byte block.
        n_full = len(buf) // 128
        for i in range(n_full):
            self._state = _compress(self._state, buf[i * 128:(i + 1) * 128])
        self._buffer = buf[n_full * 128:]

    def _finalize_state(self):
        """Return the post-padding final state tuple without mutating self."""
        # Total message length in BITS, as an unsigned 128-bit big-endian value.
        bit_len = (self._length * 8) & ((1 << 128) - 1)

        pad = b"\x80"
        # After the trailing 0x80 byte, length-in-bits occupies 16 bytes.
        # We need (len + 1 + k) % 128 == 112  (i.e. 128 - 16).
        rem = (self._length + 1) % 128
        if rem <= 112:
            zero_pad = 112 - rem
        else:
            zero_pad = 128 - rem + 112
        pad += b"\x00" * zero_pad
        # 128-bit big-endian length.
        pad += bit_len.to_bytes(16, "big")

        # Compress the padded tail starting from current buffer.
        state = self._state
        tail = self._buffer + pad
        assert len(tail) % 128 == 0
        for i in range(0, len(tail), 128):
            state = _compress(state, tail[i:i + 128])
        return state

    def digest(self) -> bytes:
        state = self._finalize_state()
        return struct.pack(">8Q", *state)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "Sha512":
        new = Sha512()
        new._state = self._state
        new._buffer = self._buffer
        new._length = self._length
        return new


def sha512(msg: bytes) -> bytes:
    """One-shot SHA-512: returns the 64-byte digest of msg."""
    h = Sha512()
    h.update(msg)
    return h.digest()
