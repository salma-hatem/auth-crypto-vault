import os
from aes_encrypt_decrypt import *

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def split_16_bytes(data):
    blocks = []
    for i in range(0, len(data), 16):
        end = min(i+16, len(data))
        blocks.append(data[i:end])
    return blocks

def CTR_encrypt(plaintext, key):
    nonce = os.urandom(12)

    blocks = split_16_bytes(plaintext)
    counter = 0
    ciphertext = b""

    for block in blocks:
        counter_block = nonce + counter.to_bytes(4, 'big')
        keystream = AES_encrypt(counter_block, key)

        cipher_block = xor(block, keystream)
        ciphertext += cipher_block

        counter += 1
        if counter >= 2**32:
            raise OverflowError("CTR counter overflow")

    return nonce + ciphertext

def CTR_decrypt(input_cipher, key):
    if len(input_cipher) < 12:
        raise ValueError("Ciphertext too short")
    
    nonce = input_cipher[:12]
    cipher = input_cipher[12:]
    
    blocks = split_16_bytes(cipher)
    counter = 0
    plaintext = b""

    for block in blocks:
        counter_block = nonce + counter.to_bytes(4, 'big')
        keystream = AES_encrypt(counter_block, key)

        text_block = xor(block, keystream)
        plaintext += text_block

        counter += 1

    return plaintext


def ctr_encrypt_with_nonce(plaintext, key, nonce):
    if len(nonce) != 12:
        raise ValueError("CTR nonce must be 12 bytes")
    blocks = split_16_bytes(plaintext)
    counter = 0
    ciphertext = b""
    for block in blocks:
        counter_block = nonce + counter.to_bytes(4, 'big')
        keystream = AES_encrypt(counter_block, key)
        ciphertext += xor(block, keystream)
        counter += 1
        if counter >= 2 ** 32:
            raise OverflowError("CTR counter overflow")
    return ciphertext


def ctr_decrypt_with_nonce(ciphertext, key, nonce):
    return ctr_encrypt_with_nonce(ciphertext, key, nonce)
