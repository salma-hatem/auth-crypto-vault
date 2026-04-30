from s_box import *
from gf_256 import *


def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]


def words_to_round_keys(words):
    round_keys = []
    for i in range(0, len(words), 4):
        key_state = [[0]*4 for _ in range(4)]
        for col in range(4):
            for row in range(4):
                key_state[row][col] = words[i + col][row]
        round_keys.append(key_state)
    return round_keys


def get_rc(total_rounds):
    rc = [1] * total_rounds
    for i in range(1, total_rounds):
        rc[i] = multiply_by_02(rc[i - 1])
    return rc


def g(word, rc):
    word = word[1:] + word[:1]
    sub_bytes_word(word)
    word[0] ^= rc
    return word


def key_expansion(key_bytes, rc, rounds=10):
    Nk = 4 # words in key
    Nb = 4 # words in block

    words = [list(key_bytes[i:i+4]) for i in range(0, 16, 4)]

    for i in range(Nk, Nb * (rounds + 1)):
        temp = words[i - 1].copy()

        if i % Nk == 0:
            temp = g(temp, rc[i // Nk - 1])

        new_word = xor_words(words[i - Nk], temp)
        words.append(new_word)

    round_keys = words_to_round_keys(words)

    return round_keys


def add_round_key(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]
    return state
