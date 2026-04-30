import numpy as np
from s_box import *
from gf_256 import *

def to_state(bytes_16):
    if len(bytes_16) != 16:
        print("Error, input bytes length not equal 16.")
        return
    return [[bytes_16[r + 4*c] for c in range(4)] for r in range(4)]


def to_flat_bytes(state):
    return bytes([state[r][c] for c in range(4) for r in range(4)])

# --------------------- Shift Rows ---------------------

def shift_rows(state):
    S = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            S[i][j] = state[i][(j + i) % 4]
    return S

def inv_shift_rows(state):
    S = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            S[i][j] = state[i][(j - i) % 4]
    return S

# --------------------- Mix Columns ---------------------
def mix_columns(state):
    result = [[0]*4 for _ in range(4)]

    for c in range(4):
        b0 = state[0][c] # 1st byte in col c
        b1 = state[1][c]
        b2 = state[2][c]
        b3 = state[3][c]

        # multiply each column by this matrix 
        # 02 03 01 01
        # 01 02 03 01
        # 01 01 02 03
        # 03 01 01 02

        result[0][c] = multiply_by_02(b0) ^ multiply_by_03(b1) ^ multiply_by_01(b2) ^ multiply_by_01(b3)
        result[1][c] = multiply_by_01(b0) ^ multiply_by_02(b1) ^ multiply_by_03(b2) ^ multiply_by_01(b3)
        result[2][c] = multiply_by_01(b0) ^ multiply_by_01(b1) ^ multiply_by_02(b2) ^ multiply_by_03(b3)
        result[3][c] = multiply_by_03(b0) ^ multiply_by_01(b1) ^ multiply_by_01(b2) ^ multiply_by_02(b3)

    return result

def inv_mix_columns(state):
    result = [[0]*4 for _ in range(4)]

    for c in range(4):
        b0 = state[0][c]
        b1 = state[1][c]
        b2 = state[2][c]
        b3 = state[3][c]

        # 0e 0b 0d 09
        # 09 0e 0b 0d
        # 0d 09 0e 0b
        # 0b 0d 09 0e

        result[0][c] = multiply_by_0e(b0) ^ multiply_by_0b(b1) ^ multiply_by_0d(b2) ^ multiply_by_09(b3)
        result[1][c] = multiply_by_09(b0) ^ multiply_by_0e(b1) ^ multiply_by_0b(b2) ^ multiply_by_0d(b3)
        result[2][c] = multiply_by_0d(b0) ^ multiply_by_09(b1) ^ multiply_by_0e(b2) ^ multiply_by_0b(b3)
        result[3][c] = multiply_by_0b(b0) ^ multiply_by_0d(b1) ^ multiply_by_09(b2) ^ multiply_by_0e(b3)

    return result
