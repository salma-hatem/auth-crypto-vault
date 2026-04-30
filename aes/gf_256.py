def shift_left(a):
    # shift left 1 bit. if result > 8 bits, reduce using 0x1b
    # & 0xFF ensures that the result is 16 bits only
    return ((a << 1) ^ 0x1b) & 0xFF if (a & 0x80) else (a << 1)


def multiply_by_01(a):
    return a

def multiply_by_02(a):
    # 2 = 10
    # shift
    return shift_left(a)

def multiply_by_03(a):
    # 3 = 11
    # shift, shift and add
    return shift_left(a) ^ a


# --------------------- Inverse ---------------------

def multiply_by_09(x):
    # 9 = 1001
    # shift, shift, shift and add
    return multiply_by_02(multiply_by_02(multiply_by_02(x))) ^ x

def multiply_by_0b(x):
    # b = 1011
    # shift, shift and add, shift and add
    temp = multiply_by_02(x)
    temp = multiply_by_02(temp) ^ x
    return multiply_by_02(temp) ^ x

def multiply_by_0d(x):
    # d = 1101
    # shift and add, shift, shift and add
    temp = multiply_by_02(x) ^ x
    temp = multiply_by_02(temp)
    return multiply_by_02(temp) ^ x

def multiply_by_0e(x):
    # e = 1110
    temp = multiply_by_02(x) ^ x
    temp = multiply_by_02(temp) ^ x
    return multiply_by_02(temp)
