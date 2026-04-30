from aes_core_functions import *
from key_scheduling import *

def AES_encrypt(data, key, rounds = 10):
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")

    if len(data) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    
    state = to_state(data)

    # get round constant list
    rc = get_rc(rounds)
    
    round_keys = key_expansion(key, rc)
    state = add_round_key(state, round_keys[0])

    for i in range(1, rounds + 1):
        # substitute
        sub_bytes_state(state)
        # shift rows
        state = shift_rows(state)

        # mix columns
        if i < rounds:
            state  = mix_columns(state)
        
        # transform key
        state  = add_round_key(state, round_keys[i])
        
    return to_flat_bytes(state)


def AES_decrypt(data, key, rounds = 10):
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")

    if len(data) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    state = to_state(data)

    # get round constant list
    rc = get_rc(rounds)
    
    round_keys = key_expansion(key, rc)
    state = add_round_key(state, round_keys[-1])

    for i in range(1, rounds + 1):
        # shift rows
        state = inv_shift_rows(state)
        # substitute
        inv_sub_bytes_state(state)
        
        # transform key
        state  = add_round_key(state, round_keys[-i - 1])

        # mix columns
        if i < rounds:
            state  = inv_mix_columns(state)
    
    return to_flat_bytes(state)
