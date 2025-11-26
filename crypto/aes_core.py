# secure_chat_sim/crypto/aes_core.py
# Pure Python AES-128 block encryption (no third-party libs).
# References: FIPS-197 algorithm steps implemented manually.

SBOX = [
    # 256-byte AES S-box
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

"""
The SBOX (Substitution Box) is the tool used exclusively for Move 1: SubBytes
SBOX is a list of 256 specific numbers. It acts as a translator dictionary.
"""

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _sub_word(word):
    return bytes([SBOX[b] for b in word])


def _rot_word(word):
    return word[1:] + word[:1]


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _mix_single_column(a):
    return bytes([
        _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
        a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
        a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
        _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2),
    ])


def _bytes_to_state(block16):
    return [list(block16[i:i+4]) for i in range(0, 16, 4)]


def _state_to_bytes(state):
    return bytes(sum(state, []))


def _add_round_key(state, round_key):
    rk_state = _bytes_to_state(round_key)
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk_state[r][c]


def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]


"""
1.Look at the data: It takes the current value of the byte (e.g., let's say the byte is 0x19 which is 25).
2.Find the address: It goes to index 25 inside the SBOX list.
3.Swap: It takes the value sitting at index 25 (which is 0xd4) and overwrites the original data.
"""


def _shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


"""
This function implements Move 2: ShiftRows (The Shuffle).
It takes the rows of your 4X4 grid and rotates them to the left by different amounts.
Ex: Imagine Row 1 is: ['A', 'B', 'C', 'D']
1.state[1][1:]: "Take everything from index 1 to the end."
    Result: ['B', 'C', 'D']
2.state[1][:1]: "Take everything from the start up to index 1."
    Result: ['A']
3. +: Glue them together.
    ['B', 'C', 'D'] + ['A'] = ['B', 'C', 'D', 'A']
"""


def _mix_columns(state):
    for c in range(4):
        # This loop runs 4 times—once for the first column, then the second, third, and fourth
        col = bytes([state[r][c] for r in range(4)])
        mixed = _mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]


"""
This code block implements Move 3: MixColumns, where we mix the data vertically.
AES processes this step one column at a time. 
"""


def key_expansion(key16):
    assert len(key16) == 16, "AES-128 requires 16-byte key"
    Nk, Nb, Nr = 4, 4, 10
    w = [key16[i*4:(i+1)*4] for i in range(Nk)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp = bytes([temp[0] ^ RCON[i//Nk], temp[1], temp[2], temp[3]])
        w.append(bytes([w[i-Nk][j] ^ temp[j] for j in range(4)]))
    round_keys = []
    for r in range(Nr+1):
        rk = b''.join(w[r*Nb + c] for c in range(Nb))
        round_keys.append(rk)
    return round_keys  # list of 11 round keys (16 bytes each)


def encrypt_block(block16, round_keys):
    assert len(block16) == 16
    state = _bytes_to_state(block16)
    _add_round_key(state, round_keys[0])
    for round_idx in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_idx])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return _state_to_bytes(state)


class AES128:
    def __init__(self, key16: bytes):
        self.key = key16
        self.round_keys = key_expansion(key16)

    def encrypt_block(self, block16: bytes) -> bytes:
        return encrypt_block(block16, self.round_keys)
