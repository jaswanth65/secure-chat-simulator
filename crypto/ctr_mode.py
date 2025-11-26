# secure_chat_sim/crypto/ctr_mode.py
from .aes_core import AES128


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ctr_encrypt(plaintext: bytes, key16: bytes, nonce: bytes) -> bytes:
    """AES-CTR encryption (also used for decryption). nonce must be 16 bytes."""
    assert len(nonce) == 16, "Use 16-byte nonce for simplicity"
    aes = AES128(key16)
    ciphertext = bytearray()
    counter = 0

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        # Counter block = nonce XOR counter (or concatenate). We'll put counter in last 8 bytes.
        ctr_bytes = counter.to_bytes(8, 'big')
        # 16 bytes total (8-byte nonce prefix + 8-byte counter)
        counter_block = nonce[:8] + ctr_bytes
        keystream = aes.encrypt_block(counter_block)
        ciphertext.extend(xor_bytes(block, keystream[:len(block)]))
        counter += 1
    return bytes(ciphertext)


# Decryption is identical to encryption in CTR:
ctr_decrypt = ctr_encrypt
