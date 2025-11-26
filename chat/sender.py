# secure_chat_sim/chat/sender.py
import os
import base64
from crypto.ctr_mode import ctr_encrypt
from auth.hmac_utils import compute_hmac


def send_secure_message(plaintext: str, aes_key16: bytes, hmac_key32: bytes):
    nonce = os.urandom(16)  # 16-byte nonce for CTR
    ct = ctr_encrypt(plaintext.encode(), aes_key16, nonce)
    mac = compute_hmac(hmac_key32, nonce + ct)
    """
    It takes your HMAC key and the data (here,ciphertext) and produces a fixed-length tag (MAC).

    """

    print(" AES Key (Base64):", base64.b64encode(aes_key16).decode())
    print(" HMAC Key (Base64):", base64.b64encode(hmac_key32).decode())
    print("Nonce (hex):", nonce.hex())
    print("Ciphertext (hex):", ct.hex())
    print("HMAC (hex):", mac.hex())

    secure_message = nonce + ct + mac
    return secure_message
