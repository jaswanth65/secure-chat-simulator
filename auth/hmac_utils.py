# secure_chat_sim/auth/hmac_utils.py
import hmac
import hashlib


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


"""
It takes your HMAC key and the data (here,nounce+ciphertext) and produces a fixed‑length tag (MAC).
"""


def verify_hmac(key: bytes, data: bytes, mac: bytes) -> bool:
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, mac)


"""
Recompute HMAC on the received data and compare to the attached MAC using a timing‑safe comparison. 
If they match, you trust the message is unmodified and from someone who knows the key.
"""
