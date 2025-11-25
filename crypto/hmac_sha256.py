import hmac
import hashlib


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, received_hmac: bytes) -> bool:
    expected_hmac = compute_hmac(key, data)
    return hmac.compare_digest(expected_hmac, received_hmac)
