from crypto.aes_ctr import encrypt_aes_ctr
from crypto.hmac_sha256 import compute_hmac


def send_secure_message(plaintext: str, aes_key: bytes, hmac_key: bytes):
    nonce, ciphertext = encrypt_aes_ctr(plaintext.encode(), aes_key)
    mac = compute_hmac(hmac_key, nonce + ciphertext)

    # Final message: nonce || ciphertext || hmac
    secure_message = nonce + ciphertext + mac

    print("Sending Secure Message:")
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("HMAC:", mac.hex())
    print("Full Message:", secure_message.hex())

    return secure_message
