from crypto.aes_ctr import decrypt_aes_ctr
from crypto.hmac_sha256 import verify_hmac


def receive_secure_message(secure_message: bytes, aes_key: bytes, hmac_key: bytes):
    nonce = secure_message[:16]
    ciphertext = secure_message[16:-32]
    received_mac = secure_message[-32:]

    print(" Received Secure Message:")
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Received HMAC:", received_mac.hex())

    if verify_hmac(hmac_key, nonce + ciphertext, received_mac):
        plaintext = decrypt_aes_ctr(nonce, ciphertext, aes_key)
        print(" HMAC Verified. Decrypted Message:", plaintext.decode())
        return plaintext
    else:
        print(" HMAC Verification Failed. Message Rejected.")
        return None
