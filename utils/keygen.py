import os
import base64


def generate_keys():
    aes_key = os.urandom(32)   # 256-bit AES key
    # generates 32 random bytes.32 X 8=256 bits.AES supports key sizes of 128, 192, or 256 bits.
    hmac_key = os.urandom(32)  # 256-bit HMAC key

    # Optional: encode for display or saving
    aes_key_b64 = base64.b64encode(aes_key).decode()
    hmac_key_b64 = base64.b64encode(hmac_key).decode()
    # Printed in Base64 for readability

    print(" AES Key (Base64):", aes_key_b64)
    print(" HMAC Key (Base64):", hmac_key_b64)

    return aes_key, hmac_key


if __name__ == "__main__":
    generate_keys()
