from utils.keygen import generate_keys
from chat.sender import send_secure_message
from chat.receiver import receive_secure_message
import os


def test_tampered_message(aes_key, hmac_key):
    print("\n Tampering Test")
    message = "This is a secure message."
    secure_msg = send_secure_message(message, aes_key, hmac_key)

    # Tamper with ciphertext
    tampered_msg = bytearray(secure_msg)
    tampered_msg[20] ^= 0xFF  # Flip one byte

    receive_secure_message(bytes(tampered_msg), aes_key, hmac_key)


if __name__ == "__main__":
    aes_key, hmac_key = generate_keys()

    print("\nChoose mode:")
    print("1. Genuine secure message")
    print("2. Tampered message test")

    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        print("\n--- Genuine Secure Message Flow ---")
        message = "Hello Bob, this is Alice!"
        secure_msg = send_secure_message(message, aes_key, hmac_key)
        receive_secure_message(secure_msg, aes_key, hmac_key)

    elif choice == "2":
        print("\n--- Tampered Message Flow ---")
        test_tampered_message(aes_key, hmac_key)

    else:
        print(" Invalid choice. Please run again and enter 1 or 2.")
