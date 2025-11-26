# secure_chat_sim/main.py
import os
from chat.sender import send_secure_message
from chat.receiver import receive_secure_message


def generate_keys():
    aes_key16 = os.urandom(16)   # AES-128 key (16 bytes)
    hmac_key32 = os.urandom(32)  # 32-byte HMAC key
    return aes_key16, hmac_key32


def run_genuine():
    aes_key, hmac_key = generate_keys()
    msg = "Hello Bob, this is Alice!"
    secure = send_secure_message(msg, aes_key, hmac_key)
    plaintext = receive_secure_message(secure, aes_key, hmac_key)
    print(" Decrypted Message:", plaintext)


def run_tampered():
    aes_key, hmac_key = generate_keys()
    msg = "Attack will be detected."
    secure = send_secure_message(msg, aes_key, hmac_key)

    tampered = bytearray(secure)
    # Flip a byte inside ciphertext region
    i = 16 + 5  # after nonce, offset inside ciphertext
    tampered[i] ^= 0xFF
    try:
        _ = receive_secure_message(bytes(tampered), aes_key, hmac_key)
        print(" Unexpected: tampering not detected!")
    except ValueError as e:
        print(str(e))


def main():
    print("1: Genuine secure message")
    print("2: Tampered message test")
    choice = input("Select (1/2): ").strip()
    if choice == "1":
        run_genuine()
    elif choice == "2":
        run_tampered()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
