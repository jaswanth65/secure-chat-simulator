# Implementation of a Secure Chat Protocol Using Python

## Overview
This project is a simplified implementation of a secure messaging protocol developed using Python. It demonstrates core principles of confidentiality and integrity through the use of AES encryption in Counter (CTR) mode and HMAC-SHA256 authentication.

The simulator showcases how secure communication can be achieved using symmetric cryptography, ensuring that messages are both encrypted and tamper-proof. Unlike traditional plaintext messaging, this protocol encrypts messages and attaches a cryptographic signature (HMAC) to verify authenticity. The design is modular, reproducible, and suitable for educational demonstrations of secure message flow, tampering detection, and key-based authentication.

## Core Components
* **AES-CTR Encryption:** Ensures message confidentiality using a 256-bit symmetric key and a unique nonce.
* **HMAC-SHA256 Authentication:** Provides integrity and authenticity by computing a MAC over the encrypted message.
* **Tampering Detection:** Demonstrates how unauthorized modifications are detected and rejected.
* **Interactive CLI:** Allows users to choose between genuine and tampered message flows.

## Project Structure
```text
secure_chat_sim/
├── main.py                 # Interactive runner for genuine vs tampered message flow
├── utils/
│   └── keygen.py           # Generates AES and HMAC keys
├── chat/
│   ├── sender.py           # Encrypts and authenticates message
│   └── receiver.py         # Verifies and decrypts message
├── crypto/
│   ├── hmac_utils.py       # HMAC computation and verification
│   └── aes_utils.py        # AES-CTR encryption and decryption
├── .gitignore              # Excludes pycache, venv, etc.
└── README.md               # Documentation file
