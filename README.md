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

## Approach

### Genuine Message Flow
1.  **Key Generation:** AES and HMAC keys are randomly generated (256-bit each).
2.  **Message Encryption:** Plaintext is encrypted using AES-CTR with a random nonce.
3.  **HMAC Computation:** A MAC is computed over `nonce||ciphertext`.
4.  **Secure Message Assembly:** Final message = `nonce + ciphertext + hmac`.
5.  **Receiver Verification:** HMAC is verified before decryption. If valid, message is decrypted and displayed.

### Tampered Message Flow
1.  A byte in the ciphertext is flipped.
2.  Receiver detects HMAC mismatch and rejects the message.

## Challenges & Solutions

### Challenges
* Understanding AES-CTR internals and nonce/counter behavior.
* Ensuring reproducibility and modular clarity.
* Designing tampering scenarios that trigger HMAC failure.
* Managing byte-level operations and encoding formats.

### Solutions
* Used Python’s `cryptography` library for AES-CTR and standard `hmac` for authentication.
* Printed all intermediate values (keys, nonce, ciphertext, HMAC) for transparency.
* Created modular files for sender, receiver, and crypto utilities.
* Designed CLI prompt to switch between genuine and tampered flows.
* Ensured reproducibility with consistent encoding and logging.

## How to Run

### Step 1: Setup Project Folder
```bash
mkdir secure_chat_sim
cd secure_chat_sim
### Step 1: Setup Project Folder
```bash
mkdir secure_chat_sim
cd secure_chat_simHow to Run
Step 1: Setup Project Folder
Bash

mkdir secure_chat_sim
cd secure_chat_sim
Step 2: Create and Activate Virtual Environment
Windows:

Bash

py -m venv venv
venv\Scripts\activate
Mac/Linux:

Bash

python3 -m venv venv
source venv/bin/activate
Step 3: Install Required Package
Bash

pip install cryptography
Step 4: Run the Simulator
Bash

python main.py
Choose 1: Genuine secure message flow

Choose 2: Tampered message test

Sample Output
Plaintext

Sample Input Message: Hello Bob, this is Alice!

AES Key (Base64): ...
HMAC Key (Base64): ...
Nonce: ...
Ciphertext: ...
HMAC: ...

HMAC Verified
Decrypted Message: Hello Bob, this is Alice!
References
Python cryptography documentation – AES-CTR mode

Python hmac and hashlib modules

SEED Labs – Message Integrity and Authentication Lab

RFC 2104 – HMAC: Keyed-Hashing for Message Authentication
