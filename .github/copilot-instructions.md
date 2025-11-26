# Copilot Instructions: Secure Chat Simulator

## Project Overview
This is an educational cryptography project implementing **authenticated encryption** for secure message transmission. The system demonstrates core security principles: confidentiality (AES-CTR encryption), integrity (HMAC-SHA256), and message authentication.

**Architecture Pattern**: Encrypt-then-MAC (EtM) - industry best practice for authenticated encryption.

## Message Flow
```
SEND: plaintext → [AES-CTR encrypt] → [HMAC-SHA256] → [format: nonce|ciphertext|mac]
RECEIVE: [format: nonce|ciphertext|mac] → [verify HMAC] → [AES-CTR decrypt] → plaintext
```

## Key Components & Patterns

### 1. Cryptographic Core (`crypto/`)
- **aes_core.py**: Pure Python AES-128 block cipher (no external crypto libraries). Implements FIPS-197 with S-box, key expansion, and encryption primitives.
  - *Pattern*: Low-level block cipher building blocks used by higher-level modes
  - *Key function*: `AES128.encrypt_block(counter_block)` - encrypts 16-byte blocks
  
- **ctr_mode.py**: Implements **CTR (Counter) mode** for stream encryption
  - *Critical detail*: Counter block = `nonce[:8] + counter.to_bytes(8, 'big')` - upper 8 bytes are nonce prefix, lower 8 bytes are counter
  - *Pattern*: `ctr_decrypt = ctr_encrypt` - CTR is symmetric (same operation for enc/dec)
  - *Contract*: Nonce **must be 16 bytes**, counter starts at 0 and increments per block

### 2. Authentication (`auth/`)
- **hmac_utils.py**: Simple HMAC-SHA256 wrapper
  - `compute_hmac(key, data)` - returns 32-byte digest
  - `verify_hmac(key, data, mac)` - uses `hmac.compare_digest()` for constant-time comparison (timing attack resistance)

### 3. Chat Interface (`chat/`)
- **sender.py**: `send_secure_message(plaintext, aes_key16, hmac_key32) → secure_message: bytes`
  - Generates fresh 16-byte nonce (critical for CTR mode security)
  - Computes MAC over `nonce + ciphertext` (not including MAC itself)
  - Returns concatenated bytes: `nonce(16) | ciphertext(variable) | mac(32)`
  - *Side effect*: Prints keys and intermediate values (debug output, remove in production)

- **receiver.py**: `receive_secure_message(secure_message, aes_key16, hmac_key32) → plaintext: str`
  - Parses: nonce=first 16 bytes, mac=last 32 bytes, ciphertext=middle
  - **Verify MAC first** (reject if invalid) - prevents processing of tampered messages
  - Then decrypt and decode
  - *Important*: `decode(errors="strict")` - fails if ciphertext wasn't valid UTF-8

### 4. Entry Point & Test Scenarios (`main.py`)
- `run_genuine()`: Happy path - send and receive unmodified message
- `run_tampered()`: Security test - flips a byte in ciphertext region, confirms HMAC detection
  - Pattern: Tamper happens at `offset 16 + 5` (inside ciphertext, after nonce)
  - Confirms integrity protection works

## Critical Security Properties

1. **Nonce Reuse Risk**: CTR mode is broken if same nonce used twice with same key. Sender generates fresh nonce per message (secure).
2. **MAC-then-Encrypt vs. Encrypt-then-MAC**: This project uses **Encrypt-then-MAC** (safest approach). MAC is computed over ciphertext, not plaintext.
3. **Timing Attacks**: HMAC verification uses `compare_digest()` for constant-time comparison - prevents timing-based forgeries.

## Common Modifications & Patterns

### Extending Message Format
If adding metadata (timestamp, sender ID):
- Include in plaintext before encryption (automatic integrity protection)
- OR include in HMAC computation before final format (preserve authentication)
- Update parse logic in `receiver.py` accordingly

### Key Derivation
Currently uses raw random keys. To add key derivation from passwords:
- Import `from crypto.kdf import derive_key` (would need to implement)
- Apply before passing to `send_secure_message()` / `receive_secure_message()`
- Keys must remain 16 bytes (AES) and 32 bytes (HMAC)

### Changing Encryption Mode
All encryption happens via `ctr_mode.py`. To switch modes (e.g., to CBC):
- Replace `ctr_encrypt()` / `ctr_decrypt()` implementations
- Maintain same signature: `(plaintext_or_ciphertext: bytes, key16: bytes, nonce: bytes) → bytes`
- Update nonce requirements if needed (other modes may use different IV sizes)
- Keep MAC computation logic unchanged (orthogonal to encryption)

## Development Workflow

**Run project**:
```bash
python main.py
# Choose 1 for genuine message or 2 for tamper test
```

**Testing security**: The tamper test (`option 2`) is the built-in integrity check. Look for "HMAC verification failed" when tampering is detected.

## No External Crypto Dependencies
This project intentionally uses pure Python AES (not `cryptography` or `pycryptodome`). This is for **educational purposes** to demonstrate algorithm internals. Production code should use battle-tested libraries (never roll your own crypto).
