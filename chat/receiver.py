# secure_chat_sim/chat/receiver.py
from crypto.ctr_mode import ctr_decrypt
from auth.hmac_utils import verify_hmac


def receive_secure_message(secure_message: bytes, aes_key16: bytes, hmac_key32: bytes) -> str:
    nonce = secure_message[:16]
    mac = secure_message[-32:]
    ct = secure_message[16:-32]

    if not verify_hmac(hmac_key32, nonce + ct, mac):
        raise ValueError(" HMAC verification failed. Message rejected.")

    pt = ctr_decrypt(ct, aes_key16, nonce)
    return pt.decode(errors="strict")
