"""
Cryptographic primitives for sneak.

Replaces the original Fernet (AES-128-CBC + HMAC) with:
  - AES-256-GCM   (authenticated encryption, no padding oracle risk)
  - Per-message key derivation via HKDF (key isolation between messages)

Wire format per encrypted message (base64-encoded):
  [ salt (16 B) | nonce (12 B) | ciphertext + GCM tag (variable) ]

Forward secrecy note:
  Each message gets its own AES key derived from (room_key, random_salt),
  so compromising one message key does not reveal others.
  However, compromising room_key itself would allow decryption of all
  messages. True per-message forward secrecy in a group setting requires
  a more complex protocol (e.g., Signal Sender Keys) and is documented
  as a future improvement.
"""

import os
import base64

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

from .constants import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    MSG_SALT_BYTES,
    HKDF_INFO_MSG,
    HKDF_INFO_ROOM,
)


def derive_room_key(password: bytes, room_salt: bytes) -> bytes:
    """Derive deterministic room key from password + room salt via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=room_salt,
        info=HKDF_INFO_ROOM,
    ).derive(password)


class MessageCrypto:
    """Encrypt/decrypt chat messages with AES-256-GCM.

    Each message uses a fresh random salt to derive a unique AES key
    from the shared room_key. This provides per-message key isolation:
    even if one message key leaks, other messages remain protected.
    """

    def __init__(self, room_key: bytes):
        if len(room_key) != AES_KEY_BYTES:
            raise ValueError(f"room_key must be {AES_KEY_BYTES} bytes")
        self._room_key = room_key

    def _derive_msg_key(self, salt: bytes) -> bytes:
        """Derive a per-message AES-256 key: HKDF(room_key, salt)."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_BYTES,
            salt=salt,
            info=HKDF_INFO_MSG,
        ).derive(self._room_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a message → base64 token.

        Returns: base64(salt ‖ nonce ‖ ciphertext+tag)
        """
        salt = os.urandom(MSG_SALT_BYTES)
        nonce = os.urandom(GCM_NONCE_BYTES)
        key = self._derive_msg_key(salt)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(salt + nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a base64 token → plaintext string.

        Raises cryptography.exceptions.InvalidTag on tampered data.
        """
        raw = base64.b64decode(token)
        salt = raw[:MSG_SALT_BYTES]
        nonce = raw[MSG_SALT_BYTES : MSG_SALT_BYTES + GCM_NONCE_BYTES]
        ciphertext = raw[MSG_SALT_BYTES + GCM_NONCE_BYTES :]
        key = self._derive_msg_key(salt)
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")

    def wipe(self):
        """Overwrite key material in memory (best-effort)."""
        self._room_key = b"\x00" * AES_KEY_BYTES
