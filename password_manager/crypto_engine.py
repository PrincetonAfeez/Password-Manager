"""Small auditable boundary around cryptography.

No other application module should import cryptography.
"""

from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import DecryptionError, EncryptionError, KDFError
from .models import KDFParams


class CryptoEngine:
    def generate_salt(self, length: int = 16) -> bytes:
        return os.urandom(length)

    def derive_key(self, password: str, salt: bytes, params: KDFParams) -> bytes:
        try:
            password_bytes = password.encode("utf-8")
            raw_key = Scrypt(
                salt=salt,
                length=params.length,
                n=params.n,
                r=params.r,
                p=params.p,
            ).derive(password_bytes)
            return base64.urlsafe_b64encode(raw_key)
        except Exception as exc:  # cryptography raises several ValueError paths
            raise KDFError("key derivation failed") from exc

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        try:
            return Fernet(key).encrypt(plaintext)
        except Exception as exc:
            raise EncryptionError("encryption failed") from exc

    def decrypt(self, key: bytes, token: bytes) -> bytes:
        try:
            return Fernet(key).decrypt(token)
        except InvalidToken as exc:
            raise DecryptionError("decryption failed") from exc
        except Exception as exc:
            raise DecryptionError("decryption failed") from exc
