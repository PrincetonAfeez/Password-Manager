"""Test CryptoEngine functionality."""

from unittest.mock import patch

import pytest

from password_manager.crypto_engine import CryptoEngine
from password_manager.errors import DecryptionError, EncryptionError, KDFError
from password_manager.models import KDFParams


def test_generate_salt_length():
    engine = CryptoEngine()
    assert len(engine.generate_salt(24)) == 24
    assert len(engine.generate_salt()) == 16


def test_derive_key_raises_kdf_error_on_failure():
    engine = CryptoEngine()
    with patch("password_manager.crypto_engine.Scrypt") as mock_scrypt:
        mock_scrypt.return_value.derive.side_effect = ValueError("bad params")
        with pytest.raises(KDFError, match="key derivation failed"):
            engine.derive_key("password", b"0" * 16, KDFParams())


def test_encrypt_raises_encryption_error():
    engine = CryptoEngine()
    key = engine.derive_key("password", b"0" * 16, KDFParams())
    with patch("password_manager.crypto_engine.Fernet") as mock_fernet:
        mock_fernet.return_value.encrypt.side_effect = RuntimeError("boom")
        with pytest.raises(EncryptionError, match="encryption failed"):
            engine.encrypt(key, b"data")


def test_decrypt_raises_decryption_error_on_invalid_token():
    engine = CryptoEngine()
    key = engine.derive_key("password", b"0" * 16, KDFParams())
    with pytest.raises(DecryptionError, match="decryption failed"):
        engine.decrypt(key, b"not-a-valid-token")


def test_decrypt_raises_decryption_error_on_generic_exception():
    engine = CryptoEngine()
    key = engine.derive_key("password", b"0" * 16, KDFParams())
    with patch("password_manager.crypto_engine.Fernet") as mock_fernet:
        mock_fernet.return_value.decrypt.side_effect = RuntimeError("unexpected")
        with pytest.raises(DecryptionError, match="decryption failed"):
            engine.decrypt(key, b"anything")
