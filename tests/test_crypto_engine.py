"""Test CryptoEngine functionality."""

import pytest

from password_manager.crypto_engine import CryptoEngine
from password_manager.errors import DecryptionError
from password_manager.models import KDFParams


def test_key_derivation_is_deterministic_for_same_salt():
    engine = CryptoEngine()
    params = KDFParams()
    salt = b"0" * 16

    first = engine.derive_key("password", salt, params)
    second = engine.derive_key("password", salt, params)

    assert first == second


def test_different_salt_gives_different_key():
    engine = CryptoEngine()
    params = KDFParams()

    first = engine.derive_key("password", b"0" * 16, params)
    second = engine.derive_key("password", b"1" * 16, params)

    assert first != second


def test_encrypt_decrypt_round_trip_and_tamper_detection():
    engine = CryptoEngine()
    key = engine.derive_key("password", b"0" * 16, KDFParams())
    token = engine.encrypt(key, b"secret body")

    assert engine.decrypt(key, token) == b"secret body"

    tampered = bytearray(token)
    tampered[-2] = ord("A") if tampered[-2] != ord("A") else ord("B")

    with pytest.raises(DecryptionError):
        engine.decrypt(key, bytes(tampered))
