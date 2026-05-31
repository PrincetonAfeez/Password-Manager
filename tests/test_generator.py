"""Test generator functionality."""

import string

import pytest

import password_manager.generator as generator_module
from password_manager.generator import generate_password


def test_generated_password_honors_length_and_classes():
    password = generate_password(length=24, symbols=False)

    assert len(password) == 24
    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.digits for char in password)
    assert all(char not in "!@#$%^&*()-_=+[]{};:,.?/" for char in password)


def test_generator_rejects_invalid_options():
    with pytest.raises(ValueError):
        generate_password(length=11)

    with pytest.raises(ValueError):
        generate_password(
            length=12,
            uppercase=False,
            lowercase=False,
            digits=False,
            symbols=False,
        )


def test_generator_uses_secrets_module():
    assert generator_module.secrets.__name__ == "secrets"
    assert "random" not in generator_module.__dict__
