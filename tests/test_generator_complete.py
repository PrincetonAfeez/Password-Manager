"""Test generator functionality."""

import string

import pytest

from password_manager.generator import generate_password


def test_minimum_length_enforced():
    with pytest.raises(ValueError, match="at least 12"):
        generate_password(length=11, uppercase=True, lowercase=False, digits=False, symbols=False)


def test_all_classes_minimum_length():
    password = generate_password(
        length=12, uppercase=True, lowercase=True, digits=True, symbols=True
    )
    assert len(password) == 12
    assert any(c in string.ascii_uppercase for c in password)
    assert any(c in string.ascii_lowercase for c in password)
    assert any(c in string.digits for c in password)
    assert any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in password)


def test_single_class():
    password = generate_password(
        length=12, uppercase=True, lowercase=False, digits=False, symbols=False
    )
    assert all(c in string.ascii_uppercase for c in password)
