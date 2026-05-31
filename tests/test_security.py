"""Test security functionality."""

from pathlib import Path

import password_manager.crypto_engine as crypto_engine


def test_crypto_engine_is_only_module_importing_cryptography():
    package = Path(__file__).resolve().parents[1] / "password_manager"
    offenders = []
    for path in package.glob("*.py"):
        if path.name == "crypto_engine.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "cryptography" in text:
            offenders.append(path.name)

    assert crypto_engine.CryptoEngine
    assert offenders == []
