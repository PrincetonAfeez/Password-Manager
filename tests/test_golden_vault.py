"""Test golden vault functionality."""

from pathlib import Path

from password_manager.vault import Vault

GOLDEN_PASSWORD = "golden-password"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "golden.pwv"


def test_golden_fixture_decrypts_and_contains_demo_entry():
    assert FIXTURE.exists(), "run: python scripts/generate_golden_vault.py"

    vault = Vault(FIXTURE)
    assert vault.verify_password(GOLDEN_PASSWORD) is True
    assert not vault.is_unlocked()

    vault.unlock(GOLDEN_PASSWORD)
    entry = vault.get_entry("example.com")
    assert entry.username == "demo-user"
    assert entry.password == "demo-entry-password"
    assert "golden fixture" in entry.notes
