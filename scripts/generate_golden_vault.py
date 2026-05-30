"""Regenerate tests/fixtures/golden.pwv for graders and CI."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from password_manager.models import EntryCreate  # noqa: E402
from password_manager.vault import Vault  # noqa: E402

GOLDEN_PASSWORD = "golden-password"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "golden.pwv"


def main() -> None:
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if FIXTURE_PATH.exists():
        FIXTURE_PATH.unlink()

    vault = Vault(FIXTURE_PATH)
    vault.initialize(GOLDEN_PASSWORD)
    vault.add_entry(
        EntryCreate(
            service="example.com",
            username="demo-user",
            password="demo-entry-password",
            url="https://example.com",
            notes="golden fixture entry",
        )
    )
    vault.lock()
    print(f"Wrote {FIXTURE_PATH} (master password: {GOLDEN_PASSWORD!r})")


if __name__ == "__main__":
    main()
