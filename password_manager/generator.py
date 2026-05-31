"""Password generation using the standard-library CSPRNG."""

from __future__ import annotations

import secrets
import string

MIN_PASSWORD_LENGTH = 12  # aligned with the vault's master-password floor


def generate_password(
    length: int = 20,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password length must be at least {MIN_PASSWORD_LENGTH}")

    groups: list[str] = []
    if uppercase:
        groups.append(string.ascii_uppercase)
    if lowercase:
        groups.append(string.ascii_lowercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not groups:
        raise ValueError("at least one character class must be enabled")
    if length < len(groups):
        raise ValueError("password length is too short for selected character classes")

    required = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + remaining

    # Fisher-Yates with secrets.randbelow keeps the required characters hidden.
    for index in range(len(chars) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        chars[index], chars[swap_index] = chars[swap_index], chars[index]

    return "".join(chars)
