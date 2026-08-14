"""
password_generator.py

Cryptographically secure password generation.

SECURITY NOTE:
We use Python's `secrets` module (not `random`) because `secrets` is
built on top of the operating system's cryptographically secure random
number generator (CSPRNG). The `random` module is deterministic and
predictable given its internal state, which makes it unsuitable for
anything security-related, including password generation.
"""

from __future__ import annotations

import string
import secrets
from dataclasses import dataclass

# Characters that are easy to mis-type or visually confuse with each other.
AMBIGUOUS_CHARS = "O0Il1|"

SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/"


class PasswordGenerationError(Exception):
    """Raised when a password cannot be generated with the given options."""


@dataclass
class GeneratorOptions:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False

    def validate(self) -> None:
        if not (4 <= self.length <= 64):
            raise PasswordGenerationError(
                "Password length must be between 4 and 64 characters."
            )
        if not any(
            [self.use_upper, self.use_lower, self.use_digits, self.use_special]
        ):
            raise PasswordGenerationError(
                "Select at least one character category "
                "(uppercase, lowercase, numbers, or special characters)."
            )


def _filtered(chars: str, exclude_ambiguous: bool) -> str:
    if exclude_ambiguous:
        return "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
    return chars


def _build_category_pools(options: GeneratorOptions) -> list[str]:
    """Return the list of active character pools (one string per category)."""
    pools: list[str] = []

    if options.use_upper:
        pool = _filtered(string.ascii_uppercase, options.exclude_ambiguous)
        if pool:
            pools.append(pool)
    if options.use_lower:
        pool = _filtered(string.ascii_lowercase, options.exclude_ambiguous)
        if pool:
            pools.append(pool)
    if options.use_digits:
        pool = _filtered(string.digits, options.exclude_ambiguous)
        if pool:
            pools.append(pool)
    if options.use_special:
        pool = _filtered(SPECIAL_CHARS, options.exclude_ambiguous)
        if pool:
            pools.append(pool)

    if not pools:
        # This can happen if exclude_ambiguous filtered out an entire
        # category (e.g. digits-only with ambiguous chars excluded and
        # no digits left). Guard against generating from an empty pool.
        raise PasswordGenerationError(
            "No usable characters remain with the current options. "
            "Try disabling 'Exclude Ambiguous Characters' or enabling "
            "another character category."
        )

    return pools


def generate_password(options: GeneratorOptions) -> str:
    """
    Generate a single cryptographically secure password that respects
    every selected character category.

    Guarantees:
      - Uses `secrets.choice` for every character (CSPRNG-backed).
      - At least one character from each selected category is present
        (as long as length allows).
      - Final character order is shuffled using a secure Fisher-Yates
        shuffle so required characters aren't predictably placed at
        the start of the password.
    """
    options.validate()
    pools = _build_category_pools(options)

    if options.length < len(pools):
        raise PasswordGenerationError(
            f"Password length must be at least {len(pools)} to include "
            "one character from every selected category."
        )

    combined_pool = "".join(pools)

    # Step 1: guarantee at least one character from each selected category.
    password_chars = [secrets.choice(pool) for pool in pools]

    # Step 2: fill the remaining length from the combined pool.
    remaining = options.length - len(password_chars)
    password_chars.extend(secrets.choice(combined_pool) for _ in range(remaining))

    # Step 3: secure shuffle (Fisher-Yates using secrets.randbelow).
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_multiple(options: GeneratorOptions, count: int) -> list[str]:
    """Generate `count` independent passwords using the same options."""
    if count < 1:
        raise PasswordGenerationError("Number of passwords must be at least 1.")
    if count > 50:
        raise PasswordGenerationError("Cannot generate more than 50 passwords at once.")
    return [generate_password(options) for _ in range(count)]
