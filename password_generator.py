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
import math
from dataclasses import dataclass
from pathlib import Path

# Characters that are easy to mis-type or visually confuse with each other.
AMBIGUOUS_CHARS = "O0Il1|"

SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/"

# Bundled locally with the app -- no network call is ever made to fetch
# word lists. See data/wordlist.txt.
_WORDLIST_PATH = Path(__file__).resolve().parent / "data" / "wordlist.txt"

MIN_PASSPHRASE_WORDS = 3
MAX_PASSPHRASE_WORDS = 10


class PasswordGenerationError(Exception):
    """Raised when a password cannot be generated with the given options."""


def load_wordlist() -> list[str]:
    """
    Load the local passphrase word list from disk.

    The list is bundled with the app (data/wordlist.txt) and is never
    downloaded, so passphrase generation works fully offline.
    """
    try:
        with _WORDLIST_PATH.open("r", encoding="utf-8") as handle:
            words = [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        raise PasswordGenerationError(
            f"Could not load the local word list at {_WORDLIST_PATH}: {exc}"
        ) from exc

    if len(words) < 50:
        raise PasswordGenerationError(
            "The local word list is too small to generate a secure passphrase."
        )
    return words


@dataclass
class GeneratorOptions:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False
    exclude_chars: str = ""      # any extra characters the user never wants
    no_repeats: bool = False     # every character appears at most once

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


def _filtered(chars: str, exclude_ambiguous: bool, extra_excluded: str = "") -> str:
    banned = (AMBIGUOUS_CHARS if exclude_ambiguous else "") + extra_excluded
    if banned:
        return "".join(c for c in chars if c not in banned)
    return chars


def _build_category_pools(options: GeneratorOptions) -> list[str]:
    """Return the list of active character pools (one string per category)."""
    pools: list[str] = []

    if options.use_upper:
        pool = _filtered(string.ascii_uppercase, options.exclude_ambiguous, options.exclude_chars)
        if pool:
            pools.append(pool)
    if options.use_lower:
        pool = _filtered(string.ascii_lowercase, options.exclude_ambiguous, options.exclude_chars)
        if pool:
            pools.append(pool)
    if options.use_digits:
        pool = _filtered(string.digits, options.exclude_ambiguous, options.exclude_chars)
        if pool:
            pools.append(pool)
    if options.use_special:
        pool = _filtered(SPECIAL_CHARS, options.exclude_ambiguous, options.exclude_chars)
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

    if options.no_repeats and options.length > len(set(combined_pool)):
        raise PasswordGenerationError(
            f"'No repeating characters' needs a pool of at least {options.length} "
            f"unique characters, but only {len(set(combined_pool))} are available."
        )

    # Step 1: guarantee at least one character from each selected category.
    password_chars: list[str] = []
    used: set[str] = set()
    for pool in pools:
        candidates = [c for c in pool if c not in used] if options.no_repeats else pool
        char = secrets.choice(candidates)
        password_chars.append(char)
        used.add(char)

    # Step 2: fill the remaining length from the combined pool.
    remaining = options.length - len(password_chars)
    for _ in range(remaining):
        if options.no_repeats:
            candidates = [c for c in combined_pool if c not in used]
        else:
            candidates = combined_pool
        char = secrets.choice(candidates)
        password_chars.append(char)
        used.add(char)

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


# ---------------------------------------------------------------------
# Passphrase mode (Issue #1 -- memorable passphrases from a local list)
# ---------------------------------------------------------------------


@dataclass
class PassphraseOptions:
    word_count: int = 5
    separator: str = "-"
    capitalize: bool = True
    include_number: bool = True

    def validate(self) -> None:
        if not (MIN_PASSPHRASE_WORDS <= self.word_count <= MAX_PASSPHRASE_WORDS):
            raise PasswordGenerationError(
                f"Word count must be between {MIN_PASSPHRASE_WORDS} and "
                f"{MAX_PASSPHRASE_WORDS}."
            )
        if len(self.separator) > 3:
            raise PasswordGenerationError("Separator must be 3 characters or fewer.")


def generate_passphrase(options: PassphraseOptions) -> str:
    """
    Generate a memorable passphrase (e.g. "correct-horse-battery-staple")
    made of words drawn from the local, bundled word list.

    Every word is chosen independently with `secrets.choice`, the same
    CSPRNG-backed primitive used for random-character passwords, so the
    passphrase's randomness comes entirely from the OS's secure random
    source -- never from anything predictable.
    """
    options.validate()
    words = load_wordlist()

    chosen = [secrets.choice(words) for _ in range(options.word_count)]
    if options.capitalize:
        chosen = [word.capitalize() for word in chosen]

    if options.include_number:
        # Insert a single securely-chosen digit at a random word boundary
        # so the passphrase isn't purely alphabetic.
        digit = str(secrets.randbelow(10))
        position = secrets.randbelow(len(chosen))
        chosen[position] = chosen[position] + digit

    return options.separator.join(chosen)


def generate_multiple_passphrases(options: PassphraseOptions, count: int) -> list[str]:
    """Generate `count` independent passphrases using the same options."""
    if count < 1:
        raise PasswordGenerationError("Number of passphrases must be at least 1.")
    if count > 50:
        raise PasswordGenerationError("Cannot generate more than 50 passphrases at once.")
    return [generate_passphrase(options) for _ in range(count)]


def calculate_passphrase_entropy(options: PassphraseOptions, wordlist_size: int | None = None) -> float:
    """
    Estimate passphrase entropy in bits: word_count * log2(wordlist_size),
    plus a small bonus for an inserted digit (log2(10) for its value times
    log2(word_count) for its position) when `include_number` is set.
    """
    if wordlist_size is None:
        wordlist_size = len(load_wordlist())
    if wordlist_size <= 1 or options.word_count <= 0:
        return 0.0

    bits = options.word_count * math.log2(wordlist_size)
    if options.include_number:
        bits += math.log2(10) + math.log2(max(options.word_count, 1))
    return round(bits, 1)


# ---------------------------------------------------------------------
# Entropy of the *generator settings* (more accurate than guessing from
# the finished string, because we know exactly how it was produced).
# ---------------------------------------------------------------------


def calculate_options_entropy(options: GeneratorOptions) -> float:
    """Bits of entropy implied by the generator options themselves."""
    try:
        pools = _build_category_pools(options)
    except PasswordGenerationError:
        return 0.0
    unique = len(set("".join(pools)))
    if unique <= 1:
        return 0.0
    if options.no_repeats:
        n = min(options.length, unique)
        return round(sum(math.log2(unique - i) for i in range(n)), 1)
    return round(options.length * math.log2(unique), 1)


# ---------------------------------------------------------------------
# PIN mode
# ---------------------------------------------------------------------

MIN_PIN_LENGTH = 4
MAX_PIN_LENGTH = 12


@dataclass
class PinOptions:
    length: int = 6
    avoid_patterns: bool = True  # reject 1111, 1234, 4321, 121212, ...

    def validate(self) -> None:
        if not (MIN_PIN_LENGTH <= self.length <= MAX_PIN_LENGTH):
            raise PasswordGenerationError(
                f"PIN length must be between {MIN_PIN_LENGTH} and {MAX_PIN_LENGTH}."
            )


def is_weak_pin(pin: str) -> bool:
    """True for all-same digits, straight runs, and short repeating blocks."""
    if len(set(pin)) == 1:
        return True
    digits = [int(c) for c in pin]
    steps = {digits[i + 1] - digits[i] for i in range(len(digits) - 1)}
    if steps in ({1}, {-1}):
        return True
    n = len(pin)
    for block in range(1, n // 2 + 1):
        if n % block == 0 and pin[:block] * (n // block) == pin:
            return True
    return False


def generate_pin(options: PinOptions) -> str:
    """Generate a numeric PIN with `secrets`, rejecting guessable shapes."""
    options.validate()
    while True:
        pin = "".join(secrets.choice(string.digits) for _ in range(options.length))
        if not options.avoid_patterns or not is_weak_pin(pin):
            return pin


def generate_multiple_pins(options: PinOptions, count: int) -> list[str]:
    if not (1 <= count <= 50):
        raise PasswordGenerationError("Number of PINs must be between 1 and 50.")
    return [generate_pin(options) for _ in range(count)]


def calculate_pin_entropy(options: PinOptions) -> float:
    return round(options.length * math.log2(10), 1)


# ---------------------------------------------------------------------
# Pronounceable mode -- consonant/vowel alternation, easy to read aloud
# ---------------------------------------------------------------------

_CONSONANTS = "bcdfghjklmnprstvwz"
_VOWELS = "aeiou"
_PRONOUNCEABLE_SYMBOLS = "!@#$%&*?"
MIN_PRONOUNCEABLE_LENGTH = 6
MAX_PRONOUNCEABLE_LENGTH = 32


@dataclass
class PronounceableOptions:
    length: int = 12
    capitalize: bool = True
    include_digits: bool = True   # adds 2 digits
    include_symbol: bool = True   # adds 1 symbol

    def extras(self) -> int:
        return (2 if self.include_digits else 0) + (1 if self.include_symbol else 0)

    def validate(self) -> None:
        if not (MIN_PRONOUNCEABLE_LENGTH <= self.length <= MAX_PRONOUNCEABLE_LENGTH):
            raise PasswordGenerationError(
                f"Length must be between {MIN_PRONOUNCEABLE_LENGTH} and "
                f"{MAX_PRONOUNCEABLE_LENGTH}."
            )


def generate_pronounceable(options: PronounceableOptions) -> str:
    """e.g. 'Bupa-style' strings like 'Rolu7Sekit!4' that can be said aloud."""
    options.validate()
    letter_count = options.length - options.extras()
    letters = [
        secrets.choice(_CONSONANTS if i % 2 == 0 else _VOWELS) for i in range(letter_count)
    ]
    if options.capitalize:
        for i in range(0, letter_count, 4):  # first letter of each 4-letter chunk
            letters[i] = letters[i].upper()

    chars = letters
    extras: list[str] = []
    if options.include_digits:
        extras += [secrets.choice(string.digits) for _ in range(2)]
    if options.include_symbol:
        extras.append(secrets.choice(_PRONOUNCEABLE_SYMBOLS))
    for extra in extras:
        chars.insert(secrets.randbelow(len(chars) + 1), extra)
    return "".join(chars)


def generate_multiple_pronounceable(options: PronounceableOptions, count: int) -> list[str]:
    if not (1 <= count <= 50):
        raise PasswordGenerationError("Number of passwords must be between 1 and 50.")
    return [generate_pronounceable(options) for _ in range(count)]


def calculate_pronounceable_entropy(options: PronounceableOptions) -> float:
    """Approximate bits: per-letter pool + digits + symbol + insertion positions."""
    letter_count = options.length - options.extras()
    bits = sum(
        math.log2(len(_CONSONANTS) if i % 2 == 0 else len(_VOWELS))
        for i in range(letter_count)
    )
    if options.include_digits:
        bits += 2 * math.log2(10)
    if options.include_symbol:
        bits += math.log2(len(_PRONOUNCEABLE_SYMBOLS))
    for k in range(options.extras()):
        bits += math.log2(letter_count + k + 1)
    return round(bits, 1)
