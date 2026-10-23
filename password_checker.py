"""
password_checker.py

Local, offline password strength analysis.

IMPORTANT SECURITY NOTE:
The password being analyzed is never written to disk, never logged,
never printed to the console, and never sent over any network. It
exists only in memory for the duration of the analysis and is
returned to the caller inside a PasswordAnalysis object.

This module makes no claim to be a substitute for real-world breach
databases (e.g. "have I been pwned" style checks). It is a local,
educational heuristic analyzer.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field

# A small, illustrative list of extremely common passwords / patterns.
# This is intentionally not exhaustive -- it's for educational feedback,
# not a real breach-database lookup.
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "admin", "welcome",
    "letmein", "monkey", "football", "iloveyou", "123456789", "abc123",
    "password1", "111111", "1234567", "sunshine", "princess", "dragon",
    "master", "login", "passw0rd", "trustno1", "starwars", "hello",
    "freedom", "whatever", "qazwsx", "zaq12wsx", "000000", "121212",
    "baseball", "superman", "batman", "shadow", "michael", "jennifer",
    "computer", "internet", "qwertyuiop", "mustang", "charlie", "access",
    "flower", "cheese", "summer", "winter", "secret", "soccer", "hunter",
    "ranger", "buster", "thomas", "tigger", "pepper", "ginger", "cookie",
    "orange", "banana", "samsung", "google", "facebook", "pokemon", "naruto",
    "liverpool", "chelsea", "arsenal", "cricket", "bollywood", "changeme",
    "default", "guest", "root", "administrator", "iloveyou", "lovely",
}

SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{};:,.<>?/|~`'\"\\")

# Adjacent-key rows on a standard QWERTY layout, used to catch keyboard
# "walks" like "qwerty" or "asdfgh" that pure sequence detection misses.
_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

# Common leetspeak substitutions, used to catch "p4ssw0rd"-style
# obfuscations of otherwise common words.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})

_DATE_PATTERN = re.compile(r"(19|20)\d{2}")


@dataclass(frozen=True)
class CrackTimeProfile:
    """
    A named attacker-speed assumption for the educational crack-time
    estimate. Real-world guess rates vary enormously by hashing
    algorithm and hardware -- these presets make that variance visible
    instead of hiding it behind one fixed number.
    """

    key: str
    label: str
    guesses_per_second: float
    description: str


# Ordered roughly fastest -> slowest attacker.
CRACK_TIME_PROFILES: list[CrackTimeProfile] = [
    CrackTimeProfile(
        "fast_offline", "Fast offline attack", 1e10,
        "Leaked, unsalted/weakly-hashed passwords cracked with modern GPU rigs.",
    ),
    CrackTimeProfile(
        "gpu_offline", "GPU offline attack (salted hash)", 1e9,
        "A salted but fast hash (e.g. SHA-256) attacked offline with GPUs.",
    ),
    CrackTimeProfile(
        "slow_hash", "Slow, well-hashed (bcrypt-like)", 1e4,
        "A deliberately slow hash (bcrypt/scrypt/Argon2) that limits guess rate.",
    ),
    CrackTimeProfile(
        "online", "Online, rate-limited", 10,
        "An online login form with lockouts/throttling limiting attempts.",
    ),
]

DEFAULT_CRACK_TIME_PROFILE = CRACK_TIME_PROFILES[0]


def get_profile(key: str) -> CrackTimeProfile:
    for profile in CRACK_TIME_PROFILES:
        if profile.key == key:
            return profile
    return DEFAULT_CRACK_TIME_PROFILE


@dataclass
class PasswordAnalysis:
    length: int = 0
    upper_count: int = 0
    lower_count: int = 0
    digit_count: int = 0
    special_count: int = 0
    score: int = 0
    level: str = "Very Weak"
    entropy_bits: float = 0.0
    crack_time_label: str = ""
    crack_time_profile_label: str = ""
    pool_size: int = 0
    entropy_formula: str = ""
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    positives: list[str] = field(default_factory=list)


def _char_counts(password: str) -> tuple[int, int, int, int]:
    upper = sum(1 for c in password if c in string.ascii_uppercase)
    lower = sum(1 for c in password if c in string.ascii_lowercase)
    digits = sum(1 for c in password if c in string.digits)
    special = sum(1 for c in password if c in SPECIAL_CHARS)
    return upper, lower, digits, special


def _has_sequential_run(password: str, run_length: int = 4) -> bool:
    """Detect ascending/descending sequences like '1234', 'abcd', 'dcba'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        window = lowered[i : i + run_length]
        codes = [ord(c) for c in window]
        ascending = all(codes[k] + 1 == codes[k + 1] for k in range(len(codes) - 1))
        descending = all(codes[k] - 1 == codes[k + 1] for k in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def _has_repeated_run(password: str, run_length: int = 3) -> bool:
    """Detect the same character repeated `run_length` or more times in a row."""
    return re.search(r"(.)\1{" + str(run_length - 1) + ",}", password) is not None


def _contains_common_pattern(password: str) -> bool:
    lowered = password.lower()
    if any(common in lowered for common in COMMON_PASSWORDS):
        return True
    # Also check a leetspeak-normalized version so "p4ssw0rd" is caught
    # the same way "password" is.
    de_leeted = lowered.translate(_LEET_MAP)
    return any(common in de_leeted for common in COMMON_PASSWORDS)


def _has_keyboard_walk(password: str, run_length: int = 4) -> bool:
    """Detect adjacent-key runs like 'qwerty', 'asdf', or their reverse."""
    lowered = password.lower()
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            window = row[i : i + run_length]
            if window in lowered or window[::-1] in lowered:
                return True
    return False


def _has_repeated_block(password: str) -> bool:
    """Detect a short block repeated back-to-back, e.g. 'abcabc' or 'x9x9x9'."""
    n = len(password)
    for block in range(2, n // 2 + 1):
        for start in range(0, n - block * 2 + 1):
            chunk = password[start : start + block]
            if password[start + block : start + block * 2] == chunk:
                return True
    return False


def _has_date_pattern(password: str) -> bool:
    """Detect an embedded 4-digit year (e.g. 1990, 2024) -- easy to guess."""
    return _DATE_PATTERN.search(password) is not None


def get_pool_size(password: str) -> int:
    """
    Size of the character pool actually *used* in the password (not
    merely selected as a generator option). Shared by entropy and
    the entropy breakdown so both stay consistent.
    """
    if not password:
        return 0

    pool_size = 0
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += len(SPECIAL_CHARS)
    # Any character outside the categories above (unicode, spaces, etc.)
    if any(
        c not in string.ascii_uppercase
        and c not in string.ascii_lowercase
        and c not in string.digits
        and c not in SPECIAL_CHARS
        for c in password
    ):
        pool_size += 10  # conservative bump for "other" characters
    return pool_size


def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits.

    Entropy here is approximated as length * log2(pool_size), where
    pool_size is the size of the character set actually *used* in the
    password (not merely selected as an option). This is a common,
    simplified approximation -- it assumes each character was chosen
    independently and uniformly at random from the observed pool,
    which is optimistic for human-chosen passwords but is a reasonable
    educational estimate.
    """
    if not password:
        return 0.0

    pool_size = get_pool_size(password)
    if pool_size <= 1:
        return 0.0

    return round(len(password) * math.log2(pool_size), 1)


@dataclass
class EntropyBreakdown:
    """A human-readable explanation of how an entropy value was derived."""

    length: int
    pool_size: int
    entropy_bits: float
    formula: str
    categories_used: list[str] = field(default_factory=list)


def entropy_breakdown(password: str) -> EntropyBreakdown:
    """
    Expose entropy as a fully explained calculation, not just a number,
    so the "why" behind the strength score is visible in the UI.
    """
    pool_size = get_pool_size(password)
    entropy = calculate_entropy(password)

    categories_used = []
    if any(c in string.ascii_uppercase for c in password):
        categories_used.append("uppercase (26)")
    if any(c in string.ascii_lowercase for c in password):
        categories_used.append("lowercase (26)")
    if any(c in string.digits for c in password):
        categories_used.append("digits (10)")
    if any(c in SPECIAL_CHARS for c in password):
        categories_used.append(f"special ({len(SPECIAL_CHARS)})")

    formula = (
        f"{len(password)} chars x log2({pool_size} possible/char) = {entropy} bits"
        if password
        else "Enter a password to see the calculation."
    )

    return EntropyBreakdown(
        length=len(password),
        pool_size=pool_size,
        entropy_bits=entropy,
        formula=formula,
        categories_used=categories_used,
    )


def estimate_crack_time_label(
    entropy_bits: float, profile: CrackTimeProfile = DEFAULT_CRACK_TIME_PROFILE
) -> str:
    """
    Educational, order-of-magnitude crack-time estimate.

    ASSUMPTIONS (clearly documented, not a guarantee):
      - The attacker's guess rate is taken from `profile`, one of
        CRACK_TIME_PROFILES. Real-world speeds vary enormously
        depending on hashing algorithm, hardware, and whether the
        attack is online (rate-limited) or offline.
      - On average, an attacker finds the password after searching
        half of the total keyspace (2^entropy / 2 attempts).

    This is NOT a precise prediction -- treat it as a rough,
    order-of-magnitude educational indicator only.
    """
    guesses_per_second = profile.guesses_per_second
    total_combinations = 2 ** entropy_bits
    seconds = (total_combinations / 2) / guesses_per_second

    if seconds < 1:
        return "Less than a second"
    if seconds < 60:
        return "Several seconds"
    if seconds < 3600:
        return "Several minutes"
    if seconds < 86400:
        return "Several hours"
    if seconds < 31_536_000:  # 1 year
        return "Several days"
    if seconds < 31_536_000 * 100:
        return "Several years"
    if seconds < 31_536_000 * 1_000_000:
        return "Centuries"
    return "Extremely long"


def _score_password(
    password: str,
    upper: int,
    lower: int,
    digits: int,
    special: int,
    entropy: float,
) -> tuple[int, list[str], list[str], list[str]]:
    """Return (score, warnings, recommendations, positives)."""
    warnings: list[str] = []
    recommendations: list[str] = []
    positives: list[str] = []
    score = 0
    length = len(password)

    if length == 0:
        return 0, ["Password is empty."], ["Enter a password to analyze."], []

    # --- Length component (max 30) ---
    if length >= 16:
        score += 30
        positives.append("Excellent length")
    elif length >= 12:
        score += 25
        positives.append("Good length")
    elif length >= 8:
        score += 15
        recommendations.append("Use at least 12 characters for stronger security.")
    elif length >= 4:
        score += 5
        warnings.append("Password is too short.")
        recommendations.append("Use at least 12 characters.")
    else:
        warnings.append("Password is too short.")
        recommendations.append("Use at least 12 characters.")

    # --- Character variety component (max 40) ---
    categories_present = sum(
        [bool(upper), bool(lower), bool(digits), bool(special)]
    )
    score += categories_present * 10

    if categories_present >= 3:
        positives.append("Contains multiple character types")
    if not upper and not lower:
        pass  # handled below
    if upper == 0:
        recommendations.append("Add uppercase characters.")
    if lower == 0:
        recommendations.append("Add lowercase characters.")
    if digits == 0:
        recommendations.append("Add numbers.")
    if special == 0:
        recommendations.append("Add special characters.")

    if categories_present == 1:
        if lower and not upper and not digits and not special:
            warnings.append("Password uses only lowercase letters.")
        elif upper and not lower and not digits and not special:
            warnings.append("Password uses only uppercase letters.")
        elif digits and not upper and not lower and not special:
            warnings.append("Password uses only numbers.")
        elif special and not upper and not lower and not digits:
            warnings.append("Password uses only special characters.")

    # --- Entropy bonus (max 20) ---
    score += min(int(entropy / 5), 20)

    # --- Pattern penalties ---
    if _contains_common_pattern(password):
        warnings.append("Password contains a common word or pattern.")
        recommendations.append("Avoid common passwords and dictionary words.")
        score -= 30
    else:
        positives.append("No obvious common pattern")

    if _has_repeated_run(password):
        warnings.append("Password contains repeated characters (e.g. 'aaaa').")
        recommendations.append("Avoid repeating the same character multiple times in a row.")
        score -= 15

    if _has_sequential_run(password):
        warnings.append("Password contains a sequential pattern (e.g. '1234', 'abcd').")
        recommendations.append("Avoid sequential characters like '1234' or 'abcd'.")
        score -= 15

    if _has_keyboard_walk(password):
        warnings.append("Password contains a keyboard pattern (e.g. 'qwerty', 'asdf').")
        recommendations.append("Avoid adjacent-key keyboard patterns.")
        score -= 15

    if _has_repeated_block(password):
        warnings.append("Password repeats the same block of characters (e.g. 'abcabc').")
        recommendations.append("Avoid repeating a short block of characters.")
        score -= 10

    if _has_date_pattern(password):
        warnings.append("Password contains what looks like a year (e.g. 1990, 2024).")
        recommendations.append("Avoid birth years or other guessable dates.")
        score -= 10

    score = max(0, min(100, score))
    return score, warnings, recommendations, positives


def _level_from_score(score: int) -> str:
    if score <= 20:
        return "Very Weak"
    if score <= 40:
        return "Weak"
    if score <= 60:
        return "Fair"
    if score <= 80:
        return "Strong"
    return "Very Strong"


def analyze_password(
    password: str, profile: CrackTimeProfile = DEFAULT_CRACK_TIME_PROFILE
) -> PasswordAnalysis:
    """
    Analyze a password and return a PasswordAnalysis with a score,
    level, statistics, entropy, crack-time estimate (for the given
    attacker-speed `profile`), warnings, and recommendations.

    The password itself is not stored on the returned object and is
    not retained anywhere by this function after it returns.
    """
    upper, lower, digits, special = _char_counts(password)
    entropy = calculate_entropy(password)
    score, warnings, recommendations, positives = _score_password(
        password, upper, lower, digits, special, entropy
    )
    crack_time = estimate_crack_time_label(entropy, profile) if password else "N/A"

    return PasswordAnalysis(
        length=len(password),
        upper_count=upper,
        lower_count=lower,
        digit_count=digits,
        special_count=special,
        score=score,
        level=_level_from_score(score) if password else "Very Weak",
        entropy_bits=entropy,
        crack_time_label=crack_time,
        crack_time_profile_label=profile.label,
        pool_size=get_pool_size(password),
        entropy_formula=entropy_breakdown(password).formula,
        warnings=warnings,
        recommendations=recommendations,
        positives=positives,
    )


# ---------------------------------------------------------------------
# Extras used by the richer UI
# ---------------------------------------------------------------------

_SECONDS = {
    "minute": 60, "hour": 3600, "day": 86_400, "year": 31_536_000,
}


def crack_time_seconds(entropy_bits: float, profile: CrackTimeProfile = DEFAULT_CRACK_TIME_PROFILE) -> float:
    """Average seconds to find the password (half the keyspace)."""
    try:
        return (2 ** entropy_bits / 2) / profile.guesses_per_second
    except OverflowError:
        return float("inf")


def format_duration(seconds: float) -> str:
    """Human-friendly duration, e.g. '3 hours', '12 years', 'over 1 billion years'."""
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        n = int(seconds)
        return f"{n} second{'s' if n != 1 else ''}"
    for unit in ("minute", "hour", "day", "year"):
        nxt = {"minute": 3600, "hour": 86_400, "day": 31_536_000}.get(unit)
        if unit == "year" or seconds < nxt:
            n = seconds / _SECONDS[unit]
            if unit == "year":
                if n >= 1e12:
                    return "over 1 trillion years"
                if n >= 1e9:
                    return f"{n / 1e9:.0f} billion years"
                if n >= 1e6:
                    return f"{n / 1e6:.0f} million years"
                if n >= 1e3:
                    return f"{n / 1e3:.0f} thousand years"
            n = max(1, int(n))
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return "a very long time"  # pragma: no cover


def format_crack_time(entropy_bits: float, profile: CrackTimeProfile = DEFAULT_CRACK_TIME_PROFILE) -> str:
    return format_duration(crack_time_seconds(entropy_bits, profile))


def crack_time_table(entropy_bits: float) -> list[tuple[CrackTimeProfile, str]]:
    """The crack-time estimate under every attacker-speed profile."""
    return [(p, format_crack_time(entropy_bits, p)) for p in CRACK_TIME_PROFILES]


def char_class(char: str) -> str:
    """'upper' | 'lower' | 'digit' | 'special' | 'other' -- used for colouring."""
    if char in string.ascii_uppercase:
        return "upper"
    if char in string.ascii_lowercase:
        return "lower"
    if char in string.digits:
        return "digit"
    if char in SPECIAL_CHARS:
        return "special"
    return "other"


def suggest_strong_alternative(password: str = "") -> str:
    """
    Offer a brand-new random password (never a tweak of the user's own
    password, so nothing about it is reused). Length scales with the
    original so the suggestion is never weaker.
    """
    from password_generator import GeneratorOptions, generate_password

    length = max(16, min(32, len(password) + 4))
    return generate_password(GeneratorOptions(length=length, exclude_ambiguous=True))
