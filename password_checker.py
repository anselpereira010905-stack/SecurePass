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
}

SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{};:,.<>?/|~`'\"\\")


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
    return any(common in lowered for common in COMMON_PASSWORDS)


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

    if pool_size <= 1:
        return 0.0

    return round(len(password) * math.log2(pool_size), 1)


def estimate_crack_time_label(entropy_bits: float) -> str:
    """
    Educational, order-of-magnitude crack-time estimate.

    ASSUMPTIONS (clearly documented, not a guarantee):
      - Attacker can attempt 10,000,000,000 (1e10) guesses per second.
        This models a fast *offline* brute-force attack against a
        leaked, weakly-hashed password list. Real-world speeds vary
        enormously depending on hashing algorithm, hardware, and
        whether the attack is online (rate-limited) or offline.
      - On average, an attacker finds the password after searching
        half of the total keyspace (2^entropy / 2 attempts).

    This is NOT a precise prediction -- treat it as a rough,
    order-of-magnitude educational indicator only.
    """
    guesses_per_second = 1e10
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


def analyze_password(password: str) -> PasswordAnalysis:
    """
    Analyze a password and return a PasswordAnalysis with a score,
    level, statistics, entropy, crack-time estimate, warnings, and
    recommendations.

    The password itself is not stored on the returned object and is
    not retained anywhere by this function after it returns.
    """
    upper, lower, digits, special = _char_counts(password)
    entropy = calculate_entropy(password)
    score, warnings, recommendations, positives = _score_password(
        password, upper, lower, digits, special, entropy
    )
    crack_time = estimate_crack_time_label(entropy) if password else "N/A"

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
        warnings=warnings,
        recommendations=recommendations,
        positives=positives,
    )
