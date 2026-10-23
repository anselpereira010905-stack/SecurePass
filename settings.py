"""
settings.py

Optional, explicitly opt-in persistence of the user's *generator
preferences* (length, character categories, passphrase settings, etc.)
between runs of SecurePass.

SECURITY NOTE -- read this before touching this file:
This module NEVER stores a generated password or any password the user
typed into the Strength Checker. It stores only small, non-sensitive
UI preferences (numbers, booleans, and short strings like a separator
character). Nothing is written to disk unless the user clicks
"Save as Default" in the Generator tab, and everything here can be
removed at any time with "Reset to Defaults".

The settings file lives at ~/.securepass/settings.json and is plain,
human-readable JSON so the user can inspect exactly what is stored.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SETTINGS_DIR = Path.home() / ".securepass"
SETTINGS_PATH = SETTINGS_DIR / "settings.json"
APP_SETTINGS_PATH = SETTINGS_DIR / "app_settings.json"


@dataclass
class GeneratorPreferences:
    """Everything here is a preference, never a secret."""

    mode: str = "characters"  # "characters" | "passphrase" | "pin" | "pronounceable"

    # Random-character mode
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False
    exclude_chars: str = ""
    no_repeats: bool = False

    # PIN mode
    pin_length: int = 6
    pin_avoid_patterns: bool = True

    # Pronounceable mode
    pron_length: int = 12
    pron_digits: bool = True
    pron_symbol: bool = True

    # Passphrase mode
    word_count: int = 5
    separator: str = "-"
    capitalize: bool = True
    include_number: bool = True


def default_preferences() -> GeneratorPreferences:
    return GeneratorPreferences()


def load_preferences() -> GeneratorPreferences:
    """
    Load saved preferences from disk, if any. Falls back to defaults if
    the file doesn't exist or is unreadable/corrupt -- this must never
    crash the app on startup.
    """
    if not SETTINGS_PATH.exists():
        return default_preferences()

    try:
        raw: dict[str, Any] = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_preferences()

    defaults = asdict(default_preferences())
    # Only accept known keys with matching types; ignore/repair anything
    # unexpected rather than trusting the file blindly.
    merged = dict(defaults)
    for key, value in raw.items():
        if key in defaults and isinstance(value, type(defaults[key])):
            merged[key] = value

    return GeneratorPreferences(**merged)


def save_preferences(preferences: GeneratorPreferences) -> None:
    """Explicitly opt-in save, triggered only by a user action."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(
        json.dumps(asdict(preferences), indent=2, sort_keys=True), encoding="utf-8"
    )


def reset_preferences() -> GeneratorPreferences:
    """Delete any saved preferences file and return fresh defaults."""
    try:
        SETTINGS_PATH.unlink(missing_ok=True)
    except OSError:
        pass
    return default_preferences()


# ---------------------------------------------------------------------
# App-level preferences (look & feel, clipboard timer). Same rules as
# above: opt-in, human-readable, and never anything secret.
# ---------------------------------------------------------------------

CLIPBOARD_CLEAR_CHOICES = (0, 15, 30, 60, 120)  # 0 = never auto-clear
THEMES = ("dark", "light")


@dataclass
class AppSettings:
    theme: str = "dark"
    clipboard_clear_seconds: int = 30
    reduce_motion: bool = False
    mask_history: bool = True


def load_app_settings() -> AppSettings:
    """Load saved app settings; unreadable/invalid values fall back to defaults."""
    if not APP_SETTINGS_PATH.exists():
        return AppSettings()
    try:
        raw: dict[str, Any] = json.loads(APP_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return AppSettings()
    if not isinstance(raw, dict):
        return AppSettings()

    result = AppSettings()
    if raw.get("theme") in THEMES:
        result.theme = raw["theme"]
    if raw.get("clipboard_clear_seconds") in CLIPBOARD_CLEAR_CHOICES:
        result.clipboard_clear_seconds = raw["clipboard_clear_seconds"]
    if isinstance(raw.get("reduce_motion"), bool):
        result.reduce_motion = raw["reduce_motion"]
    if isinstance(raw.get("mask_history"), bool):
        result.mask_history = raw["mask_history"]
    return result


def save_app_settings(app_settings: AppSettings) -> None:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    APP_SETTINGS_PATH.write_text(
        json.dumps(asdict(app_settings), indent=2, sort_keys=True), encoding="utf-8"
    )


def reset_app_settings() -> AppSettings:
    try:
        APP_SETTINGS_PATH.unlink(missing_ok=True)
    except OSError:
        pass
    return AppSettings()


def delete_all_saved_data() -> None:
    """Remove every file SecurePass has ever written to ~/.securepass."""
    reset_preferences()
    reset_app_settings()
    try:
        SETTINGS_DIR.rmdir()  # only succeeds if empty -- never deletes foreign files
    except OSError:
        pass
