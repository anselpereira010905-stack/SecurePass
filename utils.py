"""
utils.py

Small shared helpers: clipboard access, theme color constants, and the
in-memory (never persisted to disk) password history store.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field


class ClipboardError(Exception):
    """Raised when copying to the system clipboard fails."""


def copy_to_clipboard(root: tk.Tk, text: str) -> None:
    """
    Copy `text` to the system clipboard using Tkinter's built-in
    clipboard support (no external services involved).
    """
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        # update() ensures the clipboard content persists after the
        # application loses focus on some platforms.
        root.update()
    except tk.TclError as exc:
        raise ClipboardError(f"Could not access system clipboard: {exc}") from exc


@dataclass
class HistoryStore:
    """
    Holds generated passwords only in memory for the lifetime of the
    running application. Nothing here is ever written to disk.
    """
    items: list[str] = field(default_factory=list)
    max_items: int = 100

    def add(self, password: str) -> None:
        self.items.insert(0, password)
        if len(self.items) > self.max_items:
            self.items.pop()

    def remove(self, index: int) -> None:
        if 0 <= index < len(self.items):
            self.items.pop(index)

    def clear(self) -> None:
        self.items.clear()


# ---------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------

class Theme:
    BG = "#121212"
    BG_SECONDARY = "#1e1e1e"
    ACCENT = "#7c3aed"
    SUCCESS = "#22c55e"
    WARNING = "#f59e0b"
    DANGER = "#ef4444"
    TEXT = "#ffffff"
    TEXT_SECONDARY = "#a1a1aa"

    FONT_FAMILY = "Segoe UI"

    @staticmethod
    def level_color(level: str) -> str:
        return {
            "Very Weak": Theme.DANGER,
            "Weak": Theme.DANGER,
            "Fair": Theme.WARNING,
            "Strong": Theme.SUCCESS,
            "Very Strong": Theme.SUCCESS,
        }.get(level, Theme.TEXT_SECONDARY)
