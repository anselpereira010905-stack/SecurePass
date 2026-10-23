"""
utils.py

Shared helpers: the switchable dark/light theme, clipboard access with
auto-clear, the shared AppContext handed to every tab, and the
in-memory (never persisted to disk) password history store.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

MODE_LABELS = {
    "characters": "Characters",
    "passphrase": "Passphrase",
    "pin": "PIN",
    "pronounceable": "Pronounceable",
}


class ClipboardError(Exception):
    """Raised when copying to the system clipboard fails."""


def copy_to_clipboard(root: tk.Tk, text: str) -> None:
    """Copy `text` to the system clipboard using Tkinter's built-in support."""
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        # update() keeps the content alive after focus loss on some platforms.
        root.update()
    except tk.TclError as exc:
        raise ClipboardError(f"Could not access system clipboard: {exc}") from exc


class ClipboardManager:
    """
    Copies text and (optionally) wipes it again after a delay, but only
    if the clipboard still holds what *we* put there -- so we never
    clobber something the user copied from another app in the meantime.
    """

    def __init__(self, root: tk.Tk, seconds: int = 30,
                 on_tick: Callable[[int | None], None] | None = None) -> None:
        self.root = root
        self.seconds = seconds
        self.on_tick = on_tick or (lambda remaining: None)
        self._last: str | None = None
        self._after_id: str | None = None
        self._remaining = 0

    def copy(self, text: str) -> None:
        copy_to_clipboard(self.root, text)
        self._last = text
        self._cancel()
        if self.seconds > 0:
            self._remaining = self.seconds
            self.on_tick(self._remaining)
            self._after_id = self.root.after(1000, self._tick)
        else:
            self.on_tick(None)

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _tick(self) -> None:
        self._after_id = None
        self._remaining -= 1
        if self._remaining <= 0:
            self.clear_now()
            return
        self.on_tick(self._remaining)
        self._after_id = self.root.after(1000, self._tick)

    def clear_now(self) -> None:
        """Wipe the clipboard if it still contains our last copied text."""
        self._cancel()
        try:
            if self._last is not None and self.root.clipboard_get() == self._last:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
                self.root.update()
        except tk.TclError:
            pass  # clipboard empty/unavailable -- nothing to wipe
        self._last = None
        self.on_tick(None)

    def shutdown(self) -> None:
        """Called on app exit: don't leave a password on the clipboard."""
        if self._last is not None:
            self.clear_now()
        self._cancel()


@dataclass
class HistoryEntry:
    """One generated credential and the context needed to display it."""

    password: str
    created_at: datetime
    score: int
    level: str
    mode: str
    entropy_bits: float = 0.0

    def time_label(self) -> str:
        return self.created_at.strftime("%H:%M:%S")


@dataclass
class HistoryStore:
    """
    Holds generated passwords only in memory for the lifetime of the
    running application. Nothing here is ever written to disk unless
    the user explicitly chooses to export it (see HistoryTab.export).
    """
    items: list[HistoryEntry] = field(default_factory=list)
    max_items: int = 200

    def add(self, password: str, score: int = 0, level: str = "",
            mode: str = "characters", entropy_bits: float = 0.0) -> None:
        self.items.insert(
            0, HistoryEntry(password=password, created_at=datetime.now(),
                            score=score, level=level, mode=mode, entropy_bits=entropy_bits)
        )
        if len(self.items) > self.max_items:
            self.items.pop()

    def remove(self, index: int) -> None:
        if 0 <= index < len(self.items):
            self.items.pop(index)

    def clear(self) -> None:
        self.items.clear()

    def search(self, query: str, mode: str = "") -> list[tuple[int, HistoryEntry]]:
        """Return (original_index, entry) pairs matching a text query and optional mode."""
        query = query.strip().lower()
        out = []
        for i, entry in enumerate(self.items):
            if mode and entry.mode != mode:
                continue
            if query and not (
                query in entry.password.lower()
                or query in entry.level.lower()
                or query in entry.mode.lower()
            ):
                continue
            out.append((i, entry))
        return out

    def stats(self) -> dict:
        if not self.items:
            return {"count": 0, "average": 0.0, "best": 0, "weak": 0}
        scores = [e.score for e in self.items]
        return {
            "count": len(scores),
            "average": round(sum(scores) / len(scores), 1),
            "best": max(scores),
            "weak": sum(1 for s in scores if s <= 40),
        }

    # --- export formats (callers must get explicit user consent first) ---
    def export_text(self) -> str:
        return "".join(
            f"{e.time_label()}\t{e.mode}\t{e.level} ({e.score})\t{e.password}\n"
            for e in self.items
        )

    def export_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["time", "mode", "level", "score", "entropy_bits", "password"])
        for e in self.items:
            writer.writerow([e.created_at.isoformat(timespec="seconds"), e.mode, e.level,
                             e.score, e.entropy_bits, e.password])
        return buf.getvalue()

    def export_json(self) -> str:
        return json.dumps(
            [{"time": e.created_at.isoformat(timespec="seconds"), "mode": e.mode,
              "level": e.level, "score": e.score, "entropy_bits": e.entropy_bits,
              "password": e.password} for e in self.items],
            indent=2,
        )


@dataclass
class AppContext:
    """Everything a tab needs from the main window, in one object."""

    root: tk.Tk
    history: HistoryStore
    clipboard: ClipboardManager
    notify: Callable[..., None]            # notify(message, kind="info")
    on_history_change: Callable[[], None]
    reduce_motion: bool = False
    mask_history: bool = True

    def copy(self, text: str, what: str = "Copied to clipboard") -> bool:
        try:
            self.clipboard.copy(text)
        except ClipboardError as exc:
            self.notify(str(exc), "error")
            return False
        secs = self.clipboard.seconds
        suffix = f" — clears in {secs}s" if secs else ""
        self.notify(what + suffix, "success")
        return True


# ---------------------------------------------------------------------
# Theme -- two palettes sharing one set of attribute names. Call
# Theme.set_mode("dark" | "light") and rebuild the UI; every widget
# reads colours from Theme at construction time.
# ---------------------------------------------------------------------

_DARK = dict(
    BG="#080b12", BG_SECONDARY="#0f1420", BG_RAISED="#151c2d", BORDER="#222d44",
    ACCENT="#7c5cff", ACCENT_HOVER="#6b4bef", ON_ACCENT="#ffffff",
    CYAN="#2fe0d4", SUCCESS="#3ddc97", WARNING="#ffb84d", DANGER="#ff5c72",
    SYMBOL="#ff8ad0",
    TEXT="#eef2fb", TEXT_SECONDARY="#8593b0", TEXT_MUTED="#566380",
)
_LIGHT = dict(
    BG="#eef1f8", BG_SECONDARY="#ffffff", BG_RAISED="#f1f4fb", BORDER="#d6ddec",
    ACCENT="#6a4df0", ACCENT_HOVER="#5a3de0", ON_ACCENT="#ffffff",
    CYAN="#079a91", SUCCESS="#1a9d63", WARNING="#c97a0a", DANGER="#d9304a",
    SYMBOL="#c0267a",
    TEXT="#131a2c", TEXT_SECONDARY="#566482", TEXT_MUTED="#8793ad",
)


def _pick_fonts() -> tuple[str, str]:
    if sys.platform.startswith("win"):
        return "Segoe UI", "Consolas"
    if sys.platform == "darwin":
        return "Helvetica Neue", "Menlo"
    return "DejaVu Sans", "DejaVu Sans Mono"


class Theme:
    mode = "dark"

    BG = _DARK["BG"]
    BG_SECONDARY = _DARK["BG_SECONDARY"]
    BG_RAISED = _DARK["BG_RAISED"]
    BORDER = _DARK["BORDER"]
    ACCENT = _DARK["ACCENT"]
    ACCENT_HOVER = _DARK["ACCENT_HOVER"]
    ON_ACCENT = _DARK["ON_ACCENT"]
    CYAN = _DARK["CYAN"]
    SUCCESS = _DARK["SUCCESS"]
    WARNING = _DARK["WARNING"]
    DANGER = _DARK["DANGER"]
    SYMBOL = _DARK["SYMBOL"]
    TEXT = _DARK["TEXT"]
    TEXT_SECONDARY = _DARK["TEXT_SECONDARY"]
    TEXT_MUTED = _DARK["TEXT_MUTED"]

    FONT_FAMILY, MONO_FAMILY = _pick_fonts()

    # 5-step ramp used by every meter, weakest to strongest.
    METER_RAMP = ["#ff5c72", "#ff8a5c", "#ffb84d", "#8ee06b", "#3ddc97"]

    @classmethod
    def set_mode(cls, mode: str) -> None:
        palette = _LIGHT if mode == "light" else _DARK
        cls.mode = "light" if mode == "light" else "dark"
        for key, value in palette.items():
            setattr(cls, key, value)

    @classmethod
    def font(cls, size: int = 10, weight: str = "normal") -> tuple:
        return (cls.FONT_FAMILY, size, weight)

    @classmethod
    def mono(cls, size: int = 11, weight: str = "normal") -> tuple:
        return (cls.MONO_FAMILY, size, weight)

    @staticmethod
    def level_color(level: str) -> str:
        return {
            "Very Weak": Theme.DANGER,
            "Weak": Theme.DANGER,
            "Fair": Theme.WARNING,
            "Strong": Theme.SUCCESS,
            "Very Strong": Theme.CYAN,
        }.get(level, Theme.TEXT_SECONDARY)

    @staticmethod
    def score_color(score: int) -> str:
        idx = min(4, max(0, score // 21))
        return Theme.METER_RAMP[idx]

    @staticmethod
    def char_color(kind: str) -> str:
        return {
            "upper": Theme.TEXT, "lower": Theme.TEXT,
            "digit": Theme.CYAN, "special": Theme.SYMBOL, "other": Theme.WARNING,
        }.get(kind, Theme.TEXT)
