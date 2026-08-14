#!/usr/bin/env python3
"""
main.py

Entry point for SecurePass — Password Generator & Strength Checker.

Run with:
    python main.py

This application is fully local: it does not use a database, a
backend server, or any external API, and requires no internet
connection to run once Python is installed.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox

from ui.main_window import MainWindow


def main() -> None:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        # This typically happens if there is no display available
        # (e.g. running in a headless environment).
        print(f"Could not start the GUI: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        MainWindow(root)
        root.mainloop()
    except Exception as exc:  # noqa: BLE001 - top-level safety net for the GUI
        messagebox.showerror("Unexpected Error", f"SecurePass encountered an error:\n{exc}")
        raise


if __name__ == "__main__":
    main()
