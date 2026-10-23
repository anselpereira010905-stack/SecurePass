# SecurePass

SecurePass is a privacy-focused, fully offline password generator and
strength analyzer built with Python and Tkinter. Nothing you type or
generate is ever written to a database, logged, or sent over a
network — the entire app runs locally, including its passphrase word
list.

## Features

**Generator** — four modes, all using Python's `secrets` CSPRNG
- **Random** characters: 4–64 chars, per-category toggles, avoid look-alikes (`O 0 I l 1 |`), a custom "never use these characters" box, and a "no repeated characters" option
- **Passphrase**: 3–10 words from a bundled offline word list, custom separator, capitalization, optional inserted digit
- **PIN**: 4–12 digits that rejects guessable shapes (`0000`, `1234`, `4321`, `121212`)
- **Speakable**: consonant–vowel passwords you can read aloud (`Tokar@a9m7uR`), with optional digits and symbol
- Colour-coded output (letters / digits / symbols) so look-alike characters are easy to tell apart
- Entropy computed from the generator *settings* (exact, not guessed from the string), with an animated meter and average crack time
- Generate several at once, double-click a line to copy it, `Ctrl+G` to regenerate
- Optional, explicitly opt-in "Save as default" (see **Settings persistence**)

**Strength Checker**
- **Live analysis** as you type (toggleable), animated 0–100 score dial, and a character-composition bar
- Entropy estimate with a full visible breakdown (pools, formula, bits)
- **Crack-time table** for every attacker profile at once, with human-readable durations ("619 billion years")
- Pattern detection: common passwords/words (incl. leetspeak), repeated characters, repeated blocks (`abcabc`), sequences, keyboard walks, embedded years
- **"Suggest"** button that offers a fresh random password (never a tweak of yours), sized to be at least as long as yours
- Coloured preview when "Show" is on; Paste button

**Audit** (new)
- Paste or load a file of passwords (one per line) and get a grade A–F
- Finds weak, **reused** and **near-duplicate** passwords (`Summer2023!` vs `Summer2024!`)
- Results show masked values only; export a CSV report that **never contains the passwords**
- Input is wiped after the scan by default

**History**
- In-memory log with search, mode filter, sortable columns, multi-select copy/remove, and summary cards (count, average, best, weak)
- Mask / reveal toggle
- Optional export to **TXT, CSV or JSON** — gated behind an explicit confirmation, since it writes real passwords to disk

**Security Tips** — eight practical tips plus an interactive (never saved) hygiene checklist

**Settings & UX**
- **Dark / light theme** toggle (header button or `Ctrl+T`)
- **Clipboard auto-clear**: copied passwords are wiped after 15 s – 2 min, *only if the clipboard still holds what SecurePass copied*, with a live countdown; also wiped on exit
- Reduce-motion option, status-bar notifications instead of popup dialogs
- Keyboard shortcuts: `Ctrl+1…6` switch tabs, `Ctrl+G` generate, `Ctrl+T` theme
- "Delete all saved data" button

## Settings persistence

Generator *preferences* (length, character categories, passphrase word
count/separator, etc.) can optionally be saved between runs by
clicking **Save as Default** in the Generator tab. This is opt-in only
— nothing is written to disk unless you click that button.

- Stored at `~/.securepass/settings.json` (generator) and `~/.securepass/app_settings.json` (theme, clipboard timer, motion, history masking) — in plain, human-readable JSON; app settings are saved only when you click **Save app settings**
- Contains only preference values (numbers, booleans, a short separator string) — **never** a generated password or anything typed into the Strength Checker
- **Reset** restores factory defaults and deletes the settings file

## Requirements

- Python 3.11+
- Tkinter (usually bundled with Python; on Debian/Ubuntu install with `sudo apt install python3-tk` if missing)
- No third-party package is required to run the GUI

## Run

From this folder:

```powershell
python main.py
```

Or double-click `run_securepass.bat` on Windows.

## Tests

The suite covers three layers: pure generation/analysis logic, opt-in
settings persistence, and headless GUI smoke tests for the Tkinter
layer.

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Or with pytest:

```powershell
pytest
```

The GUI smoke tests (`tests/test_ui_smoke.py`) need a display. On a
headless Linux machine (e.g. CI), run them under a virtual display:

```bash
sudo apt install python3-tk xvfb
xvfb-run -a pytest
```

This is exactly what `.github/workflows/tests.yml` does on every push
and pull request.

## Project layout

```
main.py                 entry point
password_generator.py   random / passphrase / PIN / speakable generation + entropy
password_checker.py     scoring, patterns, crack-time estimates
audit.py                bulk audit (reuse + near-duplicate detection)
settings.py             opt-in preferences (generator + app)
utils.py                theme palettes, clipboard manager, history store
ui/                     Tkinter UI (widgets, one module per tab)
tests/                  logic, settings and headless GUI tests
```

## Privacy

SecurePass is designed to work entirely locally:

- Passwords generated or analyzed are never sent to a server or written to a database
- The passphrase word list is bundled with the app — generating a passphrase never touches the network
- The clipboard is wiped after a configurable delay (and on exit) if it still contains something SecurePass copied
- Audit reports and on-screen audit results never contain plaintext passwords
- Generation history exists only in memory and is erased when the app closes, unless you explicitly export it
- Saved generator preferences (if any) never include a password — see **Settings persistence** above
