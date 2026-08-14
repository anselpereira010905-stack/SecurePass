# SecurePass — Password Generator & Strength Checker

A fully local, offline desktop application for generating cryptographically
secure passwords and analyzing password strength. Built with Python and
Tkinter. **No database, no backend server, no external API, no internet
connection required.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-purple)
![Tests](https://img.shields.io/badge/tests-unittest%20%2F%20pytest-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Description

SecurePass is a student/portfolio-friendly desktop app that helps users
generate strong, random passwords and evaluate how strong an existing
password is — entirely on their own machine. All generation and analysis
logic runs locally using Python's standard library; nothing is ever sent
over a network.

## Features

### 🔐 Password Generator
- Adjustable length (4–64 characters) via slider
- Toggle uppercase, lowercase, numbers, and special characters
- Optionally exclude ambiguous characters (`O`, `0`, `I`, `l`, `1`)
- Generate multiple passwords at once
- Guarantees at least one character from every selected category
- Uses `secrets` (CSPRNG), never `random`
- Copy to clipboard, clear, and regenerate
- Live strength indicator for the generated password

### 🛡️ Password Strength Checker
- Score from 0–100 with a color-coded strength level (Very Weak → Very
  Strong)
- Visual progress bar
- Character breakdown: length, uppercase, lowercase, digits, special
- Estimated entropy (in bits), with a plain-language explanation
- Educational estimated crack-time label, with documented assumptions
- Detects common weaknesses: too short, single-category-only, repeated
  characters, sequential characters (`1234`, `abcd`), and common
  passwords/patterns (`password`, `qwerty`, `admin`, `welcome`, etc.)
- Actionable, specific recommendations

### 👁️ Show/Hide Password
Both the generator and checker support toggling plaintext visibility.

### 🕘 Session-Only Password History
- Every generated password can be reviewed, copied, or deleted
- History exists **only in memory** — never written to disk
- Clear-all button, with an explicit on-screen warning that history
  disappears when the app closes

### 📊 Entropy Estimate
Approximate entropy is calculated as `length × log2(character pool size)`
based on the character types actually present in the password. This is
a simplified, educational approximation, not a formal cryptographic
guarantee.

### ⏱️ Estimated Crack Time
An order-of-magnitude, clearly-labeled educational estimate assuming a
fast offline brute-force attack (10 billion guesses/second, average case
= half the keyspace). Real-world attacker speed varies enormously
depending on hashing algorithm and hardware — this is for intuition,
not a promise.

### 💡 Security Tips
A scrollable panel of practical password-hygiene advice.

## Technologies Used

- **Python 3.11+**
- **Tkinter / ttk** — GUI (dark theme, custom styling)
- **secrets** — cryptographically secure password generation
- **string** — character set definitions
- **re** — pattern detection (sequential/repeated characters)
- **math** — entropy calculation
- **dataclasses** — clean, typed data containers
- **unittest / pytest** — automated tests

No third-party packages are required to run the application. `pytest` is
only needed if you prefer it over the built-in `unittest` runner.

## Requirements

- Python 3.11 or later
- Tkinter (bundled with most Python installers; see note below for Linux)

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/SecurePass.git
cd SecurePass

# 2. (Optional but recommended) create a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install optional dev/test dependency (pytest)
pip install -r requirements.txt
```

**Linux users:** Tkinter sometimes isn't bundled with the system Python
and must be installed separately:

```bash
sudo apt install python3-tk        # Debian/Ubuntu
sudo dnf install python3-tkinter   # Fedora
```

## How to Run

```bash
python main.py
```

That's it — no server to start, no API key to configure, no internet
connection needed after Python is installed.

## How Password Generation Works

1. The user's selected options (length, categories, ambiguous-character
   exclusion) are validated.
2. One character pool string is built per selected category.
3. Using `secrets.choice`, one character is drawn from **each** selected
   category first, guaranteeing every required category is represented.
4. The remaining length is filled by drawing from the combined pool with
   `secrets.choice`.
5. The final character list is shuffled with a secure Fisher–Yates
   shuffle (using `secrets.randbelow` for the random index), so
   required characters aren't predictably placed at the start.

## How Strength Scoring Works

The 0–100 score is built from three components, then adjusted by
penalties:

| Component | Max Points | Basis |
|---|---|---|
| Length | 30 | Longer passwords score higher (≥16 chars = full marks) |
| Character variety | 40 | 10 points per category present (upper/lower/digit/special) |
| Entropy bonus | 20 | Scaled from the calculated entropy in bits |
| **Penalties** | −30 to −60 | Common pattern (−30), repeated run (−15), sequential run (−15) |

The final score is clamped to `0–100` and mapped to a level:

| Score | Level |
|---|---|
| 0–20 | Very Weak |
| 21–40 | Weak |
| 41–60 | Fair |
| 61–80 | Strong |
| 81–100 | Very Strong |

## Why `secrets` Instead of `random`?

Python's `random` module uses a Mersenne Twister PRNG. It is fast and
great for simulations/games, but it is **deterministic and predictable**
if enough output is observed — its internal state can, in principle, be
reconstructed. That makes it unsuitable for anything security-sensitive.

`secrets` is built specifically for security purposes: it draws from the
operating system's cryptographically secure random source (`os.urandom`
under the hood), making generated values suitable for passwords, tokens,
and similar secrets. This project uses `secrets.choice` and
`secrets.randbelow` everywhere randomness affects password content.

## Security Considerations

- All processing happens locally — no network calls are ever made.
- Passwords are never written to a file, database, or log.
- Passwords are never printed to the console.
- Password history is kept in memory only and is cleared on exit.
- The strength checker and its "common password" list are educational
  heuristics, not a real breach-database lookup (e.g. not a substitute
  for a service like "Have I Been Pwned").
- Entropy and crack-time figures are **estimates** based on documented,
  simplified assumptions — they are not guarantees of real-world
  security.
- This application does not claim to provide perfect or complete
  security; it is a learning tool and a convenience utility.

## Project Structure

```
SecurePass/
├── main.py                  # Application entry point
├── password_generator.py    # Secure password generation logic
├── password_checker.py      # Strength analysis logic
├── utils.py                 # Clipboard helper, theme colors, history store
├── ui/
│   ├── __init__.py
│   ├── main_window.py       # Root window, theming, tab assembly
│   ├── generator_tab.py     # Generator tab UI
│   ├── checker_tab.py       # Strength Checker tab UI
│   ├── history_tab.py       # History tab UI
│   └── tips_tab.py          # Security Tips tab UI
├── tests/
│   ├── __init__.py
│   ├── test_generator.py    # Tests for password_generator.py
│   └── test_checker.py      # Tests for password_checker.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Testing

Run the full test suite with `unittest`:

```bash
python -m unittest discover tests
```

or with `pytest` (after `pip install -r requirements.txt`):

```bash
pytest tests/ -v
```

Tests cover: generated password length, character-category enforcement,
ambiguous-character exclusion, empty/very-short passwords, strong/weak
password scoring, common-password detection, sequential- and
repeated-character detection, entropy calculation, and strength-level
bucketing. Tests check password *properties* (length, character
membership, score ranges) rather than printing actual password values.

## Screenshots

_Add screenshots here after running the app locally, e.g.:_

```
screenshots/
├── generator-tab.png
├── checker-tab.png
├── history-tab.png
└── tips-tab.png
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named '_tkinter'` | Install Tkinter via your OS package manager (see Installation section). |
| Window opens but looks unstyled/wrong colors | Some minimal Linux/WSL Tk builds don't fully support the `clam` ttk theme's color overrides — try updating your Tk installation. |
| Clipboard copy fails / raises an error | Some headless Linux environments lack a clipboard manager; run the app in a normal desktop session. |
| App won't launch, `TclError: no display name` | You're running in a headless environment with no GUI display. SecurePass requires a graphical desktop session. |
| "No usable characters remain" error | You've selected "Exclude Ambiguous Characters" with only a category that contains solely ambiguous characters — enable another category. |

## Future Improvements

- Passphrase (word-based) generation mode
- Optional local check against a larger offline common-password list
- Export/print security-tips as PDF
- Adjustable dark/light theme toggle
- Localization / multi-language support

## License

MIT License — see below.

```
MIT License

Copyright (c) 2026 SecurePass Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### Run Command (Quick Reference)

```bash
python main.py
```
