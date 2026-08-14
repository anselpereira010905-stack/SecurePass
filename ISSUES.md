# Suggested GitHub Issues

Copy each section below into a new GitHub Issue (title + body) once the
repo is pushed. Suggested labels are included.

---

## 1. Add a "Passphrase" generation mode
**Labels:** `enhancement`, `good first issue`

**Description**
Add an alternative generation mode that produces memorable passphrases
(e.g. `correct-horse-battery-staple`) instead of random characters, using
a small local wordlist bundled with the app (no network calls).

**Tasks**
- [ ] Bundle a small local word list (e.g. `data/wordlist.txt`)
- [ ] Add `generate_passphrase(word_count, separator)` to `password_generator.py` using `secrets.choice`
- [ ] Add a mode toggle ("Random Characters" / "Passphrase") to the Generator tab
- [ ] Add unit tests for passphrase length/word-count/separator behavior

---

## 2. Persist user's last-used generator settings (in-memory only across tabs, not to disk)
**Labels:** `enhancement`

**Description**
Currently, generator options (length, categories, exclude-ambiguous) reset
to defaults every time the app restarts. Consider whether to add optional,
clearly-opt-in local settings persistence (e.g. a non-sensitive JSON config
file storing only *preferences*, never passwords) so returning users don't
have to reconfigure the generator each time.

**Tasks**
- [ ] Decide on and document the storage format (must never include generated passwords)
- [ ] Implement save/load of generator preferences only
- [ ] Add a "Reset to defaults" button
- [ ] Update README's Security Considerations section to describe exactly what is/isn't persisted

---

## 3. Improve entropy/crack-time accuracy with configurable attacker-speed presets
**Labels:** `enhancement`, `documentation`

**Description**
The crack-time estimate currently assumes a fixed 10 billion guesses/second.
Real-world speeds vary hugely by hashing algorithm (e.g. bcrypt vs. unsalted
MD5) and hardware. Add selectable presets (e.g. "Fast offline attack",
"Slow, well-hashed (bcrypt-like)", "Online, rate-limited") so the estimate
is more educational and transparent.

**Tasks**
- [ ] Add a `CrackTimeProfile` enum/dataclass with a few named presets and documented assumptions
- [ ] Add a dropdown/combobox on the Strength Checker tab to pick a profile
- [ ] Recalculate and relabel crack time when the profile changes
- [ ] Update README with the new documented assumptions

---

## 4. Add automated GUI smoke tests
**Labels:** `testing`

**Description**
Current tests cover `password_generator.py` and `password_checker.py`
logic thoroughly, but there's no automated coverage of the Tkinter UI
layer (`ui/*.py`). Add smoke tests that instantiate the main window
(headless, e.g. via `Xvfb` in CI) and verify tabs build without error,
buttons are wired to callbacks, and basic interactions (generate, analyze,
clear history) don't raise exceptions.

**Tasks**
- [ ] Add a headless test harness (e.g. `pytest` + `Xvfb` in GitHub Actions)
- [ ] Smoke-test that `MainWindow` builds all four tabs successfully
- [ ] Simulate a "Generate Password" click and assert the strength bar updates
- [ ] Simulate "Analyze Password" and assert statistics populate
- [ ] Wire this into a GitHub Actions CI workflow (`.github/workflows/tests.yml`)

---

## 5. Add light theme / theme toggle
**Labels:** `enhancement`, `ui`

**Description**
The app currently ships with a single dark theme (see `utils.Theme` and
`ui/main_window.py`). Add a light theme and a toggle (e.g. a menu item or
button in the header) to switch between them at runtime.

**Tasks**
- [ ] Extract theme colors into two named palettes (`DarkTheme`, `LightTheme`)
- [ ] Add a runtime theme-switch function that re-applies `ttk.Style` configuration
- [ ] Add a toggle control in the header
- [ ] Confirm all custom `ttk` styles (buttons, progress bar, notebook tabs) look correct in both themes

---

### How to bulk-create these on GitHub

If you have the GitHub CLI (`gh`) installed and authenticated, you can
create all five issues in one go from the repo root:

```bash
gh issue create --title "Add a \"Passphrase\" generation mode" --body-file <(sed -n '/^## 1\./,/^---/p' ISSUES.md) --label "enhancement,good first issue"
gh issue create --title "Persist user's last-used generator settings" --body-file <(sed -n '/^## 2\./,/^---/p' ISSUES.md) --label "enhancement"
gh issue create --title "Improve entropy/crack-time accuracy with configurable attacker-speed presets" --body-file <(sed -n '/^## 3\./,/^---/p' ISSUES.md) --label "enhancement,documentation"
gh issue create --title "Add automated GUI smoke tests" --body-file <(sed -n '/^## 4\./,/^---/p' ISSUES.md) --label "testing"
gh issue create --title "Add light theme / theme toggle" --body-file <(sed -n '/^## 5\./,/^---/p' ISSUES.md) --label "enhancement,ui"
```

(Or just copy/paste each section manually into "New Issue" on GitHub.)
