# Suggested GitHub Issues

> **Status: all five issues below have been implemented** (including the light theme, added in the v2 UI overhaul). See the
> "Resolved in" note under each for what changed. This file is kept
> as a historical record of the original issue text.

Copy each section below into a new GitHub Issue (title + body) once the
repo is pushed. Suggested labels are included.

---

## 1. Add a "Passphrase" generation mode
**Labels:** `enhancement`, `good first issue`
**Resolved in:** `password_generator.py` (`generate_passphrase`, `PassphraseOptions`), `data/wordlist.txt`, `ui/generator_tab.py` mode toggle, `tests/test_password_generator.py::TestPassphrase`.

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
**Resolved in:** `settings.py` (opt-in `save_preferences`/`load_preferences`/`reset_preferences`), "Save as Default" / "Reset" buttons in `ui/generator_tab.py`, `tests/test_settings.py`. Only preferences are stored, never a password — see README's "Settings persistence" section.

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
**Resolved in:** `password_checker.py` (`CrackTimeProfile`, `CRACK_TIME_PROFILES`, `get_profile`), attacker-speed dropdown in `ui/checker_tab.py`, `tests/test_password_checker.py::TestCrackTimeProfiles`. Also added an `entropy_breakdown()` function exposing the full pool/formula explanation in the UI.

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
**Resolved in:** `tests/test_ui_smoke.py` (headless via Xvfb), `.github/workflows/tests.yml` CI workflow. Also expanded logic test coverage in `tests/test_password_generator.py` and `tests/test_password_checker.py`.

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
**Resolved in:** `utils.Theme` (two palettes + `set_mode`), header toggle / `Ctrl+T` / Settings tab in `ui/main_window.py` and `ui/settings_tab.py`; the UI is rebuilt on switch so every custom widget picks up the new colours. Covered by `tests/test_ui_smoke.py::test_theme_switch_rebuilds_and_keeps_history`.

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
