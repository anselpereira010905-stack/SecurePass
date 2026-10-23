@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
)
echo Starting SecurePass...
".venv\Scripts\python.exe" main.py
pause
