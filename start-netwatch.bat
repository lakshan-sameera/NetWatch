@echo off
:: Relaunch elevated so NetWatch can see every process and read its DLLs
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
python -m pip install --quiet psutil flask >nul 2>&1
start "" http://127.0.0.1:8765
python netwatch.py
pause
