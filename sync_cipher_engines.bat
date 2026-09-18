@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where python >nul 2>&1 || (
    echo ERROR: Python is not installed or is not available on PATH.
    exit /b 1
)

python scripts\sync_cipher_engines.py
if errorlevel 1 exit /b 1

echo Cipher engines, browser payload, and manifest are synchronized.
exit /b 0
