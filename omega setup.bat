@echo off
setlocal EnableExtensions
echo Installing common Python packages...

where python >nul 2>&1 || (
    echo ERROR: Python is not installed or is not available on PATH.
    exit /b 1
)

REM Upgrade pip
python -m pip install --upgrade pip
if errorlevel 1 exit /b 1

REM Install packages
python -m pip install ^
    virtualenv ^
    ipython ^
    jupyter ^
    requests ^
    beautifulsoup4 ^
    pandas ^
    numpy ^
    matplotlib ^
    scipy ^
    scikit-learn ^
    openpyxl ^
    pillow ^
    pyinstaller ^
    pytest ^
    black ^
    flask ^
    django ^
    python-dotenv ^
    rich

if errorlevel 1 (
    echo ERROR: One or more packages could not be installed.
    exit /b 1
)

echo.
echo All packages installed successfully.
pause
exit /b 0
