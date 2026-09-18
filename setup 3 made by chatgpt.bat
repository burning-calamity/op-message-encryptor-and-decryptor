@echo off
setlocal EnableExtensions
echo Installing a massive list of Python packages...
where python >nul 2>&1 || (
    echo ERROR: Python is not installed or is not available on PATH.
    exit /b 1
)
python -m pip install --upgrade pip
if errorlevel 1 exit /b 1

python -m pip install ^
    virtualenv ipython jupyter pip-tools python-dotenv rich typer loguru ^
    pandas numpy matplotlib seaborn plotly openpyxl xlrd tabulate pyarrow polars ^
    scikit-learn xgboost lightgbm tensorflow keras torch transformers sentence-transformers opencv-python pytorch-lightning ^
    flask django fastapi gunicorn uvicorn httpx requests aiohttp jinja2 ^
    beautifulsoup4 lxml selenium playwright scrapy pyppeteer mechanize ^
    setuptools wheel pyinstaller build twine ^
    paramiko cryptography pycryptodome scapy "requests[socks]" ^
    schedule apscheduler watchdog ^
    pytest pytest-cov tox coverage hypothesis ^
    pillow tqdm colorama faker pyyaml json5 markdown click pyautogui keyboard pynput toml

if errorlevel 1 (
    echo ERROR: One or more packages could not be installed.
    exit /b 1
)

echo.
echo MASSIVE package installation complete.
pause
exit /b 0
