@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem This pushes a version tag to GitHub. The tag starts the trusted PyPI workflow.
cd /d "%~dp0"

where git >nul 2>&1 || (
    echo ERROR: Git is not installed or is not available on PATH.
    exit /b 1
)
where python >nul 2>&1 || (
    echo ERROR: Python is not installed or is not available on PATH.
    exit /b 1
)
git rev-parse --show-toplevel >nul 2>&1 || (
    echo ERROR: This folder is not a Git repository.
    exit /b 1
)

for /f "delims=" %%B in ('git branch --show-current') do set "BRANCH=%%B"
if /i not "%BRANCH%"=="main" (
    echo ERROR: PyPI releases must be tagged from main. Current branch: %BRANCH%
    echo Merge the pull request, then run:
    echo   git switch main
    echo   git pull --ff-only origin main
    exit /b 1
)

for /f "delims=" %%S in ('git status --porcelain') do set "DIRTY=1"
if defined DIRTY (
    echo ERROR: The working tree is not clean. Commit or discard changes first.
    git status --short
    exit /b 1
)

git fetch origin || exit /b 1
git pull --ff-only origin main || exit /b 1

echo Running tests and building the release artifacts...
python -m pytest -q || exit /b 1
python -m build || (
    echo ERROR: Package build failed. Install the builder with: python -m pip install build
    exit /b 1
)

for /f "delims=" %%V in ('python -c "from ars_occultandarum_litterarum._version import __version__; print(__version__)"') do set "VERSION=%%V"
if not defined VERSION (
    echo ERROR: Could not read the package version.
    exit /b 1
)
set "TAG=v%VERSION%"

git rev-parse --verify --quiet "refs/tags/%TAG%" >nul
if not errorlevel 1 (
    echo ERROR: Local tag %TAG% already exists. PyPI versions cannot be overwritten.
    exit /b 1
)
git ls-remote --exit-code --tags origin "refs/tags/%TAG%" >nul 2>&1
if not errorlevel 1 (
    echo ERROR: Remote tag %TAG% already exists. Increment _version.py first.
    exit /b 1
)

echo.
echo This will publish package version %VERSION% by pushing tag %TAG% to GitHub.
set /p "CONFIRM=Type %TAG% to continue: "
if /i not "%CONFIRM%"=="%TAG%" (
    echo Cancelled.
    exit /b 1
)

git tag -a "%TAG%" -m "Release %VERSION%" || exit /b 1
git push origin "%TAG%" || (
    echo ERROR: Tag push failed. Removing the local tag so you can retry safely.
    git tag -d "%TAG%" >nul 2>&1
    exit /b 1
)

echo Release tag %TAG% was pushed successfully.
echo Follow the workflow at:
echo https://github.com/burning-calamity/op-message-encryptor-and-decryptor/actions/workflows/publish-to-pypi.yml
exit /b 0
