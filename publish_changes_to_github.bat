@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Run from the repository root even when launched from File Explorer.
cd /d "%~dp0"
set "REMOTE_URL="
set "BRANCH="
set "COMMIT_MESSAGE="

where git >nul 2>&1 || (
    echo ERROR: Git is not installed or is not available on PATH.
    echo Install Git for Windows from https://git-scm.com/download/win
    exit /b 1
)

git rev-parse --show-toplevel >nul 2>&1 || (
    echo ERROR: This folder is not a Git repository.
    echo Clone it first with:
    echo   git clone --recurse-submodules https://github.com/burning-calamity/op-message-encryptor-and-decryptor.git
    exit /b 1
)

git remote get-url origin >nul 2>&1 || (
    echo ERROR: The repository has no origin remote.
    exit /b 1
)

for /f "delims=" %%R in ('git remote get-url origin') do set "REMOTE_URL=%%R"
for /f "delims=" %%B in ('git branch --show-current') do set "BRANCH=%%B"

if not defined BRANCH (
    set "BRANCH=update-%RANDOM%-%RANDOM%"
    call git switch -c "%%BRANCH%%" || exit /b 1
)

echo Repository: %REMOTE_URL%
echo Branch:     %BRANCH%
echo.

git submodule update --init --recursive || exit /b 1

if exist scripts\sync_cipher_engines.py (
    echo Synchronizing cipher engine copies...
    python scripts\sync_cipher_engines.py || exit /b 1
)

if exist tests\test_basic.py (
    echo Running Python tests before publishing...
    python -m pytest -q || (
        echo ERROR: Tests failed. Nothing was pushed.
        exit /b 1
    )
)

git add --all || exit /b 1
git diff --cached --quiet
if errorlevel 1 (
    set "COMMIT_MESSAGE=%~1"
    if not defined COMMIT_MESSAGE set /p "COMMIT_MESSAGE=Commit message: "
    if not defined COMMIT_MESSAGE set "COMMIT_MESSAGE=Update project files"
    call git commit -m "%%COMMIT_MESSAGE%%" || exit /b 1
) else (
    echo No uncommitted file changes were found; pushing existing commits.
)

echo Pushing %BRANCH% to GitHub...
git push --set-upstream origin "%BRANCH%" || (
    echo ERROR: Push failed. Check your GitHub login and whether the remote branch changed.
    exit /b 1
)

if /i "%BRANCH%"=="main" (
    echo Changes were pushed directly to main.
    exit /b 0
)

where gh >nul 2>&1 || (
    echo.
    echo The branch was pushed successfully.
    echo Install GitHub CLI to create the pull request automatically:
    echo   winget install --id GitHub.cli
    echo Then run: gh pr create --base main --head "%BRANCH%" --fill
    exit /b 0
)

gh auth status >nul 2>&1 || (
    echo The branch was pushed, but GitHub CLI is not logged in.
    echo Run: gh auth login
    echo Then run: gh pr create --base main --head "%BRANCH%" --fill
    exit /b 0
)

gh pr view "%BRANCH%" --json url --jq .url >nul 2>&1
if errorlevel 1 (
    gh pr create --base main --head "%BRANCH%" --fill || exit /b 1
) else (
    echo A pull request already exists for %BRANCH%.
)

gh pr view "%BRANCH%" --web
echo Done.
exit /b 0
