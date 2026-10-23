@echo off
echo ===================================================
echo   FileGuard - Push to GitHub (Vidhi-huub/FileGuard)
echo ===================================================
echo.

echo Checking GitHub CLI authentication status...
"C:\Program Files\GitHub CLI\gh.exe" auth status >nul 2>&1
if %errorlevel% neq 0 (
    echo You need to log into GitHub once.
    echo Please follow the prompts below to authenticate via your browser:
    echo.
    "C:\Program Files\GitHub CLI\gh.exe" auth login -p https -h github.com -w
)

echo.
echo Pushing project to https://github.com/Vidhi-huub/FileGuard.git ...
".venv\Scripts\git.cmd" push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo   SUCCESS! All files pushed to GitHub successfully:
    echo   https://github.com/Vidhi-huub/FileGuard
    echo ===================================================
) else (
    echo.
    echo Push failed. Please verify repository access permissions.
)
pause
