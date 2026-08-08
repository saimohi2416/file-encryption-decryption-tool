@echo off
TITLE SecureVault Enterprise Launcher
color 0B

echo ===================================================
echo     SecureVault Enterprise - Desktop Client
echo ===================================================
echo.
echo Initializing local server and native window wrapper...
echo Please wait...
echo.

:: Try 'py' launcher first (avoids Windows App Execution Alias prompt)
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py desktop_app.py
    goto check_status
)

:: Fallback to standard 'python' command
python desktop_app.py

:check_status
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Python could not be executed. 
    echo Please ensure Python is installed and added to your PATH.
    pause
)

