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

:: Try using the standard 'python' command
python desktop_app.py
if %ERRORLEVEL% NEQ 0 (
    echo [Warning] 'python' command failed. Trying 'py' command...
    py desktop_app.py
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Python could not be executed. 
    echo Please ensure Python is installed and added to your PATH.
    pause
)
