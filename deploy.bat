@echo off
TITLE SecureVault Deployer
color 0A

echo ==========================================================
echo    SecureVault Enterprise - Git ^& Vercel Auto-Deployer
echo ==========================================================
echo.

:: Check Git
where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git command not found. Please install Git and try again.
    pause
    exit /b 1
)

echo [1/4] Staging files...
git add .
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git add failed.
    pause
    exit /b 1
)

echo.
echo [2/4] Committing changes...
set COMMIT_MSG="Configure MongoDB Cloud Sync & automated deployment"
git commit -m %COMMIT_MSG%
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] No changes to commit or commit failed.
)

echo.
echo [3/4] Pushing to remote repository...
:: Get current branch name
for /f "tokens=*" %%a in ('git branch --show-current') do set BRANCH=%%a
if "%BRANCH%"=="" set BRANCH=main

echo Pushing to branch: %BRANCH%...
git push origin %BRANCH%
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Git push failed. Please verify your remote credentials and network.
) else (
    echo [SUCCESS] Pushed to Git remote successfully.
)

echo.
echo [4/4] Deploying to Vercel...
echo Running Vercel deployment (runs locally via npx)...
call npx vercel --prod --yes
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [WARNING] Vercel CLI deployment failed or was cancelled.
    echo If your GitHub repo is linked directly to Vercel, the push in step 3
    echo has already triggered an automatic cloud rebuild/redeploy!
) else (
    echo [SUCCESS] Vercel deployment completed successfully!
)

echo.
echo ==========================================================
echo    DEPLOYS FINISHED. SecureVault is now updated!
echo ==========================================================
echo.
pause
