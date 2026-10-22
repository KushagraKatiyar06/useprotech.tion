@echo off
setlocal enabledelayedexpansion
title UseProtection - Setup and Run
cd /d "%~dp0"

echo ============================================
echo   UseProtection - one-stop setup and launch
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH. Install Python 3.10+ and re-run this script.
    pause
    exit /b 1
)

where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found on PATH. Install Node 18+ and re-run this script.
    pause
    exit /b 1
)

echo [1/5] Python virtual environment
if not exist venv (
    echo       Creating venv...
    python -m venv venv
) else (
    echo       Already exists, skipping.
)

echo.
echo [2/5] Backend dependencies
call venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed. See the output above.
    pause
    exit /b 1
)

echo.
echo [3/5] API keys
if not exist .env (
    copy .env.example .env >nul
    echo       Created .env from .env.example.
    echo       Opening it in Notepad - add your E2B / Gemini / VirusTotal keys,
    echo       then save and close the window to continue.
    notepad .env
) else (
    echo       .env already exists, skipping.
)

echo.
echo [4/5] Frontend dependencies
call npm install --prefix frontend
if errorlevel 1 (
    echo [ERROR] npm install failed. See the output above.
    pause
    exit /b 1
)

if not exist frontend\.env.local (
    copy frontend\.env.local.example frontend\.env.local >nul
)

echo.
echo [5/5] Starting backend and frontend
start "UseProtection Backend"  cmd /k "venv\Scripts\activate.bat && uvicorn app:app --reload"
start "UseProtection Frontend" cmd /k "cd frontend && npm run dev"

echo       Waiting for the frontend dev server to come up...
timeout /t 8 /nobreak >nul
start http://localhost:3000

echo.
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:3000
echo.
echo Two new terminal windows are running the servers - close them to stop.
pause
