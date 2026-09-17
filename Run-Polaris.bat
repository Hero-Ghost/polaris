@echo off
chcp 65001 >nul
title Polaris - Windows Diagnostics & Stability Suite

echo ========================================================
echo   Polaris - כוכב הצפון של המערכת שלך
echo ========================================================
echo.

cd /d "%~dp0"

:: 1. Check if single-file compiled exe exists
if exist "Polaris.exe" (
    echo [OK] מפעיל קובץ עצמאי (Single-File Standalone)...
    start "" "Polaris.exe"
    exit /b 0
)

if exist "dist\Polaris.exe" (
    echo [OK] מפעיל קובץ עצמאי (Single-File Standalone)...
    start "" "dist\Polaris.exe"
    exit /b 0
)

:: 2. Find Python executable
set "PY_CMD="

python --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python"
    goto :RUN_PY
)

py --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py"
    goto :RUN_PY
)

if exist "%LocalAppData%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LocalAppData%\Programs\Python\Python311\python.exe"
    goto :RUN_PY
)

if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
    set "PY_CMD=%LocalAppData%\Programs\Python\Python312\python.exe"
    goto :RUN_PY
)

if exist "%LocalAppData%\Programs\Python\Python310\python.exe" (
    set "PY_CMD=%LocalAppData%\Programs\Python\Python310\python.exe"
    goto :RUN_PY
)

if exist "C:\Program Files\Python311\python.exe" (
    set "PY_CMD=C:\Program Files\Python311\python.exe"
    goto :RUN_PY
)

echo [!] לא נמצא Python מותקן במערכת.
echo פתח את הקובץ לאחר התקנת Python או הפעל את Polaris.exe.
pause
exit /b 1

:RUN_PY
echo [+] מפעיל את Polaris באמצעות: %PY_CMD%
"%PY_CMD%" main.py
if %errorlevel% neq 0 (
    echo.
    echo [!] נראה שחסרות תלויות. מתקין מ-requirements.txt...
    if exist "requirements.txt" (
        "%PY_CMD%" -m pip install -r requirements.txt
    ) else (
        "%PY_CMD%" -m pip install psutil pywebview
    )
    echo [+] מנסה להריץ שוב...
    "%PY_CMD%" main.py
)

pause
