@echo off
setlocal enabledelayedexpansion
title AS Inspect - Auto Setup & Launcher
color 0B

echo ========================================================
echo        AS Inspect - Understand applications with evidence.
echo        Developed by Abu Safyan
echo ========================================================
echo.

:: 1. Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=python"
    goto :PYTHON_FOUND
)

py --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=py"
    goto :PYTHON_FOUND
)

if exist "C:\Program Files\Python314\python.exe" (
    set "PY_CMD=C:\Program Files\Python314\python.exe"
    goto :PYTHON_FOUND
)

:: 2. Auto-download Python if missing
echo [-] Python was not found on this system.
echo [*] Downloading and installing Python automatically...
echo Please wait a moment...

set "PY_URL=https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
set "PY_INSTALLER=%TEMP%\python_installer.exe"

powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('%PY_URL%', '%PY_INSTALLER%')"

if not exist "%PY_INSTALLER%" (
    echo [!] Download failed. Please install Python manually from python.org
    pause
    exit /b 1
)

echo [*] Installing Python silently with PATH configured...
"%PY_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1

del "%PY_INSTALLER%" >nul 2>&1
set "PY_CMD=python"
echo [+] Python installed successfully!

:PYTHON_FOUND
echo [+] Python environment ready.
echo [*] Installing required dependencies (pefile, pytest)...
"%PY_CMD%" -m pip install --quiet --upgrade pip
"%PY_CMD%" -m pip install --quiet pefile pytest

echo.
echo ========================================================
echo [+] AS Inspect Setup Complete!
echo ========================================================
echo.
echo Usage examples:
echo   "%PY_CMD%" apps/cli/as_inspect_cli.py analyze C:\Windows\System32\notepad.exe
echo   "%PY_CMD%" apps/cli/as_inspect_cli.py hash target.exe
echo.

if "%~1"=="" (
    echo Drop a file here to analyze, or use command line arguments.
    set /p "TARGET=Enter path to file or folder to inspect: "
    if not "!TARGET!"=="" (
        "%PY_CMD%" apps/cli/as_inspect_cli.py analyze "!TARGET!" --format html
    )
) else (
    "%PY_CMD%" apps/cli/as_inspect_cli.py %*
)

pause
