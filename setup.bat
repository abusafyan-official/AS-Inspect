@echo off
setlocal enabledelayedexpansion
title AS Inspect - Automated Setup

:: 1. Check if python is directly available
python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    python setup.py
    exit /b %ERRORLEVEL%
)

:: 2. Check py launcher
py --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py setup.py
    exit /b %ERRORLEVEL%
)

:: 3. Check common Python installation paths on Windows
for %%P in (
    "C:\Program Files\Python314\python.exe"
    "C:\Program Files\Python313\python.exe"
    "C:\Program Files\Python312\python.exe"
    "C:\Program Files\Python311\python.exe"
    "C:\Program Files\Python310\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
) do (
    if exist %%P (
        echo [*] Found installed Python at %%P
        %%P setup.py
        exit /b %ERRORLEVEL%
    )
)

:: 4. If Python is NOT found anywhere, auto-download and install it silently
echo.
echo ========================================================
echo  AS Inspect: Python was not detected on this system.
echo  Downloading and installing Python automatically...
echo ========================================================
echo.

set "PY_URL=https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
set "INSTALLER=%TEMP%\python_setup_%RANDOM%.exe"

powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Write-Host 'Downloading Python from python.org...'; (New-Object System.Net.WebClient).DownloadFile('%PY_URL%', '%INSTALLER%')"

if not exist "%INSTALLER%" (
    echo [ERROR] Failed to download Python.
    pause
    exit /b 1
)

echo [*] Installing Python silently with PATH configured...
"%INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1

del "%INSTALLER%" >nul 2>&1

echo [+] Python installed successfully!
echo [*] Launching AS Inspect setup...

:: Try launching python from newly installed standard path or command
if exist "C:\Program Files\Python311\python.exe" (
    "C:\Program Files\Python311\python.exe" setup.py
) else (
    python setup.py
)

exit /b %ERRORLEVEL%
