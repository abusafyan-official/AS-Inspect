@echo off
setlocal enabledelayedexpansion

:: 1. Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    python "%~dp0setup.py" %*
    exit /b %ERRORLEVEL%
)

py --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py "%~dp0setup.py" %*
    exit /b %ERRORLEVEL%
)

:: 2. If Python is NOT found, auto-download and install it silently
echo [!] Python is not installed on this system.
echo [*] Downloading and installing official Python automatically...
echo Please wait 30-60 seconds...

set "PY_URL=https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
set "INSTALLER=%TEMP%\python_setup_%RANDOM%.exe"

powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('%PY_URL%', '%INSTALLER%')"

if not exist "%INSTALLER%" (
    echo [ERROR] Failed to download Python automatically.
    echo Please install Python manually from https://python.org
    pause
    exit /b 1
)

echo [*] Installing Python silently with PATH enabled...
"%INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1

del "%INSTALLER%" >nul 2>&1

echo [+] Python installed successfully!
echo [*] Launching AS Inspect setup...

python "%~dp0setup.py" %*
exit /b %ERRORLEVEL%
