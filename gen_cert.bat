@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Generating Local Self-Signed SSL/TLS Certificates
echo ============================================================

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py gen_cert.py
    goto :done
)

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python gen_cert.py
    goto :done
)

where openssl >nul 2>nul
if %ERRORLEVEL% equ 0 (
    if not exist certs mkdir certs
    openssl req -x509 -newkey rsa:2048 -nodes -keyout certs\key.pem -out certs\cert.pem -days 365 -subj "/CN=127.0.0.1"
    copy /y certs\cert.pem cert.pem >nul
    copy /y certs\key.pem key.pem >nul
    echo Certificates generated using openssl CLI.
    goto :done
)

echo ERROR: Neither Python nor OpenSSL was found in PATH.
echo Please install Python with the 'cryptography' library or OpenSSL.
pause
exit /b 1

:done
echo.
echo Certificate setup completed successfully.
pause
