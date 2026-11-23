@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   Starting SSL/TLS-Enabled Secure Web Application
echo ============================================================

if not exist "certs\cert.pem" (
    if not exist "cert.pem" (
        echo Certificates missing. Generating certificates...
        call gen_cert.bat
    )
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py app.py
    goto :exit
)

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python app.py
    goto :exit
)

if exist "C:\Users\Asus Zenbook\AppData\Local\Python\pythoncore-3.14-64\python.exe" (
    "C:\Users\Asus Zenbook\AppData\Local\Python\pythoncore-3.14-64\python.exe" app.py
    goto :exit
)

echo ERROR: Python was not found in PATH or standard installation directory.
pause
exit /b 1

:exit
pause
