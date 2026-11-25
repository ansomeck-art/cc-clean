@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

set "DIR=%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8765"

set "PY_CMD="

:: 1. Prefer Windows Python Launcher (skips broken Microsoft Store python.exe stub)
py -3 -c "import sys; assert sys.version_info >= (3, 9)" >nul 2>&1
if !errorlevel! equ 0 (
    set "PY_CMD=py -3"
    goto :found
)

:: 2. Try python / python3 on PATH
python -c "import sys; assert sys.version_info >= (3, 9)" >nul 2>&1
if !errorlevel! equ 0 (
    set "PY_CMD=python"
    goto :found
)

python3 -c "import sys; assert sys.version_info >= (3, 9)" >nul 2>&1
if !errorlevel! equ 0 (
    set "PY_CMD=python3"
    goto :found
)

:: 3. Probe common Windows installation paths
for %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "C:\Program Files\Python3*" "C:\Python3*") do (
    for /d %%P in (%%D) do (
        if exist "%%P\python.exe" (
            "%%P\python.exe" -c "import sys; assert sys.version_info >= (3, 9)" >nul 2>&1
            if !errorlevel! equ 0 (
                set "PY_CMD="%%P\python.exe""
                goto :found
            )
        )
    )
)

echo [ERROR] Python 3.9+ not found. Please install Python 3 from https://www.python.org/downloads/
echo         (Tip: check "Add python.exe to PATH" during installation.)
pause
exit /b 1

:found
echo Starting Region Guard on http://127.0.0.1:%PORT% ...
echo Press Ctrl+C in this window to stop the server.
echo.
%PY_CMD% "%DIR%server.py" --host 127.0.0.1 --port %PORT% --open
if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Region Guard exited with code !errorlevel!.
    pause
)
endlocal
