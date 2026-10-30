@echo off
REM FreeMove — Windows build script.
REM Produces a single self-contained dist\FreeMove.exe (no Python
REM needed on the target PC). Run from the repo root:
REM     build_windows.bat
setlocal

python -m pip install --upgrade pip
python -m pip install pyinstaller cryptography pytest
if errorlevel 1 goto :fail

echo Running tests...
python -m pytest tests\ -q
if errorlevel 1 goto :fail

echo Building FreeMove.exe...
pyinstaller --noconfirm freemove.spec
if errorlevel 1 goto :fail

echo.
echo Done: dist\FreeMove.exe
goto :eof

:fail
echo.
echo BUILD FAILED — see the output above.
exit /b 1
