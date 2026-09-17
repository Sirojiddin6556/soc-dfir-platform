@echo off
setlocal
cd /d "%~dp0\.."

if exist "target\release\desktop-app.exe" (
    echo Starting SOC/DFIR Platform Desktop (Release)...
    start "" "%CD%\target\release\desktop-app.exe"
) else if exist "target\debug\desktop-app.exe" (
    echo Starting SOC/DFIR Platform Desktop (Debug)...
    start "" "%CD%\target\debug\desktop-app.exe"
) else (
    echo Building desktop-app.exe...
    cargo build --release -p desktop-app
    start "" "%CD%\target\release\desktop-app.exe"
)

