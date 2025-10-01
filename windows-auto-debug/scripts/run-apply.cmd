@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\windows-autodebug-plain.ps1" -Apply
pause
