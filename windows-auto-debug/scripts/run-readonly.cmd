@echo off
set REPORT=%~dp0..\examples\win-health.txt
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\windows-autodebug-plain.ps1" -Report "%REPORT%"
echo Report written to: %REPORT%
pause
