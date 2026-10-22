@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy-windows.ps1" -StartOnly %*
set "start_exit=%errorlevel%"
if not "%start_exit%"=="0" echo Startup exited with code %start_exit%. See the error above.
pause
exit /b %start_exit%
