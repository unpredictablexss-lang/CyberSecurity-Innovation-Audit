@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy-windows.ps1" %*
set "deploy_exit=%errorlevel%"
if not "%deploy_exit%"=="0" echo Deployment exited with code %deploy_exit%. See the error above.
pause
exit /b %deploy_exit%
