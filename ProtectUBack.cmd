@echo off
setlocal
cd /d "%~dp0"
set "LAUNCHER=%~dp0project\protect_launcher.py"
if not exist "%LAUNCHER%" set "LAUNCHER=%~dp0protect_launcher.py"
rem No args -> the menu (option 11 runs an agent in the PUB-OS prison).
rem With args -> pass straight through, e.g.  ProtectUBack.cmd run python3 -c "print(1)"
if "%~1"=="" (
  python "%LAUNCHER%" menu
) else (
  python "%LAUNCHER%" %*
)
pause
