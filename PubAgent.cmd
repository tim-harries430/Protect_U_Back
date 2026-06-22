@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
set "LAUNCHER=%SCRIPT_DIR%project\pub_agent_launcher.py"
if not exist "%LAUNCHER%" set "LAUNCHER=%SCRIPT_DIR%pub_agent_launcher.py"

if not exist "%LAUNCHER%" (
    echo PUB_AGENT: launcher not found:
    echo   %LAUNCHER%
    echo.
    pause
    exit /b 1
)

set "PY_CMD=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo PUB_AGENT: Python was not found. Install Python or add it to PATH.
        echo.
        pause
        exit /b 1
    )
    set "PY_CMD=py -3"
)

if "%~1"=="" goto :interactive

%PY_CMD% "%LAUNCHER%" %*
exit /b %ERRORLEVEL%

:interactive
echo PUB Agent Launcher
echo.
echo No profile was provided. Choose the supervised agent path:
echo   [1] cd  - Codex CLI through PUB runner
echo   [2] cc  - Claude Code through PUB runner
echo   [H] help
echo   [Q] quit
echo.
set /p "CHOICE=Select: "
if /I "%CHOICE%"=="1" goto :run_cd
if /I "%CHOICE%"=="cd" goto :run_cd
if /I "%CHOICE%"=="2" goto :run_cc
if /I "%CHOICE%"=="cc" goto :run_cc
if /I "%CHOICE%"=="H" goto :help
if /I "%CHOICE%"=="HELP" goto :help
exit /b 0

:run_cd
%PY_CMD% "%LAUNCHER%" cd --project-root "%CD%"
goto :finish

:run_cc
%PY_CMD% "%LAUNCHER%" cc --project-root "%CD%"
goto :finish

:help
%PY_CMD% "%LAUNCHER%" --help

:finish
set "STATUS=%ERRORLEVEL%"
echo.
echo PUB_AGENT: exited with code %STATUS%
pause
exit /b %STATUS%
