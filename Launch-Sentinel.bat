@echo off
REM Sentinel DDoS Mitigation System - Launcher Bootstrap
REM
REM This batch file delegates to the PowerShell launcher for better
REM subprocess spawning and environment variable handling.

setlocal EnableExtensions

set ACTION=%1
set PROFILE=%2
set DASH=%3

if /I "%ACTION%"=="" set ACTION=start
if /I "%ACTION%"=="baseline" (
	set ACTION=start
	set PROFILE=baseline
)
if /I "%ACTION%"=="progressive" (
	set ACTION=start
	set PROFILE=progressive
)
if /I "%ACTION%"=="full" (
	set ACTION=start
	set PROFILE=full
)
if /I "%ACTION%"=="production" (
	set ACTION=start
	set PROFILE=production
)
if "%PROFILE%"=="" set PROFILE=production

set DASH_ARG=
if /I "%DASH%"=="open" set DASH_ARG=-OpenDashboard
if /I "%DASH%"=="opendashboard" set DASH_ARG=-OpenDashboard

echo.
echo ========================================================
echo   Sentinel DDoS Mitigation System Launcher
echo ========================================================
echo.
echo Delegating to PowerShell launcher...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-Sentinel.ps1" -Action "%ACTION%" -LaunchMode "%PROFILE%" -RepoRoot "%~dp0." -WSLDistro "kali-linux" %DASH_ARG%

exit /b %errorlevel%
