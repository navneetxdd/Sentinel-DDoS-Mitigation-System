@echo off
setlocal

title Sentinel Launch Manager
color 0A

if not defined SENTINEL_WSL_DISTRO set "SENTINEL_WSL_DISTRO=kali-linux"
if not defined SENTINEL_PROFILE set "SENTINEL_PROFILE=baseline"

call :apply_profile "%SENTINEL_PROFILE%"

for /f "delims=" %%i in ('wsl -d %SENTINEL_WSL_DISTRO% -u root -e wslpath "%~dp0."') do set "WSL_REPO=%%i"
if not defined WSL_REPO (
	echo [FAIL] Unable to resolve the repository path inside WSL.
	echo        Check that the %SENTINEL_WSL_DISTRO% distro is installed and running.
	goto :end
)

echo ========================================================
echo   Sentinel DDoS Mitigation System - One-Click Launcher
echo ========================================================
echo Repo path in WSL: %WSL_REPO%
echo Profile: %SENTINEL_INTEGRATION_PROFILE%
echo.

echo [1/5] Verifying and compiling the backend pipeline in WSL...
wsl -d %SENTINEL_WSL_DISTRO% -u root -e bash -lc "cd '%WSL_REPO%' && make pipeline"
if errorlevel 1 goto :end

echo.
echo [2/5] Launching SDN controller...
start cmd /k "title Sentinel SDN Controller && wsl -d %SENTINEL_WSL_DISTRO% -u root -e bash -lc 'cd ''%WSL_REPO%'' && python3 scripts/start_ryu.py'"

echo.
echo [3/5] Launching C backend data plane...
start cmd /k "title Sentinel C Backend && wsl -d %SENTINEL_WSL_DISTRO% -u root -e bash -lc 'cd ''%WSL_REPO%'' && SENTINEL_INTEGRATION_PROFILE=%SENTINEL_INTEGRATION_PROFILE% SENTINEL_ENABLE_INTEL_FEED=%SENTINEL_ENABLE_INTEL_FEED% SENTINEL_ENABLE_MODEL_EXTENSION=%SENTINEL_ENABLE_MODEL_EXTENSION% SENTINEL_ENABLE_CONTROLLER_EXTENSION=%SENTINEL_ENABLE_CONTROLLER_EXTENSION% SENTINEL_ENABLE_SIGNATURE_FEED=%SENTINEL_ENABLE_SIGNATURE_FEED% SENTINEL_ENABLE_DATAPLANE_EXTENSION=%SENTINEL_ENABLE_DATAPLANE_EXTENSION% sudo ./sentinel_pipeline -i lo -q 0 -w 8765 --controller http://127.0.0.1:8080'"

echo.
echo [4/5] Launching SHAP Explain API...
start cmd /k "title Sentinel Explain API && if exist .venv\Scripts\python.exe (.venv\Scripts\python.exe explain_api.py --port 5001) else (python explain_api.py --port 5001)"

echo.
echo [5/5] Launching React frontend...
start cmd /k "title Sentinel Frontend && cd frontend && if not exist node_modules npm install && npm run dev"

echo.
echo ========================================================
echo All subsystems launched.
echo ========================================================
echo Quick commands:
echo   Start SDN Controller: wsl -d %SENTINEL_WSL_DISTRO% -u root -e bash -lc "cd '%WSL_REPO%' && python3 scripts/start_ryu.py"
echo   Open WSL Shell:       wsl -d %SENTINEL_WSL_DISTRO% -u root
echo.

:end
cmd /k

:apply_profile
set "_PROFILE=%~1"
if /I "%_PROFILE%"=="full" goto :profile_full
if /I "%_PROFILE%"=="progressive" goto :profile_progressive
goto :profile_baseline

:profile_baseline
set "SENTINEL_INTEGRATION_PROFILE=baseline"
set "SENTINEL_ENABLE_INTEL_FEED=0"
set "SENTINEL_ENABLE_MODEL_EXTENSION=0"
set "SENTINEL_ENABLE_CONTROLLER_EXTENSION=0"
set "SENTINEL_ENABLE_SIGNATURE_FEED=0"
set "SENTINEL_ENABLE_DATAPLANE_EXTENSION=0"
goto :eof

:profile_progressive
set "SENTINEL_INTEGRATION_PROFILE=progressive"
set "SENTINEL_ENABLE_INTEL_FEED=1"
set "SENTINEL_ENABLE_MODEL_EXTENSION=1"
set "SENTINEL_ENABLE_CONTROLLER_EXTENSION=0"
set "SENTINEL_ENABLE_SIGNATURE_FEED=1"
set "SENTINEL_ENABLE_DATAPLANE_EXTENSION=0"
goto :eof

:profile_full
set "SENTINEL_INTEGRATION_PROFILE=full"
set "SENTINEL_ENABLE_INTEL_FEED=1"
set "SENTINEL_ENABLE_MODEL_EXTENSION=1"
set "SENTINEL_ENABLE_CONTROLLER_EXTENSION=1"
set "SENTINEL_ENABLE_SIGNATURE_FEED=1"
set "SENTINEL_ENABLE_DATAPLANE_EXTENSION=1"
goto :eof
