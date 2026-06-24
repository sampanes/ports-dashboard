@echo off
REM ============================================================================
REM  start-ports-dashboard.bat
REM  Launches the ports dashboard in a TITLED console (window title:
REM  "ports-dashboard") so it's findable/killable. It always starts a local
REM  browser URL on this PC, and also binds the current Tailscale IP when
REM  Tailscale is online.
REM
REM  Idempotent: kills any prior instance of itself before starting.
REM  Must run in your interactive desktop session for window-title names to
REM  resolve -- just double-click it or run from cmd. Do NOT run as a service.
REM ============================================================================
setlocal

set "TITLE=ports-dashboard"
set "PORT=18790"
set "HOST_ARGS=--host 127.0.0.1"

REM --- optional: grab the tailnet IPv4 for the phone URL ---
set "TSIP="
set "TSERR=%TEMP%\ports-dashboard-tailscale-status.txt"
python "%~dp0local_dev_tools\tailscale_self_ip.py" > "%TSERR%.out" 2> "%TSERR%"
if not errorlevel 1 for /f "usebackq delims=" %%i in ("%TSERR%.out") do if not defined TSIP set "TSIP=%%i"
del "%TSERR%" >nul 2>&1
del "%TSERR%.out" >nul 2>&1
if defined TSIP set "HOST_ARGS=%HOST_ARGS% --host %TSIP%"

REM --- idempotent: kill any prior instance of myself (by window title) ---
taskkill /FI "WINDOWTITLE eq %TITLE%*" /T /F >nul 2>&1

echo Starting "%TITLE%" on port %PORT%.
start "%TITLE%" cmd /k python "%~dp0ports_dashboard.py" %HOST_ARGS% --port %PORT%

timeout /t 1 /nobreak >nul
start "" "http://127.0.0.1:%PORT%/"

echo.
echo   This PC:               http://127.0.0.1:%PORT%/
if defined TSIP (
  echo   Phone ^(Tailscale up^):  http://%TSIP%:%PORT%/
) else (
  echo   Phone ^(Tailscale^):     unavailable right now; dashboard still started locally.
)
echo   Stop:                  stop-ports-dashboard.bat
echo   Is it running?:        status-ports-dashboard.bat
endlocal
