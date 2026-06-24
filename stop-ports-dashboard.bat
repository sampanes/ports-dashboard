@echo off
REM ============================================================================
REM  stop-ports-dashboard.bat
REM  Teardown for the ports dashboard: kill by window title, then a port-based
REM  fallback in case the title ever changed.
REM ============================================================================
setlocal

set "TITLE=ports-dashboard"
set "PORT=18790"

echo Stopping "%TITLE%" ...
taskkill /FI "WINDOWTITLE eq %TITLE%*" /T /F >nul 2>&1

REM --- fallback: kill whatever is still LISTENING on PORT ---
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /R /C:":%PORT% .*LISTENING"') do (
  echo   killing leftover PID %%p on port %PORT%
  taskkill /PID %%p /F >nul 2>&1
)

echo Done.
endlocal
