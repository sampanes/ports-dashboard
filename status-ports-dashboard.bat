@echo off
REM ============================================================================
REM  status-ports-dashboard.bat  --  quick "is it running?" check
REM ============================================================================
setlocal

set "TITLE=ports-dashboard"
set "PORT=18790"

echo === window-title check ("%TITLE%") ===
tasklist /v /FI "WINDOWTITLE eq %TITLE%*" 2>nul | findstr /I "python" || echo   not running (by title)

echo.
echo === port %PORT% listener check ===
netstat -ano | findstr /R /C:":%PORT% .*LISTENING" || echo   nothing listening on %PORT%

echo.
echo === dashboard URLs ===
echo   This PC:               http://127.0.0.1:%PORT%/
for /f "delims=" %%i in ('python "%~dp0local_dev_tools\tailscale_self_ip.py" 2^>nul') do if not defined TSIP set "TSIP=%%i"
if defined TSIP (
  echo   Phone ^(Tailscale up^):  http://%TSIP%:%PORT%/
) else (
  echo   Phone ^(Tailscale^):     unavailable right now
)
endlocal
