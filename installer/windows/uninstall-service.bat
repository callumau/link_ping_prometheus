@echo off
setlocal EnableExtensions

:: ============================================================================
:: link_ping_prometheus - Windows service uninstaller
:: Run from an ELEVATED (Administrator) command prompt.
::
:: Removes everything the installer created:
::   - stops the service and waits until fully STOPPED (no file locks)
::   - uninstalls the service and its event-log source
::   - deletes %ProgramFiles%\link_ping_prometheus (binary)
::   - scrubs credential environment variables from the service registry key
::   - optionally deletes C:\ProgramData\link_ping_prometheus (logs)
:: ============================================================================

set "SERVICE_NAME=link_ping_prometheus"
set "INSTALL_DIR=%ProgramFiles%\link_ping_prometheus"
set "INSTALLED_EXE=%INSTALL_DIR%\link_ping_prometheus.exe"
set "LOG_DIR=C:\ProgramData\link_ping_prometheus\logs"
set "DATA_DIR=C:\ProgramData\link_ping_prometheus"

net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script must run from an elevated Administrator prompt.
    exit /b 1
)

echo === Stopping %SERVICE_NAME% ===
sc.exe stop "%SERVICE_NAME%" >nul 2>&1
echo Waiting for service to stop...
:wait_stop
timeout /t 2 /nobreak >nul
sc.exe query "%SERVICE_NAME%" 2>nul | findstr /i "STOPPED" >nul && goto :stopped
sc.exe query "%SERVICE_NAME%" 2>nul | findstr /i "1060" >nul && goto :not_installed
goto :wait_stop
:not_installed
echo Service is not installed ^(nothing to stop^).
goto :remove_files
:stopped
echo Service stopped.

:: === Uninstall service + event-log source ====================================
if exist "%INSTALLED_EXE%" (
    "%INSTALLED_EXE%" -svc=uninstall
) else (
    echo Installed binary not found at "%INSTALLED_EXE%" - removing via sc.exe only.
    sc.exe delete "%SERVICE_NAME%"
)

:: === Remove Program Files placement (binary) =================================
:remove_files
if exist "%INSTALL_DIR%" (
    echo === Removing "%INSTALL_DIR%" ===
    del /f /q "%INSTALLED_EXE%" >nul 2>&1
    rmdir /s /q "%INSTALL_DIR%" >nul 2>&1
    if exist "%INSTALL_DIR%" echo WARNING: could not fully remove "%INSTALL_DIR%" - close anything using it and delete manually.
)

:: === Scrub credential environment variables ==================================
set "ENV_KEY=HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Environment"
reg delete "%ENV_KEY%" /v LINK_PING_METRICS_USER /f >nul 2>&1
reg delete "%ENV_KEY%" /v LINK_PING_METRICS_PASS /f >nul 2>&1
reg delete "%ENV_KEY%" /v LINK_PING_ECHO_SECRET /f >nul 2>&1

:: === Optional: remove ProgramData logs =======================================
echo.
set /p "DEL_LOGS=Delete log directory %DATA_DIR%? [y/N]: "
if /i not "%DEL_LOGS%"=="y" goto :done

echo === Removing "%DATA_DIR%" ===
if exist "%LOG_DIR%" (
    :: Reset the restrictive ACL so removal cannot be blocked by it.
    icacls "%LOG_DIR%" /reset >nul 2>&1
    rmdir /s /q "%LOG_DIR%" >nul 2>&1
)
rmdir "%DATA_DIR%" >nul 2>&1
if exist "%DATA_DIR%" (
    echo WARNING: could not fully remove "%DATA_DIR%". Delete manually:
    echo        rmdir /s /q "%DATA_DIR%"
) else (
    echo Logs deleted.
)

:done
echo.
echo Uninstall complete.
endlocal
