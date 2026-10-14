@echo off
setlocal EnableExtensions

:: ============================================================================
:: link_ping_prometheus - Windows service uninstaller
:: Run from an ELEVATED (Administrator) command prompt.
::
:: Removes everything the installer created:
::   - stops the service and waits until fully STOPPED (no file locks; bounded)
::   - uninstalls the service and its event-log source (exit codes checked)
::   - discovers a CUSTOM log directory from the persisted ImagePath
::     BEFORE the service key disappears (sc.exe qc cannot answer afterwards)
::   - scrubs credential environment variables pre-deletion
::   - deletes %ProgramFiles%\link_ping_prometheus (binary)
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
set "WAIT_STOP_COUNT=0"
:wait_stop
timeout /t 2 /nobreak >nul
sc.exe query "%SERVICE_NAME%" 2>nul | findstr /i "STOPPED" >nul && goto :stopped
sc.exe query "%SERVICE_NAME%" 2>nul | findstr /i "1060" >nul && goto :not_installed
set /a WAIT_STOP_COUNT+=1
if %WAIT_STOP_COUNT% GEQ 60 (
    echo ERROR: service did not reach STOPPED within 120s - STOP_PENDING is stuck.
    echo Close anything holding the exe open ^(or run: taskkill /f /im link_ping_prometheus.exe^), then rerun this script.
    exit /b 1
)
goto :wait_stop

:not_installed
echo Service is not installed ^(nothing to stop^).
goto :cleanup_custom

:stopped
echo Service stopped.

:: === Uninstall service + event-log source ====================================
:: Exit codes are CHECKED: a failed uninstall (e.g. the service is
:: MARKED_FOR_DELETE while a lingering handle pins it) must NOT delete the
:: binary - a registered service pointing at a missing exe fails the next
:: install with ERROR_SERVICE_EXISTS while nothing works.
if exist "%INSTALLED_EXE%" (
    "%INSTALLED_EXE%" -svc=uninstall
    if errorlevel 1 (
        echo ERROR: service uninstall failed - the exe was NOT removed because the service registry key still points to it.
        echo Most likely the service is MARKED_FOR_DELETE: wait for the process/handles to close, then rerun this script.
        exit /b 1
    )
) else (
    echo Installed binary not found at "%INSTALLED_EXE%" - removing via sc.exe only.
    sc.exe delete "%SERVICE_NAME%"
    if errorlevel 1 (
        echo ERROR: sc.exe delete failed ^(1060 = not installed; 1072 = MARKED_FOR_DELETE - wait for handles to close, then rerun this script^).
        exit /b 1
    )
    rem kardianos removes the event-log source only via its -svc=uninstall
    rem path; a bare sc.exe delete would otherwise orphan
    rem HKLM\...\EventLog\Application\link_ping_prometheus forever.
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\%SERVICE_NAME%" /f >nul 2>&1
)

:: === Discover + remove a custom log directory, scrub credential env vars =====
:: MUST run while the service registry key still exists where a custom value
:: was persisted: sc.exe qc reads the persisted ImagePath from
:: HKLM\...\Services, and once that key is gone the query fails (1060) and the
:: discovery is dead code - a wizard-custom log directory (topology-bearing
:: logs, restrictive ACL) would be left on disk while the uninstall reports
:: complete. The value is parsed in PowerShell (never expanded into a cmd
:: command line); if anything fails, the uninstall falls back to the
:: default-path behavior below.
:cleanup_custom
set "SVC_LOG_DIR="
REM PowerShell regex note: quote characters are written as \x22 escapes - a raw
REM quote inside the cmd-quoted -Command string toggles cmd quoting and the
REM .NET regex would then see an unterminated character set. sc.exe qc wraps
REM long ImagePaths across lines, so the whole output is joined before
REM matching. The regex handles both renderings kardianos/x-sys produces for
REM the persisted ImagePath: a value with spaces is stored quoted
REM (-log-file="C:\Logs X\service.log"), one without is stored bare
REM (-log-file=C:\Logs\service.log); either way the log FILE path is captured
REM and Split-Path yields its directory.
REM The result is captured via a temp file, not for /f: nesting this command
REM inside for /f's IN(...) clause re-enters cmd quoting for the caret and the
REM single quotes, which is exactly the fragile layering the installer avoids
REM elsewhere (flat lines, no parenthesized blocks around user-derived text).
set "SVC_QC_TMP=%TEMP%\lpp_svc_qc.txt"
powershell -NoProfile -Command "$bp=((sc.exe qc '%SERVICE_NAME%' 2>$null) -join ' '); if ($bp -match '-log-file=(?:\x22([^\x22]+)\x22|(\S+))') { if ($Matches[1]) { Split-Path ($Matches[1]) -Parent } else { Split-Path ($Matches[2]) -Parent } }" > "%SVC_QC_TMP%" 2>nul
set /p SVC_LOG_DIR=<"%SVC_QC_TMP%"
del "%SVC_QC_TMP%" >nul 2>&1
if not "%SVC_LOG_DIR%"=="" if /i not "%SVC_LOG_DIR%"=="%LOG_DIR%" (
    echo === Removing custom log directory "%SVC_LOG_DIR%" ===
    icacls "%SVC_LOG_DIR%" /reset >nul 2>&1
    rmdir /s /q "%SVC_LOG_DIR%" >nul 2>&1
    if exist "%SVC_LOG_DIR%" echo WARNING: could not fully remove "%SVC_LOG_DIR%" - close anything using it and delete manually.
)

:: Credential scrub runs while the key still exists: a failed delete left it
:: on disk, and kardianos's uninstall would only remove the values with the
:: whole key. Idempotent, and harmless (no-op) when the key is already gone.
set "ENV_KEY=HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Environment"
reg delete "%ENV_KEY%" /v LINK_PING_METRICS_USER /f >nul 2>&1
reg delete "%ENV_KEY%" /v LINK_PING_METRICS_PASS /f >nul 2>&1
reg delete "%ENV_KEY%" /v LINK_PING_ECHO_SECRET /f >nul 2>&1
reg delete "%ENV_KEY%" /v LINK_PING_ECHO_SECRET_OLD /f >nul 2>&1

:: === Remove Program Files placement (binary) =================================
:remove_files
if exist "%INSTALL_DIR%" (
    echo === Removing "%INSTALL_DIR%" ===
    del /f /q "%INSTALLED_EXE%" >nul 2>&1
    rmdir /s /q "%INSTALL_DIR%" >nul 2>&1
    if exist "%INSTALL_DIR%" echo WARNING: could not fully remove "%INSTALL_DIR%" - close anything using it and delete manually.
)

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
