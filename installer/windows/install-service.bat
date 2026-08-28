@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: ============================================================================
:: link_ping_prometheus - Windows service installer wizard (enterprise)
::
:: Run from an ELEVATED (Administrator) command prompt.
::
:: Interactive wizard: asks for deployment settings, validates them BEFORE
:: installing, then installs a hardened service:
::   - SCM recovery: restart on failure after 5s; escalating ladder 5s/30s/60s
::   - Delayed auto-start; dependencies on Tcpip + W32Time
::   - Binary placed in %ProgramFiles%\link_ping_prometheus (Admins-only write)
::   - ACL-hardened log dir; per-service SID granted write access to it only
::   - Credentials NEVER persisted into the service config (env vars instead)
::   - Lifecycle/fatal events go to the Windows Event Log
::
:: Re-running on an existing installation performs an in-place UPGRADE:
:: identical binary is a no-op; differing binary is stop/swap/start with all
:: parameters preserved. To change parameters, uninstall first, then install.
:: ============================================================================

:: ----------------------- DEFAULTS (wizard will ask) -------------------------
set "SERVICE_NAME=link_ping_prometheus"
:: Source binary. Defaults to next to this script; the service itself runs
:: from %INSTALL_DIR% below (Program Files - Admins-only write ACL).
set "EXE_PATH=%~dp0link_ping_prometheus.exe"
set "INSTALL_DIR=%ProgramFiles%\link_ping_prometheus"
set "DEF_METRICS=127.0.0.1:2112"
set "DEF_LOG_DIR=C:\ProgramData\link_ping_prometheus\logs"
:: -----------------------------------------------------------------------------

:: --- 1. Admin check ----------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script must run from an elevated Administrator prompt.
    exit /b 1
)

if not exist "%EXE_PATH%" (
    echo ERROR: Binary not found: "%EXE_PATH%"
    echo Place this script next to link_ping_prometheus.exe or edit EXE_PATH.
    exit /b 1
)
for %%I in ("%EXE_PATH%") do set "EXE_PATH=%%~fI"

set "INSTALLED_EXE=%INSTALL_DIR%\link_ping_prometheus.exe"

:: --- Upgrade-in-place when the service already exists ------------------------
:: Only the binary is replaced; snapshotted parameters are never touched.
sc.exe query "%SERVICE_NAME%" >nul 2>&1
if errorlevel 1 goto :wizard

for /f "skip=1 delims=" %%H in ('certutil -hashfile "%INSTALLED_EXE%" SHA256 ^| findstr /v /i "certutil"') do (
    set "OLD_HASH=%%H"
    goto :got_installed_hash
)
:got_installed_hash
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%EXE_PATH%" SHA256 ^| findstr /v /i "certutil"') do (
    set "NEW_HASH=%%H"
    goto :got_source_hash
)
:got_source_hash

if /i "%OLD_HASH%"=="%NEW_HASH%" (
    echo Service already installed and binary is identical to "%EXE_PATH%". Nothing to do.
    echo To change deployment parameters run uninstall-service.bat first, then re-run this wizard.
    exit /b 0
)

echo === Updating %SERVICE_NAME% ===
echo     installed: ...%OLD_HASH:~-24%
echo     new:       ...%NEW_HASH:~-24%
echo Parameters remain unchanged; swapping binary only.

sc.exe stop "%SERVICE_NAME%" >nul 2>&1
echo Waiting for service to stop...
:wait_stop
timeout /t 2 /nobreak >nul
sc.exe query "%SERVICE_NAME%" | findstr /i "STOPPED" >nul || goto :wait_stop

copy /y "%EXE_PATH%" "%INSTALLED_EXE%" >nul || (
    echo ERROR: failed to replace "%INSTALLED_EXE%" - service is STOPPED. Restore manually:
    echo        copy /y "%EXE_PATH%" "%INSTALLED_EXE%"
    exit /b 1
)

echo === Starting updated service ===
sc.exe start "%SERVICE_NAME%"
sc.exe query "%SERVICE_NAME%" | findstr /i "STATE"
echo.
echo Done. Verify version via metrics: link_ping_build_info{version=...}
exit /b 0

:: ============================================================================
:: Wizard: collect and validate settings BEFORE touching anything, so an
:: invalid combination can never produce a broken install ^(the binary fail-
:: fast-exits on bad config, which SCM reports only as "error 1067"^).
:: ============================================================================
:wizard
echo.
echo === link_ping_prometheus service installation wizard ===
echo.

:wiz_mode
set "RUN_MODE="
set /p "RUN_MODE=Mode - server, client, or both [both]: "
if "%RUN_MODE%"=="" set "RUN_MODE=both"
if /i "%RUN_MODE%"=="server" goto :mode_ok
if /i "%RUN_MODE%"=="client" goto :mode_ok
if /i "%RUN_MODE%"=="both"   goto :mode_ok
echo   Invalid mode "%RUN_MODE%" - enter server, client, or both.
goto :wiz_mode
:mode_ok

:wiz_metrics
set "METRICS_ADDR="
set /p "METRICS_ADDR=Metrics listen address [%DEF_METRICS%]: "
if "%METRICS_ADDR%"=="" set "METRICS_ADDR=%DEF_METRICS%"
echo   NOTE: localhost binds are scrape-able only from this machine; use ":2112" to expose remotely (firewall-restrict it).

REM Client half needs something to probe.
if /i "%RUN_MODE%"=="server" goto :wiz_allow_ask

:wiz_targets
set "TARGETS_FILE="
set "SINGLE_TARGET="
echo What should the client half probe?
echo   [1] A targets JSON file (multiple targets, name+address pairs)
echo   [2] A single host:port endpoint
set /p "TGT_CHOICE=Choice [1]: "
if "%TGT_CHOICE%"=="" set "TGT_CHOICE=1"
if /i "%TGT_CHOICE%"=="2" goto :wiz_single

:wiz_targets_file
set /p "TARGETS_FILE=Path to targets JSON file: "
if "%TARGETS_FILE%"=="" (
    echo   REQUIRED: without a targets file nothing would be probed.
    goto :wiz_targets_file
)
if not exist "%TARGETS_FILE%" (
    echo   File not found: "%TARGETS_FILE%"
    goto :wiz_targets_file
)
goto :wiz_allow_ask

:wiz_single
set /p "SINGLE_TARGET=Single target address (host:port, e.g. 192.168.1.60:4000): "
if "%SINGLE_TARGET%"=="" (
    echo   REQUIRED: without a target nothing would be probed.
    goto :wiz_single
)
echo %SINGLE_TARGET% | findstr /r /c:":" >nul || (
    echo   Missing port - use host:port form, e.g. 192.168.1.60:4000.
    goto :wiz_single
)

:wiz_allow_ask
REM Server half fail-closes without an allowlist - this is not optional.
if /i "%RUN_MODE%"=="client" goto :wiz_logdir

:wiz_allow
set "ALLOW_LIST="
echo Client IP allowlist - IPs of probers allowed to send probes TO this node.
echo Fail-closed: the echo server REFUSES to start without at least one IP.
set /p "ALLOW_LIST=Comma-separated IPs (REQUIRED): "
if "%ALLOW_LIST%"=="" (
    echo   REQUIRED: cannot be empty - see error above.
    goto :wiz_allow
)

:wiz_logdir
set "LOG_DIR="
set /p "LOG_DIR=Log directory [%DEF_LOG_DIR%]: "
if "%LOG_DIR%"=="" set "LOG_DIR=%DEF_LOG_DIR%"

:wiz_account
set "SERVICE_ACCOUNT="
echo Optional least-privilege service account (Enter = LocalSystem default^).
set /p "SERVICE_ACCOUNT=e.g. NT AUTHORITY\LocalService or DOMAIN\svc-linkping$ [skip]: "

echo.
echo === Summary ================================================================
echo   Mode           : %RUN_MODE%
if not "%TARGETS_FILE%"=="" echo   Targets file   : %TARGETS_FILE%
if not "%SINGLE_TARGET%"=="" echo   Single target  : %SINGLE_TARGET%
if not "%ALLOW_LIST%"==""   echo   Allow list     : %ALLOW_LIST%
echo   Metrics address: %METRICS_ADDR%
echo   Log directory  : %LOG_DIR%
if "%SERVICE_ACCOUNT%"=="" (echo   Service account: LocalSystem ^(default^)) else (echo   Service account: %SERVICE_ACCOUNT%)
echo   Binary         : %INSTALLED_EXE%
echo ============================================================================
:wiz_confirm
set "CONFIRM="
set /p "CONFIRM=Install with these settings? [y/N]: "
if /i "%CONFIRM%"=="y" goto :confirmed
echo Cancelled - nothing was installed.
exit /b 1
:confirmed

:: --- Place binary (Program Files: Admins-only-write location; weak binary-
:: path ACLs are the classic Windows persistence attack, MITRE T1574.011). ---
echo === Placing binary in "%INSTALL_DIR%" ===
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" || (
    echo ERROR: could not create "%INSTALL_DIR%"
    exit /b 1
)
copy /y "%EXE_PATH%" "%INSTALLED_EXE%" >nul || (
    echo ERROR: could not copy binary to "%INSTALL_DIR%"
    exit /b 1
)
set "EXE_PATH=%INSTALLED_EXE%"

echo === Installing %SERVICE_NAME% from "%EXE_PATH%" ===

:: Log directory with restrictive ACLs -----------------------------------------
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
icacls "%LOG_DIR%" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" >nul || (
    echo ERROR: failed to ACL "%LOG_DIR%"
    exit /b 1
)

:: Install (arguments are snapshotted at install time) --------------------------
set "INSTALL_ARGS=-mode=%RUN_MODE% -metrics=%METRICS_ADDR%"
if not "%TARGETS_FILE%"==""  set "INSTALL_ARGS=%INSTALL_ARGS% -targets=%TARGETS_FILE%"
if not "%SINGLE_TARGET%"=="" set "INSTALL_ARGS=%INSTALL_ARGS% -target=%SINGLE_TARGET%"
if not "%ALLOW_LIST%"==""    set "INSTALL_ARGS=%INSTALL_ARGS% -allow=%ALLOW_LIST%"
set "INSTALL_ARGS=%INSTALL_ARGS% -log-file=%LOG_DIR%\service.log"

"%EXE_PATH%" %INSTALL_ARGS% -svc=install
if errorlevel 1 (
    echo ERROR: service installation failed.
    exit /b 1
)

:: Post-install hardening -------------------------------------------------------
:: Escalating restart ladder: SCM retries at 5s, 30s, then 60s; the failure
:: counter resets daily. (The binary already sets a uniform 5s retry; this
:: adds backoff so a persistent failure does not hot-loop.)
sc.exe failure "%SERVICE_NAME%" reset= 86400 actions= restart/5000/restart/30000/restart/60000 >nul || echo WARNING: could not set failure actions ^(SCM recovery from install remains active^).

:: Per-service SID lets us ACL resources to NT SERVICE\%SERVICE_NAME% itself
:: instead of broad groups - least privilege for file access.
sc.exe sidtype "%SERVICE_NAME%" unrestricted >nul || echo WARNING: could not set service SID type.

icacls "%LOG_DIR%" /grant "NT SERVICE\%SERVICE_NAME%:(OI)(CI)M" >nul || echo WARNING: could not grant log-dir write access to the service SID.

:: Optional dedicated account (LocalSystem is the default otherwise).
if not "%SERVICE_ACCOUNT%"=="" (
    sc.exe config "%SERVICE_NAME%" obj= "%SERVICE_ACCOUNT%" || (
        echo ERROR: failed to set service account "%SERVICE_ACCOUNT%"
        exit /b 1
    )
)

:: Credential environment variables (optional) ----------------------------------
:: The service reads LINK_PING_METRICS_USER/PASS and LINK_PING_ECHO_SECRET
:: from its process environment. The per-service Environment registry key is
:: the delivery mechanism. NOTE: that key is readable by all local users -
:: treat these values as non-secret-grade or restrict interactive logon on
:: this host. Press Enter to skip any value you do not need.
echo.
echo === Optional credential environment variables (Enter to skip) ===
set "ENV_KEY=HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Environment"

set /p "MUser=Metrics basic-auth user: "
if not "%MUser%"=="" reg add "%ENV_KEY%" /v LINK_PING_METRICS_USER /t REG_SZ /d "%MUser%" /f >nul

set /p "MPass=Metrics basic-auth password: "
if not "%MPass%"=="" reg add "%ENV_KEY%" /v LINK_PING_METRICS_PASS /t REG_SZ /d "%MPass%" /f >nul

set /p "ESecret=Echo HMAC secret: "
if not "%ESecret%"=="" reg add "%ENV_KEY%" /v LINK_PING_ECHO_SECRET /t REG_SZ /d "%ESecret%" /f >nul

:: Start and verify -------------------------------------------------------------
echo.
echo === Starting service ===
sc.exe start "%SERVICE_NAME%"
timeout /t 3 /nobreak >nul
sc.exe query "%SERVICE_NAME%" | findstr /i "STATE"

echo.
echo Done. Event Log source "%SERVICE_NAME%" (Application) carries lifecycle/fatal events.
echo Logs: %LOG_DIR%\service.log
endlocal
