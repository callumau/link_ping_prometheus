#Requires -Version 5.1
<#
.SYNOPSIS
Pull the shared link_ping_prometheus targets.json from a git repo and
install it atomically, for the mesh deployment described in
docs/mesh-deployment.md.

.DESCRIPTION
The config repo holds topology only (site names and addresses) - NEVER the
HMAC secret or metrics credentials. Access is a read-only deploy key
pinned by a known_hosts file, so a compromise of this host cannot author
the fleet's topology.

Every parameter falls back to the matching LINK_PING_CONFIG_* environment
variable, which is what the Ansible pull block sets at machine scope for
the scheduled task:
  LINK_PING_CONFIG_REPO          SSH clone URL (git@github.com:org/mesh-config.git)
  LINK_PING_CONFIG_BRANCH        branch to track (default: main)
  LINK_PING_CONFIG_WORK          scratch checkout directory
  LINK_PING_CONFIG_DEST          directory holding the live targets.json
  LINK_PING_CONFIG_KEY           read-only deploy key
  LINK_PING_CONFIG_KNOWN_HOSTS   pinned known_hosts file
  LINK_PING_CONFIG_FILE          filename inside the repo (default: targets.json)

Exit status is non-zero on any failure, including a pulled file that does
not parse: the previous targets.json is left untouched in that case, and
the agent's own reload validation would keep the running set anyway.

The running agent never reads a half-written file: the new file is moved
over the live path inside the same directory, which is an atomic rename on
one volume.

A WINDOWS SERVICE HAS NO SIGHUP. The pulled file only takes effect because
the service runs with -targets-reload-interval; without that flag the pull
succeeds and the agent keeps probing the old topology until someone
restarts it. This script cannot detect that - it is a service flag.

The task must run as an account with write access to the destination
directory. The Ansible block schedules it as SYSTEM, which owns
C:\Program Files\LinkPing.

.EXAMPLE
.\pull-config.ps1 -Repo git@github.com:org/mesh-config.git `
  -Work C:\ProgramData\link_ping_prometheus\config-repo `
  -Dest 'C:\Program Files\LinkPing' `
  -Key C:\ProgramData\link_ping_prometheus\pull_config\deploy_key `
  -KnownHosts C:\ProgramData\link_ping_prometheus\pull_config\known_hosts
#>
[CmdletBinding()]
param(
    [string]$Repo = $env:LINK_PING_CONFIG_REPO,
    [string]$Branch = $(if ($env:LINK_PING_CONFIG_BRANCH) { $env:LINK_PING_CONFIG_BRANCH } else { 'main' }),
    [string]$Work = $(if ($env:LINK_PING_CONFIG_WORK) { $env:LINK_PING_CONFIG_WORK } else { 'C:\ProgramData\link_ping_prometheus\config-repo' }),
    [string]$Dest = $env:LINK_PING_CONFIG_DEST,
    [string]$Key = $env:LINK_PING_CONFIG_KEY,
    [string]$KnownHosts = $env:LINK_PING_CONFIG_KNOWN_HOSTS,
    [string]$File = $(if ($env:LINK_PING_CONFIG_FILE) { $env:LINK_PING_CONFIG_FILE } else { 'targets.json' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tag = 'link_ping_pull_config'

function Write-PullLog {
    param([string]$Message)
    # stderr is captured by the Task Scheduler / WinRM transcript, and the
    # Windows event log gets the same line, so an unattended failure leaves
    # a trace. Never logs the key or its contents - only paths.
    Write-Host "${tag}: $Message"
    try { Write-EventLog -LogName Application -Source 'link_ping_prometheus' -EventId 4001 -EntryType Information -Message $Message -ErrorAction Stop } catch { }
}

function Fail {
    param([string]$Message)
    Write-Host "${tag}: ERROR: $Message" -ForegroundColor Red
    try { Write-EventLog -LogName Application -Source 'link_ping_prometheus' -EventId 4002 -EntryType Error -Message $Message -ErrorAction Stop } catch { }
    exit 1
}

if ([string]::IsNullOrEmpty($Repo)) { Fail 'no repository: pass -Repo or set LINK_PING_CONFIG_REPO' }
if ([string]::IsNullOrEmpty($Dest)) { Fail 'no destination: pass -Dest or set LINK_PING_CONFIG_DEST' }
if ([string]::IsNullOrEmpty($Key)) { Fail 'no deploy key: pass -Key or set LINK_PING_CONFIG_KEY' }
if ([string]::IsNullOrEmpty($KnownHosts)) { Fail 'no known_hosts: pass -KnownHosts or set LINK_PING_CONFIG_KNOWN_HOSTS' }

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail 'git is not installed or not on PATH' }

# Serialise runs: a slow clone must not race the next scheduled tick.
# Global\ so the name is machine-wide; a zero-timeout wait means an
# overlapping run skips this tick instead of queueing.
$mutex = New-Object System.Threading.Mutex($false, 'Global\LinkPingConfigPull')
try {
    if (-not $mutex.WaitOne(0)) {
        Write-PullLog 'another run holds the pull mutex; skipping this tick'
        exit 0
    }
} catch {
    Fail "cannot acquire the pull mutex: $($_.Exception.Message)"
}

try {
    if (-not (Test-Path -LiteralPath $Key -PathType Leaf)) { Fail "deploy key not found: $Key" }

    # Well-known SIDs, not localized account names: IdentityReference.Value
    # returns the display name ("VORDEFINIERT\Benutzer" on a German host), so
    # a name list silently matches nothing there. SIDs are language-neutral,
    # the same reason the plays' icacls calls use *S-1-5-...
    $broadSids = @(
        'S-1-1-0',      # Everyone
        'S-1-5-32-545', # BUILTIN\Users
        'S-1-5-11',     # Authenticated Users
        'S-1-5-32-546', # Guests
        'S-1-5-7'       # ANONYMOUS LOGON
    )
    $wide = @((Get-Acl -LiteralPath $Key).Access | Where-Object {
            if ($_.AccessControlType -ne 'Allow') { return $false }
            try {
                $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                return $false
            }
            return $broadSids -contains $sid
        })
    if ($wide.Count -gt 0) {
        Fail "$Key is readable by a broad local principal: the deploy key must be restricted (icacls /inheritance:r /grant SYSTEM:F Administrators:F)"
    }

    if (-not (Test-Path -LiteralPath $KnownHosts -PathType Leaf)) { Fail "known_hosts not found: $KnownHosts" }

    # StrictHostKeyChecking=yes with an explicit UserKnownHostsFile: an
    # unknown host key is refused instead of being learned on first use, so
    # a rogue server cannot collect the key's authentication.
    # IdentitiesOnly stops ssh from offering any other key the host
    # happens to have. BatchMode keeps an unattended run from blocking on a
    # prompt. Passed per-invocation (-c) so nothing depends on the host's
    # global git config.
    $sshCommand = 'ssh -i "{0}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="{1}" -o BatchMode=yes' -f $Key, $KnownHosts

    # Repository-local configuration is executable content: core.fsmonitor is
    # spawned as a command on fetch/reset and core.hooksPath selects hooks
    # that run in the same commands (measured on git 2.56: both fire even on
    # a no-op or failed fetch). This task runs as SYSTEM, so a writable
    # .git/config would be a SYSTEM code-execution primitive. The DIRECTORY
    # OWNERSHIP enforced by the play is the primary control; these -c
    # overrides are defence in depth for checkouts that predate it.
    $noHooks = Join-Path ([System.IO.Path]::GetTempPath()) 'link_ping_no_hooks'
    $gitHardening = @('-c', 'core.fsmonitor=false', '-c', "core.hooksPath=$noHooks")

    if (Test-Path -LiteralPath (Join-Path $Work '.git')) {
        # Refuse a checkout this task does not own: with a foreign owner the
        # whole .git (config, hooks) is writable by that account. Git's
        # safe.directory refusal would also abort the fetch, but failing here
        # says why instead of surfacing "dubious ownership".
        $allowedOwners = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM, Administrators
        foreach ($p in @($Work, (Join-Path $Work '.git'))) {
            $ownerSid = $null
            try {
                $ownerSid = (New-Object System.Security.Principal.NTAccount(
                        (Get-Acl -LiteralPath $p).Owner)).Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                Fail "cannot resolve the owner of $p; refusing an unverified checkout"
            }
            if ($allowedOwners -notcontains $ownerSid) {
                Fail "$p is owned by $ownerSid, not SYSTEM or Administrators: a non-administrative owner can rewrite .git/config and .git/hooks (which run as SYSTEM). Delete the checkout and re-run."
            }
        }

        # The checkout must still point at the configured repository; a
        # swapped remote would install a different topology.
        $recorded = (& git -C $Work config --get remote.origin.url) | Out-String
        $recorded = $recorded.Trim()
        if ($LASTEXITCODE -ne 0 -or $recorded -ne $Repo) {
            Fail "$Work fetches $recorded, not $Repo; move it aside and re-run"
        }

        Write-PullLog "fetching $Repo ($Branch)"
        & git @gitHardening -c "core.sshCommand=$sshCommand" -C $Work fetch --depth 1 origin $Branch
        if ($LASTEXITCODE -ne 0) { Fail "git fetch failed (exit $LASTEXITCODE)" }
        & git @gitHardening -C $Work reset --hard "origin/$Branch"
        if ($LASTEXITCODE -ne 0) { Fail "git reset failed (exit $LASTEXITCODE)" }
    } elseif (Test-Path -LiteralPath $Work) {
        Fail "$Work exists but is not a git checkout; move it aside and re-run"
    } else {
        Write-PullLog "cloning $Repo ($Branch) into $Work"
        $parent = Split-Path -Parent $Work
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        & git @gitHardening -c "core.sshCommand=$sshCommand" clone --depth 1 --branch $Branch $Repo $Work
        if ($LASTEXITCODE -ne 0) { Fail "git clone failed (exit $LASTEXITCODE)" }
    }

    $src = Join-Path $Work $File
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Fail "$File not found in the repository (looked at $src)" }

    # Validate BEFORE touching the live file, so a truncated pull (or a bad
    # branch) leaves the current topology running.
    try {
        $parsed = Get-Content -LiteralPath $src -Raw | ConvertFrom-Json
    } catch {
        Fail "$src is not valid JSON; keeping the previous $File"
    }
    # The agent expects a JSON array of target objects. An empty array is
    # accepted by the binary (it warns that all probing stopped), but a
    # non-array document would be rejected on reload - catch it here.
    if ($null -ne $parsed -and $parsed -isnot [System.Array]) {
        Fail "$src is not a JSON array of targets; keeping the previous $File"
    }

    if (-not (Test-Path -LiteralPath $Dest)) {
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    }

    # Install atomically: same directory, then Move-Item -Force, which is a
    # rename on one volume. The agent (and the reload reader) sees either
    # the old file or the new one, never a partial write.
    $tmp = Join-Path $Dest ('.' + $File + '.tmp.' + $PID)
    $live = Join-Path $Dest $File
    Copy-Item -LiteralPath $src -Destination $tmp -Force
    if ((Test-Path -LiteralPath $live) -and -not (Compare-Object (Get-Content -LiteralPath $live -Raw) (Get-Content -LiteralPath $tmp -Raw))) {
        Remove-Item -LiteralPath $tmp -Force
        Write-PullLog "$File unchanged"
        exit 0
    }
    Move-Item -LiteralPath $tmp -Destination $live -Force
    Write-PullLog "installed $live from $Repo@$Branch"

    # The agent picks the new file up on its -targets-reload-interval (a
    # Windows service has no SIGHUP). A parse or validation failure inside
    # the agent keeps the previous set running.
    exit 0
} finally {
    if ($mutex) {
        try { $mutex.ReleaseMutex() } catch { }
        $mutex.Dispose()
    }
}
