#!/bin/sh
# Pull the shared link_ping_prometheus targets.json from a git repo and
# install it atomically, for the mesh deployment described in
# docs/mesh-deployment.md.
#
# The config repo holds topology only (site names and addresses) - NEVER
# the HMAC secret or metrics credentials. Access is a read-only deploy key
# pinned by a known_hosts file, so a compromise of this host cannot author
# the fleet's topology.
#
# Usage:
#   pull-config.sh [REPO [BRANCH [DEST_DIR [KEY [KNOWN_HOSTS]]]]]
#
# Every argument falls back to the matching LINK_PING_CONFIG_* environment
# variable, which is what the systemd oneshot unit supplies through
# EnvironmentFile:
#   LINK_PING_CONFIG_REPO          SSH clone URL (git@github.com:org/mesh-config.git)
#   LINK_PING_CONFIG_BRANCH        branch to track (default: main)
#   LINK_PING_CONFIG_WORK          scratch checkout directory
#   LINK_PING_CONFIG_DEST          directory holding the live targets.json
#   LINK_PING_CONFIG_KEY           read-only deploy key (mode 0600)
#   LINK_PING_CONFIG_KNOWN_HOSTS   pinned known_hosts file
#   LINK_PING_CONFIG_FILE          filename inside the repo (default: targets.json)
#
# Exit status is non-zero on any failure, including a pulled file that does
# not parse: the previous targets.json is left untouched in that case, and
# the agent's own reload validation would keep the running set anyway.
#
# The running agent never reads a half-written file: the new file is
# renamed over the live path inside its own directory, which is atomic.
# Overlapping timer runs are serialised with flock.

set -eu

TAG=link_ping_pull_config

# stderr for the journal (systemd) and logger for syslog, so a pull that
# fails while no one is watching still leaves a trace. Never logs the key
# or its contents - only paths.
log() {
    printf '%s: %s\n' "$TAG" "$*" >&2
    if command -v logger >/dev/null 2>&1; then
        logger -t "$TAG" -- "$*" || true
    fi
}

die() {
    log "ERROR: $*"
    exit 1
}

repo=${1:-${LINK_PING_CONFIG_REPO:-}}
branch=${2:-${LINK_PING_CONFIG_BRANCH:-main}}
dest=${3:-${LINK_PING_CONFIG_DEST:-}}
key=${4:-${LINK_PING_CONFIG_KEY:-}}
known_hosts=${5:-${LINK_PING_CONFIG_KNOWN_HOSTS:-}}
work=${LINK_PING_CONFIG_WORK:-/var/lib/link_ping_pull_config/repo}
file=${LINK_PING_CONFIG_FILE:-targets.json}

[ -n "$repo" ] || die "no repository: pass it as the first argument or set LINK_PING_CONFIG_REPO"
[ -n "$dest" ] || die "no destination: pass it as the third argument or set LINK_PING_CONFIG_DEST"
[ -n "$key" ] || die "no deploy key: pass it as the fourth argument or set LINK_PING_CONFIG_KEY"
[ -n "$known_hosts" ] || die "no known_hosts: pass it as the fifth argument or set LINK_PING_CONFIG_KNOWN_HOSTS"

command -v git >/dev/null 2>&1 || die "git is not installed"

# Serialise runs: a slow clone must not race the next timer tick. flock is
# the only supported path - without it, skip the run rather than risk two
# writers on the same live file.
command -v flock >/dev/null 2>&1 || die "flock (util-linux) is required to serialise runs"
lock=/run/lock/link_ping_pull_config.lock
exec 9>"$lock" || die "cannot open lock file $lock"
if ! flock -n 9; then
    log "another run holds $lock; skipping this tick"
    exit 0
fi

# A key any other local user can read is refused by ssh itself; fail with a
# clearer message first. Darwin's stat -f %Lp is the fallback for a non-GNU
# userland.
[ -f "$key" ] || die "deploy key not found: $key"
key_mode=$(stat -c '%a' "$key" 2>/dev/null || stat -f '%Lp' "$key" 2>/dev/null || true)
case "$key_mode" in
    "")
        log "WARNING: cannot determine the mode of $key; ssh will refuse it if it is group/world-readable"
        ;;
    *)
        if [ "$((0$key_mode & 077))" -ne 0 ]; then
            die "$key has mode $key_mode: group/world-accessible private keys are refused (chmod 600)"
        fi
        ;;
esac

[ -f "$known_hosts" ] || die "known_hosts not found: $known_hosts"

# StrictHostKeyChecking=yes with an explicit UserKnownHostsFile: an unknown
# host key is refused instead of being learned on first use, so a rogue
# server cannot collect the key's authentication. IdentitiesOnly stops ssh
# from offering any other key the host happens to have. BatchMode keeps an
# unattended run from blocking on a prompt.
GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts -o BatchMode=yes"
export GIT_SSH_COMMAND

if [ -d "$work/.git" ]; then
    log "fetching $repo ($branch)"
    git -C "$work" fetch --depth 1 origin "$branch" || die "git fetch failed"
    git -C "$work" reset --hard "origin/$branch" || die "git reset failed"
elif [ -e "$work" ]; then
    die "$work exists but is not a git checkout; move it aside and re-run"
else
    log "cloning $repo ($branch) into $work"
    mkdir -p "$(dirname "$work")"
    git clone --depth 1 --branch "$branch" "$repo" "$work" || die "git clone failed"
fi

src=$work/$file
[ -f "$src" ] || die "$file not found in the repository (looked at $src)"

# Validate BEFORE touching the live file, so a truncated pull (or a bad
# branch) leaves the current topology running. python3 is preferred; jq is
# the fallback.
if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "$src" >/dev/null || die "$src is not valid JSON; keeping the previous $file"
elif command -v jq >/dev/null 2>&1; then
    jq empty "$src" >/dev/null 2>&1 || die "$src is not valid JSON; keeping the previous $file"
else
    die "neither python3 nor jq is available to validate $src"
fi

mkdir -p "$dest" || die "cannot create $dest"

# Install atomically: same directory, then rename. The agent (and the
# reload reader) sees either the old file or the new one, never a partial
# write. The temp name is dot-prefixed and removed on any failure.
tmp=$dest/.$file.tmp.$$
cp "$src" "$tmp" || die "cannot write $tmp"
chmod 0644 "$tmp" || { rm -f "$tmp"; die "cannot chmod $tmp"; }
if [ -f "$dest/$file" ] && cmp -s "$tmp" "$dest/$file"; then
    rm -f "$tmp"
    log "$file unchanged"
    exit 0
fi
mv -f "$tmp" "$dest/$file" || { rm -f "$tmp"; die "cannot install $dest/$file"; }
log "installed $dest/$file from $repo@$branch"

# The agent picks the new file up on its -targets-reload-interval (or on
# SIGHUP where one is available); no service restart is needed. A parse or
# validation failure inside the agent keeps the previous set running.
exit 0
