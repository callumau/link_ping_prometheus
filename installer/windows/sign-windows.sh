#!/bin/sh
# Sign Windows executables with Authenticode, or explain why nothing was signed.
#
# Called from GoReleaser's per-build post hook so the signature lands on the
# binary BEFORE it is wrapped in a zip/tar. Signing the archive afterwards is
# useless: the .exe inside stays unsigned.
#
# Configuration is entirely environment-driven, and an unconfigured run is a
# successful no-op so a plain `goreleaser build --snapshot` (or any developer
# build) keeps working. Set WINDOWS_SIGN_REQUIRED=1 in CI to make a missing
# certificate fatal instead.
#
#   WINDOWS_SIGN_CERT   PEM certificate (leaf + intermediates), or
#   WINDOWS_SIGN_KEY    PEM private key
#   -- or --
#   WINDOWS_SIGN_PFX        PKCS#12 bundle holding both
#   WINDOWS_SIGN_PFX_PASS   its password (may be empty)
#
#   WINDOWS_SIGN_TS     RFC 3161 timestamp URL
#                       (default http://timestamp.digicert.com; empty = no timestamp)
#   WINDOWS_SIGN_DESC   description shown in the UAC/SmartScreen prompt
#   WINDOWS_SIGN_URL    "expanded description" URL
#   WINDOWS_SIGN_REQUIRED  1 = fail when no certificate is configured
#
# A timestamp is not optional in practice: without one, every signature stops
# being valid the day the certificate expires, and a long-lived deployment would
# have to re-sign and re-release.
#
# PUBLIC TRUST: this script signs with whatever key it is given. A self-signed
# certificate produces a valid signature that Windows does not trust unless the
# root is deployed to the machine trust store (GPO/Intune/Ansible). A CA-issued
# or SignPath Foundation certificate produces one that SmartScreen/AppLocker
# accept out of the box. See docs/release-signing.md.
set -eu

usage() {
    echo "usage: $0 <file.exe> [more.exe...]" >&2
    echo "  signs Windows PE binaries in place with Authenticode; no-op when no" >&2
    echo "  WINDOWS_SIGN_CERT/WINDOWS_SIGN_KEY or WINDOWS_SIGN_PFX is configured" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage

desc=${WINDOWS_SIGN_DESC:-Link Ping Prometheus}
url=${WINDOWS_SIGN_URL:-https://github.com/callumau/link_ping_prometheus}
ts=${WINDOWS_SIGN_TS-http://timestamp.digicert.com}
required=${WINDOWS_SIGN_REQUIRED:-0}

pem_configured=0
pfx_configured=0
[ -n "${WINDOWS_SIGN_CERT:-}" ] && [ -n "${WINDOWS_SIGN_KEY:-}" ] && pem_configured=1
[ -n "${WINDOWS_SIGN_PFX:-}" ] && pfx_configured=1

# A half-configured PEM pair is a mistake, not a "no-op" state, so check it
# before deciding there is nothing to do.
if [ -n "${WINDOWS_SIGN_CERT:-}" ] && [ -z "${WINDOWS_SIGN_KEY:-}" ]; then
    echo "sign-windows: WINDOWS_SIGN_CERT is set without WINDOWS_SIGN_KEY" >&2
    exit 1
fi
if [ -z "${WINDOWS_SIGN_CERT:-}" ] && [ -n "${WINDOWS_SIGN_KEY:-}" ]; then
    echo "sign-windows: WINDOWS_SIGN_KEY is set without WINDOWS_SIGN_CERT" >&2
    exit 1
fi

if [ "$pem_configured" -eq 0 ] && [ "$pfx_configured" -eq 0 ]; then
    if [ "$required" = "1" ]; then
        echo "sign-windows: WINDOWS_SIGN_REQUIRED=1 but no signing certificate is configured" >&2
        echo "sign-windows: set WINDOWS_SIGN_PFX (+ WINDOWS_SIGN_PFX_PASS) or WINDOWS_SIGN_CERT/WINDOWS_SIGN_KEY" >&2
        exit 1
    fi
    echo "sign-windows: no signing certificate configured; Windows binaries are left UNSIGNED (SmartScreen will warn). See docs/release-signing.md." >&2
    exit 0
fi

if ! command -v osslsigncode >/dev/null 2>&1; then
    echo "sign-windows: osslsigncode is not installed; it is the open-source Authenticode signer used here." >&2
    echo "sign-windows: install it from https://github.com/mtrojnar/osslsigncode (Arch: osslsigncode, Debian: osslsigncode, Homebrew: osslsigncode)" >&2
    exit 1
fi

# verify_signed prints the verify output and returns 0 when a signature exists
# and its digest matches. The exit status cannot be used directly: a self-signed
# certificate (the enterprise/self-managed path) makes osslsigncode exit 1 even
# though it reports "Number of verified signatures: 1".
verify_signed() {
    out=$(osslsigncode verify -in "$1" 2>&1 || true)
    case "$out" in
    *"Number of verified signatures: 1"*) return 0 ;;
    esac
    return 1
}

sign_one() {
    file=$1
    case "$file" in
    *.exe) ;;
    *)
        # GoReleaser runs this hook for every GOOS; only Windows binaries are PE.
        return 0
        ;;
    esac
    if [ ! -f "$file" ]; then
        echo "sign-windows: no such file: $file" >&2
        exit 1
    fi
    magic=$(head -c 2 "$file" | od -An -tx1 | tr -d ' \n')
    if [ "$magic" != "4d5a" ]; then
        echo "sign-windows: $file is not a PE executable (magic $magic, want 4d5a)" >&2
        exit 1
    fi
    if verify_signed "$file"; then
        echo "sign-windows: $file is already signed; leaving it alone"
        return 0
    fi

    tmp="$file.signed"
    rm -f "$tmp"
    set -- sign -h sha256 -n "$desc" -i "$url" -in "$file" -out "$tmp"
    if [ "$pfx_configured" -eq 1 ]; then
        set -- "$@" -pkcs12 "$WINDOWS_SIGN_PFX"
        if [ -n "${WINDOWS_SIGN_PFX_PASS:-}" ]; then
            set -- "$@" -pass "$WINDOWS_SIGN_PFX_PASS"
        fi
    else
        set -- "$@" -certs "$WINDOWS_SIGN_CERT" -key "$WINDOWS_SIGN_KEY"
    fi
    if [ -n "$ts" ]; then
        set -- "$@" -ts "$ts"
    fi

    if ! osslsigncode "$@"; then
        rm -f "$tmp"
        echo "sign-windows: signing failed for $file" >&2
        exit 1
    fi
    if ! verify_signed "$tmp"; then
        rm -f "$tmp"
        echo "sign-windows: signature verification failed for $file" >&2
        exit 1
    fi
    mv "$tmp" "$file"
    echo "sign-windows: signed $file"
}

for f in "$@"; do
    sign_one "$f"
done
