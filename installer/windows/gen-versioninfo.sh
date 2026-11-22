#!/bin/sh
# Generate the Windows VERSIONINFO resources for the release binaries.
#
# Go does not emit a PE version resource, and SignPath Foundation requires the
# signed binaries to carry product name/version metadata (their artifact
# configuration *enforces* it, so a binary without these attributes cannot be
# signed at all). The resource also gives Windows Explorer, the UAC prompt and
# Add/Remove Programs the right product name and version.
#
# goversioninfo is a pinned tool dependency (`go tool` reads go.mod, so the
# version and checksum come from this module, not from a floating install).
# `-platform-specific` writes resource_windows_{386,amd64,arm,arm64}.syso next
# to this module's package, where the Go toolchain picks them up automatically
# for the matching GOOS/GOARCH.
#
# usage: gen-versioninfo.sh <version>
#   <version> is the release version without a leading "v" (e.g. 0.9.0). The
#   same value is what -X main.version receives, so link_ping_build_info and the
#   PE resource agree.
set -eu

version=${1:-}
if [ -z "$version" ]; then
    echo "usage: $0 <version>" >&2
    exit 2
fi

# The PE version fields are numeric; a snapshot version like "0.9.0-next" keeps
# its string form in StringFileInfo and propagates the numeric prefix. Strip a
# leading v for operators who pass a tag.
version=${version#v}

# Remove stale resources first: a renamed or removed arch would otherwise keep
# a syso the toolchain would still link into that target.
rm -f resource_windows_*.syso

go tool goversioninfo -platform-specific \
    -product-name "Link Ping Prometheus" \
    -product-version "$version" \
    -file-version "$version" \
    -propagate-ver-strings \
    -company "link_ping_prometheus" \
    -description "UDP echo link monitor: Prometheus latency, loss and jitter" \
    -original-name "link_ping_prometheus.exe" \
    -internal-name "link_ping_prometheus" \
    ./installer/windows/versioninfo.json

for f in resource_windows_*.syso; do
    [ -f "$f" ] || {
        echo "gen-versioninfo: no .syso files were produced" >&2
        exit 1
    }
done
echo "gen-versioninfo: embedded version $version in $(ls resource_windows_*.syso | tr '\n' ' ')"
