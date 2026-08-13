#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

mkdir -p build

VERSION="$(date -u +%Y%m%d.%H%M)"
LDFLAGS="-X main.version=$VERSION"

echo "Building Linux... (version $VERSION)"
go build -ldflags "$LDFLAGS" -o build/link_ping_prometheus .

echo "Building Windows... (version $VERSION)"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o build/link_ping_prometheus.exe .

echo "Done: build/link_ping_prometheus, build/link_ping_prometheus.exe"
