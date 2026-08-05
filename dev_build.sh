#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

mkdir -p build

echo "Building Linux..."
go build -o build/link_ping_prometheus .

echo "Building Windows..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/link_ping_prometheus.exe .

echo "Done: build/link_ping_prometheus, build/link_ping_prometheus.exe"
