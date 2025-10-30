#!/usr/bin/env bash
set -euo pipefail
export GOROOT="/home/duongtc/568E/Haitac/go"
export PATH="/home/duongtc/568E/Haitac/go/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR"

echo "Building linux/amd64 binary..."
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

cd "$ROOT_DIR"
go build -trimpath -ldflags "-s -w" -o "$BIN_DIR/portforwarder" ./
echo "Built: $BIN_DIR/portforwarder"
