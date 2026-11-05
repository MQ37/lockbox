#!/bin/sh
# Format-check, vet, test and build lockbox in rootless podman: offline, read-only
# source, RAM-only scratch. Output: ./dist/lockbox (static linux/amd64).
# Usage: ./build.sh [test|build]   (default: both)
set -eu
cd "$(dirname "$0")"
MOD=${GOMODCACHE_HOST:-$HOME/go/pkg/mod}
IMG=${GO_IMAGE:-docker.io/library/golang:1.25}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
base() { podman run --rm --network=none --read-only --tmpfs /tmp:exec,size=2g \
  -e GOPROXY=off -e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false -e CGO_ENABLED=0 \
  -e GOCACHE=/tmp/gc -e GOMODCACHE=/mod -e HOME=/tmp/home -v "$MOD":/mod:ro "$@"; }
# Safety: tests never see ~/.lockbox (the container has its own HOME and TestMain
# redirects HOME again). As a belt-and-braces check, the real database's hash is
# compared before and after; a change aborts loudly. Back up first for any real-data work.
REAL=${LOCKBOX_REAL_DB:-$HOME/.lockbox/lockbox.db}
before=""; [ -f "$REAL" ] && before=$(sha256sum "$REAL" | cut -d' ' -f1)
trap 'if [ -n "$before" ] && [ "$(sha256sum "$REAL" | cut -d" " -f1)" != "$before" ]; then echo "!!! the real lockbox database CHANGED during build.sh: restore from your backup" >&2; fi' EXIT
case "${1:-all}" in
  test|all)
    # copy the source to tmpfs: tests run the freshly built ./lockbox binary there
    base -v "$PWD":/src:ro -w /tmp "$IMG" sh -ec '
      cp -r /src /tmp/work && cd /tmp/work
      test -z "$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
      go vet ./...
      go build -o lockbox .
      go test ./... -count=1'
    ;;
esac
case "${1:-all}" in
  build|all)
    mkdir -p dist
    base -e GOOS=linux -e GOARCH=amd64 -v "$PWD":/src:ro -v "$PWD/dist":/out -w /src "$IMG" \
      go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/lockbox .
    sha256sum dist/lockbox
    ;;
esac
