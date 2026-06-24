#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

mkdir -p bin
go test -tags ci ./...
go vet -tags ci ./...
go build -trimpath -o bin/pgp-client ./cmd/pgp-client
go build -trimpath -o bin/pgp-client-cli ./cmd/pgp-client-cli
