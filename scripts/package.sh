#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

TARGET=${1:-}
if [ -n "$TARGET" ]; then
  exec go run fyne.io/tools/cmd/fyne@v1.7.2 package --target "$TARGET" --src ./cmd/pgp-client
fi
exec go run fyne.io/tools/cmd/fyne@v1.7.2 package --src ./cmd/pgp-client
