#!/bin/zsh
set -eu

: "${PGP_CLIENT_RECIPIENT:?Set PGP_CLIENT_RECIPIENT to the full fingerprint}"
CLI=${PGP_CLIENT_CLI:-pgp-client-cli}

for file in "$@"; do
  "$CLI" encrypt --recipient "$PGP_CLIENT_RECIPIENT" "$file" "$file.gpg"
done
