#!/bin/zsh
set -eu

: "${PGP_CLIENT_RECIPIENT:?Defina PGP_CLIENT_RECIPIENT com o fingerprint completo}"
CLI=${PGP_CLIENT_CLI:-pgp-client-cli}

for file in "$@"; do
  "$CLI" encrypt --recipient "$PGP_CLIENT_RECIPIENT" "$file" "$file.gpg"
done
