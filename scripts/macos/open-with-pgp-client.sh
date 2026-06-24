#!/bin/zsh
set -eu

for file in "$@"; do
  open -a "PGP Client" -- "$file"
done
