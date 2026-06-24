$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

New-Item -ItemType Directory -Force -Path bin | Out-Null
go test -tags ci ./...
go vet -tags ci ./...
go build -trimpath -o bin/pgp-client.exe ./cmd/pgp-client
go build -trimpath -o bin/pgp-client-cli.exe ./cmd/pgp-client-cli
