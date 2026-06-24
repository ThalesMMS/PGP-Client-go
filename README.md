# PGP Client Go

Cross-platform desktop OpenPGP client written in Go and Fyne. The project is an independent implementation inspired by MacPGP workflows and visual organization: an operation sidebar, searchable keyring and detail panel, using a dark interface with orange accents.

## Features

- Local keyring with search, filters, sorting, details, local trust and fingerprint comparison.
- RSA 2048, 3072 or 4096-bit key generation with optional expiration and passphrase.
- Public or private key import, export, deletion and revocation.
- Encryption for multiple recipients or by password, with ASCII armor, compression and optional embedded signature.
- Text and file decryption, including embedded signature detection and verification.
- Detached, inline and cleartext signatures; text and file verification.
- System credential vault and temporary in-memory passphrase cache.
- Authenticated encrypted backups with Argon2id and AES-256-GCM.
- HKP/HKPS server search, import and publishing.
- Drag and drop, files received from the operating system and CLI automation.
- English interface with persistent preferences.

## Quick Start

General requirements:

- Go 1.23 or newer.
- C compiler and native libraries required by Fyne for the operating system.
- macOS: Xcode Command Line Tools.
- Linux: OpenGL, X11 and the related development packages.
- Windows: compatible GCC toolchain, usually through MSYS2/MinGW-w64.

```bash
git clone <your-repository>
cd PGP-Client-go
go mod download
make test
make run
```

The `test` target uses Fyne's `ci` tag and therefore does not open a window or require a display server.

## Build

```bash
# Native GUI and CLI
make build

# CLI only
make build-cli

# Headless GUI build for CI code validation
make build-ci

# Native package for the current system
make package
```

The binaries produced by `make build` are written to `bin/`.

Also available:

```bash
./scripts/build.sh
./scripts/package.sh          # current system
./scripts/package.sh darwin   # request an explicit target from fyne package
```

Cross-compiling Fyne applications may require SDKs and toolchains for the target system; packaging on macOS, Linux or Windows itself is usually the most predictable option.

## Interface Use

1. Open **Keyring** and generate or import a key.
2. Review the fingerprint through an independent channel before marking the key as verified.
3. In **Encrypt**, select one or more recipients, or use password mode.
4. In **Decrypt**, provide the passphrase when prompted. Output is confirmed only after the operation completes without errors.
5. Use **Sign** and **Verify** for detached, inline or cleartext signatures.
6. Open **File > Create encrypted backup** to protect the keyring and preferences.

Files can also be dragged into the window. Routing considers content and extension: keys go to import; PGP messages to decryption; `.sig`, ASCII-armored or cleartext signatures to verification; all other files to encryption.

## CLI

```text
pgp-client-cli list [--json]
pgp-client-cli generate --name NAME --email EMAIL [--bits 3072] [--expires 730]
pgp-client-cli import FILE [FILE...]
pgp-client-cli export-public  --key FINGERPRINT --out FILE
pgp-client-cli export-private --key FINGERPRINT --out FILE
pgp-client-cli encrypt --recipient FINGERPRINT [--recipient ...] [--sign FINGERPRINT] INPUT OUTPUT
pgp-client-cli decrypt INPUT OUTPUT
pgp-client-cli sign --key FINGERPRINT [--mode detached|inline|cleartext] INPUT OUTPUT
pgp-client-cli verify --mode detached|inline|cleartext --signature SIGNATURE [--data DATA] [--out OUTPUT]
pgp-client-cli backup OUTPUT.pgpbackup
pgp-client-cli restore [--settings] BACKUP.pgpbackup
pgp-client-cli keyserver-search QUERY
pgp-client-cli keyserver-import FINGERPRINT_OR_KEYID
pgp-client-cli keyserver-upload FINGERPRINT
pgp-client-cli lock
```

When an interactive terminal is available, secrets are requested without echo. For automation, the CLI accepts `PGP_CLIENT_PASSPHRASE` and `PGP_CLIENT_PASSWORD`; environment variables can be observed by privileged processes or diagnostic tools, so use them only in controlled environments.

## Storage

The directory is derived from `os.UserConfigDir()` and receives the `pgp-client-go` subdirectory:

- macOS: usually `~/Library/Application Support/pgp-client-go`
- Linux: usually `~/.config/pgp-client-go`
- Windows: usually `%AppData%\pgp-client-go`

Private keys are written with `0600` permissions on POSIX systems. A key without a passphrase remains unprotected on disk; the application allows this mode for compatibility but recommends passphrase protection.

## Security

- Core file operations and local persistence use temporary files in the same directory and replace the destination only after successful close and sync; native GUI dialogs validate writes and closing of the stream supplied by Fyne.
- Inline content is saved as verified only after cryptographic validation.
- Keyserver responses have a size limit, timeout and require HTTPS, except for `localhost`/`127.0.0.1` in tests.
- Backups use an authenticated envelope and defensive limits for Argon2id parameters.
- Persistent passphrases use the native vault through `go-keyring`; the session cache remains in memory only and can be cleared through **Lock now**.

See [SECURITY.md](SECURITY.md) for the threat model and limitations.

## MacPGP Parity

The OpenPGP flows and main visual structure were reproduced in Go/Fyne. Native macOS extensions - Finder Sync, Quick Look, Thumbnail and Share Extension - require App Extension targets, signing and packaging from the Xcode ecosystem. They cannot be implemented as pure Fyne components. The project provides file opening, drag and drop, MIME metadata, CLI and Automator instructions as a practical alternative.

The detailed matrix is in [docs/FEATURE_MATRIX.md](docs/FEATURE_MATRIX.md), and macOS integration is in [docs/MACOS_INTEGRATION.md](docs/MACOS_INTEGRATION.md).

## Architecture

```text
cmd/pgp-client/       graphical executable
cmd/pgp-client-cli/   command-line interface
internal/ui/          Fyne composition and presentation state
internal/pgp/         OpenPGP use cases, backup and keyserver
internal/storage/     keyring, preferences and secret vaults
internal/fileutil/    transactional file writes
internal/model/       shared contracts and models
```

The graphical layer does not handle cryptographic primitives directly. UI and CLI depend on the same `pgp.Service`, which reduces behavioral divergence and enables deterministic tests with in-memory storage and vaults.

Additional details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tests

```bash
go test -tags ci ./...
go test -race -tags ci ./...
go vet -tags ci ./...
```

The suite covers encryption for multiple recipients, embedded signatures, three signature formats, correct recipient selection during streaming, passphrase errors and fallback, backup and tampering, import without downgrading private keys, generation rollback, atomic writes, HKP parsing, file routing and Fyne page rendering. The validation log for this delivery is in [docs/VALIDATION.md](docs/VALIDATION.md).

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
