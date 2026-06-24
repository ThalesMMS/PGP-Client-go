# Architecture

## Goals

The structure separates presentation, cryptographic use cases and persistence. This prevents Fyne callbacks from implementing security rules and lets the GUI, CLI and tests use the same semantics.

## Layers

### `internal/model`

Contains shared DTOs, enums and errors: key projection, preferences, encryption, decryption, signing and verification requests and results.

### `internal/storage`

Responsible for:

- configuration directory;
- ASCII-armored public and private certificates;
- local trust/verification metadata;
- preferences;
- native vault abstraction;
- temporary passphrase cache.

The `SecretStore` abstraction allows tests to replace the system vault with an in-memory implementation.

### `internal/pgp`

`Service` is the use-case facade. It coordinates:

- key generation, import, export, revocation and removal;
- unlocking and passphrase retrieval;
- in-memory or streaming encryption/decryption;
- in-memory or streaming signing/verification;
- backup and restore;
- HKP/HKPS.

The layer uses GopenPGP and ProtonMail `go-crypto`, but does not know about widgets, dialogs or window state.

### `internal/ui`

`Desktop` keeps only presentation state: current page, selected key, received file and Fyne references. Potentially slow operations run outside the UI thread and return their results through `fyne.Do`.

### `internal/fileutil`

Centralizes transactional writes. `PendingFile` allows confirmation to be delayed until after validations, such as inline signature verification.

### `cmd`

- `pgp-client` creates the default service, forwards file arguments and starts the GUI.
- `pgp-client-cli` exposes the same use cases to scripts, CI and system integrations.

## Dependency Flow

```text
cmd/pgp-client     -> internal/pgp -> internal/storage -> filesystem/keyring
internal/ui        ->      |               |
                           |               -> internal/model
                           -> internal/fileutil

cmd/pgp-client-cli -> internal/pgp
```

`storage` does not depend on `pgp` or `ui`; `pgp` does not depend on `ui`. This direction reduces cycles and allows infrastructure replacement in tests.

## Concurrency

- `Service` protects preferences with `RWMutex`.
- `Store` serializes keyring and JSON mutations.
- `SecretCache` protects its map and overwrites removed buffers.
- The UI runs use cases in goroutines and performs visual mutations on the Fyne thread.
- File operations observe `context.Context` in 128 KiB blocks.

## Persistence

Files are written in the same directory as the destination and committed by rename. This prevents partial final files on write, cancellation or validation failures. The keyring format is deliberately simple and auditable:

```text
pgp-client-go/
  keys/
    <FINGERPRINT>.public.asc
    <FINGERPRINT>.secret.asc
  metadata.json
  settings.json
```

When importing a public version of a key that already has local private material, storage preserves the private version.
