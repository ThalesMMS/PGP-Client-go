# Development

## Main Commands

```bash
go mod download
go fmt ./...
go vet -tags ci ./...
go test -tags ci ./...
go test -race -tags ci ./...
```

The `ci` tag replaces Fyne's graphical driver with an in-memory driver. To run the real application, install the native system dependencies and use:

```bash
go run ./cmd/pgp-client
```

## Conventions

- Cryptographic rules belong in `internal/pgp`, never in UI callbacks.
- Writes that produce final artifacts should use `internal/fileutil`.
- Do not log plaintext, passphrases, private keys or backup contents.
- New network paths must have a timeout, response limit and explicit TLS/redirect policy.
- Signature errors should be distinguished from parsing, I/O and missing-key errors.
- Tests must not access real keyservers or the real system vault.

## Dependencies

Update versions deliberately and run the full suite. For Fyne changes, validate at least:

- headless rendering with `-tags ci`;
- native build on the target system;
- file dialogs;
- drag and drop;
- the package produced by `fyne package`.
