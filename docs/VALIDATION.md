# Delivery Validation

Environment used on 2026-06-24: Linux x86_64, Go 1.23.2.

Completed successfully:

```bash
go mod tidy
go fmt ./...
go vet -tags ci ./...
go test -tags ci ./...
go test -race -tags ci ./...
go build -trimpath -tags ci ./cmd/pgp-client
go build -trimpath ./cmd/pgp-client-cli
go run fyne.io/tools/cmd/fyne@v1.7.2 package --tags ci --src ./cmd/pgp-client
```

A CLI smoke test was also run with an isolated configuration directory:

1. generated two RSA 2048 keys;
2. listed JSON and selected by fingerprint;
3. encrypted for Bob with Alice's signature;
4. decrypted and validated the embedded signature;
5. created and verified a detached signature;
6. created a backup;
7. restored into an empty keyring and confirmed two keys.

The suite also covers correct recipient selection during streaming decryption, symmetric files without attempts to unlock unrelated keys, fallback after a stale vault secret, generation rollback when the vault fails and routing of files received by the GUI.

The native Linux GUI link was not run in this container because OpenGL/X11 development headers were unavailable. Fyne's `ci` tag validates all UI composition with the in-memory driver, including rendering the five pages. For distribution, run `make build` and `make package` on a system with the native dependencies described in the README.
