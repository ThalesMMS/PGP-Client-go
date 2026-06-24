# macOS Integration

## Application

Package on macOS to produce `PGP Client.app`:

```bash
make package
```

Move the bundle to `/Applications` and open it once so Launch Services registers the package metadata and declared type association.

## Open Files In PGP Client

The graphical executable interprets paths received on the command line:

- keys with `.key`/`.pub` extension or ASCII-armored content: import;
- PGP messages: decryption;
- `.sig`, ASCII-armored or cleartext signatures: verification;
- other files: encryption.

In Finder, **Open With > PGP Client** uses this flow when the association is available. You can also drag the file into the window.

## Quick Action Through Automator

1. Open Automator and create a **Quick Action**.
2. Configure it to receive **files or folders** in Finder.
3. Add **Run Shell Script**.
4. Select `/bin/zsh` and pass input **as arguments**.
5. Paste:

```zsh
for file in "$@"; do
  open -a "PGP Client" -- "$file"
done
```

The equivalent script is in `scripts/macos/open-with-pgp-client.sh`.

## Direct CLI Automation

Install `pgp-client-cli` in a directory on `PATH` and use full fingerprints:

```bash
pgp-client-cli encrypt \
  --recipient RECIPIENT_FINGERPRINT \
  document.pdf document.pdf.gpg
```

For an encryption Quick Action without secret-key use, configure `PGP_CLIENT_RECIPIENT` and use `scripts/macos/encrypt-selected.sh`. Do not write passphrases inside Automator scripts.

## Native Extensions

Finder Sync, Quick Look, Thumbnail and Share Extension are separate bundles loaded by macOS. They require App Extension targets, specific Info.plist files, sandbox/entitlements, signing and, in some cases, App Groups. The Fyne GUI and a Go binary do not generate those targets automatically.

A future expansion could keep the OpenPGP engine in Go and add a minimal Xcode workspace that invokes the CLI or a shared C library. This considerably increases the distribution surface and should include sandbox tests, path review and protection against plaintext leaks in previews.
