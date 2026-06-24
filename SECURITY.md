# Security

## Threat Model

PGP Client protects content from third-party reading or modification when the keys, passphrases, algorithms and endpoints in use are trusted. It does not protect an already compromised computer, a logged-in user with equivalent privileges, malware with process access, keyboard/screen capture or malicious binary replacement.

## Key Protection

- Private keys can be stored encrypted with a passphrase; this is the recommended mode.
- The local file for a private key receives `0600` permissions on POSIX systems.
- Remembered passphrases are delegated to the operating system's native vault.
- The session cache keeps copies in memory for a limited time and overwrites buffers when they expire, are replaced or the session is locked. Go and its garbage collector cannot guarantee physical erasure of every transient copy.
- Private exports and backups should be treated as highly sensitive material.

## File Integrity

Core file operations - encryption, decryption, signing, inline verification and export used by the CLI - plus keyring persistence write to a temporary file in the destination directory and commit the result only after writing and syncing complete. On Windows, where renaming over an existing destination is not supported in the same way, the implementation attempts the rename and removes the destination only after that platform-specific failure. Saves started by native GUI dialogs use the stream supplied by Fyne; the application validates writing/closing and applies restrictive permissions when the destination is a private local file.

Content extracted from an inline signature does not replace the destination until the signature is valid. During decryption, OpenPGP authenticates the ciphertext before the temporary file is committed; an invalid embedded signature is reported separately from the message's cryptographic integrity.

## Backup

The `.pgpbackup` format uses:

- Argon2id for key derivation;
- random 128-bit salt;
- AES-256-GCM;
- random nonce;
- authentication of the format header as associated data;
- size and Argon2id cost limits during restore.

A weak password remains vulnerable to offline guessing. Use a long, unique passphrase and keep tested offline copies.

## Network And Keyservers

- The client accepts HKPS/HTTPS; HTTP is restricted to `localhost` and `127.0.0.1` for tests.
- Insecure redirects and excessive redirect chains are blocked.
- Requests have a timeout and responses are limited to 16 MiB.
- Publishing a key may disclose identities and email addresses. Some keyservers do not allow complete later removal.
- A downloaded key does not become trusted automatically; validate the fingerprint through an independent channel.

## Cryptographic Limitations

- Local generation uses RSA 2048/3072/4096 to maintain parity with the reference application.
- The client imports other algorithms supported by the library, but not every historical combination or OpenPGP extension is guaranteed.
- Trust and verified-fingerprint marks are local metadata; they do not implement a full Web of Trust.
- Revocation changes the local key. To notify third parties, export/publish the revoked version through appropriate channels.

## Vulnerability Reporting

Do not publish sensitive data, private keys, passphrases or backups in an issue. When maintaining this project in a repository, configure a private security channel and include version, operating system, minimal steps and observed impact.
