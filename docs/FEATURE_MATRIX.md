# Feature Matrix

| Area | Status | Notes |
|---|---|---|
| Searchable and filterable keyring | Implemented | Public/secret, expiration, revocation, trust and local verification |
| RSA 2048/3072/4096 generation | Implemented | Optional expiration and passphrase |
| Import/export/delete | Implemented | Binary and ASCII armor; private export with restrictive mode |
| Local revocation | Implemented | The revoked key can be exported/published |
| Fingerprint copy/compare | Implemented | Verification marking is local metadata |
| Text encryption | Implemented | Multiple recipients, password, armor, compression, signature |
| File encryption | Implemented | Streaming and transactional confirmation |
| Decryption | Implemented | Private key or password; embedded signature |
| Signing/verification | Implemented | Detached, inline and cleartext; text and file |
| Native credential vault | Implemented | macOS Keychain, Secret Service/KWallet and Windows Credential Manager through `go-keyring` |
| Session cache/lock | Implemented | Configurable TTL and manual lock |
| Encrypted backup | Implemented | Optional keys, metadata and preferences during restore |
| HKP/HKPS | Implemented | Search, download and upload |
| Drag and drop | Implemented | Content/extension-based routing |
| File opening by the application | Implemented | Process arguments and MIME metadata |
| CLI automation | Implemented | Same service layer as the GUI |
| Finder Sync Extension | Not included | Requires native App Extension target in Xcode/Swift/Obj-C |
| Quick Look Extension | Not included | Requires native macOS target and signing |
| Thumbnail Extension | Not included | Requires native macOS target |
| Share Extension | Not included | Requires App Extension target and entitlements |

## Interpretation

Functional parity covers the OpenPGP flows and the main application experience. Features that live inside Finder or Apple's extension system do not belong to the Fyne runtime; the delivered alternative is the combination of file opening, drag and drop, CLI and Automator Quick Actions.
