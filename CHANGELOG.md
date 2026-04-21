# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-04-21

### Added

- COSE_Sign1 cryptographic signature verification for mDOC credentials.
- MobileSecurityObject (MSO) validity enforcement: strict ISO 18013-5 dates — `signed`, `validFrom`, `validUntil`. Future-signed and inconsistent windows are rejected.
- Digest verification of every `IssuerSignedItem` against the MSO's `valueDigests` — tampered items fail with `MalformedCredentialError`.
- `ParseOptions.expectedDocType?: string` — optional lock on the accepted credential type to defend against doc-type confusion.

### Changed (breaking)

- `MdocParser` now performs real cryptographic verification. Previously, any CBOR-shaped mDOC was accepted. Callers must now supply trusted issuer certificates (or opt out with `skipTrustCheck: true`).
- Strict MSO validity: credentials with future `signed` timestamps, `validFrom > validUntil`, or `signed` outside the validity window are rejected with `MalformedCredentialError`.
- Removed the silent "fall back to the first namespace if EUDI PID namespace is missing" behaviour. Every namespace present in the credential is verified against the MSO.

### Security

- Closes the largest remaining crypto gap in 0.2.x: forged mDOCs are no longer accepted.

[0.3.0]: https://github.com/openeudi/openid4vp/releases/tag/v0.3.0

## [0.2.1] — 2026-04-19

### Changed

- `ParseOptions.trustedCertificates: []` no longer silently skips trust checking. Parsing now throws `MalformedCredentialError` unless the caller also passes `skipTrustCheck: true`. Callers that previously relied on the silent-skip behaviour must update.

### Added

- `ParseOptions.skipTrustCheck?: boolean` — explicit opt-in for trust-less parsing (demo/mock environments).

### Security

- Dropped `cose-js` dependency (imported but unused), which transitively pulled `elliptic ≤ 6.6.1` (GHSA-848j-6mx2-7j84). Removes a low-severity supply-chain exposure. COSE_Sign1 verification — when added — will use Web Crypto directly.

[0.2.1]: https://github.com/openeudi/openid4vp/releases/tag/v0.2.1

## [0.1.0] - 2026-04-11

### Added

- SD-JWT VC credential parser with selective disclosure, SHA-256 hashing, and x5c certificate extraction
- mDOC/mDL credential parser with CBOR decoding, COSE_Sign1 verification, and ISO 18013-5 compliance
- Authorization request builder for OpenID4VP flows with presentation definitions
- Presentation format dispatcher with automatic format detection (string for SD-JWT, binary for mDOC)
- ICredentialParser strategy interface for custom parser implementations
- Certificate trust verification against provided trusted certificate lists
- Nonce validation and replay protection
- 5 error classes: InvalidSignatureError, ExpiredCredentialError, UnsupportedFormatError, MalformedCredentialError, NonceValidationError
- Full TypeScript types with strict mode
- Dual ESM/CJS build output
- 39 unit tests with synthetic test fixtures
