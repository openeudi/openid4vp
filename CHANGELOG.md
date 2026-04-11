# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
