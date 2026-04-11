# Contributing to @openeudi/openid4vp

Thank you for your interest in contributing to OpenEUDI. This document explains how to get started.

## Quick Start

```bash
git clone https://github.com/openeudi/openid4vp.git
cd openid4vp
npm install
npm test        # Run tests (vitest)
npm run build   # Build (tsup)
```

## Architecture Overview

The package parses and validates EUDI Wallet credential presentations:

- **`src/parsers/`** - Credential format parsers (ICredentialParser interface):
  - `sd-jwt.parser.ts` - SD-JWT VC parser (selective disclosure, SHA-256, x5c certificate extraction)
  - `mdoc.parser.ts` - mDOC/mDL parser (CBOR decoding, COSE_Sign1, ISO 18013-5 DeviceResponse)
  - `parser.interface.ts` - Strategy interface with canParse and parse methods
- **`src/presentation.ts`** - parsePresentation() dispatcher that auto-detects format and routes to correct parser
- **`src/authorization.ts`** - createAuthorizationRequest() builds OpenID4VP authorization requests with presentation definitions
- **`src/types/`** - TypeScript interfaces (CredentialFormat, CredentialClaims, PresentationResult, IssuerInfo, AuthorizationRequest)
- **`src/errors.ts`** - InvalidSignatureError, ExpiredCredentialError, UnsupportedFormatError, MalformedCredentialError, NonceValidationError

## Development Workflow

1. Create a branch from `main`
2. Write tests first (TDD encouraged)
3. Implement your changes
4. Run `npm test` and `npx tsc --noEmit` before pushing
5. Open a Pull Request

## Commit Messages

We use conventional commits:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `chore:` - Maintenance
- `test:` - Tests
- `refactor:` - Code restructuring

## Pull Request Process

1. Fill out the PR template
2. All CI checks must pass (typecheck, test, build)
3. Maintainer will review within 1 week
4. Squash merge preferred

## Issue Labels

- `bug` - Something is broken
- `enhancement` - New feature request
- `good-first-issue` - Good for newcomers
- `help-wanted` - Community help welcome
- `documentation` - Docs improvements
- `security` - Security related

## Code Style

- Follow existing patterns in the codebase
- Strict TypeScript (`"strict": true`) - no `any`
- ESM imports with `.js` extensions
- Tests mirror source structure: `src/parsers/sd-jwt.parser.ts` -> `tests/sd-jwt.parser.spec.ts`
- Test fixtures go in `tests/fixtures/`

## Developer Certificate of Origin (DCO)

By contributing, you certify that you wrote the code or have the right to submit it under the Apache 2.0 license. Sign off your commits:

```bash
git commit -s -m "feat: add feature"
```

This adds a `Signed-off-by: Your Name <your@email.com>` line to your commit message.
