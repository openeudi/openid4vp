# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added (library)

- `createSignedAuthorizationRequest` now also emits `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` in `client_metadata` alongside the OpenID4VP 1.0 Final `encrypted_response_enc_values_supported` plural array. This is an additive ID3-compatibility bridge for verifiers (e.g. the OIDF conformance suite's `EncryptVPResponse` condition) that read the older singular fields directly. Existing 1.0 Final consumers are unaffected.

### CI / Infrastructure

- Added automated OIDF verifier-conformance testing in CI (`@openeudi/openid4vp` workstream D).
  - PR happy-flow gate via `oidf-pr.yml` (paths-filter; ~5 min). Strong end-to-end gate: requires the suite to reach `/response`, the orchestrator to verify the encrypted authorization response (decrypt + state match + SD-JWT VC signature against the supplied issuer JWK), and zero verifier-side exceptions. Allow-listed suite failures alone cannot turn the gate green.
  - Tag-push full-plan release artefact via `oidf-release.yml`.
  - Self-hosted conformance suite via `docker/oidf-conformance-suite/` (GHCR-prebuilt image at a pinned upstream git ref).
  - Allow-list at `scripts/oidf-ci/allowlist.json` ships with two `harness`-category entries (`EnsureRequestUriIsHttps`, `EnsureValidResponseUriForAuthorizationEndpointRequest`) — the local verifier-server runs plain HTTP for simplicity; production CI clears these once an nginx sidecar terminates TLS in front of the verifier.
  - Manual hosted-demo escape hatch retained as `scripts/manual-oidf-run.{ts,mjs}`.

## [0.7.0] — 2026-04-24

### Added

- `createSignedAuthorizationRequest` builds OpenID4VP signed request objects (JAR per RFC 9101 / OpenID4VP 1.0 §5.10) with `x5c` cert chain, `client_id_scheme: x509_san_dns` binding via `client_id` prefix, and validates that the signing key's public SPKI matches the leaf certificate.
- `verifyAuthorizationResponse` consumes OpenID4VP 1.0 §8.1 Authorization Response envelopes (object-keyed `vp_token`), unwraps `direct_post.jwt` JWE-encrypted responses, and delegates presentation verification to the existing `verifyPresentation`.
- `decryptAuthorizationResponse` unwraps `direct_post.jwt` JWE envelopes. Supported JWE: `alg: ECDH-ES` + `enc: A128GCM|A256GCM` per HAIP.
- `AuthorizationResponse`, `EncryptedResponse`, `VerifyAuthorizationResponseOptions`, `SignedAuthorizationRequestInput`, `SignedAuthorizationRequest` types.
- `SignedRequestBuildError`, `UnsupportedJweError`, `DecryptionFailedError`, `MissingDecryptionKeyError`, `MultipleCredentialsNotSupportedError` error classes.

### Changed

- No breaking changes to existing public API. `verifyPresentation`'s signature is unchanged (still accepts `unknown`).

### Known limitations

- Multi-credential DCQL presentations (multiple query ids, or multiple presentations per query id) are rejected with `MultipleCredentialsNotSupportedError`. Single-credential single-presentation works end-to-end.
- Client Identifier Prefix `x509_hash` (HAIP 1.0 final's mandated scheme) is not yet supported — only `x509_san_dns` (the OIDF test profile).
- Self-signed certs are accepted for the verifier's own identity; full HAIP 1.0 final constraints (non-self-signed, anchor excluded from `x5c`) are not enforced.

## [0.6.0] — 2026-04-24

### Added

- `value_mismatch` is now emitted by `verifyPresentation` when a credential's claim is present but excluded by a DCQL `values:` filter. Previously this case was misreported as `missing_claims`.

### Changed

- Specific `UnmatchedReason` values (`format_mismatch`, `vct_mismatch`, `doctype_mismatch`, `missing_claims`, `value_mismatch`, `trusted_authority_mismatch`) are now sourced directly from `@openeudi/dcql@0.2.0`'s `matchQuery` output. The internal post-processor (`refineUnmatched` / `classifyMismatch`) that replicated dcql's classification has been removed.
- README documents a privacy caveat: `match.unmatched` diagnostics are verifier-internal and must not be echoed into OpenID4VP wire responses or end-user-visible errors.

### Dependencies

- `@openeudi/dcql`: `^0.1.1` → `^0.2.0` (breaking change in dcql — see its 0.2.0 changelog).

## [0.5.0] — 2026-04-23

### Added — workstream A.1 (X.509 chain building)

- Public `TrustStore` plug interface with `StaticTrustStore` and `CompositeTrustStore` implementations (`src/trust/`).
- Public `Fetcher` type and `Cache` interface with `InMemoryCache` LRU default.
- `OpenID4VPError` base class; `TrustAnchorNotFoundError`, `CertificateChainError` subclasses.
- `ParseOptions.trustStore`, `ParseOptions.revocationPolicy`, `ParseOptions.fetcher`, `ParseOptions.cache`, `ParseOptions.clockSkewTolerance` fields.
- `PresentationResult.trust` field populated when `trustStore` is used (chain, anchor, revocationStatus).
- RFC 5280 chain validation (pragmatic subset): signature, validity period with clock-skew tolerance, algorithm allowlist, issuer/subject DN chaining, AKI/SKI match, basicConstraints (cA + pathLenConstraint), keyUsage, nameConstraints (DN, DNS, RFC 822, URI).

### Added — workstream A.2 (revocation checking)

- `RevokedCertificateError` — thrown when a definitive `revoked` response comes back from CRL or OCSP (`code: 'certificate_revoked'`, `.serial`, `.revokedAt`, optional `.reason`).
- `RevocationCheckFailedError` — thrown only under `revocationPolicy: 'require'` when the status cannot be determined (`code: 'revocation_check_failed'`).
- `ParseOptions.revocationPolicy: 'prefer' | 'require'` now work (previously threw at construct time).
- OCSP and CRL revocation checking per RFC 6960 + RFC 5280 §5: OCSP preferred, CRL fallback, responses cached via the injected `Cache`.
- OCSP responses verified against (a) direct issuer signature or (b) responder sub-cert carrying `id-kp-OCSPSigning` EKU with chain validated via `ChainBuilder`.
- Out of scope for this release: OCSP stapling, delta CRLs, signed OCSP requests. Captured in spec §7.5.

### Dependencies — A.2

- Added devDependencies: `@peculiar/asn1-ocsp@^2.6.1`, `@peculiar/asn1-cms@^2.6.1`.

### Added — workstream A.3 (EU LOTL client)

- Public `LotlTrustStore` — fetches the EU LOTL (default `https://ec.europa.eu/tools/lotl/eu-lotl.xml`), verifies XML-DSig against a bundled set of signing anchors, resolves all national TLs, and exposes `TrustAnchor[]` with populated `LotlAnchorMetadata` (country, serviceName, qualified, loa).
- `LotlFetchError` (`code: 'lotl_fetch_failed'`, carries `url` + optional `cause`) and `LotlSignatureError` (`code: 'lotl_signature_invalid'`).
- `TrustAnchor.trustedAuthorityIds` — derived from `ServiceDigitalIdentity` SKI for LOTL anchors, synthesized from the anchor's own SKI for static-store anchors. `TrustEvaluator` populates `trustedAuthorityIds` on every result.
- `PresentationResult.trust.provenance` — `{ loa, qualified, country, serviceName }` populated when the chain terminates at a LOTL-sourced anchor (spec §8.5).
- `DecodedCredential.trusted_authority_ids` — now populated by `verifyPresentation`. DCQL queries with `trusted_authorities` filters work correctly for the first time (the 0.4.0 known-limitation is closed).
- LOTL refresh: 24h default, single-flight, graceful degradation on failure (serves cached snapshot + logs via `console.warn`).
- ETSI-URI → LoA mapping for the current eIDAS Article 8 notified levels (`substantial`, `high`).

### Dependencies — A.3

- Added dependencies: `xadesjs@^2.6.7`, `xmldsigjs@^2.8.7` (installed versions from Task 1).
- Added dependency: `@xmldom/xmldom@^0.9.0` — promoted from devDep to runtime dep in Task 7 because `LotlFetcher` uses it.

### Known limitations

- The EU LOTL signing anchors are bundled at release time. When the European Commission rotates signing certs (rare — ~2-3 year cadence), a patch release of this package is required. Consumers can override the bundled set via `new LotlTrustStore({ signingAnchors: [...] })` for emergency rotations.
- LOTL refresh runs on-demand (first `getAnchors` triggers the fetch, then honors `refreshInterval`). There is no background-timer variant in 0.5.0 — consumers wanting fixed-interval refresh can call a noop `getAnchors` in a timer of their own.

### Deprecated

- `ParseOptions.trustedCertificates` — kept working for 0.4.0 byte-equality behavior; scheduled for removal in 1.0.0. Migrate to `trustStore: new StaticTrustStore([...rootCAs])` for RFC 5280 chain validation.

## [0.4.0] — 2026-04-21

### Added

- `verifyPresentation(vpToken, query, options)` — parses a VP token and matches it against a DCQL query; returns `{ parsed, match, submission, valid }`. Return-not-throw for mismatches; crypto/structural failures still throw.
- `buildHaipQuery(input)` — ergonomic helper producing HAIP-compliant DCQL queries. Auto-namespaces mDOC claim paths via `HAIP_DOCTYPE_NAMESPACES` (known EUDI doctypes) with fallback for unknown doctypes.
- `validateHaipQuery(query)` / `isHaipQuery(query)` — HAIP profile validators with 7 discriminated error codes.
- `HaipValidationError` (with `code` and optional `credentialId`) and `HaipValidationCode` union.
- `HAIP_DOCTYPE_NAMESPACES` exported constant — mapping of known EUDI mDOC doctypes to claim namespaces (ISO mDL, EUDI PID).
- `PresentationResult` extended with optional `vct`, `docType`, and `namespacedClaims` fields (SD-JWT `vct` surfaced; mDOC doctype and namespace-grouped claims surfaced for DCQL matching).
- Re-exports from `@openeudi/dcql`: `DcqlQuery`, `DcqlMatchResult`, `DcqlSubmission`, `DcqlValidationError`, `DcqlMatchError`, `DcqlValidationErrorCode`.

### Changed (breaking)

- `createAuthorizationRequest(input, query)` now takes a DCQL query as its second argument. Previous input fields (`requestedAttributes`, `acceptedFormats`) removed.
- `AuthorizationRequest.dcqlQuery` replaces `.presentationDefinition`.
- The URI parameter `dcql_query` replaces `presentation_definition` (OpenID4VP 1.0 final §5.4). Wallets on OpenID4VP 1.0 final expect this.

### Changed

- mDOC parser now preserves namespace grouping in `PresentationResult.namespacedClaims` alongside the existing flat `claims` object. SD-JWT parser now includes `vct` in the output.
- Paired `@openeudi/core` bumped to 0.4.0 (version sync only; no API change).

### Removed (breaking)

- Dropped `@sphereon/pex` and `@sphereon/ssi-types` dependencies (previously declared but never imported — cleanup, not a PEX-to-DCQL swap). Consumers that transitively imported types from these packages must install them directly.

### Dependencies

- Added `@openeudi/dcql@^0.1.1`.

### Known limitations (deferred to a later release)

- **Specific `UnmatchedReason` values are restored via a local classifier.** `@openeudi/dcql@0.1.1`'s public `matchQuery` collapses all credential rejection reasons into `'no_credential_found'`. `verifyPresentation` post-processes `match.unmatched` to expose the specific reason (`format_mismatch`, `vct_mismatch`, `doctype_mismatch`, `missing_claims`, `trusted_authority_mismatch`) by replicating the matcher's classification locally. This workaround can be removed when `@openeudi/dcql` surfaces the specific reasons at its outer API.
- `trusted_authority_ids` on decoded credentials is always empty in this release. Queries using `trusted_authorities` will always report `trusted_authority_mismatch`. Populating this requires AKI (Authority Key Identifier) derivation from the issuer certificate — planned for a later release alongside the EU LOTL client.
- HAIP wrapping-request checks (`client_id_scheme: x509_san_dns`, signed request objects, `response_mode: direct_post.jwt` enforcement) are not implemented. `validateHaipQuery` is query-layer only.
- `validateHaipQuery` does not check `values:` filter shapes beyond presence.

### Migration from 0.3.x

```diff
- const req = createAuthorizationRequest({
-   clientId, responseUri, nonce,
-   requestedAttributes: ['age_over_18'],
-   acceptedFormats: ['sd-jwt-vc'],
- });
+ import { buildHaipQuery, createAuthorizationRequest } from '@openeudi/openid4vp';
+ const query = buildHaipQuery({
+   credentialId: 'pid',
+   format: 'dc+sd-jwt',
+   vctValues: ['https://pid.eu/v1'],
+   claims: ['age_over_18'],
+ });
+ const req = createAuthorizationRequest(
+   { clientId, responseUri, nonce },
+   query,
+ );
```

To verify a returned VP token:

```ts
import { verifyPresentation } from '@openeudi/openid4vp';

const result = await verifyPresentation(vpToken, query, { nonce, trustedCertificates });
if (!result.valid) {
    console.warn('VP did not satisfy the query:', result.match.unmatched);
}
```

Note: `ParseOptions` in this package accepts `{ nonce, trustedCertificates, audience?, allowedAlgorithms?, skipTrustCheck?, expectedDocType? }`. It does NOT accept `clientId` or `verifyCrypto` — those are not part of the current options shape.

If you imported types from `@sphereon/pex` or `@sphereon/ssi-types` transitively via this package, install those packages directly — they are no longer transitive.

[0.7.0]: https://github.com/openeudi/openid4vp/releases/tag/v0.7.0
[0.6.0]: https://github.com/openeudi/openid4vp/releases/tag/v0.6.0
[0.5.0]: https://github.com/openeudi/openid4vp/releases/tag/v0.5.0
[0.4.0]: https://github.com/openeudi/openid4vp/releases/tag/v0.4.0

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
