# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.16.1] — 2026-10-22

### Fixed

- **One malformed certificate extension no longer breaks trust evaluation.**
  `@peculiar/x509` 2.x decodes every extension on first access and throws if
  any one is malformed, then caches an empty list, so the certificate looks
  extension-less from then on. The EU age-verification reference PKI ("Age
  Verification Issuer CA 01" on the acceptance AV-TL, and its Document
  Signers) encodes IssuerAltName as a nested Extension; with it in a
  `StaticTrustStore`, the constructor threw and every `verifyAvPresentation`
  failed, including wallet error responses.
  - Every extension read now goes through `src/trust/extensions.ts`, which
    decodes each extension on its own from the raw DER.
  - Fail closed: a certificate with a malformed or duplicated extension is
    refused (`CertificateChainError`, new reason `malformed_extension`), and
    reading a malformed extension throws rather than reporting it absent. The
    one exception is a **non-critical IssuerAltName** (`2.5.29.18`), which
    plays no part in path validation; a critical one is still refused.
  - `StaticTrustStore` skips a certificate it cannot use (not X.509, or a
    malformed extension other than that) instead of throwing, and lists it in
    the new `rejectedAnchors` property. `LotlTrustStore` and provenance
    resolution skip such a listed certificate rather than failing the lookup.
  - The AV spec's Annex A example now verifies against the reference CA as
    published on the AV-TL (`valid`, `ageVerified`).

## [0.16.0] — 2026-10-21

### Changed — BREAKING

- **`@openeudi/dcql` ^0.3.0** (was ^0.2.0; EID-204). dcql 0.3 `validateQuery`
  rejects queries OpenID4VP 1.0 §6–§7 forbids, and openid4vp now applies it to
  every query it emits or vouches for:
  - `createAuthorizationRequest`, `createSignedAuthorizationRequest` and
    `createDcApiRequest` run `validateQuery` on the query before anything else
    that reads it, and throw dcql's `DcqlValidationError` (`code`, `path`,
    re-exported). Until now they emitted any query unchecked, which a
    conformant wallet then refused.
  - `validateHaipQuery` and `validateCredentialSetQuery` run the dcql rules
    after the HAIP rules, as `HaipValidationError` with the new code
    `INVALID_DCQL` (the message carries dcql's JSON pointer and code); a
    credential id outside `[A-Za-z0-9_-]` is the new `INVALID_CREDENTIAL_ID`.
    `isHaipQuery` follows. `buildHaipQuery` and `buildCredentialSetQuery` check
    what they build the same way (e.g. a `credentialId` with a `.`, or a
    `trustedAuthorities` entry with empty `values`, now throws).
  - Re-exported types widened: `DcqlValidationErrorCode` gained `invalid_id`,
    and `match.unmatched[].reason` (`UnmatchedReason`) gained
    `holder_binding_required`. An exhaustive `switch` over either will flag it.
  - `verifyPresentation` / `verifyAuthorizationResponse` /
    `verifyDcApiResponse` do not validate the query (unchanged).

  **Migration:**
  - Give every credential query a `meta`: `{ vct_values: [...] }` for
    `dc+sd-jwt`, `{ doctype_value: '...' }` for `mso_mdoc`, `{}` for other
    formats. `buildHaipQuery` already does.
  - Use only `[A-Za-z0-9_-]` in credential and claim ids; claim ids must be
    unique, and every claim needs one when `claim_sets` is present.
  - Write `mso_mdoc` claim paths as exactly `['<namespace>', '<element>']`.
  - Drop empty `claims`, `values` or `trusted_authorities` arrays rather than
    sending them empty.
  - Catch `DcqlValidationError` around the request builders if queries come
    from configuration; `HaipValidationError` `INVALID_DCQL` /
    `INVALID_CREDENTIAL_ID` around the HAIP helpers.

### Changed

- `verifyPresentation` fills the dcql 0.3 `DecodedCredential` fields:
  - `vct_aliases`: the issuer-signed `aka_vcts` plus the `vctAncestors` chain,
    transitively, with `vct` left as the credential's real type. This replaces
    substituting the inherited type the presented query asked for into `vct`.
    The presented entry matches exactly as before. A side effect, only for a
    query with several same-format entries: another entry now matches when it
    lists any of the credential's types, where before it was compared with the
    one substituted type.
  - `holder_bound`: `true` for an accepted presentation with a verified KB-JWT
    or mdoc device authentication, `false` for an accepted bearer SD-JWT VC,
    unset when the parser rejected the presentation. **Security-relevant:** a
    bearer presentation accepted under an entry that opts out of holder binding
    no longer satisfies another entry that requires it
    (`holder_binding_required`). The 0.14.0 enforcement that rejects the
    presentation itself (`parsed.valid: false`) is kept, because DCQL alone
    would let an optional `credential_sets` alternative pass.
  - typed `trusted_authorities` (`{ type, values }`) instead of the deprecated
    `trusted_authority_ids`. The 0.14.0 type prefixing (`aki:…`) of both sides
    is kept, so matching and the deprecated hex `aki` alias are unchanged.

### Security (dependencies)

- `@xmldom/xmldom` ^0.9.12 (was 0.9.10) and, through `xml-core` 1.2.6, no more 0.8.x copy
  under `xmldsigjs` / `xadesjs`: fixes the 2026 xmldom advisories (XML injection that bypasses
  `requireWellFormed`, and quadratic-time / ReDoS parsing). The LOTL / national trusted-list
  XMLDSig path parses untrusted XML with it.
- `uuid` ^11.1.1 (missing buffer bounds check in v3/v5/v6).

### Added

- **Credential status for mdoc — the MSO `status` via a CWT Token Status List**
  (draft-ietf-oauth-status-list-21 §5.2, §6.3; ISO/IEC 18013-5 MSO; EID-205).
  Until now `statusPolicy` only checked the SD-JWT VC `status` claim, so a
  revoked or suspended mdoc was accepted until `validUntil`.
  - The mdoc parser reads `status.status_list: { idx, uri }` from the
    issuer-signed MSO and resolves it with the same `statusPolicy`
    (`skip` default / `prefer` / `require`) semantics as SD-JWT VC, after
    signature, digests, validity, trust and device authentication have all
    passed (§8.3). `PresentationResult.credentialStatus` is now set for mdoc
    too. An mdoc without an MSO `status` yields `outcome: 'absent'`.
  - `StatusListResolver` verifies `statuslist+cwt` tokens: fetched with
    `Accept: application/statuslist+cwt`; COSE_Sign1 (untagged, `#6.18` or
    `#6.61(#6.18)`) with `typ` (16) `application/statuslist+cwt` and `alg` in
    the protected header and an attached payload; signer from `x5chain` (33,
    protected or unprotected, not both) validated against the resolver's own
    `trustStore` (anchor never taken from, nor allowed inside, `x5chain` —
    the JWT rule); claims `sub` (2) == uri, `iat` (6), `nbf` (5), `exp` (4),
    `ttl` (65534) and `status_list` (65533) with a byte-string `lst`. Size
    caps, the cache (bounded `ttl`, never past `exp`), concurrent-fetch
    sharing and the HTTPS-only guarded fetcher are shared with the JWT path.
    No new dependency: COSE verification reuses the mdoc `cbor-x` code.
  - `resolve`, `getStatusList` and `prefetch` take an optional
    `{ format: 'jwt' | 'cwt' }` (default `'jwt'`, so existing calls are
    unchanged). The cache is keyed by format and `uri`; an mdoc reference is
    only ever resolved as a CWT.
  - Wired through `verifyPresentation`, `verifyAuthorizationResponse`,
    `verifyDcApiResponse` and `verifyAvPresentation`. The AV profile gains
    `statusPolicy` / `statusListResolver` options (default `'skip'`),
    `credentialStatus` on the result and the failure code
    `'credential_status'`; an AV attestation without `status` still verifies.
  - `decodeStatusList` accepts `lstEncoding: 'bytes'` for a CWT `lst`.
  - Exported `STATUS_LIST_CWT_TYP`, `STATUS_LIST_CWT_MEDIA_TYPE` and the types
    `StatusListTokenFormat`, `StatusListFormatOptions` and
    `StatusListLstEncoding`. `VerifiedStatusList.format` records the format.

## [0.15.0] — 2026-10-21

### Changed — BREAKING

- **The default mDOC SessionTranscript is now the OpenID4VP 1.0 Final
  `OpenID4VPHandover`** (§B.2.6.1, `sessionTranscriptProfile: 'openid4vp-1.0'`).
  Up to 0.14.0 the default was the ISO 18013-7 Annex B `OID4VPHandover` of
  draft-era (ID2/ID3) wallets, so every 1.0 Final mDOC wallet failed device
  authentication unless the caller opted in.
  - It is now also auto-built for **unencrypted `direct_post`** envelopes,
    with the `null` JWK thumbprint the spec requires. Pass `clientId`,
    `responseUri` and `nonce` as before. Previously no transcript was built
    there and the mDOC parser failed closed.
  - The transcript is only built when the presented credential is
    `mso_mdoc`. An encrypted SD-JWT VC response therefore no longer needs
    `verifierEncryptionJwk` under the 1.0 profile.
  - An encrypted `mso_mdoc` response under the new default throws
    `MissingVerifierEncryptionKeyError` when `verifierEncryptionJwk` is missing
    (unchanged behaviour of the 1.0 profile). The error is now raised after
    decryption instead of before.
  - The Annex B layout is renamed `'oid4vp-draft-annex-b'`. `'iso-18013-7'`
    stays as a deprecated alias and will be removed in 1.0.0.

  **Migration:**
  - Verifying 1.0 Final wallets with the default: pass `verifierEncryptionJwk`
    (the public JWK you sent in `client_metadata.jwks`) for `direct_post.jwt`.
    If you passed `sessionTranscriptProfile: 'openid4vp-1.0'` already, nothing
    changes. If you built the null-thumbprint transcript by hand for
    `direct_post`, you can drop it.
  - Still verifying draft-era wallets: pass
    `sessionTranscriptProfile: 'oid4vp-draft-annex-b'`.
  - Callers who pass `mdocSessionTranscript` explicitly are unaffected.

### Added

- **`verifier_info` in authorization requests** (OpenID4VP 1.0 §5.1). Both
  `createSignedAuthorizationRequest` and `createAuthorizationRequest` accept
  `verifierInfo: Array<{ format, data, credential_ids? }>` and emit it as
  `verifier_info`: in the signed request object, or JSON-encoded in the
  unsigned URI. It is validated before signing: a non-empty array, a non-empty
  `format`, a non-empty `data` string or an object, and `credential_ids`, when
  present, non-empty and each matching a DCQL Credential Query `id`. For the
  two ETSI TS 119 472-2 V1.3.1 formats, `registrar_dataset` and
  `registration_cert`, `credential_ids` is refused (RO-03, RO-14), each may
  appear once, `registrar_dataset` data must be a non-empty object (RO-05) and
  `registration_cert` data a string (RO-16). Failures raise
  `SignedRequestBuildError` with the new code `invalid_verifier_info` (signed)
  or `TypeError` (unsigned).
- **`registrarDatasetVerifierInfo(dataset)`** builds the `registrar_dataset`
  element that TS 119 472-2 V1.3.1 makes mandatory (RO-01 to RO-12), with the
  TS 119 475 V1.2.1 Annex B member names: `identifier`, `srvDescription`,
  `registryURI`, `intendedUseIdentifier`, `purpose`, `policyURI` and the
  optional `credential`.
- **`registrationCertVerifierInfo(wrprc)`** builds the `registration_cert`
  element (RO-13 to RO-16) from a WRPRC: a compact JWS whose header `typ` is
  `rc-wrp+jwt`, or CWT bytes. `data` is the base64url encoding of the
  serialized certificate, as RO-16 requires.
- Exported types `VerifierInfo`, `RegistrarDataset`, `RegistrarIdentifier`,
  `RegistrarCredential`, `RegistrarClaim` and `MultiLangString`.
- **Credential status checking — IETF Token Status List
  (draft-ietf-oauth-status-list-21) for SD-JWT VC.** A revoked or suspended
  credential was previously accepted until its `exp`. New `StatusListResolver`
  fetches the `statuslist+jwt` token at `status.status_list.uri`
  (`Accept: application/statuslist+jwt`, HTTPS-only guarded fetcher), verifies
  `typ`, the `x5c` signature and chain against its own `trustStore` (anchor
  never taken from, nor allowed inside, `x5c`), `sub === uri`, `iat`, `nbf`,
  `exp` and `ttl`, decompresses `lst` with a size cap and reads the entry at
  `idx` (`bits` 1/2/4/8). Verified lists are cached in memory by `uri` for the
  bounded `ttl`, never past `exp`; concurrent lookups share one fetch;
  `prefetch(uri)` refreshes out of band. Decompression uses
  `DecompressionStream('deflate')` with a `node:zlib` fallback — no new
  dependency.
- **`statusPolicy: 'skip' | 'prefer' | 'require'`** and
  **`statusListResolver`** on `ParseOptions` / `VerifyOptions`, mirroring
  `revocationPolicy`. A definitive INVALID / SUSPENDED / unrecognised status, an
  out-of-range `idx`, or a malformed `status` claim (HAIP 1.0 §6.1: it MUST
  contain `status_list`) yields `valid: false`. When no statement can be made
  (list unreachable, untrusted, expired, malformed) `'prefer'` accepts with
  `credentialStatus.outcome: 'unavailable'` and a `warning`; `'require'` throws
  `StatusListError`. The status is checked only after the credential itself
  validated (§8.3).
- `PresentationResult.credentialStatus` exposes the outcome (`checked` /
  `unavailable` / `absent` / `rejected`, status, raw value, `uri`, `idx`,
  `fromCache`).
- `StatusListError` (`code: 'status_list_error'`, `reason`, `uri`), plus
  `decodeStatusList` / `readStatusValue` and the related types.
- **W3C Digital Credentials API, phase 1: OpenID4VP over the DC API**
  (OpenID4VP 1.0 Final Appendix A, HAIP 1.0 §5.2).
  - `createDcApiRequest(input, query)` returns the
    `{ protocol, data }` entry for
    `navigator.credentials.get({ digital: { requests } })`.
    - `openid4vp-v1-unsigned`: plain parameters, no `client_id` (§A.2).
    - `openid4vp-v1-signed`: JWS Request Object in `data.request`, with
      `client_id` (`x509_hash` by default, as HAIP requires; `x509_san_dns`
      also accepted) and the REQUIRED `expected_origins`.
    - `response_mode` `dc_api.jwt` (default) or `dc_api`. For `dc_api.jwt` the
      encryption JWK is published with `use: 'enc'` and a `kid` (its RFC 7638
      thumbprint when absent). A JWK with a private `d` member is refused.
    - `verifierInfo` is accepted and validated as for the redirect-flow
      builders (`DcApiRequestBuildError('invalid_verifier_info')`) and emitted
      as `verifier_info`: in the Request Object when signed, as a plain `data`
      member when unsigned.
    - Signed requests run the same certificate checks as
      `createSignedAuthorizationRequest`, including `trust_anchor_in_chain`.
    - Only protocol strings from the W3C closed set are emitted.
      `openid4vp-v1-multisigned` and `org-iso-mdoc` throw
      `DcApiRequestBuildError('unsupported_protocol')`.
  - `verifyDcApiResponse(response, query, options)`:
    - KB-JWT `aud` must be `origin:<origin>`, also for signed requests
      (§A.4, §B.3.6). `requireKeyBinding` defaults to `true` on this path.
    - mDOC uses the new `OpenID4VPDCAPIHandover` SessionTranscript (§B.2.6.2).
    - The KB-JWT audience is always derived from `origin`, so the 0.14.0
      `MissingAudienceError` cannot be hit (or bypassed) here; a conflicting
      caller `audience` throws `DcApiResponseError('audience_conflict')`.
    - An unencrypted response to a `dc_api.jwt` request is rejected.
    - Wallet error objects (`data: { error }`, also inside a decrypted
      `dc_api.jwt` payload) throw the 0.14.0 `WalletErrorResponseError`
      (`code`, `description`, `state`, `uri`).
    - `statusPolicy` / `statusListResolver` and the other `VerifyOptions` are
      forwarded as for `verifyAuthorizationResponse`.
  - `buildOpenID4VPDCAPIHandoverSessionTranscript({ origin, nonce, verifierEncryptionJwk? })`,
    checked against the spec's example vector.
  - `DC_API_PRESENTATION_PROTOCOLS`, `DcApiRequestBuildError`,
    `DcApiResponseError` and the `DcApi*` types.
- **EU Age Verification (AV app) profile: the OpenID4VP fallback**
  (AV technical specification Annex A §A.4, §A.6; EID-202). New `src/av/` module.
  - `createAvAuthorizationRequest(input)` builds the unsigned by-value request
    `av://?response_type=vp_token&response_mode=direct_post&client_id=redirect_uri:<response_uri>&response_uri=…&nonce=…&dcql_query=…&client_metadata=…[&state=…]`.
    The DCQL query asks for `mso_mdoc` doctype `eu.europa.ec.av.1`, claim
    `["eu.europa.ec.av.1", "age_over_NN"]` (default 18).
    - `response_uri` must be `https:`. The nonce is generated (256 bits) unless supplied.
    - `client_metadata.vp_formats_supported` is `mso_mdoc` with ES256/ES384/ES512,
      as the reference verifier advertises. `vpFormatsSupported: null` omits it.
    - `baseUri` can replace `av://`.
    - The result carries everything verification needs (`clientId`, `responseUri`,
      `nonce`, `state`, `ageThreshold`, `credentialId`).
  - `verifyAvPresentation(body, { request, trustStore })` verifies the AV app's
    `direct_post` form body. It accepts a raw string, `URLSearchParams` or a parsed object.
    - Wallet errors throw `WalletErrorResponseError`. A `state` or `vp_token`
      shape mismatch throws `AvResponseError`.
    - The `DeviceResponse` must hold exactly one `eu.europa.ec.av.1` document.
      Only boolean `age_over_NN` elements in namespace `eu.europa.ec.av.1` are
      accepted: any other attribute rejects the presentation (§A.4.2 "SHALL NOT
      include any other attribute"). Device-signed elements are rejected too.
    - The issuer chain is validated against the caller's AV trust store.
      Device authentication runs over the OpenID4VP 1.0 `OpenID4VPHandover`
      `[redirect_uri:<response_uri>, nonce, null, response_uri]`, verified
      byte-for-byte against the Annex A example.
    - Returns `{ valid, ageVerified, ageOver, … }`. `age_over_18: false` is a
      valid presentation with `ageVerified: false`.
  - `AvRequestBuildError`, `AvResponseError` and the `AV_*` constants are exported.
- `ParseOptions.mdocDocumentSignerEkus` (and `ChainBuilderOptions.documentSignerEkus`):
  the Document Signer EKUs accepted for `mso_mdoc` chains. The default is
  unchanged (`1.0.18013.5.1.2`). The AV reference issuer signs with EKU
  `1.3.130.2.0.0.1.2`, which `verifyAvPresentation` accepts.
- `SessionTranscriptProfile` type export.

### Notes

- `statusPolicy` defaults to `'skip'`, so existing callers see no change. The
  intent is to default to `'prefer'` in 1.0.
- The mdoc MSO `status` (`statuslist+cwt`) is not evaluated yet;
  `statusPolicy` applies to SD-JWT VC only.

### Internal

- The signed-request certificate checks (SAN/hostname binding, signer key
  match, `self_signed_leaf`, `trust_anchor_in_chain`) and `x5c` signing moved
  from `createSignedAuthorizationRequest` into a shared `request-signing`
  module used by both request builders. Behaviour and error codes are
  unchanged.

## [0.14.0] — 2026-10-21

### Security (library)

- KB-JWT audience is now bound to the verifier by default
  ([GHSA-3v3j-fghh-r2gg](https://github.com/openeudi/openid4vp/security/advisories/GHSA-3v3j-fghh-r2gg)).
  `aud` was previously checked only when the optional `audience` option was passed, so a
  presentation could be relayed from one verifier to another.
- The DCQL `require_cryptographic_holder_binding` requirement (default `true`) is now
  enforced ([GHSA-r8q4-fcxm-v42q](https://github.com/openeudi/openid4vp/security/advisories/GHSA-r8q4-fcxm-v42q)).
  A bearer SD-JWT VC without `cnf` and without a KB-JWT was previously accepted with
  default options.

### Changed — BREAKING

- **A key binding JWT is now always checked against the verifier's
  identifier.** OpenID4VP 1.0 Appendix B.3.6 requires the KB-JWT `aud` to be
  the Client Identifier, and RFC 9901 §7.3 makes checking it part of holder
  binding. `aud` was previously compared only when `audience` was passed, so a
  presentation made out to another verifier — or with no `aud` at all — was
  accepted. Now:
  - `verifyAuthorizationResponse` uses `clientId` as the default `audience`.
  - Verifying a KB-JWT with no `audience` available throws the new
    `MissingAudienceError`.
  - `aud` must be a single string equal to `audience`. A missing `aud`, a
    foreign one, and an array `aud` (even one containing the audience) yield
    `valid: false` — B.3.6 names one value.

  **Migration:** pass `clientId` to `verifyAuthorizationResponse` (most
  callers already do for mDOC), or `audience` to `verifyPresentation` /
  `parsePresentation` / the parsers — the `client_id` you put in the request.

- **KB-JWT `typ`, `iat`, `nonce`, `sd_hash` and `aud` are required, and `iat`
  is bounded** (RFC 9901 §4.3, §7.3 steps 5d–5e). `typ` must be `kb+jwt`
  (`application/kb+jwt` accepted). `iat` may be at most `kbJwtMaxAge` seconds
  old (new option, default 300) and not in the future, each widened by
  `clockSkewTolerance` (default 60). KB-JWT claim failures now report
  `Key binding JWT claim validation failed: …` instead of the signature
  message. The OIDF `1final-neg-iat-past` / `-future` profiles, previously
  flagged as a known divergence, are now expected to reject like every other
  negative profile.

  **Migration:** none for conformant wallets. Raise `kbJwtMaxAge` if your flow
  holds a presentation longer than five minutes before verifying it.

- **The DCQL query's `require_cryptographic_holder_binding` is enforced.**
  OpenID4VP 1.0 §6.1 makes it default to `true`, but the library only required
  a KB-JWT when the credential carried `cnf`, so a bearer SD-JWT VC (no `cnf`,
  no KB-JWT) verified with default options — and could be replayed, since the
  nonce never entered the check. `verifyPresentation` and
  `verifyAuthorizationResponse` now return `valid: false` for such a
  presentation unless the credential query it matched opts out. mDOC is
  unchanged (device authentication was already mandatory). The parsers and
  `parsePresentation`, which do not see the query, keep their behaviour.

  **Migration:** to accept bearer credentials on purpose, set
  `require_cryptographic_holder_binding: false` on that credential query.

- **`trusted_authorities` `aki` values are base64url AuthorityKeyIdentifier
  key ids, and each value matches only its own type.** OpenID4VP 1.0 §6.1.1.1
  defines an `aki` value as the base64url KeyIdentifier of an
  AuthorityKeyIdentifier in the credential's chain; the library offered the
  anchor's SKI in hex, so a conformant query never matched. Ids are now
  derived from the AKI of every certificate in the validated chain plus the
  anchor SKI, all base64url. dcql 0.2.0 pools the values of all
  `trusted_authorities` entries, so an `etsi_tl` entry could be satisfied by an
  `aki` id; matching now tags both sides with their type. `LotlTrustStore`
  anchors also offer `etsi_tl` ids (the national TL URL and the LOTL URL).

  **Migration:** send base64url `aki` values. For one release a hex value that
  denotes the same key id still matches, with a one-time `console.warn`.
  `TrustEvaluationResult.trustedAuthorityIds` and
  `TrustAnchor.trustedAuthorityIds` are deprecated in favour of the typed
  `trustedAuthorities`; untyped ids set by a custom `TrustStore` keep matching
  every type, as before.

- **Certificates with unrecognised critical extensions are rejected**
  (RFC 5280 §4.2), with `CertificateChainError` reason
  `unrecognised_critical_extension`, on every certificate of the path (the
  configured trust anchor itself is exempt, as RFC 5280 §6.1 treats it as
  input). Recognised: basicConstraints, keyUsage, extKeyUsage, subjectAltName,
  nameConstraints, AKI, SKI, CRL distribution points, authorityInfoAccess and
  qcStatements. Policy processing is not implemented, so a critical
  certificatePolicies, policyConstraints, policyMappings or inhibitAnyPolicy is
  refused instead of ignored. Checked against the certificates in the
  2026-04-23 LOTL snapshot and the EU acceptance PID-providers list: critical
  extensions there are basicConstraints, keyUsage, extKeyUsage and (one
  Norwegian PID provider) qcStatements, all accepted.

  **Migration:** none expected for EU trusted-list certificates. A private CA
  that marks another extension critical has to stop doing so.

- **`createSignedAuthorizationRequest` rejects a `certificateChain` that ends
  in the trust anchor.** HAIP 1.0 §5: "The X.509 certificate of the trust
  anchor MUST NOT be included in the x5c JOSE header". A chain of more than one
  certificate whose last certificate is self-signed now throws
  `SignedRequestBuildError` with the new code `trust_anchor_in_chain`.

  **Migration:** pass the leaf and intermediates only.

### Added

- `WalletErrorResponseError` (`code`, `description`, `state`, `uri`): thrown by
  `verifyAuthorizationResponse` for an OpenID4VP 1.0 §8.5 error response
  (`access_denied`, `wallet_unavailable`, …), encrypted or not, instead of a
  bare `TypeError`.
- SD-JWT VC type inheritance for DCQL `vct_values` (OpenID4VP 1.0 Appendix
  B.3.5): a credential also matches through its issuer-signed `aka_vcts`
  (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2) and through the new
  `vctAncestors` option, e.g. `{ 'urn:eudi:pid:de:1': ['urn:eudi:pid:1'] }`
  (walked transitively). `parsed.vct` still reports the credential's own type;
  the new `PresentationResult.akaVcts` carries the issuer-signed aliases. Type
  Metadata is not fetched. Built on dcql 0.2.0's exact `vct` match until dcql
  gains alias support.
- `_sd_alg` support: `sha-384` and `sha-512` in addition to the default
  `sha-256`, for disclosure digests and the KB-JWT `sd_hash`. Any other value
  is rejected (it was previously ignored and SHA-256 used).
- `createSignedAuthorizationRequest` gives an encryption JWK without `kid` its
  RFC 7638 thumbprint as `kid` (OpenID4VP 1.0 §5.1 requires one); a `kid` you
  set is kept. The JSDoc and README now state HAIP's per-request ephemeral
  encryption key rule.
- `TrustEvaluationResult.trustedAuthorities` / `TrustAnchor.trustedAuthorities`
  (typed `{ type, value }` ids) and the `TrustedAuthorityId` type.
- `"engines": { "node": ">=22" }`. CI runs on Node 22 and 24 (it ran only on
  Node 20, which reached end of life on 2026-04-30); the release-time OIDF run
  uses Node 24, like `release.yml`.

### Fixed

- A disclosure presented twice and a digest that appears more than once (in
  the payload or a disclosed value) are rejected (RFC 9901 §4.2, §7.1).
- Disclosures are decoded as strict base64url. The standard-alphabet decoder
  used before silently mis-decoded `-` / `_`; a standard-alphabet disclosure is
  now rejected.
- `trustedCertificates` is optional in `ParseOptions`. It was `@deprecated`
  but still required, even alongside `trustStore`.

### Documentation

- README: the quick start and query examples used `age_over_18`,
  `issuer.country` and `vctValues: ["https://pid.eu/v1"]`; they now use
  `vct` `urn:eudi:pid:1` with `birthdate` (the SD-JWT VC PID name;
  `birth_date` is the mdoc element). The `credential_sets` example used
  `urn:eu.europa.ec.eudi:pid:1`. "Custom parsers" implied a registration API
  that does not exist and is replaced by a description of the fixed parsers.
  The mDOC section claimed only the `eu.europa.ec.eudi.pid.1` namespace is
  extracted. The OIDF coverage statement now lists what the workflows run.
  ARF references point at v3.0.0. The eIDAS Pro link is `eidas-pro.com`.
- `CredentialClaims`' named `age_over_18`, `age_over_21`, `nationality`,
  `resident_country` and `family_name_birth` fields are `@deprecated` (not PID
  claims; the PID has `nationalities`). The type is otherwise unchanged and
  stays assignable to `Record<string, unknown>`.
- JSDoc: `revocationPolicy` (`'prefer'` / `'require'` are implemented), the
  `mdocSessionTranscript` handover choice, `buildCredentialSetQuery`'s PID
  identifiers.
- SECURITY.md: supported versions are 0.13.x.

## [0.13.0] — 2026-10-02

### Changed — BREAKING

- **SD-JWT VC `typ` is now enforced: only `dc+sd-jwt` is accepted.**
  draft-ietf-oauth-sd-jwt-vc-19 (2026-09-15) removed the transitional
  `vc+sd-jwt` media type. The parser previously did not check `typ` at all, so
  any value — or none — was accepted. A missing or foreign `typ` now yields
  `valid: false`; `application/dc+sd-jwt` and case variants are accepted per
  RFC 7515 §4.1.9.

  **Migration:** wallets that still emit `vc+sd-jwt` can be accepted
  temporarily with the new, already-deprecated `allowLegacyVcSdJwtTyp: true`
  option. It will be removed in 1.0.0.

- **Trust-module fetches are now SSRF-guarded by default.** When no `fetcher`
  is supplied, `LotlTrustStore` (LOTL + national TLs), CRL and OCSP retrieval
  previously used bare `globalThis.fetch`. They now use
  `createGuardedFetcher({ allowHttp: true })`, which refuses loopback / private
  / link-local / cloud-metadata targets (by literal and by every resolved
  address, IPv4 and IPv6 incl. `::ffff:` mapped), follows at most 3 redirects
  and re-validates each, never downgrades https → http, and bounds each
  exchange at 15 s and 16 MiB.

  **Migration:** a CA, OCSP responder or trusted list on a private network
  needs `fetcher: createGuardedFetcher({ allowHttp: true, allowPrivateNetworks: true })`.
  Supplying any `fetcher` keeps working exactly as before — it replaces the
  default, guards included.

### Added

- `createGuardedFetcher(options)` — a `Fetcher` implementing the SD-JWT VC
  draft-19 HTTP retrieval rules (HTTPS-only by default, SSRF checks including
  redirect targets, manual bounded redirects, timeout, streamed size cap).
  Exported for applications that dereference SD-JWT VC URLs themselves —
  this library does not fetch issuer metadata, `jwks_uri`, Type Metadata,
  status lists or `x5u`. DNS-rebinding limits are documented in the README.
- `GuardedFetchError` (`code: 'guarded_fetch_rejected'`, `reason`, `url`) and
  `GUARDED_FETCH_DEFAULTS`.
- **IACA → document-signer chain building on the `trustStore` path.** The EU
  PID-providers list (ETSI TS 119 602) publishes, for most providers, an ISO
  18013-5 IACA root rather than the document-signer (DS) certificate that signs
  the PID. A credential whose signer chains to an anchor now verifies;
  previously the parsers handed only `x5c[0]` / `x5chain[0]` to the chain
  builder and dropped the rest, and a DS listed *as* the anchor was never found
  because anchors were looked up by the signer's issuer only.
  - `x5c[1..]` (SD-JWT VC) and `x5chain[1..]` (mDOC) are passed to the chain
    builder as untrusted path candidates. They are never anchors.
  - A signer that is itself in the trust store (byte-identical DER) is trusted
    directly — the "listed cert is the signer" case keeps working.
  - Every certificate must be valid now **and** at issuance time (MSO
    `validityInfo.signed`, SD-JWT `iat`).
  - `mso_mdoc` chains follow the ISO 18013-5 Annex B profile: the DS must carry
    EKU `1.0.18013.5.1.2` (new `CertificateChainError` reason
    `extended_key_usage`) and `keyUsage` is mandatory on the DS and every CA.
    SD-JWT VC is unaffected. A directly-listed signer is exempt.
  - Chains are capped at 5 certificates (leaf and anchor included).

  `trustedCertificates` (deprecated) is unchanged and still byte-equality only:
  to accept IACA-issued PIDs, pass `trustStore: new StaticTrustStore([...])`.

### Fixed

- `createGuardedFetcher` treated a host that resolved to **no** addresses as
  public — the private-address check found nothing to block and let the
  request through. Node's resolver throws instead of answering empty, so the
  built-in default was not affected, but an injected `lookup` that returns `[]`
  (for example one that swallows its own errors) waved every hostname through.
  An empty answer now fails closed as `dns_resolution_failed`, on the first
  request and on every redirect hop. Runtimes without `node:dns` keep their
  documented literal-only checks; that case is distinguished from an empty
  answer.
- On the `trustStore` path a credential's `x5c` / `x5chain` may carry at most
  10 certificates, signer included; a longer list is rejected as `MalformedCredentialError` before any entry is
  parsed. Every entry is parsed and triggers its own trust-store lookup, so
  the presenter-controlled list length bounded work the chain builder's own
  limits did not. Real lists carry two to four. `trustedCertificates`
  (byte-equality) is unaffected, as it never reads past the signer.
- `ChainBuilder` could loop forever on a self-issued, non-anchor certificate in
  the intermediates pool; it now refuses certificates already on the path and
  enforces the maximum chain length. Not reachable from the parsers before this
  release (they passed no intermediates), but it is with the change above.
- Among intermediates sharing a Subject DN, the issuer is now chosen by
  verified signature rather than first DN match, so a look-alike in `x5c`
  cannot shadow the genuine issuer. Closure at an anchor is still by signature
  only — Subject-DN equality never establishes trust (GHSA-4c2f-96cf-f5fc).
- `ChainBuilder` committed to the first intermediate whose signature verified
  and gave up if that certificate then failed a check, even when another
  intermediate with the same Subject DN would have completed the chain. A
  re-issued intermediate shipped next to its expired predecessor was rejected
  or accepted depending only on the order of `x5c` / `x5chain`, and of two
  cross-signed copies only the first listed was ever tried. Path search now
  backtracks across same-subject candidates, so the result no longer depends
  on certificate order. Anchors are still tried in order, first valid chain
  wins. Not reachable before this release (the parsers passed no
  intermediates).
- Because backtracking lets an attacker-supplied pool force work exponential
  in its size, each `build` is capped at 32 signature verifications (new
  `ChainBuilderOptions.maxSignatureChecks`), shared across all anchors tried.
  Exhausting it fails closed with `CertificateChainError` reason
  `path_length`. A legitimate path needs a handful.
- `TrustEvaluator` de-duplicated candidate anchors by serial number, which is
  only unique per issuer, so a distinct anchor from another CA with the same
  serial was silently dropped. `CompositeTrustStore` de-duplicated by SKI, which
  dropped a re-issued certificate on the same key. Both now de-duplicate by DER
  identity.

## [0.12.0] — 2026-09-24

### Added

- `buildCredentialSetQuery` and `validateCredentialSetQuery` — build and validate a
  DCQL `credential_sets` disjunction, offering a wallet a choice of credentials in
  a single request.

  The motivating case is a proof-of-age check, which has two mutually exclusive
  routes in two formats: a Proof-of-Age attestation (`mso_mdoc`, `age_over_18` in
  namespace `eu.europa.ec.av.1`) or a PID (`dc+sd-jwt`, `birth_date`, threshold
  computed by the verifier). The PID carries **no** age attribute — CIR (EU)
  2024/2977 Annex, as amended by CIR 2026/1731, defines no `age_over_*`
  attribute — and proof-of-age attestations have almost no issuer coverage yet, so
  a verifier that wants the privacy-preserving answer *when available* and a
  working answer *otherwise* has to offer both at once. `buildHaipQuery` builds
  exactly one credential and cannot express this.

  Option order is a privacy preference signal — most-preferred first. Wallets are
  not obliged to honour it.

  **Scope and ceiling.** This delivers the plain `mso_mdoc` attestation path over
  OpenID4VP. It is **not** Zero-Knowledge Proof age verification. The AV technical
  specification (Annex A, §A.6) is explicit that ZKP — its *preferred* mechanism —
  "[is] not supported over OpenID for Verifiable Presentations in this version of
  the profile, since no standardized DCQL query for requesting Zero-Knowledge Proof
  is available"; ZKP rides only the W3C Digital Credentials API. Plain mDoc is the
  profile's designated fallback for that transport, so this is the best OpenID4VP
  can do by the specification's own design. Revisit when a standardised DCQL ZKP
  query exists.

  Doctype and namespace are both `eu.europa.ec.av.1`, per
  [`av-doc-technical-specification`](https://github.com/eu-digital-identity-wallet/av-doc-technical-specification/blob/8b9728752bd8d8eede6077ade4be8900949de2d9/docs/annexes/annex-A/annex-A-av-profile.md)
  Annex A §A.4.1–§A.4.2, pinned to commit `8b97287` (spec 1.1.0, merged 2026-09-02
  via PR #66 — the newest tag is still `v1.0.6`, so the content is untagged).
  Because the doctype and namespace are the same string, `buildHaipQuery`'s
  existing doctype→namespace fallback already produces the correct claim path and
  `HAIP_DOCTYPE_NAMESPACES` needs no new entry.

  New `HaipValidationError` codes: `EMPTY_OPTIONS`, `DUPLICATE_CREDENTIAL_ID`,
  `MISSING_CREDENTIAL_SETS`, `UNKNOWN_OPTION_REFERENCE`.

### Fixed

- A missing `xmldsigjs` crypto engine was reported as a trusted-list **signature**
  failure. `LotlFetcher.verifyAgainst` caught every exception and returned
  `false`, so `XMLJS0014: WebCrypto module is not found` was indistinguishable
  from a genuine trust failure and surfaced as
  `no signing anchor verified the signature on <url>` — sending at least one
  integrator bisecting a perfectly valid national trusted list. The per-anchor
  `console.warn` did name the real error, but it was emitted once per anchor and
  buried under the summary line that callers actually act on.

  `LotlFetcher` now checks for a registered engine up front and throws the new
  `LotlConfigurationError` before performing any network request. Because a
  missing engine means *no* list can ever verify, it is not subject to the
  §8.4 graceful-degradation paths: `NationalTlResolver` re-throws it instead of
  warning and skipping the country, and `LotlTrustStore` re-throws it instead of
  serving a cached snapshot it could never refresh. Ordinary per-country fetch
  and signature failures degrade exactly as before.

  Note for anyone writing a similar guard: `xmldsig.Application.crypto` is a
  getter that *throws* when no engine is registered rather than returning a
  falsy value, so `if (!Application.crypto)` propagates the raw `XmlError`
  instead of catching the condition.

  Engine registration stays the consumer's responsibility — the library does not
  pick a WebCrypto provider on your behalf — but that requirement is now
  documented in the README next to `trustStore`, and the failure names the
  remedy. ([#51](https://github.com/openeudi/openid4vp/issues/51))

### Unchanged (deliberately)

- `validateHaipQuery` still rejects `credential_sets` with
  `CREDENTIAL_SETS_DISALLOWED`, and `isHaipQuery` still returns `false` for a
  disjunction. HAIP-minimal genuinely disallows them; the disjunction is a
  separate profile with its own validator, not a relaxation of this one. Tests pin
  that boundary against erosion.
- `buildHaipQuery`, `verifyPresentation` and `verifyAuthorizationResponse` are
  unchanged. `verifyPresentation` already resolved dual-format `credential_sets`
  queries (0.11.1, #48), and `verifyAuthorizationResponse`'s
  `MultipleCredentialsNotSupportedError` guard never applied to a disjunction — a
  wallet satisfies one option and returns one presentation. Both were verified
  against the Proof-of-Age shape before this work began, and a response presenting
  *both* options is still rejected.

## [0.11.1] — 2026-09-06

### Fixed

- `verifyPresentation` resolved which query credential a presentation represents
  by format alone, so a query listing several entries of the same format —
  distinguished only by `vct_values` or `doctype_value` — attributed the
  presentation to whichever was listed first. `match.credentialId` then named a
  credential the wallet never presented, and the same query id appeared in both
  `matches` and `unmatched` carrying a `vct_mismatch` against the entry it was
  reported as matching. Resolution now narrows by format and then by credential
  type, falling back to first-listed only when no entry constrains the type.
  Verification itself was sound — the credential did satisfy some entry's
  constraints — but a verifier branching on `match.credentialId` could attribute
  a presentation to the wrong requested credential.
  ([#41](https://github.com/openeudi/openid4vp/issues/41))

  `verifyAuthorizationResponse` was never affected: it resolves by `queryIds[0]`,
  the id the wallet actually keyed the `vp_token` with.

## [0.11.0] — 2026-09-01

### Changed (library)

- **BREAKING**: `createSignedAuthorizationRequest` now rejects a self-signed leaf
  certificate with the new `SignedRequestBuildError` code `self_signed_leaf`.
  HAIP 1.0 Final requires the verifier certificate to chain to a trust anchor the
  wallet recognises; a self-signed leaf asserts an identity nothing vouches for,
  so a wallet enforcing the profile rejects the request object. Failing at build
  time is better than emitting a request no conforming wallet will honour. This
  closes the last of the README's documented HAIP divergences.

  The check calls `isSelfSigned()`, which verifies the leaf's signature against
  its own public key rather than comparing Subject and Issuer DN strings. That
  distinction is deliberate: [GHSA-4c2f-96cf-f5fc](https://github.com/openeudi/openid4vp/security/advisories/GHSA-4c2f-96cf-f5fc)
  was a DN-string-equality bug, and a DN comparison here would both miss a
  re-signed certificate and wrongly reject a legitimate cross-signed one.

  **Migration:** verifiers using a self-signed certificate for their own identity
  should move to a CA-issued certificate. To keep the previous behaviour for local
  development or tests, pass `allowSelfSignedCertificate: true`.

  Verification of wallet presentations is unaffected — this concerns only the
  verifier's own request-signing certificate.

### Added (library)

- `allowSelfSignedCertificate?: boolean` on `SignedAuthorizationRequestInput`
  (default `false`), the documented escape hatch for the above.

## [0.10.1] — 2026-09-01

### Fixed

- `verifyAuthorizationResponse` and `verifyPresentation` decided how to decode a
  presentation — and which credential id to label the match with — from
  `query.credentials[0]`, the first entry in the DCQL query, rather than the
  credential the wallet actually presented. For a single-format query the two
  coincide, so nothing was visibly broken; for a dual-format query built with
  `credential_sets`, only the first-listed format could ever verify and the other
  failed closed with a parser error. `verifyAuthorizationResponse` now resolves
  the presented credential by `queryIds[0]` (the id the wallet keyed the
  `vp_token` with, per OpenID4VP 1.0 §8.1); `verifyPresentation`, which has no
  `queryIds`, resolves by the presented credential's format. Reported and fixed
  by @mkascel (eudi-verify) in [#39](https://github.com/openeudi/openid4vp/pull/39).

  Two notes for consumers: a `vp_token` keyed by an id absent from the query
  previously decoded as `query.credentials[0]`'s format and could verify, and now
  fails closed. `match.credentialId` remains unreliable for *same-format*
  multi-credential queries — pre-existing, tracked in
  [#41](https://github.com/openeudi/openid4vp/issues/41).

## [0.10.0] — 2026-08-20

### Added

- `createSignedAuthorizationRequest` accepts `clientIdPrefix?: 'x509_san_dns' | 'x509_hash'`,
  defaulting to `x509_san_dns` so existing callers are unaffected. With `x509_hash`
  the `client_id` becomes `x509_hash:` followed by the unpadded base64url SHA-256
  hash of the DER-encoded leaf certificate, per OpenID4VP 1.0 Final §5.9.3
  (unpadded base64url per RFC 7515 §2). HAIP 1.0 Final mandates this prefix, and
  the OpenID Foundation's HAIP verifier test plan pins it with no variant to
  override — so `x509_san_dns` alone cannot pass that plan. `hostname` is now
  optional and is required only for `x509_san_dns`; when supplied under either
  prefix it is still validated against the leaf certificate's SAN DNSName values.
  A new `missing_hostname` `SignedRequestBuildErrorCode` covers the
  hostname-required case.
- This prefix is validated by an OpenID Foundation certification: eudi-verify 1.4.0
  is [certified](https://openid.net/certification/certified-oid4vp-haip-final/)
  for `OID4VP-1.0+HAIP-1.0 Verifier iso_mdl direct_post.jwt` (14 Aug 2026), a plan
  that pins `client_id_prefix=x509_hash`.

### Removed

- `createSignedAuthorizationRequest` no longer emits the singular
  `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc`
  `client_metadata` fields. Those fields were removed from OpenID4VP before 1.0
  Final; the OIDF conformance suite reads `alg` from `client_metadata.jwks` and
  `enc` from `encrypted_response_enc_values_supported`, not from the singular
  fields.

## [0.9.3] — 2026-08-20

### Fixed

- The `reflect-metadata` auto-load shipped in 0.9.2 did not actually work in the
  published bundles: importing `@openeudi/openid4vp` on 0.9.2 without a
  consumer-side `import "reflect-metadata"` still threw
  `tsyringe requires a reflect polyfill`, in **both** the ESM and CJS builds.
  `src/index.ts` did import the polyfill first, but the bundler hoists external
  *named* imports (`@peculiar/x509`) above bare side-effect imports, so tsyringe
  evaluated before the polyfill was installed. The build now injects the polyfill
  ahead of the entry module (`inject` in `tsup.config.ts`), which holds for both
  formats. Consumers on 0.9.2 who added a manual preload can drop it. Reported by
  @mkascel (eudi-verify) in [openeudi/core#8](https://github.com/openeudi/core/issues/8).
  `tests/bundle-polyfill-order.test.ts` now imports both built bundles in a clean
  child process with no preload, so this cannot regress silently again.

## [0.9.2] — 2026-07-24

### Fixed

- The package now imports the `reflect-metadata` polyfill at its entry point and
  declares it as a runtime dependency (previously dev-only). `@openeudi/openid4vp`
  transitively depends on `@peculiar/x509`, which uses `tsyringe` and reads
  decorator metadata at runtime; consumers that did not already load the polyfill
  (e.g. apps without a DI framework) hit a `Reflect.getMetadata is not a function`
  crash unless they knew to `import "reflect-metadata"` before this library. The
  polyfill now loads automatically in both ESM and CJS output. Reported by
  @mkascel (eudi-verify) in [openeudi/core#8](https://github.com/openeudi/core/issues/8).
- `VERSION` export now reports the correct package version (was stale at `0.8.0`).

## [0.9.1] — 2026-07-14

### Security (library)

- `verifyAuthorizationResponse`'s encrypted-response path now fails loudly with a
  new `MissingVerifierEncryptionKeyError` when `sessionTranscriptProfile` is
  `'openid4vp-1.0'` and no `verifierEncryptionJwk` is supplied, instead of
  silently building a null-thumbprint `OpenID4VPHandover` SessionTranscript that
  would only surface as an opaque device-authentication failure later.
- `buildOpenID4VPHandoverSessionTranscript`'s internal JWK thumbprint
  computation now throws if the EC JWK is missing `crv`, `x`, or `y`, instead of
  silently interpolating `"undefined"` into the canonical JSON and producing a
  well-formed but incorrect thumbprint.

## [0.9.0] — 2026-07-13

### Security (library)

- Fixed a critical holder-binding / device-authentication bypass ([GHSA-h548-cr7v-4v97](https://github.com/openeudi/openid4vp/security/advisories/GHSA-h548-cr7v-4v97))
  affecting both supported credential formats:
  - **SD-JWT VC**: the parser now fails closed when a holder-bound credential
    (issuer JWT carries a `cnf` claim) is presented without its key binding JWT
    (KB-JWT). Previously the KB-JWT's nonce was validated only when a KB-JWT
    happened to be present, so an attacker who captured or intercepted a
    holder-bound SD-JWT VC could strip the trailing KB-JWT and replay the
    credential without proving possession of the holder key. A new
    `requireKeyBinding` option on `ParseOptions` extends the requirement to
    credentials that lack `cnf` entirely.
  - **mDOC / ISO 18013-5**: the parser now performs full §9.1.3 device
    authentication — verifying the `DeviceSignature` (COSE_Sign1) over
    `DeviceAuthentication`, which binds the `SessionTranscript`/nonce, against
    the EC2 device key committed in the MSO's `deviceKeyInfo`. Previously only
    the issuer-signed data (`issuerSigned`) was verified, so a captured or
    replayed mDOC device response was accepted with no proof the presenting
    device held the credentialed key. `DeviceMac` (COSE_Mac0) is not supported
    and is explicitly rejected. A new `mdocSessionTranscript` option on
    `ParseOptions` carries the transcript bytes; `verifyAuthorizationResponse`
    can auto-build it for `direct_post.jwt` from the new `clientId`/`responseUri`
    options and the JWE's `mdoc-generated-nonce`, or callers may construct it
    themselves via the newly exported `buildOid4vpSessionTranscript`.

  Reported by Emir Çoban (https://github.com/EmirCobanOfficial). All users
  should upgrade.

### Added (library)

- OID4VP 1.0-Final `OpenID4VPHandover` `SessionTranscript` support: a new
  `sessionTranscriptProfile?: 'iso-18013-7' | 'openid4vp-1.0'` option on
  `VerifyAuthorizationResponseOptions` (default `'iso-18013-7'`, the existing
  Annex B/`apu`-derived transcript) selects the OpenID4VP 1.0-Final handover
  shape for `verifyAuthorizationResponse`'s `direct_post`/`direct_post.jwt`
  auto-build instead. A new `verifierEncryptionJwk?: JsonWebKey` option
  carries the verifier's response-encryption public JWK, used to derive the
  handover's RFC 7638 JWK thumbprint on the encrypted path. The newly exported
  `buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri,
  verifierEncryptionJwk? })` builds the transcript
  (`[null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce,
  jwk_thumbprint | null, response_uri]))]]`) for callers who need it outside
  `verifyAuthorizationResponse`. Unlike the Annex B profile, this transcript
  does not read the JWE `apu` header.
- Both the holder-binding fix above and the new `OpenID4VPHandover` support
  are validated against the OIDF conformance suite acting as an independent
  ISO 18013-5 mdl wallet: the `oid4vp-1final-verifier-happy-flow` plan
  (`iso_mdl` and `sd_jwt_vc`) is accepted, and the holder-binding negatives
  (`invalid-session-transcript` for mdoc; `invalid-kb-jwt-nonce`,
  `invalid-kb-jwt-aud`, `invalid-kb-jwt-signature`, `invalid-sd-hash`,
  `invalid-credential-signature` for SD-JWT) are correctly rejected. One
  documented divergence: KB-JWT `iat` recency is **not** enforced — replay is
  bound by the mandatory `nonce` check instead.

### Fixed (library)

- mDOC `IssuerSignedItem` digest verification now hashes the full tag-24
  `IssuerSignedItemBytes` (`#6.24(bstr .cbor IssuerSignedItem)`) per ISO
  18013-5 §9.1.2.4, rather than the inner `IssuerSignedItem` CBOR alone.
  The previous, narrower hash input rejected real-wallet-issued mdocs
  (fail-closed correctness bug, not a security weakening).

### Changed (library)

- **BREAKING**: Holder-binding verification is now fail-closed for both
  credential formats. Credentials that previously verified successfully
  without proof of possession — a holder-bound SD-JWT VC missing its KB-JWT,
  or an mDOC device response missing (or using `DeviceMac` for) device
  authentication — are now rejected. Verifiers that relied on the permissive
  prior behavior must supply the new options (`mdocSessionTranscript` /
  `clientId` + `responseUri`, and optionally `requireKeyBinding`) to keep
  verifying legitimate presentations.

## [0.8.1] — 2026-07-08

### Security (library)

- Fixed a critical trust-chain validation flaw ([GHSA-4c2f-96cf-f5fc](https://github.com/openeudi/openid4vp/security/advisories/GHSA-4c2f-96cf-f5fc)): X.509 chain building
  terminated on Subject Distinguished Name **string equality** rather than on
  cryptographic closure to a trust anchor. A self-signed certificate that reused
  a trusted anchor's Subject DN string was accepted as the chain terminus with
  no signature verification, so a credential signed with the attacker's key was
  trusted as issued under a trusted authority. Chain closure now requires the
  terminating certificate to be byte-identical to the trust anchor (the
  signature-verified closure path is unchanged). As defense-in-depth,
  `TrustEvaluator` now selects the terminating anchor by DER byte-identity and
  throws instead of silently falling back to the first candidate anchor.
  Reported by Reza Shokri — Quellkern e.U. (https://augenmass.tech), GitHub
  @devdotbo. All users should upgrade.

## [0.8.0] — 2026-04-26

### Added (library)

- `createSignedAuthorizationRequest` now also emits `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` in `client_metadata` alongside the OpenID4VP 1.0 Final `encrypted_response_enc_values_supported` plural array. This is an additive ID3-compatibility bridge for verifiers (e.g. the OIDF conformance suite's `EncryptVPResponse` condition) that read the older singular fields directly. Existing 1.0 Final consumers are unaffected.

- `verifyAuthorizationResponse` / `verifyPresentation` accept an optional `trustedIssuerJwks: JsonWebKey[]` parameter on `ParseOptions`. When the SD-JWT VC's issuer JWT lacks an `x5c` header, the parser looks up the issuer key by `kid` against the supplied JWK set (or by `kty`/`crv` when no `kid` is present); the matched JWK is the trust anchor and cert-chain evaluation is skipped. Default behaviour unchanged — `x5c` is still required when this option is absent. Use case: harness setups (e.g. OIDF conformance suite) where the wallet signs without `x5c` and the verifier knows the signing key out-of-band. Not recommended for production verifiers; cert-chain trust evaluation via `trustStore` is the recommended path.

### Fixed (library)

- SD-JWT disclosure-hash verification now correctly handles 2-element array-element disclosures (`[salt, value]` per SD-JWT spec §5.2.1) and transitively-nested disclosures. The previous strict check required every disclosure's hash to be in the top-level `_sd` array, which false-rejected SD-JWT VCs that use array placeholders (`{"...": "<hash>"}`) for arrays — e.g. the EU PID `nationalities` claim — or that nest `_sd` inside disclosed object values — e.g. `place_of_birth.country`. The fixed check seeds anchor sets from the issuer JWT and expands them transitively as each disclosure anchors, accepting the credential only when every disclosure anchors against some `_sd` entry (3-element) or `{"...": "<hash>"}` placeholder (2-element). Tampered or extraneous disclosures are still rejected.

### CI / Infrastructure

- Added automated OIDF verifier-conformance testing in CI (`@openeudi/openid4vp` workstream D).
  - PR happy-flow gate via `oidf-pr.yml` (paths-filter; ~5 min). Strong end-to-end gate: requires the suite to reach `/response`, the orchestrator to route the conformance response through the library's full `verifyAuthorizationResponse` pipeline (decrypt + state match + SD-JWT VC disclosure / hash integrity / KB-JWT / DCQL matching), and zero verifier-side exceptions. Allow-listed suite failures alone cannot turn the gate green.
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

[0.8.0]: https://github.com/openeudi/openid4vp/releases/tag/v0.8.0
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
