# @openeudi/openid4vp

OpenID4VP credential parsing and validation for EUDI Wallets. Supports SD-JWT VC and mDOC credential formats with issuer trust verification, expiry checking, selective disclosure claim extraction, and DCQL-based credential matching.

## Install

```bash
npm install @openeudi/openid4vp
```

## Quick start

Parse a Verifiable Presentation token and extract identity claims:

```ts
import { parsePresentation } from "@openeudi/openid4vp";

const result = await parsePresentation(vpToken, {
  trustedCertificates: [issuerCertBytes],
  nonce: "expected-nonce-value",
});

if (result.valid) {
  console.log(result.format); // 'sd-jwt-vc' | 'mdoc'
  console.log(result.claims.age_over_18); // true
  console.log(result.issuer.country); // 'DE'
} else {
  console.error(result.error);
}
```

`parsePresentation` automatically detects the credential format. String tokens with `~` separators are parsed as SD-JWT VC; binary `Uint8Array` tokens are parsed as CBOR-encoded mDOC.

## Authorization requests

Build an OpenID4VP authorization request URI to send to an EUDI Wallet. The request carries a DCQL query ([Digital Credentials Query Language](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)) describing the credentials you want:

```ts
import { buildHaipQuery, createAuthorizationRequest } from "@openeudi/openid4vp";

const query = buildHaipQuery({
  credentialId: "pid",
  format: "dc+sd-jwt",
  vctValues: ["https://pid.eu/v1"],
  claims: ["age_over_18"],
});

const request = createAuthorizationRequest(
  {
    clientId: "x509_san_dns:verifier.example.com",
    responseUri: "https://verifier.example.com/cb",
    nonce: crypto.randomUUID(),
  },
  query,
);

console.log(request.uri);
// openid4vp://authorize?response_type=vp_token&response_mode=direct_post&...

console.log(request.state);
// auto-generated UUID unless you provide one

console.log(request.dcqlQuery);
// the DCQL query embedded in the request
```

### AuthorizationRequestInput

| Field          | Type     | Required | Description                                    |
| -------------- | -------- | -------- | ---------------------------------------------- |
| `clientId`     | `string` | Yes      | Your verifier client identifier                |
| `responseUri`  | `string` | Yes      | Callback URL for the wallet response           |
| `nonce`        | `string` | Yes      | Challenge nonce for replay protection          |
| `state`        | `string` | No       | Session state (auto-generated UUID if omitted) |

The second argument is a DCQL `Query` object. Use `buildHaipQuery` (below) or hand-construct one and validate it via `validateHaipQuery`.

## HAIP helpers

For the High Assurance Interoperability Profile (HAIP) commonly used by EUDI Wallets:

```ts
import { buildHaipQuery, validateHaipQuery } from "@openeudi/openid4vp";

// Build a HAIP-compliant DCQL query:
const query = buildHaipQuery({
  credentialId: "pid",
  format: "dc+sd-jwt",
  vctValues: ["https://pid.eu/v1"],
  claims: ["age_over_18", "given_name"],
});

// Or validate a hand-built DCQL query:
validateHaipQuery(query); // throws HaipValidationError on violation
```

Supported formats: `dc+sd-jwt` and `mso_mdoc`. Other formats (e.g., `jwt_vc_json`) will be rejected by the validator.

Known EUDI doctypes auto-namespace their claim paths (e.g., `org.iso.18013.5.1.mDL` → claims under `org.iso.18013.5.1`). Unknown doctypes use the full doctype string as the namespace.

## Verifying presentations against a query

Use `verifyPresentation` to combine crypto/structural verification with DCQL matching in a single call:

```ts
import { verifyPresentation } from "@openeudi/openid4vp";

const result = await verifyPresentation(vpToken, query, {
  nonce,
  trustedCertificates,
});

if (result.valid) {
  console.log("matched claims:", result.match.matches[0].extractedClaims);
  console.log("submission:", result.submission);
} else {
  console.warn("mismatch reasons:", result.match.unmatched);
  // each entry: { queryId, reason, detail? }
  // reason ∈ { format_mismatch, vct_mismatch, doctype_mismatch, missing_claims, value_mismatch, trusted_authority_mismatch, no_credential_found /* only when the candidate list is empty */ }
}
```

Mismatches return `valid: false` — they do not throw. Only crypto/structural failures (malformed VP tokens, invalid signatures, expired credentials) and malformed DCQL queries throw exceptions.

> **Privacy — diagnostics are verifier-internal.** `match.unmatched[].reason` and `detail` (including `value_mismatch`) are intended for verifier-side logging, debugging, and admin UIs. OpenID4VP §11 warns that per-claim verification outcomes can reveal wallet contents to observers. Do NOT echo these diagnostics into the OpenID4VP wire response sent back to the wallet, into end-user-visible error messages that another party could correlate, or into public analytics/third-party logs. The protocol's own error codes are the public interface; these fields are your internal instrumentation.

## Signed authorization requests (x509_san_dns)

For flows that require a signed request object (JAR) per OpenID4VP 1.0 §5.10, use `createSignedAuthorizationRequest`:

```ts
import { createSignedAuthorizationRequest } from "@openeudi/openid4vp";

const req = await createSignedAuthorizationRequest({
  hostname: "verifier.example.com",
  requestUri: "https://verifier.example.com/request.jwt",
  responseUri: "https://verifier.example.com/response",
  nonce,
  signer: verifierKeyPair,          // CryptoKeyPair with public+private
  certificateChain: [leafCertDer],  // DER-encoded, leaf SAN DNSName must equal hostname
  encryptionKey: {
    publicJwk: encryptionPublicJwk, // must include alg, e.g. "ECDH-ES"
  },
  vpFormatsSupported: {
    "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] },
  },
}, dcqlQuery);

// req.uri — the short URI to hand to the wallet
// req.requestObject — the JWS the verifier must host at requestUri
//                     (Content-Type: application/oauth-authz-req+jwt)
```

The caller hosts `req.requestObject` at `requestUri` (the library does not host HTTP). The library verifies that the signing key's public SPKI matches the leaf certificate's public key — an attempt to sign with a mismatched key fails with `SignedRequestBuildError: signing_key_cert_mismatch`.

The emitted `client_metadata` carries both shapes for compatibility:

- 1.0 Final plural — `encrypted_response_enc_values_supported: ["A128GCM", ...]`
- ID3 singular — `authorization_encrypted_response_alg: "ECDH-ES"`, `authorization_encrypted_response_enc: "A128GCM"`

Verifiers reading either shape (e.g. the OIDF conformance suite reads ID3 directly) work without bespoke configuration.

## Authorization responses (direct_post and direct_post.jwt)

Wallets POST the Authorization Response to your `responseUri`. The library is stateless — you MUST compare the envelope's `state` against the value you issued before treating the response as trustworthy. The recommended pattern differs slightly between the unencrypted and encrypted modes.

### Unencrypted (`direct_post`)

The envelope arrives as form-encoded JSON; parse it, check `state`, then verify:

```ts
import { verifyAuthorizationResponse } from "@openeudi/openid4vp";

const envelope = parsedVpTokenObject; // { vp_token, state, ... }

if (envelope.state !== submittedState) {
  throw new Error("state mismatch — possible CSRF / replay");
}

const result = await verifyAuthorizationResponse(envelope, dcqlQuery, {
  trustedCertificates: [issuerCertDer],
  nonce,
});
```

### Encrypted (`direct_post.jwt`)

The wallet wraps the envelope in a JWE. Decrypt explicitly so you can check `state` against the decrypted envelope **before** verification runs:

```ts
import {
  decryptAuthorizationResponse,
  verifyAuthorizationResponse,
} from "@openeudi/openid4vp";

const decrypted = await decryptAuthorizationResponse(
  form.get("response"), // the JWE string
  verifierEncryptionPrivateKey,
);

if (decrypted.state !== submittedState) {
  throw new Error("state mismatch — possible CSRF / replay");
}

const result = await verifyAuthorizationResponse(decrypted, dcqlQuery, {
  trustedCertificates: [issuerCertDer],
  nonce,
});
```

`verifyAuthorizationResponse` also accepts the JWE directly via `{ response: jwe }` together with `options.decryptionKey` — but that path makes the `state` check easy to skip, since the caller never holds the decrypted envelope. Prefer the explicit two-step pattern above.

`verifyAuthorizationResponse` accepts the OpenID4VP 1.0 §8.1 envelope shape: `vp_token` is always an object keyed by DCQL credential query id, with arrays of presentations. This release supports **single-credential single-presentation only** — multi-credential queries or multi-presentation arrays throw `MultipleCredentialsNotSupportedError`.

#### mDOC SessionTranscript on the encrypted path

Verifying an mDOC credential requires the ISO 18013-5 `SessionTranscript` the device signed over (see [mDOC](#mdoc) below). For `direct_post.jwt`, `verifyAuthorizationResponse` can auto-build the `SessionTranscript` for you, in one of two profiles selected via `options.sessionTranscriptProfile`:

- **`'iso-18013-7'` (default)** — the ISO 18013-7 Annex B OID4VP transcript, matching id2/id3-era wallets. Pass `options.clientId` and `options.responseUri` alongside the usual `options.nonce`, and the library derives the `mdoc-generated-nonce` from the JWE's `apu` header to construct the transcript before verification runs.

  ```ts
  const result = await verifyAuthorizationResponse(envelope, dcqlQuery, {
    trustedCertificates: [issuerCertDer],
    nonce,
    decryptionKey: verifierEncryptionPrivateKey,
    clientId: verifierClientId,
    responseUri: verifierResponseUri,
  });
  ```

- **`'openid4vp-1.0'`** — the OpenID4VP 1.0-Final `OpenID4VPHandover` transcript, for wallets that implement the final spec's SessionTranscript shape instead of the Annex B one. Pass `sessionTranscriptProfile: 'openid4vp-1.0'` together with `clientId`, `responseUri`, `nonce`, and — for the encrypted path — `verifierEncryptionJwk` (the verifier's response-encryption public JWK, used to derive the handover's JWK thumbprint). This profile does **not** read the JWE `apu` header.

  ```ts
  const result = await verifyAuthorizationResponse(envelope, dcqlQuery, {
    trustedCertificates: [issuerCertDer],
    nonce,
    decryptionKey: verifierEncryptionPrivateKey,
    clientId: verifierClientId,
    responseUri: verifierResponseUri,
    sessionTranscriptProfile: 'openid4vp-1.0',
    verifierEncryptionJwk, // verifier's response-encryption public JWK
  });
  ```

  The transcript is `[null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwk_thumbprint | null, response_uri]))]]`, where `jwk_thumbprint` is the RFC 7638 SHA-256 thumbprint of `verifierEncryptionJwk` (or `null` when the response is unencrypted). Callers who need this transcript outside `verifyAuthorizationResponse` can use the exported `buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri, verifierEncryptionJwk? })`.

If you already have the transcript bytes (or are verifying an mDOC outside either auto-build path, e.g. the unencrypted `direct_post` flow), pass `options.mdocSessionTranscript: Uint8Array` explicitly — it always takes precedence over either auto-built value. `buildOid4vpSessionTranscript({ clientId, responseUri, nonce, mdocGeneratedNonce })` (Annex B) and `buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri, verifierEncryptionJwk? })` (1.0-Final) are both exported for callers who need to construct a transcript themselves. Without a transcript, the mDOC parser fails closed — see [mDOC](#mdoc).

### Supported JWE algorithms

`direct_post.jwt` decryption supports:

- `alg`: `ECDH-ES` (driven by the encryption JWK's `alg` parameter)
- `enc`: `A128GCM`, `A256GCM` (HAIP requires both)

Other algorithms throw `UnsupportedJweError`.

### ParseOptions / VerifyOptions

Both `parsePresentation` and `verifyPresentation` accept:

- `nonce` (required) — the nonce bound into the VP token at creation time.
- `requireKeyBinding?` — force SD-JWT holder-binding verification even when the issuer JWT carries no `cnf` claim. When the credential **is** holder-bound (`cnf` present), a KB-JWT is **always** required regardless of this flag — fail-closed, not opt-in. This flag only extends the requirement to credentials that lack `cnf`. Default `false`. See [SD-JWT VC](#sd-jwt-vc).
- `mdocSessionTranscript?` — CBOR bytes of the ISO 18013-5 `SessionTranscript` for the current OpenID4VP exchange. **Required** to verify mDOC device authentication; the mDOC parser fails closed without it. For `direct_post.jwt`, `verifyAuthorizationResponse` can build this for you from `clientId`/`responseUri` — see [mDOC SessionTranscript on the encrypted path](#mdoc-sessiontranscript-on-the-encrypted-path). See [mDOC](#mdoc).
- `sessionTranscriptProfile?` — *(`VerifyAuthorizationResponseOptions` only — the `direct_post`/`direct_post.jwt` auto-build described above)* which `SessionTranscript` shape to build from `clientId`/`responseUri`/`nonce`: `'iso-18013-7'` (default) builds the Annex B, `apu`-derived transcript for id2/id3-era wallets; `'openid4vp-1.0'` builds the OpenID4VP 1.0-Final `OpenID4VPHandover` transcript instead. See [mDOC SessionTranscript on the encrypted path](#mdoc-sessiontranscript-on-the-encrypted-path).
- `verifierEncryptionJwk?` — *(`VerifyAuthorizationResponseOptions` only)* the verifier's response-encryption public JWK. Required on the encrypted path when `sessionTranscriptProfile: 'openid4vp-1.0'` is used, to derive the handover's JWK thumbprint; ignored for the `'iso-18013-7'` profile.
- `trustedCertificates` (required when `trustStore` is unset) — DER-encoded issuer leaf certificates for the 0.4.x byte-equality trust check. Deprecated since 0.5.0 — pass an empty array and supply `trustStore` for production deployments.
- `trustStore?` — `TrustStore` instance for full RFC 5280 chain validation (e.g. `LotlTrustStore`, `StaticTrustStore`, or `CompositeTrustStore`). When set, takes precedence over `trustedCertificates`.
- `revocationPolicy?` — `'skip'` (default) | `'prefer'` | `'require'`. Controls whether the chain validator consults OCSP / CRL.
- `fetcher?` — HTTP transport for CRL/OCSP/LOTL fetches. Defaults to `globalThis.fetch`.
- `cache?` — cache for CRL/OCSP/LOTL artefacts. Defaults to `new InMemoryCache()`.
- `clockSkewTolerance?` — seconds of slack applied to certificate validity checks. Default 60.
- `trustedIssuerJwks?` — opt-in alternate trust path for SD-JWT VCs whose issuer JWT lacks an `x5c` header. The library matches by `kid` (or iterates the array when no `kid` is present) and skips chain validation entirely. Intended for harness setups (e.g. OIDF conformance suite) where the wallet signs without `x5c` and the verifier knows the signing key out-of-band. **Not recommended for production verifiers** — `trustStore` is the secure path.
- `audience?` — expected audience for key binding JWT verification.
- `allowedAlgorithms?` — restrict signature algorithms. Defaults to `['ES256','ES384','ES512']`.
- `skipTrustCheck?` — skip trust checks entirely (dev/test only).
- `expectedDocType?` — for mDOC verification, lock the credential `docType` (or SD-JWT `vct`).

## Supported formats

### SD-JWT VC

Selective Disclosure JSON Web Token Verifiable Credentials. The token is a string in `jwt~disclosure~kb` format. The parser:

- Decodes the issuer JWT and extracts the `x5c` certificate chain
- Verifies the issuer certificate against your trusted set
- Checks credential expiry from the `exp` claim
- Resolves selective disclosures using SHA-256
- Enforces holder binding (key binding JWT / KB-JWT): **mandatory whenever the issuer JWT carries a `cnf` claim** — the credential is holder-bound and verification fails closed if the KB-JWT is missing. Set `requireKeyBinding: true` to extend this requirement to credentials without `cnf`. When a KB-JWT is required, the parser verifies its signature against the `cnf.jwk` holder key and validates its claims: a non-empty `nonce` (matched against `options.nonce`), `sd_hash` (over the SD-JWT + disclosures), `audience` (when `options.audience` is set), and standard JWT claims including `iat`.

> **Breaking change (0.9.0):** prior releases only validated the KB-JWT's nonce when a KB-JWT happened to be present and silently accepted holder-bound credentials presented *without* one. As of 0.9.0, a holder-bound credential missing its KB-JWT is rejected outright — see [CHANGELOG](./CHANGELOG.md).

### mDOC

Mobile Document credentials as defined in ISO 18013-5. The token is a CBOR-encoded `Uint8Array` containing a DeviceResponse. The parser:

- Decodes the CBOR DeviceResponse structure
- Extracts the issuer certificate from the COSE_Sign1 `issuerAuth` (x5chain label 33)
- Verifies the certificate against your trusted set
- Checks the validity period from `validityInfo`
- Extracts claims from the `eu.europa.ec.eudi.pid.1` namespace
- Verifies each `IssuerSignedItem`'s digest against the MSO's `valueDigests`, computed over the full tag-24 `IssuerSignedItemBytes` (`#6.24(bstr .cbor IssuerSignedItem)`) per ISO 18013-5 §9.1.2.4 — not just the inner CBOR — matching how real wallets encode mdocs. mDOC verification, including this digest check and device authentication below, is validated against the OIDF conformance suite acting as an independent ISO 18013-5 mdl wallet.
- Performs full ISO 18013-5 §9.1.3 device authentication: verifies the `DeviceSignature` (COSE_Sign1) over `DeviceAuthentication`, which binds the `SessionTranscript`/nonce, using the EC2 device key committed in the MSO's `deviceKeyInfo`. **`DeviceMac` (COSE_Mac0) is not supported and is rejected.** The parser fails closed if `deviceSigned`, the `SessionTranscript` (`options.mdocSessionTranscript`), or the device key is missing — a captured `issuerSigned` payload alone is no longer accepted as proof of presentation.

> **Breaking change (0.9.0):** prior releases verified only the issuer-signed data (`issuerSigned`), so a replayed or intercepted mDOC device response — without any proof the presenting device held the credentialed key — was accepted. As of 0.9.0, device authentication is mandatory and fails closed; see [CHANGELOG](./CHANGELOG.md).

## Custom parsers

Implement `ICredentialParser` to add support for additional credential formats:

```ts
import type { ICredentialParser, ParseOptions, CredentialFormat, PresentationResult } from "@openeudi/openid4vp";

class MyCustomParser implements ICredentialParser {
  readonly format: CredentialFormat = "sd-jwt-vc"; // or 'mdoc'

  canParse(vpToken: unknown): boolean {
    // Return true if this parser can handle the token
    return typeof vpToken === "string" && vpToken.startsWith("custom:");
  }

  async parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult> {
    // Validate trust using options.trustedCertificates
    // Verify nonce using options.nonce
    // Extract and return claims
    return {
      valid: true,
      format: this.format,
      claims: { age_over_18: true },
      issuer: { certificate: new Uint8Array(), country: "DE" },
    };
  }
}
```

### PresentationResult

| Field    | Type               | Description                                |
| -------- | ------------------ | ------------------------------------------ |
| `valid`  | `boolean`          | Whether the credential passed all checks   |
| `format` | `CredentialFormat` | `'sd-jwt-vc'` or `'mdoc'`                  |
| `claims` | `CredentialClaims` | Extracted identity claims                  |
| `issuer` | `IssuerInfo`       | Issuer certificate and country             |
| `error`  | `string?`          | Reason for failure when `valid` is `false` |

## Error types

| Error class                | Default message                           | Thrown when                                        |
| -------------------------- | ----------------------------------------- | -------------------------------------------------- |
| `InvalidSignatureError`    | Credential signature validation failed    | Signature verification fails                       |
| `ExpiredCredentialError`   | Credential has expired                    | Credential `exp` or `validUntil` is in the past    |
| `UnsupportedFormatError`   | Unsupported credential format: `{format}` | Token format is not SD-JWT VC or mDOC              |
| `MalformedCredentialError` | Credential structure is malformed         | Token cannot be decoded or is structurally invalid |
| `NonceValidationError`     | Nonce does not match expected value       | Key binding JWT nonce does not match               |
| `HaipValidationError`      | HAIP query constraint violated            | DCQL query fails `validateHaipQuery`               |

```ts
import { MalformedCredentialError, ExpiredCredentialError } from "@openeudi/openid4vp";

try {
  const result = await parsePresentation(vpToken, options);
} catch (err) {
  if (err instanceof MalformedCredentialError) {
    // Token structure could not be decoded
  }
}
```

## Scope and limitations

This library implements the **verifier side** of OpenID4VP for SD-JWT VC and mDOC credentials.

**What is implemented:**

- **SD-JWT VC** — full cryptographic verification (issuer JWT signature via `x5c`, transitive disclosure-hash check, key binding JWT signature + `sd_hash`, nonce check). Holder binding (KB-JWT) is **mandatory and fails closed** whenever the issuer JWT carries a `cnf` claim; `requireKeyBinding` extends the requirement to credentials without `cnf`. Optional `trustedIssuerJwks` alternate trust path for VCs without `x5c`.
- **mDOC / ISO 18013-5** `mso_mdoc` format — CBOR decoding, claim extraction, COSE_Sign1 signature verification, MobileSecurityObject validity enforcement, IssuerSignedItem digest verification. Device authentication (ISO 18013-5 §9.1.3) is **mandatory and fails closed**: the `DeviceSignature` (COSE_Sign1) over `DeviceAuthentication`/`SessionTranscript` is verified against the MSO-committed device key. `DeviceMac` (COSE_Mac0) is **not supported and is rejected**.
- **DCQL** — authorization request builder with DCQL query, matching via [@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql), `verifyPresentation` for combined crypto + match.
- **HAIP** — `buildHaipQuery` / `validateHaipQuery` helpers for the High Assurance Interoperability Profile.
- **Signed authorization requests (JAR)** — `createSignedAuthorizationRequest` per RFC 9101 / OpenID4VP 1.0 §5.10 with `x509_san_dns` client-id binding. Emits both 1.0 Final and ID3 `client_metadata` shapes for verifier interop.
- **Encrypted responses** — `decryptAuthorizationResponse` for `direct_post.jwt` (ECDH-ES + A128GCM/A256GCM), `verifyAuthorizationResponse` for the 1.0 §8.1 object-keyed `vp_token` envelope.
- **X.509 chain validation** — RFC 5280 chain building including `nameConstraints`, `StaticTrustStore`, `CompositeTrustStore`.
- **Revocation checking** — OCSP-first with CRL fallback (`revocationPolicy: 'skip' | 'prefer' | 'require'`).
- **EU List of Trusted Lists** — `LotlTrustStore` resolves national trust lists via signed XML fetch + XAdES verification; populates `provenance` (LoA, qualified status, country, service name) on verified presentations.
- **OIDF conformance** — automated against the OpenID Foundation conformance suite in CI (`oidf-pr.yml` happy-flow gate, `oidf-release.yml` full plan).
- **Algorithm allowlist** — ES256/384/512 (ECDSA only per EUDI policy); configurable via `allowedAlgorithms`.

**What is NOT yet implemented** (planned for follow-up releases):

- Multi-credential DCQL queries (multiple query ids) and multi-presentation arrays per query id — currently rejected with `MultipleCredentialsNotSupportedError`.
- `client_id_scheme: x509_hash` (HAIP 1.0 final's mandated scheme) — only `x509_san_dns` is supported today.
- Self-signed-leaf rejection per HAIP 1.0 final's strict constraint (current behaviour accepts self-signed leaves for the verifier's own identity).
- SIOPv2 (Self-Issued OpenID Provider) identity flows.

EUDI Architecture Reference Framework (ARF) alignment: tracks OpenID4VP 1.0 final. Full ARF 1.4+ profile compliance will be added before a stable 1.0.

## OIDF Conformance Testing

Verifier-side conformance is automated against a self-hosted OpenID Foundation conformance suite. See `docs/manual-testing/oidf-interop.md` for both the CI orchestrator (`npm run oidf:ci -- --profile=happy-flow|full`) and the manual hosted-demo escape hatch.

## Related packages

- **[@openeudi/core](https://www.npmjs.com/package/@openeudi/core)** -- Framework-agnostic EUDI Wallet verification protocol engine with session management and QR code generation.
- **[@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql)** -- DCQL query matching engine used internally by `verifyPresentation`.
- **[eIDAS Pro](https://eidas-pro.eu)** -- Managed verification service with admin dashboard, webhook integrations, and plugin support for WooCommerce and Shopify.

## Migration

See [CHANGELOG.md](./CHANGELOG.md) for per-release changes. Key migration moments:

- **0.4.0** — `presentationDefinition` (PEX) replaced by DCQL queries; `verifyPresentation` introduced.
- **0.5.0** — `trustStore` option added for RFC 5280 chain validation; `trustedCertificates` deprecated.
- **0.6.0** — DCQL surfaces specific `UnmatchedReason` values via `@openeudi/dcql@0.2.0` (BREAKING for callers reading `match.unmatched[].reason`).
- **0.7.0** — `createSignedAuthorizationRequest`, `decryptAuthorizationResponse`, `verifyAuthorizationResponse` for HAIP / 1.0 §8.1 envelopes.
- **0.8.0** — additive: ID3 `client_metadata` bridge, `trustedIssuerJwks` opt-in, transitive SD-JWT disclosure check.

## License

[Apache 2.0](./LICENSE)
