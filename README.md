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

### Supported JWE algorithms

`direct_post.jwt` decryption supports:

- `alg`: `ECDH-ES` (driven by the encryption JWK's `alg` parameter)
- `enc`: `A128GCM`, `A256GCM` (HAIP requires both)

Other algorithms throw `UnsupportedJweError`.

### ParseOptions / VerifyOptions

Both `parsePresentation` and `verifyPresentation` accept:

- `nonce` (required) — the nonce bound into the VP token at creation time.
- `trustedCertificates` (required) — the set of trusted issuer certificates for crypto verification.
- `audience?` — expected audience.
- `allowedAlgorithms?` — restrict signature algorithms.
- `skipTrustCheck?` — skip trust-list checks (dev/test only).
- `expectedDocType?` — for mDOC verification.

## Supported formats

### SD-JWT VC

Selective Disclosure JSON Web Token Verifiable Credentials. The token is a string in `jwt~disclosure~kb` format. The parser:

- Decodes the issuer JWT and extracts the `x5c` certificate chain
- Verifies the issuer certificate against your trusted set
- Checks credential expiry from the `exp` claim
- Validates the nonce in the key binding JWT
- Resolves selective disclosures using SHA-256

### mDOC

Mobile Document credentials as defined in ISO 18013-5. The token is a CBOR-encoded `Uint8Array` containing a DeviceResponse. The parser:

- Decodes the CBOR DeviceResponse structure
- Extracts the issuer certificate from the COSE_Sign1 `issuerAuth` (x5chain label 33)
- Verifies the certificate against your trusted set
- Checks the validity period from `validityInfo`
- Extracts claims from the `eu.europa.ec.eudi.pid.1` namespace

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

**What is implemented (v0.4.x):**

- SD-JWT VC: full cryptographic verification (issuer JWT signature via x5c, disclosure hashes, key binding JWT signature + sd_hash, nonce check)
- mDOC / ISO 18013-5 *mso_mdoc* format: CBOR decoding and claim extraction
- mDOC / COSE_Sign1 cryptographic signature verification
- mDOC MobileSecurityObject validity enforcement (strict ISO 18013-5)
- mDOC IssuerSignedItem digest verification
- `expectedDocType` ParseOptions to lock the credential type
- Algorithm allowlist (ES256/384/512 — ECDSA only per EUDI policy)
- Authorization request builder with DCQL query
- DCQL query matching via [@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql)
- HAIP query build/validate helpers
- `verifyPresentation` — combined crypto + DCQL match in one call
- Certificate trust check via byte-equality against a caller-supplied trusted set

**What is NOT yet implemented** (planned for follow-up releases — do not assume compliance in production until present):

- X.509 certificate chain building and validation beyond leaf-byte-equality
- EU List of Trusted Lists (LOTL) / ETSI TL resolution
- Certificate revocation (CRL, OCSP)
- OpenID Foundation conformance test suite integration
- SIOPv2 (Self-Issued OpenID Provider) identity flows

EUDI Architecture Reference Framework (ARF) alignment: tracks OpenID4VP 1.0 final. Full ARF 1.4+ profile compliance will be added before a stable 1.0.

## OIDF Conformance Testing

Verifier-side conformance is automated against a self-hosted OpenID Foundation conformance suite. See `docs/manual-testing/oidf-interop.md` for both the CI orchestrator (`npm run oidf:ci -- --profile=happy-flow|full`) and the manual hosted-demo escape hatch.

## Related packages

- **[@openeudi/core](https://www.npmjs.com/package/@openeudi/core)** -- Framework-agnostic EUDI Wallet verification protocol engine with session management and QR code generation.
- **[@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql)** -- DCQL query matching engine used internally by `verifyPresentation`.
- **[eIDAS Pro](https://eidas-pro.eu)** -- Managed verification service with admin dashboard, webhook integrations, and plugin support for WooCommerce and Shopify.

## Migration from 0.3.x

See [CHANGELOG.md](./CHANGELOG.md) for the full 0.4.0 migration guide (breaking changes and new APIs).

## License

[Apache 2.0](./LICENSE)
