# @openeudi/openid4vp

OpenID4VP credential parsing and validation for EUDI Wallets. Supports SD-JWT VC and mDOC credential formats with issuer trust verification, expiry checking, and selective disclosure claim extraction.

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

Build an OpenID4VP authorization request URI to send to an EUDI Wallet:

```ts
import { createAuthorizationRequest } from "@openeudi/openid4vp";

const request = createAuthorizationRequest({
  requestedAttributes: ["age_over_18", "resident_country"],
  acceptedFormats: ["sd-jwt-vc", "mdoc"],
  responseUri: "https://your-app.com/api/verify/callback",
  clientId: "your-client-id",
  nonce: crypto.randomUUID(),
});

console.log(request.uri);
// openid4vp://authorize?response_type=vp_token&response_mode=direct_post&...

console.log(request.state);
// auto-generated UUID unless you provide one

console.log(request.presentationDefinition);
// OID4VP presentation definition with input descriptors
```

### AuthorizationRequestInput

| Field                 | Type                 | Required | Description                                    |
| --------------------- | -------------------- | -------- | ---------------------------------------------- |
| `requestedAttributes` | `string[]`           | Yes      | Claims to request (e.g. `age_over_18`)         |
| `acceptedFormats`     | `CredentialFormat[]` | Yes      | `'sd-jwt-vc'` and/or `'mdoc'`                  |
| `responseUri`         | `string`             | Yes      | Callback URL for the wallet response           |
| `clientId`            | `string`             | Yes      | Your verifier client identifier                |
| `nonce`               | `string`             | Yes      | Challenge nonce for replay protection          |
| `state`               | `string`             | No       | Session state (auto-generated UUID if omitted) |

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

### ParseOptions

| Field                 | Type           | Description                          |
| --------------------- | -------------- | ------------------------------------ |
| `trustedCertificates` | `Uint8Array[]` | Issuer certificates to trust         |
| `nonce`               | `string`       | Expected nonce for replay protection |
| `skipTrustCheck`      | `boolean?`     | Explicit opt-in to skip the trust check. When omitted or `false`, `trustedCertificates` must be non-empty — otherwise parsing throws `MalformedCredentialError`. Use `true` for demo/mock environments. |

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

**What is implemented (v0.3.x):**

- SD-JWT VC: full cryptographic verification (issuer JWT signature via x5c, disclosure hashes, key binding JWT signature + sd_hash, nonce check)
- mDOC / ISO 18013-5 *mso_mdoc* format: CBOR decoding and claim extraction
- mDOC / COSE_Sign1 cryptographic signature verification
- mDOC MobileSecurityObject validity enforcement (strict ISO 18013-5)
- mDOC IssuerSignedItem digest verification
- `expectedDocType` ParseOptions to lock the credential type
- Algorithm allowlist (ES256/384/512 — ECDSA only per EUDI policy)
- Authorization request builder
- Certificate trust check via byte-equality against a caller-supplied trusted set

**What is NOT yet implemented** (planned for follow-up releases — do not assume compliance in production until present):

- X.509 certificate chain building and validation beyond leaf-byte-equality
- EU List of Trusted Lists (LOTL) / ETSI TL resolution
- Certificate revocation (CRL, OCSP)
- DCQL query / credential matching — see [@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql)
- OpenID4VP HAIP (High Assurance Interoperability Profile) constraint validation
- OpenID Foundation conformance test suite integration
- SIOPv2 (Self-Issued OpenID Provider) identity flows

EUDI Architecture Reference Framework (ARF) alignment: tracks OpenID4VP 1.0 final. HAIP and ARF 1.4+ profile compliance will be added before a stable 1.0.

## Related packages

- **[@openeudi/core](https://www.npmjs.com/package/@openeudi/core)** -- Framework-agnostic EUDI Wallet verification protocol engine with session management and QR code generation.
- **[eIDAS Pro](https://eidas-pro.eu)** -- Managed verification service with admin dashboard, webhook integrations, and plugin support for WooCommerce and Shopify.

## License

[Apache 2.0](./LICENSE)
