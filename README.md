# @openeudi/openid4vp

Open-source OpenID4VP credential parsing and validation for SD-JWT VC and mDOC/mDL formats.

> **Status:** Planning phase. Seeking [NGI Zero Commons Fund](https://nlnet.nl/commonsfund/) support.

## What is this?

`@openeudi/openid4vp` is a TypeScript library that parses and validates verifiable credentials presented through the [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocol. It supports the two credential formats mandated by [eIDAS 2.0](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation):

- **SD-JWT VC** -- Selective Disclosure JSON Web Tokens (RFC 9449)
- **mDOC/mDL** -- Mobile Document / Mobile Driving License (ISO 18013-5)

## Features

- **Format auto-detection** -- automatically identifies SD-JWT vs mDOC credential format
- **SD-JWT VC parser** -- decodes disclosures, validates JWT signatures against issuer certificates
- **mDOC parser** -- decodes CBOR DeviceResponse, validates COSE_Sign1 signatures
- **Authorization request generation** -- creates OpenID4VP authorization requests for wallet apps
- **Pluggable parser architecture** -- `ICredentialParser` interface for custom formats
- **Typed error classes** -- specific errors for parsing, validation, and signature failures
- **Dual format** -- ships ESM + CJS with full TypeScript declarations
- **Zero framework dependencies** -- works with any JavaScript/TypeScript runtime

## Installation

```bash
npm install @openeudi/openid4vp
```

## Quick Start

```typescript
import { parsePresentation } from '@openeudi/openid4vp';

// Parse a VP Token from a wallet response
const result = await parsePresentation(vpToken);

if (result.valid) {
  console.log('Format:', result.format);     // 'sd-jwt' or 'mdoc'
  console.log('Claims:', result.claims);      // { age_over_18: true, resident_country: 'DE', ... }
  console.log('Issuer:', result.issuer);      // { name: '...', country: 'DE', certificate: ... }
} else {
  console.error('Validation failed:', result.error);
}
```

### Create Authorization Request

```typescript
import { createAuthorizationRequest } from '@openeudi/openid4vp';

const authRequest = createAuthorizationRequest({
  requestedAttributes: ['age_over_18', 'resident_country'],
  responseUri: 'https://example.com/callback',
  nonce: crypto.randomUUID(),
});

// Encode as QR code or deep link for wallet app
console.log(authRequest.uri);
```

## Architecture

```
parsePresentation(vpToken)
├── Format detection (SD-JWT vs mDOC)
├── SD-JWT Parser
│   ├── Decode header.payload.signature~disclosure1~disclosure2~...
│   ├── Validate JWT signature against issuer certificate
│   └── Verify selective disclosures match hash claims
└── mDOC Parser
    ├── Decode CBOR DeviceResponse (ISO 18013-5)
    ├── Validate COSE_Sign1 signature
    └── Extract IssuerSignedItem claims

Result: PresentationResult { valid, format, claims, issuer, error? }
```

## Extracted Claims

| Claim | Description |
|-------|-------------|
| `age_over_18` | Age verification (18+) |
| `age_over_21` | Age verification (21+) |
| `resident_country` | Country of residence (ISO 3166-1 alpha-2) |
| `nationality` | Nationality |
| `family_name_birth` | Family name at birth |

## Related Packages

| Package | Description |
|---------|-------------|
| [`@openeudi/core`](https://github.com/openeudi/core) | Framework-agnostic EUDI Wallet verification SDK |

## EU Coverage

Supports credential verification from all 27 EU member states when combined with issuer certificate validation against EU Trusted Lists.

## Contributing

Contributions are welcome! Please open an issue to discuss your idea before submitting a pull request.

## License

[MIT](LICENSE)

## Acknowledgements

This project is applying for funding from the [NGI Zero Commons Fund](https://nlnet.nl/commonsfund/), a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu/) initiative.
