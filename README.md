# @openeudi/openid4vp

OpenID4VP credential parsing and validation for EUDI Wallets. Supports SD-JWT VC and mDOC credential formats with issuer trust verification, expiry checking, selective disclosure claim extraction, and DCQL-based credential matching.

## Install

```bash
npm install @openeudi/openid4vp
```

## Security and maturity

This library verifies credentials for identity and age-assurance flows, so its posture is stated here rather than left to be inferred from the feature list.

**No independent third-party security audit has been carried out.** The code has not been reviewed by an external security firm.

**Two high-severity vulnerabilities have been found and fixed, both reported by outside researchers:**

| Advisory | Issue | Fixed in |
| -------- | ----- | -------- |
| [GHSA-4c2f-96cf-f5fc](https://github.com/openeudi/openid4vp/security/advisories/GHSA-4c2f-96cf-f5fc) (CVE-2026-75522) | X.509 chain building terminated on Subject DN string equality rather than cryptographic closure, so a forged certificate reusing a trusted anchor's DN was accepted without signature verification | 0.8.1 |
| [GHSA-h548-cr7v-4v97](https://github.com/openeudi/openid4vp/security/advisories/GHSA-h548-cr7v-4v97) (CVE-2026-77456) | Holder binding was not enforced: an SD-JWT VC's KB-JWT was optional, and mDOC device authentication was never verified, so a captured presentation could be replayed | 0.9.0 |

Both are fixed. Both were found externally rather than by this project's own testing — weigh that accordingly when deciding how much to rely on the library, and **always run the latest release**.

**Pre-1.0.** While the version is below 1.0, minor bumps may contain breaking changes; see the [migration list](#migration). Full EUDI ARF (v3.0.0 at the time of writing) profile compliance is a 1.0 goal, not a current claim.

**What is independently exercised.** The OpenID Foundation conformance suite runs against this library in CI on every pull request, covering the 1.0-Final verifier happy flow for both `sd_jwt_vc` and `iso_mdl` plus the holder-binding negatives. Separately, a downstream deployment built on this library — [eudi-verify](https://github.com/eudi-verify/eudi-verify) 1.4.0 — is [OpenID Certified](https://openid.net/certification/certified-oid4vp-haip-final/) for the `OID4VP-1.0+HAIP-1.0 Verifier iso_mdl direct_post.jwt` profile (14 Aug 2026). That certification is the deployment's, not the library's, but it exercised this code.

Known functional gaps that bear on what you can rely on are listed under [Scope and limitations](#scope-and-limitations). To report a vulnerability, use private reporting as described in [SECURITY.md](./SECURITY.md) — please do not open a public issue.

## Quick start

Parse a Verifiable Presentation token and extract identity claims:

```ts
import { parsePresentation, StaticTrustStore } from "@openeudi/openid4vp";

const result = await parsePresentation(vpToken, {
  // DER certificates of the PID providers you accept (e.g. from the PID-providers list)
  trustStore: new StaticTrustStore(listedCertificates),
  nonce: "expected-nonce-value",
  // Your client_id as sent in the request: the KB-JWT `aud` must equal it
  audience: "x509_san_dns:verifier.example.com",
});

if (result.valid) {
  console.log(result.format); // 'sd-jwt-vc' | 'mdoc'
  console.log(result.vct); // 'urn:eudi:pid:1', or a national type such as 'urn:eudi:pid:de:1'
  console.log(result.claims.birthdate); // '1990-01-01' — a PID has no age_over_18; derive the age from this
} else {
  console.error(result.error);
}
```

`parsePresentation` automatically detects the credential format. String tokens with `~` separators are parsed as SD-JWT VC; binary `Uint8Array` tokens are parsed as CBOR-encoded mDOC. It verifies one credential and does not know your DCQL query, so it cannot apply the query's holder-binding requirement — use `verifyAuthorizationResponse` (or `verifyPresentation`) in a real verifier.

## Authorization requests

Build an OpenID4VP authorization request URI to send to an EUDI Wallet. The request carries a DCQL query ([Digital Credentials Query Language](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)) describing the credentials you want:

```ts
import { buildHaipQuery, createAuthorizationRequest } from "@openeudi/openid4vp";

const query = buildHaipQuery({
  credentialId: "pid",
  format: "dc+sd-jwt",
  vctValues: ["urn:eudi:pid:1"],
  claims: ["birthdate"],
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
  vctValues: ["urn:eudi:pid:1"],
  claims: ["birthdate", "given_name"],
});

// Or validate a hand-built DCQL query:
validateHaipQuery(query); // throws HaipValidationError on violation
```

Supported formats: `dc+sd-jwt` and `mso_mdoc`. Other formats (e.g., `jwt_vc_json`) will be rejected by the validator.

Known EUDI doctypes auto-namespace their claim paths (e.g., `org.iso.18013.5.1.mDL` → claims under `org.iso.18013.5.1`). Unknown doctypes use the full doctype string as the namespace.

### Offering the wallet a choice (`credential_sets`)

Some questions can be answered by more than one credential. The clearest case is
proof of age: a wallet may hold a **Proof-of-Age attestation** (`mso_mdoc`, with
`age_over_18` in namespace `eu.europa.ec.av.1`) or only a **PID** (`dc+sd-jwt`,
carrying `birthdate` — the PID has no age attribute, so the verifier computes the
threshold; `birth_date` is the mdoc element name of the PID). Asking for both in one request avoids a second wallet interaction:

```ts
import { buildCredentialSetQuery } from "@openeudi/openid4vp";

const query = buildCredentialSetQuery({
  options: [
    // Most-preferred first — discloses only a boolean.
    {
      credentialId: "age-attestation",
      format: "mso_mdoc",
      doctypeValue: "eu.europa.ec.av.1",
      claims: ["age_over_18"],
    },
    // Fallback — the verifier computes the threshold from birthdate.
    {
      credentialId: "pid",
      format: "dc+sd-jwt",
      vctValues: ["urn:eudi:pid:1"],
      claims: ["birthdate"],
    },
  ],
});
```

The wallet satisfies **one** option and returns **one** presentation;
`verifyAuthorizationResponse` resolves it by the id the wallet keyed `vp_token`
with. Option order is a privacy preference signal, not a constraint — wallets are
not obliged to honour it.

Validate a hand-built disjunction with `validateCredentialSetQuery`. Note this is
deliberately **not** HAIP-minimal: `validateHaipQuery` rejects `credential_sets`
and `isHaipQuery` returns `false` for these queries.

> **`match.unmatched` is non-empty on success here.** A disjunction is satisfied
> when the wallet takes **one** option, so the option it did *not* take is
> reported as unmatched — typically with `format_mismatch` or `vct_mismatch`
> against the credential the wallet never held. That is the expected result, not
> a failure:
>
> ```ts
> // Wallet presented the PID; the attestation option was not taken.
> result.valid                  // true
> result.match.satisfied        // true
> result.match.matches          // [{ queryId: "pid", ... }]
> result.match.unmatched        // [{ queryId: "age-attestation", reason: "format_mismatch" }]
> ```
>
> Gate on `result.valid` (or `match.satisfied`), **never** on
> `match.unmatched.length === 0`. The latter is the correct test only for a query
> without `credential_sets`, and silently rejects every valid disjunction
> response. If you log `unmatched` as "mismatch reasons" (as the verification
> example below does), expect a benign entry per successful disjunction and
> filter accordingly so it does not trip alerting.

> **Not ZKP.** This is the plain `mso_mdoc` attestation path. The AV technical
> specification's preferred mechanism — a Zero-Knowledge Proof — is not supported
> over OpenID4VP (no standardised DCQL query for it exists); it rides only the W3C
> Digital Credentials API. Plain mDoc is the profile's designated fallback for this
> transport.

## Verifying presentations against a query

Use `verifyPresentation` to combine crypto/structural verification with DCQL matching in a single call:

```ts
import { verifyPresentation } from "@openeudi/openid4vp";

const result = await verifyPresentation(vpToken, query, {
  nonce,
  audience: verifierClientId, // expected KB-JWT `aud`
  trustStore,
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

Mismatches return `valid: false` — they do not throw. Only crypto/structural failures (malformed VP tokens, invalid signatures, expired credentials), configuration faults (`MissingAudienceError`) and malformed DCQL queries throw exceptions.

**Holder binding follows the query.** OpenID4VP 1.0 §6.1 makes `require_cryptographic_holder_binding` default to `true`, so a bearer SD-JWT VC (no `cnf`, no KB-JWT) yields `valid: false` unless the matched credential query sets `require_cryptographic_holder_binding: false`. mDOC device authentication is always required.

**National PID types.** A wallet may answer `vct_values: ["urn:eudi:pid:1"]` with a national PID such as `urn:eudi:pid:de:1` (PID Rulebook PID_14, OpenID4VP 1.0 Appendix B.3.5). Such a credential matches when its issuer-signed `aka_vcts` lists a requested type, or when you declare the inheritance out of band:

```ts
await verifyPresentation(vpToken, query, {
  nonce,
  audience: verifierClientId,
  trustStore,
  vctAncestors: { "urn:eudi:pid:de:1": ["urn:eudi:pid:1"] }, // walked transitively
});
// result.parsed.vct is still the credential's own type, 'urn:eudi:pid:de:1'
```

Type Metadata is never fetched to resolve `extends`.

**`trusted_authorities`.** An `aki` value is the base64url (unpadded) KeyIdentifier of an AuthorityKeyIdentifier in the credential's certificate chain (OpenID4VP 1.0 §6.1.1.1); the library offers the AKI of every certificate in the validated chain plus the anchor's SKI. An `etsi_tl` value is a trusted-list URL — `LotlTrustStore` anchors offer their national TL and the LOTL. Each value only satisfies an entry of its own type. The hex SKI form used before 0.14.0 still matches `aki` for one release, with a one-time deprecation warning.

The `else` branch above is the right place to read `unmatched` for an ordinary
query. For a **`credential_sets` disjunction** it is not the whole story: the
option the wallet did not take is reported as unmatched even when `valid` is
`true`. See [Offering the wallet a choice](#offering-the-wallet-a-choice-credential_sets).

> **Privacy — diagnostics are verifier-internal.** `match.unmatched[].reason` and `detail` (including `value_mismatch`) are intended for verifier-side logging, debugging, and admin UIs. OpenID4VP §11 warns that per-claim verification outcomes can reveal wallet contents to observers. Do NOT echo these diagnostics into the OpenID4VP wire response sent back to the wallet, into end-user-visible error messages that another party could correlate, or into public analytics/third-party logs. The protocol's own error codes are the public interface; these fields are your internal instrumentation.

## Signed authorization requests (x509_san_dns, x509_hash)

For flows that require a signed request object (JAR) per OpenID4VP 1.0 §5.10, use `createSignedAuthorizationRequest`:

```ts
import { createSignedAuthorizationRequest } from "@openeudi/openid4vp";

const req = await createSignedAuthorizationRequest({
  clientIdPrefix: "x509_san_dns",   // or "x509_hash"; defaults to "x509_san_dns"
  hostname: "verifier.example.com", // required for x509_san_dns; optional for x509_hash
  requestUri: "https://verifier.example.com/request.jwt",
  responseUri: "https://verifier.example.com/response",
  nonce,
  signer: verifierKeyPair,          // CryptoKeyPair with public+private
  certificateChain: [leafCertDer],  // DER; leaf (+ intermediates), never the trust anchor; leaf SAN DNSName must include hostname when one is given
  encryptionKey: {
    publicJwk: encryptionPublicJwk, // a fresh key pair per request; must include alg, e.g. "ECDH-ES"
  },
  vpFormatsSupported: {
    "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] },
  },
}, dcqlQuery);

// req.uri — the short URI to hand to the wallet
// req.requestObject — the JWS the verifier must host at requestUri
//                     (Content-Type: application/oauth-authz-req+jwt)
```

`clientIdPrefix: "x509_hash"` sets `client_id` to `x509_hash:` followed by the base64url-encoded SHA-256 hash of the DER-encoded leaf certificate, per OpenID4VP 1.0 §5.9.3 (referenced by HAIP 1.0 Final for its mandated Client Identifier Prefix). `hostname` is not required in this mode, since the `client_id` is derived from the certificate rather than the host. If you do supply one it is still checked against the leaf SAN DNSName values — a supplied hostname that the certificate does not cover is treated as a misconfiguration (`hostname_cert_mismatch`) rather than silently ignored.

The caller hosts `req.requestObject` at `requestUri` (the library does not host HTTP). The library verifies that the signing key's public SPKI matches the leaf certificate's public key — an attempt to sign with a mismatched key fails with `SignedRequestBuildError: signing_key_cert_mismatch`.

### Self-signed verifier certificates are rejected

HAIP 1.0 Final requires the verifier certificate to chain to a trust anchor the wallet recognises. A self-signed leaf asserts an identity nothing vouches for, so a wallet enforcing the profile will reject the request object. `createSignedAuthorizationRequest` therefore **rejects a self-signed leaf by default** with `SignedRequestBuildError: self_signed_leaf`, failing at build time rather than emitting a request no conforming wallet will honour.

```ts
// Local development or tests only — not valid under HAIP 1.0 Final.
await createSignedAuthorizationRequest({
  ...input,
  allowSelfSignedCertificate: true,
}, dcqlQuery);
```

The check verifies the leaf's signature against its own public key rather than comparing Subject and Issuer DN strings. That distinction is deliberate: [GHSA-4c2f-96cf-f5fc](https://github.com/openeudi/openid4vp/security/advisories/GHSA-4c2f-96cf-f5fc) was a DN-string-equality bug, and a DN comparison here would both miss a re-signed certificate and wrongly reject a legitimate cross-signed one.

The emitted `client_metadata` carries the 1.0 Final shape: `encrypted_response_enc_values_supported: ["A128GCM", ...]`.

### Request keys and certificate chain (HAIP 1.0 §5)

- **Ephemeral encryption key.** "Verifiers MUST supply ephemeral encryption public keys specific to each Authorization Request." Generate a new `encryptionKey` for every request and keep its private key only to decrypt that request's response. The library cannot tell whether a key was reused, so this is on you.
- **`kid`.** OpenID4VP 1.0 §5.1 requires a `kid` on every JWK in `client_metadata.jwks`. A `publicJwk` without one is given its RFC 7638 SHA-256 thumbprint as `kid`; a `kid` you set is kept.
- **No trust anchor in `x5c`.** "The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE header." A `certificateChain` with more than one certificate whose last certificate is self-signed is rejected with `SignedRequestBuildError: trust_anchor_in_chain`. Pass the leaf and any intermediates only.

### Verifier info and registration certificates (`verifier_info`)

`verifierInfo` adds the OpenID4VP 1.0 §5.1 `verifier_info` parameter: attestations about the verifier, each `{ format, data, credential_ids? }`. ETSI TS 119 472-2 V1.3.1 (§6.3.2.2) makes it **mandatory** in an EUDI Wallet request object. It must hold a `registrar_dataset` element with the data the relying party registered with its national Registrar, plus a `registration_cert` element when the relying party holds a registration certificate (WRPRC, ETSI TS 119 475). Two helpers build these elements:

```ts
import {
  createSignedAuthorizationRequest,
  registrarDatasetVerifierInfo,
  registrationCertVerifierInfo,
} from "@openeudi/openid4vp";

const verifierInfo = [
  registrarDatasetVerifierInfo({
    identifier: [{ type: "http://data.europa.eu/eudi/id/LEI", identifier: "LEIXG-529900T8BM49AURSDO55" }],
    srvDescription: [{ lang: "en", content: "Age check at checkout" }],
    registryURI: "https://registrar.example/api",
    intendedUseIdentifier: registeredIntendedUseId,
    purpose: [{ lang: "en", content: "Checking the legal minimum age" }],
    policyURI: "https://shop.example/privacy",
    // optional: the attestations and claims registered for this intended use
    credential: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claim: [{ path: ["birthdate"] }] }],
  }),
  // only when the relying party holds a WRPRC: compact JWS (typ rc-wrp+jwt) or CWT bytes
  registrationCertVerifierInfo(wrprcJws),
];

const req = await createSignedAuthorizationRequest({ ...input, verifierInfo }, dcqlQuery);
```

Rules the builder enforces before signing (`SignedRequestBuildError: invalid_verifier_info`):

- `verifierInfo` is a non-empty array, each `format` a non-empty string, and each `data` a non-empty string or an object.
- `credential_ids`, when present, is non-empty and each entry matches the `id` of a Credential Query in the DCQL query.
- `registrar_dataset` and `registration_cert` never carry `credential_ids` (TS 119 472-2 RO-03, RO-14), and each appears at most once. ARF RPRC_19 allows "a single registration certificate" per request.

Other formats are passed through unchanged. The signed and unsigned builders emit only `format`, `data` and `credential_ids`.

Notes:

- **Encoding of `registration_cert`.** RO-16 requires `data` to be "the base64url encoding of the serialized RP registration certificate". For a JWT WRPRC, `registrationCertVerifierInfo` therefore base64url-encodes the compact JWS string itself, so the JWS is encoded twice.
- **Intermediaries.** When you request on behalf of another relying party, `identifier` and the WRPRC are the **final** relying party's, not yours (TS 119 472-2 RO-12 NOTE 2, TS 119 475 §4.5), while the request is signed with the intermediary's access certificate.
- **Data model inconsistencies.** TS 119 472-2 types `Credential.meta` and `Claim.path` as text, while the TS 119 475 Annex C example uses DCQL-style objects and arrays. The helper accepts both and passes them through unchanged.
- `createAuthorizationRequest` (unsigned) accepts `verifierInfo` too and JSON-encodes it into the URI. Nothing binds it to the verifier, though, so profiles that rely on it expect a signed request object.

## Authorization responses (direct_post and direct_post.jwt)

Wallets POST the Authorization Response to your `responseUri`. The library is stateless — you MUST compare the envelope's `state` against the value you issued before treating the response as trustworthy. The recommended pattern differs slightly between the unencrypted and encrypted modes.

### Unencrypted (`direct_post`)

The envelope arrives as form-encoded JSON; parse it, check `state`, then verify.

**mDOC SessionTranscript:** pass `clientId` and `responseUri` (exactly as sent in the request) and `verifyAuthorizationResponse` auto-builds the OpenID4VP 1.0 Final `OpenID4VPHandover` transcript with a `null` JWK thumbprint, as §B.2.6.1 requires for unencrypted responses:

```ts
import { verifyAuthorizationResponse } from "@openeudi/openid4vp";

const envelope = parsedVpTokenObject; // { vp_token, state, ... }

if (envelope.state !== submittedState) {
  throw new Error("state mismatch — possible CSRF / replay");
}

const result = await verifyAuthorizationResponse(envelope, dcqlQuery, {
  trustedCertificates: [issuerCertDer],
  nonce,
  clientId: verifierClientId,
  responseUri: verifierResponseUri,
  // auto-builds OpenID4VPHandover [client_id, nonce, null, response_uri]
});
```

Draft-era (Annex B) wallets have no unencrypted transcript the library can derive (there is no JWE `apu`); pass `mdocSessionTranscript` explicitly for them.

Without a transcript, the mDOC parser fails closed (`claims: {}`, no `docType` on the failure result). DCQL matching against that doctype-less parse can then surface a misleading `doctype_mismatch` even when the wallet sent the correct credential — prefer `parsed.error` when diagnosing.

For `direct_post.jwt` auto-build (`openid4vp-1.0` / legacy Annex B), see [mDOC SessionTranscript on the encrypted path](#mdoc-sessiontranscript-on-the-encrypted-path).

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
  trustStore,
  nonce,
  clientId: verifierClientId, // also the expected KB-JWT `aud`
});
```

If the wallet answered with an OpenID4VP 1.0 §8.5 error response (for example the user declined), `verifyAuthorizationResponse` throws `WalletErrorResponseError` with the wallet's `code` (`access_denied`, `wallet_unavailable`, …), `description` and `state` — encrypted or not.

`verifyAuthorizationResponse` also accepts the JWE directly via `{ response: jwe }` together with `options.decryptionKey` — but that path makes the `state` check easy to skip, since the caller never holds the decrypted envelope. Prefer the explicit two-step pattern above.

`verifyAuthorizationResponse` accepts the OpenID4VP 1.0 §8.1 envelope shape: `vp_token` is always an object keyed by DCQL credential query id, with arrays of presentations. This release supports **single-credential single-presentation only** — multi-credential queries or multi-presentation arrays throw `MultipleCredentialsNotSupportedError`.

#### mDOC SessionTranscript on the encrypted path

Verifying an mDOC credential requires the ISO 18013-5 `SessionTranscript` the device signed over (see [mDOC](#mdoc) below). When the presented credential is `mso_mdoc` and `clientId`, `responseUri` and `nonce` are passed, `verifyAuthorizationResponse` auto-builds it in the profile selected by `options.sessionTranscriptProfile`:

- **`'openid4vp-1.0'` (default)** — the OpenID4VP 1.0 Final `OpenID4VPHandover` transcript (§B.2.6.1). For `direct_post.jwt` also pass `verifierEncryptionJwk` (the response-encryption public JWK you sent in the request); its thumbprint is part of the transcript, and an encrypted mDOC response without it throws `MissingVerifierEncryptionKeyError`. For unencrypted `direct_post` the thumbprint is `null` and `verifierEncryptionJwk` is ignored. This profile does **not** read the JWE `apu` header.

  ```ts
  const result = await verifyAuthorizationResponse(envelope, dcqlQuery, {
    trustedCertificates: [issuerCertDer],
    nonce,
    decryptionKey: verifierEncryptionPrivateKey,
    clientId: verifierClientId,
    responseUri: verifierResponseUri,
    verifierEncryptionJwk, // verifier's response-encryption public JWK
  });
  ```

- **`'oid4vp-draft-annex-b'`** — the legacy ISO 18013-7 Annex B `OID4VPHandover`, for draft-era (ID2/ID3) wallets. The library derives the `mdoc-generated-nonce` from the JWE `apu` header, so this works for `direct_post.jwt` only. `'iso-18013-7'` is a deprecated alias (it was the default up to 0.13.0).

  ```ts
  const result = await verifyAuthorizationResponse(envelope, dcqlQuery, {
    trustedCertificates: [issuerCertDer],
    nonce,
    decryptionKey: verifierEncryptionPrivateKey,
    clientId: verifierClientId,
    responseUri: verifierResponseUri,
    sessionTranscriptProfile: 'oid4vp-draft-annex-b',
  });
  ```

  The 1.0 transcript is `[null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwk_thumbprint | null, response_uri]))]]`, where `jwk_thumbprint` is the RFC 7638 SHA-256 thumbprint of `verifierEncryptionJwk` (or `null` when the response is unencrypted). Callers who need this transcript outside `verifyAuthorizationResponse` can use the exported `buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri, verifierEncryptionJwk? })`.

If you already have the transcript bytes (or are verifying an mDOC outside either auto-build path), pass `options.mdocSessionTranscript: Uint8Array` explicitly — it always takes precedence over either auto-built value. `buildOid4vpSessionTranscript({ clientId, responseUri, nonce, mdocGeneratedNonce })` (Annex B) and `buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri, verifierEncryptionJwk? })` (1.0-Final) are both exported for callers who need to construct a transcript themselves. Without a transcript, the mDOC parser fails closed — see [mDOC](#mdoc). For the plain `direct_post` pattern, see [Unencrypted (`direct_post`)](#unencrypted-direct_post).

### Supported JWE algorithms

`direct_post.jwt` decryption supports:

- `alg`: `ECDH-ES` (driven by the encryption JWK's `alg` parameter)
- `enc`: `A128GCM`, `A256GCM` (HAIP requires both)

Other algorithms throw `UnsupportedJweError`.

### ParseOptions / VerifyOptions

Both `parsePresentation` and `verifyPresentation` accept:

- `nonce` (required) — the nonce bound into the VP token at creation time.
- `audience?` — the verifier's Client Identifier, which the KB-JWT `aud` must equal (OpenID4VP 1.0 Appendix B.3.6). **Required whenever a KB-JWT is verified** — `MissingAudienceError` is thrown otherwise. `verifyAuthorizationResponse` defaults it to `clientId`. An array `aud` is rejected. `verifyDcApiResponse` always uses `origin:<origin>` instead (see [Digital Credentials API](#digital-credentials-api)).
- `requireKeyBinding?` — force SD-JWT holder-binding verification even when the issuer JWT carries no `cnf` claim. When the credential **is** holder-bound (`cnf` present), a KB-JWT is **always** required regardless of this flag — fail-closed, not opt-in. Default `false` for the parsers; `verifyPresentation` / `verifyAuthorizationResponse` also require it whenever the matched query does not set `require_cryptographic_holder_binding: false`. See [SD-JWT VC](#sd-jwt-vc).
- `kbJwtMaxAge?` — largest accepted KB-JWT age in seconds, judged by `iat` and widened by `clockSkewTolerance` on both sides. Default 300.
- `vctAncestors?` — *(`verifyPresentation` / `verifyAuthorizationResponse`)* out-of-band SD-JWT VC type inheritance, e.g. `{ "urn:eudi:pid:de:1": ["urn:eudi:pid:1"] }`. See [Verifying presentations against a query](#verifying-presentations-against-a-query).
- `mdocSessionTranscript?` — CBOR bytes of the ISO 18013-5 `SessionTranscript` for the current OpenID4VP exchange. **Required** to verify mDOC device authentication; the mDOC parser fails closed without it. `verifyAuthorizationResponse` can build this for you from `clientId`/`responseUri` — see [mDOC SessionTranscript on the encrypted path](#mdoc-sessiontranscript-on-the-encrypted-path). See [mDOC](#mdoc).
- `sessionTranscriptProfile?` — *(`VerifyAuthorizationResponseOptions` only — the `direct_post`/`direct_post.jwt` auto-build described above)* which `SessionTranscript` shape to build from `clientId`/`responseUri`/`nonce`: `'openid4vp-1.0'` (default) builds the OpenID4VP 1.0 Final `OpenID4VPHandover`; `'oid4vp-draft-annex-b'` (deprecated alias `'iso-18013-7'`) builds the Annex B, `apu`-derived transcript for draft-era wallets. See [mDOC SessionTranscript on the encrypted path](#mdoc-sessiontranscript-on-the-encrypted-path).
- `verifierEncryptionJwk?` — *(`VerifyAuthorizationResponseOptions` only)* the verifier's response-encryption public JWK. Required for an encrypted `mso_mdoc` response under the default `'openid4vp-1.0'` profile, to derive the handover's JWK thumbprint; ignored for unencrypted responses and for the Annex B profile.
- `trustedCertificates?` — DER-encoded issuer leaf certificates for the 0.4.x byte-equality trust check, used only when `trustStore` is unset. Deprecated since 0.5.0 — supply `trustStore` instead. Optional since 0.14.0.
- `trustStore?` — `TrustStore` instance for full RFC 5280 chain validation (e.g. `LotlTrustStore`, `StaticTrustStore`, or `CompositeTrustStore`). When set, takes precedence over `trustedCertificates`.

  The signer certificate (`x5c[0]` / `x5chain[0]`) is trusted when it **is** an anchor (byte-identical DER) or **chains to** one through verified signatures; the remaining `x5c` / `x5chain` entries are untrusted path candidates and never anchors. A list longer than 10 certificates, signer included, is rejected as malformed before any entry is parsed. Anchors may therefore be roots — such as the IACA certificates an ETSI TS 119 602 PID-providers list publishes — or the document-signer certificate itself:

  ```ts
  import { StaticTrustStore } from "@openeudi/openid4vp";

  // DER bytes of every certificate listed for the PID providers you accept:
  // IACA roots and directly-listed signer certificates alike.
  const trustStore = new StaticTrustStore(listedCertificates);
  await parsePresentation(vpToken, { trustStore, nonce, mdocSessionTranscript });
  ```

  Each link's signature, validity now **and** at issuance time (MSO `signed` / SD-JWT `iat`), `basicConstraints` cA + `keyUsage` keyCertSign on every CA, `digitalSignature` on the signer, `pathLenConstraint`, `nameConstraints` and a 5-certificate maximum are enforced, and a path certificate with a critical extension the validator does not process (anything but basicConstraints, keyUsage, extKeyUsage, subjectAltName, nameConstraints, AKI/SKI, CRL distribution points, AIA and qcStatements) is rejected with `reason: 'unrecognised_critical_extension'` (RFC 5280 §4.2) — policy extensions included, since policy processing is not implemented. For `mso_mdoc`, built chains must also follow the ISO 18013-5 Annex B profile: the document signer carries EKU `1.0.18013.5.1.2` (`reason: 'extended_key_usage'` otherwise) and `keyUsage` is mandatory. A signer that is itself the listed anchor is trusted by presence and exempt from that profile. Anchors are never matched by Subject DN alone.

  > **`LotlTrustStore` requires an `xmldsigjs` crypto engine.** Trusted lists are
  > verified as signed XML, and this library does not pick a WebCrypto provider on
  > your behalf. Register one **once at startup**, before any trusted-list fetch:
  >
  > ```ts
  > import * as xmldsig from "xmldsigjs";
  > import { Crypto } from "@peculiar/webcrypto";
  >
  > xmldsig.Application.setEngine("NodeJS", new Crypto());
  > ```
  >
  > Omit it and `LotlTrustStore` throws `LotlConfigurationError` on first use,
  > naming this as the cause. `StaticTrustStore` is unaffected.

- `mdocDocumentSignerEkus?` — EKUs accepted on an `mso_mdoc` Document Signer when the chain is built to a CA anchor (at least one must be present). Default `['1.0.18013.5.1.2']`. A signer that is itself the anchor is not EKU-checked.
- `revocationPolicy?` — `'skip'` (default) | `'prefer'` | `'require'`. Controls whether the chain validator consults OCSP / CRL.
- `statusPolicy?` — `'skip'` (default) | `'prefer'` | `'require'`. Whether the SD-JWT VC `status` claim, or the mdoc MSO `status`, is checked against its Token Status List. See [Credential status (Token Status List)](#credential-status-token-status-list).
- `statusListResolver?` — the `StatusListResolver` used when `statusPolicy` is not `'skip'`.
- `fetcher?` — HTTP transport for CRL/OCSP/LOTL fetches. Defaults to a guarded fetcher — see [Network access](#network-access). A fetcher you supply **replaces** the guards; wrap it with `createGuardedFetcher({ fetch: yourFetcher })` to keep them.
- `cache?` — cache for CRL/OCSP/LOTL artefacts. Defaults to `new InMemoryCache()`.
- `clockSkewTolerance?` — seconds of slack applied to certificate validity checks and to the KB-JWT `iat`/`exp`/`nbf` checks. Default 60.
- `trustedIssuerJwks?` — opt-in alternate trust path for SD-JWT VCs whose issuer JWT lacks an `x5c` header. The library matches by `kid` (or iterates the array when no `kid` is present) and skips chain validation entirely. Intended for harness setups (e.g. OIDF conformance suite) where the wallet signs without `x5c` and the verifier knows the signing key out-of-band. **Not recommended for production verifiers** — `trustStore` is the secure path.
- `allowedAlgorithms?` — restrict signature algorithms. Defaults to `['ES256','ES384','ES512']`.
- `skipTrustCheck?` — skip trust checks entirely (dev/test only).
- `expectedDocType?` — for mDOC verification, lock the credential `docType` (or SD-JWT `vct`).
- `allowLegacyVcSdJwtTyp?` — **deprecated**. Also accept the legacy `vc+sd-jwt` issuer-JWT `typ`, which draft-ietf-oauth-sd-jwt-vc-19 removed. Default `false`; only for interoperating with wallets that have not migrated yet. Removed in 1.0.0.

### Network access

The library dereferences URLs only inside the trust module, and only when you opt into it:

| Fetch | When | Method |
|---|---|---|
| EU LOTL + national trusted lists | `LotlTrustStore` | GET |
| CRL distribution points | `revocationPolicy` `'prefer'`/`'require'` | GET |
| OCSP responders (AIA) | `revocationPolicy` `'prefer'`/`'require'` | POST |
| Token Status Lists (`status.status_list.uri`, SD-JWT VC and mdoc MSO) | `statusPolicy` `'prefer'`/`'require'` | GET |

It does **not** fetch SD-JWT VC issuer metadata (`/.well-known/jwt-vc-issuer`), `jwks_uri`, Type Metadata (`vct` resolution — use `aka_vcts` or `vctAncestors`), or `x5u`. Issuer keys come from `x5c` or `trustedIssuerJwks`. **If your application dereferences any of those itself, it is responsible for applying the SD-JWT VC draft-19 HTTP retrieval rules** — `createGuardedFetcher()` (HTTPS-only by default) is exported for exactly that.

All trust-module fetches go through `createGuardedFetcher({ allowHttp: true })` unless you pass `fetcher`; `StatusListResolver` defaults to the HTTPS-only `createGuardedFetcher()`. It enforces:

- `https:` only by default (`allowHttp: true` for the trust module: RFC 5280 CRLs and RFC 6960 OCSP are conventionally plain HTTP and every artefact is signature-verified); never an `https` → `http` redirect downgrade.
- No loopback, RFC 1918, CGNAT, link-local (incl. `169.254.169.254`), ULA (incl. `fd00:ec2::254`), multicast, documentation or reserved targets — checked on the URL host *and* on every address it resolves to, including IPv4-mapped/compatible, NAT64 and 6to4 IPv6 forms. `localhost`/`*.localhost` are refused by name. A host that resolves to no addresses at all is refused as `dns_resolution_failed` rather than treated as public.
- Redirects handled manually (`maxRedirects`, default 3); each target is re-validated before it is requested, and credentials headers are dropped on cross-origin hops.
- One timeout (`timeoutMs`, default 15 000) for DNS, all hops and the body.
- A size cap (`maxResponseBytes`, default 16 MiB), enforced from `Content-Length` and again while streaming.

Rejections throw `GuardedFetchError` with a `reason` (`insecure_scheme`, `private_address`, `too_many_redirects`, `response_too_large`, `timeout`, …).

```ts
import { createGuardedFetcher, LotlTrustStore } from "@openeudi/openid4vp";

const fetcher = createGuardedFetcher({ allowHttp: true, timeoutMs: 10_000, maxResponseBytes: 32 * 1024 * 1024 });
const trustStore = new LotlTrustStore({ signingAnchors, fetcher });
```

> **Limits.** DNS rebinding: the guard resolves and validates the host, then the transport resolves it *again*, so a hostile DNS server can answer differently the second time. `fetch` gives no portable way to pin the validated address. If attacker-influenced URLs reach your verifier, also route egress through a filtering proxy, or inject a `fetch` whose connector checks the connected address (e.g. an undici `Agent` with a validating `connect.lookup`). In runtimes without `node:dns` (browsers, some edge workers) only IP literals and `localhost` are checked unless you pass `lookup`. Caching is handled by the `cache` option, not the fetcher.

### Credential status (Token Status List)

Implements [draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/) for both credential formats. A credential whose issuer-signed data carries `status.status_list: { idx, uri }` is checked against the Status List Token at `uri`:

| Credential | Where the reference is | Status List Token fetched |
|---|---|---|
| SD-JWT VC (SD-JWT VC draft-19 §2.4, HAIP 1.0 §6.1) | `status` claim of the issuer-signed JWT | `statuslist+jwt` (§5.1) |
| mdoc (ISO/IEC 18013-5 MSO, draft-21 §6.3) | `status` element of the issuer-signed MSO | `statuslist+cwt` (§5.2) |

The same `statusPolicy`, `statusListResolver` and `credentialStatus` apply to both, on `verifyPresentation`, `verifyAuthorizationResponse`, `verifyDcApiResponse` and `verifyAvPresentation`. An mdoc reference is only ever resolved as a CWT, an SD-JWT VC reference only as a JWT; one resolver handles both.

```ts
import { StaticTrustStore, StatusListResolver, verifyAuthorizationResponse } from "@openeudi/openid4vp";

// Once per process: the cache must outlive a single presentation.
const statusListResolver = new StatusListResolver({
  // Status-list SIGNER anchors — e.g. the PID-providers LoTE `PID/Revocation`
  // services — kept separate from the issuance anchors.
  trustStore: new StaticTrustStore(revocationServiceCertificates),
});

const result = await verifyAuthorizationResponse(envelope, query, {
  trustedCertificates: [],
  trustStore,
  nonce,
  statusPolicy: "require",
  statusListResolver,
});
result.parsed.credentialStatus; // { outcome: 'checked', status: 'valid', value: 0, uri, idx, ... }
```

**Policy semantics** (mirrors `revocationPolicy`):

| Situation | `'skip'` (default) | `'prefer'` | `'require'` |
|---|---|---|---|
| Status VALID (`0x00`) | not checked | accepted | accepted |
| INVALID (`0x01`), SUSPENDED (`0x02`), any other value | not checked | `valid: false` | `valid: false` |
| `idx` out of range of an authentic list (§8.3 step 6) | not checked | `valid: false` | `valid: false` |
| `status` present but malformed / no `status_list` (HAIP §6.1) | not checked | `valid: false` | `valid: false` |
| No statement possible: list unreachable, untrusted signer, bad signature, expired, `sub` mismatch, malformed list | not checked | accepted, `credentialStatus.outcome: 'unavailable'` + `warning` | throws `StatusListError` |
| No `status` claim | not checked | accepted, `outcome: 'absent'` | accepted, `outcome: 'absent'` |

The status check runs only after the credential itself has fully validated (signature, trust, disclosures, key binding): a credential that is already invalid never triggers a fetch (§8.3). `statusPolicy` other than `'skip'` without a `statusListResolver` throws `StatusListError` (`reason: 'configuration'`). The default stays `'skip'` in 0.x for backward compatibility; it is intended to become `'prefer'` in 1.0. For PIDs, use `'require'` unless a documented ARF VCR_14 risk analysis allows `'prefer'`.

**What the resolver verifies** for each Status List Token:

- fetched with `GET` and `Accept: application/statuslist+jwt` (mdoc: `application/statuslist+cwt`) through the guarded fetcher (HTTPS only, no private targets, bounded redirects, 15 s, 16 MiB);
- JWT: compact JWS with `typ: statuslist+jwt` and an allowed `alg` (ES256/384/512 by default), signed by `x5c[0]`;
- CWT: COSE_Sign1 (untagged, `#6.18` or `#6.61(#6.18)`) with `typ` (16) `application/statuslist+cwt` and `alg` (1, ES256/384/512) in the **protected** header, an attached payload, signed by `x5chain[0]` (33, protected or unprotected but not both);
- the `x5c` / `x5chain` chain validates (RFC 5280) against the resolver's `trustStore`; anchors are never taken from the token, and an anchor found *inside* the chain is refused (set `acceptPinnedSigner: true` only if your anchor is the signer certificate itself);
- `sub` (CWT 2) equals the referenced `uri`; `iat` (6) present and not in the future; `nbf` (5) / `exp` (4) honoured with `clockSkewTolerance` (60 s); `ttl` (65534), if present, is a positive number; optional `maxListAgeSeconds` freshness limit on `iat`;
- `status_list` (CWT 65533): `bits` ∈ {1, 2, 4, 8}, `lst` ZLIB/DEFLATE — base64url text in a JWT, a raw byte string in a CWT — decompressed under a 16 MiB cap (`maxListBytes`).

**Caching.** Verified lists are cached in memory by format and `uri` until `ttl` elapses — bounded to `[minTtlSeconds, maxTtlSeconds]` (default 60 s – 24 h, `defaultTtlSeconds` 300 s when the token has no `ttl`) — and never past `exp`. The cache is LRU-bounded (`maxCacheEntries`, default 100); concurrent lookups of one `uri` share one fetch; failures are not cached. Call `statusListResolver.prefetch(uri)` (mdoc lists: `prefetch(uri, { format: 'cwt' })`) on a schedule to refresh lists out of band (ARF VCR_13–VCR_15) rather than on the presentation path. `clock` is injectable for tests.

**Separate anchors.** Status List Tokens are signed by a *status issuer*, which in the EUDI trust framework is published as its own service type (TS 119 602 `SvcType/PID/Revocation`), not as an issuance service. Give the resolver those anchors; do not reuse the credential `trustStore` unless the issuer demonstrably signs its lists with its issuance chain (then combine both with `CompositeTrustStore`). The chain profile is `generic`: the `id-kp-oauthStatusSigning` EKU (§10) is not required, because its OID is still unassigned.

**Not yet covered:** Status List Aggregation (§9) and historical resolution (§8.4, `time` parameter) are not implemented; status-list keys must come from `x5c` / `x5chain` (no `kid` / `jwks` resolution); a CWT `typ` given as a CoAP Content-Format number is refused (none is registered yet).

## Digital Credentials API

`createDcApiRequest` and `verifyDcApiResponse` implement **OpenID4VP over the W3C Digital Credentials API** (OpenID4VP 1.0 Final Appendix A, HAIP 1.0 §5.2). The browser mediates the wallet call, so there is no QR code, no `request_uri` and no `response_uri`: the server builds a request, the frontend passes it to `navigator.credentials.get()`, and the frontend posts the result back to the server for verification. This library only runs on the server side.

Supported protocols (`DigitalCredentialGetRequest.protocol`):

| Protocol | Built by | Notes |
| --- | --- | --- |
| `openid4vp-v1-unsigned` | `protocol: 'openid4vp-v1-unsigned'` | §A.3.1. Parameters in clear; `client_id` omitted. The browser's origin authenticates the verifier. |
| `openid4vp-v1-signed` | `protocol: 'openid4vp-v1-signed'` | §A.3.2.1. JWS Request Object in `data.request`, with `client_id` (`x509_hash` by default, as HAIP requires) and the REQUIRED `expected_origins`. Same certificate checks as `createSignedAuthorizationRequest`, including `trust_anchor_in_chain`. |
| `openid4vp-v1-multisigned` | — | Not supported (JWS JSON Serialization). Rejected with `unsupported_protocol`. |
| `org-iso-mdoc` | — | Not supported yet (ISO/IEC 18013-7 Annex C). See below. |

Both variants accept `verifierInfo` (validated as for `createSignedAuthorizationRequest`, `DcApiRequestBuildError('invalid_verifier_info')`) and emit it as `verifier_info`: inside the Request Object when signed, as a plain `data` member when unsigned. Wallets enforcing ETSI TS 119 472-2 or HAIP expect it in a signed request.

The library only emits protocol strings from the W3C closed `DigitalCredentialPresentationProtocol` set (exported as `DC_API_PRESENTATION_PROTOCOLS`). Browsers reject other strings.

**Server: build the request**

```ts
import { createDcApiRequest, buildHaipQuery } from "@openeudi/openid4vp";

// Ephemeral response-encryption key per request (dc_api.jwt is the default and HAIP's requirement).
const encKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const encryptionJwk = { ...(await crypto.subtle.exportKey("jwk", encKeys.publicKey)), alg: "ECDH-ES" };

const dcRequest = await createDcApiRequest(
  {
    protocol: "openid4vp-v1-unsigned", // or 'openid4vp-v1-signed' + expectedOrigins, signer, certificateChain
    nonce: crypto.randomUUID(),
    encryptionKey: { publicJwk: encryptionJwk },
    vpFormatsSupported: { "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] } },
  },
  buildHaipQuery({ credentialId: "pid", format: "dc+sd-jwt", vctValues: ["urn:eudi:pid:1"], claims: ["birthdate"] }),
);

// Keep nonce, the encryption key pair and the query in the server-side session.
// Send dcRequest.request (JSON) to the browser.
```

**Browser: call the wallet** (integrator code; not part of this package)

```ts
const request = await fetch("/dc-api/request").then((r) => r.json()); // = dcRequest.request
const credential = await navigator.credentials.get({
  mediation: "required",
  digital: { requests: [request] },
});
await fetch("/dc-api/response", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ protocol: credential.protocol, data: credential.data }),
});
```

Feature-detect with `typeof DigitalCredential !== "undefined"` and, where available, `DigitalCredential.userAgentAllowsProtocol("openid4vp-v1-unsigned")`. Fall back to the redirect / QR flow otherwise.

**Server: verify the response**

```ts
import { verifyDcApiResponse, WalletErrorResponseError } from "@openeudi/openid4vp";

try {
  const result = await verifyDcApiResponse(body, session.dcqlQuery, {
    origin: "https://shop.example", // from configuration, never from the request
    nonce: session.nonce,
    responseMode: "dc_api.jwt",
    protocol: "openid4vp-v1-unsigned",
    decryptionKey: session.encKeys.privateKey,
    verifierEncryptionJwk: session.encryptionJwk, // needed for mso_mdoc
    trustStore,
    trustedCertificates: [],
  });
  if (!result.valid) throw new Error(result.parsed.error ?? "presentation rejected");
} catch (err) {
  if (err instanceof WalletErrorResponseError) {
    // e.g. err.code === 'access_denied' — the user declined in the wallet
  }
  throw err;
}
```

What `verifyDcApiResponse` enforces:

- `protocol` is one of the two supported values, and equals `options.protocol` when set (`DcApiResponseError`: `unsupported_protocol`, `protocol_mismatch`).
- A wallet error object (`data: { error }`, §A.4, or `{ error }` inside a decrypted `dc_api.jwt` payload) throws `WalletErrorResponseError` (`code`, `description`, `state`, `uri`) — the same class as `verifyAuthorizationResponse`.
- The envelope matches `responseMode` (default `dc_api.jwt`): an unencrypted `vp_token` in reply to a `dc_api.jwt` request throws `unencrypted_response`; a JWE in reply to `dc_api` throws `unexpected_encrypted_response`. Decryption uses the same ECDH-ES + A128GCM/A256GCM allow-list as `direct_post.jwt`.
- SD-JWT VC: the KB-JWT `aud` must be `origin:<origin>` (§A.4, also for **signed** requests: the `client_id` is never the audience over the DC API) and `nonce` must match. A KB-JWT is required by default (`requireKeyBinding` defaults to `true` here), because it is the only thing that binds an SD-JWT presentation to the origin.
- mDOC: the device signature must cover the `OpenID4VPDCAPIHandover` SessionTranscript `[null, null, ["OpenID4VPDCAPIHandover", sha256(cbor([origin, nonce, jwkThumbprint | null]))]]` (§B.2.6.2), built automatically. The thumbprint is that of `verifierEncryptionJwk` for `dc_api.jwt` and `null` for `dc_api`. `buildOpenID4VPDCAPIHandoverSessionTranscript` is exported.
- There is no `state` over the DC API (§A.2). Bind the response to your session with the `nonce`, and use each nonce once.
- The other `VerifyOptions` (`trustStore`, `statusPolicy` / `statusListResolver`, `vctAncestors`, …) apply as for `verifyAuthorizationResponse`; `audience` is derived from `origin`, and a conflicting value throws `audience_conflict`.

`origin` must be the serialized origin exactly as the browser sends it (`https://shop.example`, no path or trailing slash). `http:` is accepted only for `localhost` / loopback, since the API needs a secure context. For a signed request listing several `expected_origins`, pass the origin the page was actually served from.

**Not in this release:**

- `org-iso-mdoc` (ISO/IEC 18013-7 Annex C, phase 2). The EU age-verification profile uses this protocol as its default DC API transport.
- Zero-knowledge proofs of age (for example Longfellow, phase 3). They are only available over that transport and probably belong in a separate package.
- `openid4vp-v1-multisigned`, `transaction_data` and multi-credential responses.

**Browser status** (checked 2026-10-20; re-check before relying on it):

- Chromium plans to stop passing unregistered protocol strings to the platform. Its [Intent to Ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/fc7awi_7hYo/m/M0K1zP7IBQAJ) holds the removal until the start of 2027. Requests built by this library already use registered strings only.
- WebKit renamed the IDL dictionary `DigitalCredentialRequest` to `DigitalCredentialGetRequest` to follow the spec ([WebKit bug 304311](https://bugs.webkit.org/show_bug.cgi?id=304311)). The JavaScript object shape (`{ protocol, data }`) is unchanged.

## EU Age Verification (AV app) profile

`createAvAuthorizationRequest` and `verifyAvPresentation` implement the **OpenID4VP fallback** of the [EU Age Verification technical specification](https://github.com/eu-digital-identity-wallet/av-doc-technical-specification), Annex A §A.6. Use it to accept a Proof of Age attestation from an AV app (the EU "mini wallet") by deep link or QR code. What the profile fixes:

- The request goes to the AV app as plain query parameters, `av://?…` by default ("at least a custom URL scheme av:// MUST be supported"). It is not signed and there is no `request` / `request_uri` ("support for JAR is not required").
- `response_type=vp_token`, `response_mode=direct_post` (unencrypted), `client_id=redirect_uri:<response_uri>`, a `nonce`, and an optional `state`.
- The DCQL query asks for one `mso_mdoc` credential of doctype `eu.europa.ec.av.1` and claim `["eu.europa.ec.av.1", "age_over_18"]` (or another `age_over_NN`).
- Relying Parties do not register and need no certificate: "The registration of Relying Parties that request age verification … is not required." TLS on `response_uri` is the only verifier authentication.

**Server: build the request**

```ts
import { createAvAuthorizationRequest } from "@openeudi/openid4vp";

const avRequest = createAvAuthorizationRequest({
  responseUri: `https://shop.example/av/response/${sessionId}`, // https only
  state: sessionId, // optional per Annex A; the reference verifier always sends one
  // ageThreshold: 18, nonce: generated (256 bits), baseUri: "av://"
});

// Persist everything verification needs, keyed by the session.
await sessions.save(sessionId, {
  responseUri: avRequest.responseUri,
  nonce: avRequest.nonce,
  state: avRequest.state,
  ageThreshold: avRequest.ageThreshold,
});

// Render avRequest.uri as a QR code (desktop) or a link (same device):
// av://?response_type=vp_token&response_mode=direct_post&client_id=redirect_uri%3Ahttps%3A%2F%2F…
```

`client_metadata` carries `vp_formats_supported` for `mso_mdoc` (ES256/ES384/ES512, as the reference verifier advertises), because OpenID4VP 1.0 §5.9.3 passes all verifier metadata that way under `redirect_uri:`. Pass `vpFormatsSupported: null` to leave it out, like the Annex A example.

**Server: verify the AV app's POST to `response_uri`**

```ts
import {
  verifyAvPresentation,
  StaticTrustStore,
  WalletErrorResponseError,
} from "@openeudi/openid4vp";

// Anchors of authorised Attestation Providers from the Commission's AV trusted
// list. Keep them apart from PID-provider anchors.
const avTrustStore = new StaticTrustStore(avProviderCertificatesPem);

app.post("/av/response/:sessionId", express.urlencoded({ extended: false }), async (req, res) => {
  const persisted = await sessions.take(req.params.sessionId); // single use
  try {
    const result = await verifyAvPresentation(req.body, { request: persisted, trustStore: avTrustStore });
    await sessions.complete(req.params.sessionId, { ageVerified: result.ageVerified, failure: result.failure });
    res.json({}); // §8.2: may return { redirect_uri } for same-device flows
  } catch (err) {
    if (err instanceof WalletErrorResponseError) {
      // user declined (access_denied) or the app failed
    }
    res.status(400).json({ error: "invalid_request" });
  }
});
```

What `verifyAvPresentation` checks:

- `state` matches the request, when the request had one. `vp_token` holds exactly one presentation, under the requested credential id. Otherwise it throws `AvResponseError`. A wallet error response (`error=access_denied`, …) throws `WalletErrorResponseError`.
- The `DeviceResponse` has exactly one document, with `docType` `eu.europa.ec.av.1` and status 0. The MSO `docType` must match too.
- Data model (§A.4.2): "A Proof of Age Attestation SHALL NOT include any other attribute." Any namespace other than `eu.europa.ec.av.1`, or any element other than a boolean `age_over_NN`, rejects the presentation (`failure: 'unexpected_attribute'` / `'invalid_attribute_value'`). It is not ignored: such a credential does not conform to the data model, and accepting it would mean processing personal data the RP never asked for. Device-signed elements are rejected too.
- Issuer signature, digests and MSO validity. The issuer chain must validate against `trustStore`. A Document Signer under a CA anchor must carry EKU `1.3.130.2.0.0.1.2` (the AV reference issuer's) or `1.0.18013.5.1.2` (ISO 18013-5); override with `documentSignerEkus`. Revocation is skipped by default ("Attestation revocation is not required").
- Device authentication over the OpenID4VP 1.0 `OpenID4VPHandover` SessionTranscript `[clientId, nonce, null, responseUri]` (§B.2.6.1, `null` because the response is not encrypted). It is byte-identical to the Annex A example transcript.
- With `statusPolicy: 'prefer' | 'require'` and a `statusListResolver`, the MSO `status` (`statuslist+cwt`) when the attestation carries one (`failure: 'credential_status'` for a non-VALID status). Proof of Age attestations normally carry none and still verify (`credentialStatus.outcome: 'absent'`). Default `'skip'`.
- The requested `age_over_NN` is disclosed (`failure: 'missing_attribute'` otherwise).

Result: `{ valid, ageVerified, ageOver, ageThreshold, ageOverAttribute, issuer, trust, state, credentialStatus?, failure?, error? }`. **Gate access on `ageVerified`.** `valid: true` with `ageOver: false` is a genuine attestation that says the holder is *not* over the threshold. Trust failures throw `TrustAnchorNotFoundError` / `CertificateChainError`, as everywhere else in this library.

Use each `nonce` once. The spec recommends treating a plain-mdoc Proof of Age attestation as single use; the AV app enforces that, and nonce binding prevents replay to your verifier.

**Not covered:** the W3C Digital Credentials API transport with `org-iso-mdoc` and zero-knowledge proofs (Annex A §A.8, the profile's preferred mechanism), and issuance. The request carries no `verifier_info`: it is unsigned under `redirect_uri:`, so nothing could bind it to the verifier.

**Known interop issue:** the AV reference implementation's certificates (the Annex A §A.11 Document Signer and the "Age Verification Issuer CA 01" bundled in the AV Android app) encode `IssuerAltName` as a nested Extension instead of `GeneralNames`. `@peculiar/x509` cannot parse it, so `StaticTrustStore` and chain validation throw on those certificates. RFC 5280 §4.2 requires a recognised extension to be processed, so this library fails closed rather than skipping it.

## Supported formats

### SD-JWT VC

Selective Disclosure JSON Web Token Verifiable Credentials. The token is a string in `jwt~disclosure~kb` format. The parser:

- Requires the issuer JWT `typ` to be `dc+sd-jwt` (draft-ietf-oauth-sd-jwt-vc-19); the legacy `vc+sd-jwt` is rejected unless `allowLegacyVcSdJwtTyp` is set
- Decodes the issuer JWT and extracts the `x5c` certificate chain
- Verifies the issuer certificate against your trusted set
- Checks credential expiry from the `exp` claim
- Resolves selective disclosures with the issuer's `_sd_alg` (`sha-256` by default; `sha-384` and `sha-512` also supported, anything else rejected). Disclosures must be base64url; a disclosure sent twice, or a digest that appears more than once, is rejected (RFC 9901 §7.1)
- Enforces holder binding (key binding JWT / KB-JWT): **mandatory whenever the issuer JWT carries a `cnf` claim** — the credential is holder-bound and verification fails closed if the KB-JWT is missing. Set `requireKeyBinding: true` to extend this requirement to credentials without `cnf` (the query-level default does this for you in `verifyPresentation`). When a KB-JWT is present, the parser verifies its signature against the `cnf.jwk` holder key and checks RFC 9901 §7.3: `typ` is `kb+jwt`; `iat`, `nonce`, `sd_hash` and `aud` are present; `nonce` equals `options.nonce`; `aud` is a single string equal to `options.audience`; `sd_hash` matches; and `iat` is no older than `kbJwtMaxAge` (300 s) nor in the future, give or take `clockSkewTolerance`.

> **Breaking change (0.9.0):** prior releases only validated the KB-JWT's nonce when a KB-JWT happened to be present and silently accepted holder-bound credentials presented *without* one. As of 0.9.0, a holder-bound credential missing its KB-JWT is rejected outright — see [CHANGELOG](./CHANGELOG.md).

### mDOC

Mobile Document credentials as defined in ISO 18013-5. The token is a CBOR-encoded `Uint8Array` containing a DeviceResponse. The parser:

- Decodes the CBOR DeviceResponse structure
- Extracts the issuer certificate from the COSE_Sign1 `issuerAuth` (x5chain label 33)
- Verifies the certificate against your trusted set — with `trustStore`, by building a chain from the document signer to an anchor such as an IACA (see [`trustStore`](#parseoptions--verifyoptions))
- Checks the validity period from `validityInfo`
- Extracts the claims of every namespace (into `claims`, and grouped by namespace into `namespacedClaims`)
- Verifies each `IssuerSignedItem`'s digest against the MSO's `valueDigests`, computed over the full tag-24 `IssuerSignedItemBytes` (`#6.24(bstr .cbor IssuerSignedItem)`) per ISO 18013-5 §9.1.2.4 — not just the inner CBOR — matching how real wallets encode mdocs. mDOC verification, including this digest check and device authentication below, is validated against the OIDF conformance suite acting as an independent ISO 18013-5 mdl wallet.
- Performs full ISO 18013-5 §9.1.3 device authentication: verifies the `DeviceSignature` (COSE_Sign1) over `DeviceAuthentication`, which binds the `SessionTranscript`/nonce, using the EC2 device key committed in the MSO's `deviceKeyInfo`. **`DeviceMac` (COSE_Mac0) is not supported and is rejected.** The parser fails closed if `deviceSigned`, the `SessionTranscript` (`options.mdocSessionTranscript`), or the device key is missing — a captured `issuerSigned` payload alone is no longer accepted as proof of presentation.

> **Breaking change (0.9.0):** prior releases verified only the issuer-signed data (`issuerSigned`), so a replayed or intercepted mDOC device response — without any proof the presenting device held the credentialed key — was accepted. As of 0.9.0, device authentication is mandatory and fails closed; see [CHANGELOG](./CHANGELOG.md).

## Parsers

`parsePresentation`, `verifyPresentation` and `verifyAuthorizationResponse` use a fixed pair of parsers — `SdJwtParser` and `MdocParser`, both exported for direct use. There is no API to register another format; `ICredentialParser` is exported as the type those two implement.

### PresentationResult

| Field              | Type                    | Description                                                                 |
| ------------------ | ----------------------- | --------------------------------------------------------------------------- |
| `valid`            | `boolean`               | Whether the credential passed all checks                                    |
| `format`           | `CredentialFormat`      | `'sd-jwt-vc'` or `'mdoc'`                                                   |
| `claims`           | `CredentialClaims`      | Every disclosed claim by name; treat as `Record<string, unknown>`           |
| `issuer`           | `IssuerInfo`            | Issuer certificate; `country` is a TLD guess for SD-JWT and `''` for mDOC   |
| `vct`              | `string?`               | SD-JWT VC type                                                              |
| `akaVcts`          | `string[]?`             | Issuer-signed `aka_vcts` (SD-JWT VC)                                        |
| `docType`          | `string?`               | mDOC docType                                                                |
| `namespacedClaims` | `Record<…>?`            | mDOC claims grouped by namespace                                            |
| `trust`            | `TrustEvaluationResult?`| Chain, anchor, revocation, provenance, `trustedAuthorities` (with `trustStore`) |
| `credentialStatus` | `CredentialStatusResult?` | Token Status List outcome when `statusPolicy` is `'prefer'` / `'require'` (SD-JWT VC and mdoc) |
| `error`            | `string?`               | Reason for failure when `valid` is `false`                                  |

`CredentialClaims` still declares `age_over_18`, `age_over_21`, `nationality`, `resident_country` and `family_name_birth`, deprecated: an EU PID has none of the age fields, and its SD-JWT VC form uses `nationalities` (an array). They go in 1.0.0.

## Error types

| Error class                | Default message                           | Thrown when                                        |
| -------------------------- | ----------------------------------------- | -------------------------------------------------- |
| `InvalidSignatureError`    | Credential signature validation failed    | Signature verification fails                       |
| `ExpiredCredentialError`   | Credential has expired                    | Credential `exp` or `validUntil` is in the past    |
| `UnsupportedFormatError`   | Unsupported credential format: `{format}` | Token format is not SD-JWT VC or mDOC              |
| `MalformedCredentialError` | Credential structure is malformed         | Token cannot be decoded or is structurally invalid |
| `NonceValidationError`     | Nonce does not match expected value       | Key binding JWT nonce does not match               |
| `HaipValidationError`      | HAIP query constraint violated            | DCQL query fails `validateHaipQuery`               |
| `LotlConfigurationError`   | No xmldsigjs crypto engine registered     | `LotlTrustStore` used without `Application.setEngine` |
| `GuardedFetchError`        | refusing … / exceeds … / timed out      | A guarded fetch is refused or cut off (`reason`)   |
| `MissingAudienceError`     | An expected audience is required …      | A KB-JWT is verified without `audience` (or `clientId`) |
| `WalletErrorResponseError` | Wallet returned an error response: `{code}` | The wallet sent an OpenID4VP §8.5 error response (`code`, `description`, `state`) |
| `CertificateChainError`    | (per check)                             | Chain validation fails; see `reason` (e.g. `unrecognised_critical_extension`) |
| `SignedRequestBuildError`  | (per check)                             | `createSignedAuthorizationRequest` (or a signed `createDcApiRequest`) input is invalid; see `code` (e.g. `trust_anchor_in_chain`, `invalid_verifier_info`) |
| `StatusListError`          | Status List Token … / status_list …     | Token Status List unusable under `statusPolicy: 'require'`, or misconfiguration (`reason`) |
| `DcApiRequestBuildError`   | (per `code`)                              | `createDcApiRequest` refuses its input             |
| `DcApiResponseError`       | (per `code`)                              | DC API response has the wrong protocol or envelope, or `origin` is misconfigured |
| `AvRequestBuildError`      | (per `code`)                              | `createAvAuthorizationRequest` refuses its input   |
| `AvResponseError`          | (per `code`)                              | AV response has the wrong `state` or `vp_token` shape, or the verification context is not an AV request |

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

- **SD-JWT VC** — full cryptographic verification (issuer JWT signature via `x5c`, transitive disclosure-hash check with `_sd_alg`, key binding JWT signature, `typ`, `sd_hash`, `nonce`, `aud` and `iat` window). Holder binding (KB-JWT) is **mandatory and fails closed** whenever the issuer JWT carries a `cnf` claim, and whenever the matched DCQL query does not opt out with `require_cryptographic_holder_binding: false`. Optional `trustedIssuerJwks` alternate trust path for VCs without `x5c`.
- **mDOC / ISO 18013-5** `mso_mdoc` format — CBOR decoding, claim extraction, COSE_Sign1 signature verification, MobileSecurityObject validity enforcement, IssuerSignedItem digest verification. Device authentication (ISO 18013-5 §9.1.3) is **mandatory and fails closed**: the `DeviceSignature` (COSE_Sign1) over `DeviceAuthentication`/`SessionTranscript` is verified against the MSO-committed device key. `DeviceMac` (COSE_Mac0) is **not supported and is rejected**.
- **DCQL** — authorization request builder with DCQL query, matching via [@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql), `verifyPresentation` for combined crypto + match.
- **HAIP** — `buildHaipQuery` / `validateHaipQuery` helpers for the High Assurance Interoperability Profile, plus `buildCredentialSetQuery` / `validateCredentialSetQuery` for `credential_sets` disjunctions.
- **Signed authorization requests (JAR)** — `createSignedAuthorizationRequest` per RFC 9101 / OpenID4VP 1.0 §5.10 with `x509_san_dns` or `x509_hash` client-id binding. Emits the OpenID4VP 1.0 Final `client_metadata` shape. Self-signed verifier leaf certificates are rejected by default per HAIP 1.0 Final.
- **Encrypted responses** — `decryptAuthorizationResponse` for `direct_post.jwt` (ECDH-ES + A128GCM/A256GCM), `verifyAuthorizationResponse` for the 1.0 §8.1 object-keyed `vp_token` envelope.
- **W3C Digital Credentials API** — `createDcApiRequest` / `verifyDcApiResponse` for `openid4vp-v1-unsigned` and `openid4vp-v1-signed`, with `dc_api` and `dc_api.jwt` (OpenID4VP 1.0 Appendix A). See [Digital Credentials API](#digital-credentials-api).
- **EU Age Verification profile** — `createAvAuthorizationRequest` / `verifyAvPresentation` for the AV app's OpenID4VP fallback (`av://`, `redirect_uri:`, `direct_post`, plain `eu.europa.ec.av.1` mdoc). See [EU Age Verification (AV app) profile](#eu-age-verification-av-app-profile).
- **X.509 chain validation** — RFC 5280 chain building including `nameConstraints`, `StaticTrustStore`, `CompositeTrustStore`; IACA → document-signer chains for `mso_mdoc` with the ISO 18013-5 Annex B certificate profile.
- **Revocation checking** — OCSP-first with CRL fallback (`revocationPolicy: 'skip' | 'prefer' | 'require'`).
- **Credential status** — IETF Token Status List via `StatusListResolver` and `statusPolicy: 'skip' | 'prefer' | 'require'`: `statuslist+jwt` for SD-JWT VC, `statuslist+cwt` for the mdoc MSO `status`.
- **EU List of Trusted Lists** — `LotlTrustStore` resolves national trust lists via signed XML fetch + XAdES verification; populates `provenance` (LoA, qualified status, country, service name) on verified presentations.
- **OIDF conformance** — automated against the OpenID Foundation conformance suite in CI: `oidf-pr.yml` runs the OpenID4VP 1.0-Final verifier happy flow for `sd_jwt_vc` and `iso_mdl` (`x509_san_dns`, signed request); `oidf-release.yml` adds that plan's negative modules (session transcript, KB-JWT nonce / aud / signature / `iat` past and future, `sd_hash`, credential signature). There is no HAIP plan run and no `x509_hash` run yet; `--profile=full` is a single ID3 happy-flow module.
- **Algorithm allowlist** — ES256/384/512 (ECDSA only per EUDI policy); configurable via `allowedAlgorithms`.

**What is NOT yet implemented** (planned for follow-up releases):

- Multi-credential DCQL queries (multiple query ids) and multi-presentation arrays per query id — currently rejected with `MultipleCredentialsNotSupportedError`.
- SIOPv2 (Self-Issued OpenID Provider) identity flows.
- Digital Credentials API: `org-iso-mdoc` (ISO/IEC 18013-7 Annex C), ZKP proofs of age, and `openid4vp-v1-multisigned`.

EUDI Architecture Reference Framework (ARF) alignment: tracks OpenID4VP 1.0 final. Full ARF profile compliance (ARF v3.0.0, 2026-07-23, at the time of writing) is a goal for a stable 1.0.

## OIDF Conformance Testing

Verifier-side conformance is automated against a self-hosted OpenID Foundation conformance suite. See `docs/manual-testing/oidf-interop.md` for both the CI orchestrator (`npm run oidf:ci -- --profile=happy-flow|full`) and the manual hosted-demo escape hatch.

## Related packages

- **[@openeudi/core](https://www.npmjs.com/package/@openeudi/core)** -- Framework-agnostic EUDI Wallet verification protocol engine with session management and QR code generation.
- **[@openeudi/dcql](https://www.npmjs.com/package/@openeudi/dcql)** -- DCQL query matching engine used internally by `verifyPresentation`.
- **[eIDAS Pro](https://eidas-pro.com)** -- Managed verification service with admin dashboard, webhook integrations, and plugin support for WooCommerce and Shopify.

## Community integrations

Third-party projects built on this library. These are **not** maintained or audited by OpenEUDI -- evaluate them on their own merits.

- **[eudi-verify](https://github.com/eudi-verify/eudi-verify)** -- Relying-party widget and API, running `@openeudi/openid4vp` as one of two pluggable verifier engines. Includes public [interop notes](https://github.com/eudi-verify/eudi-verify/blob/main/docs/INTEROP.md) covering `mso_mdoc` age-over-18 against an EU Age Verification reference wallet. Demo: [demo.eudi-verify.eu](https://demo.eudi-verify.eu/).

Built something on `@openeudi/openid4vp`? Open an issue and we're happy to consider listing it here.

## Migration

See [CHANGELOG.md](./CHANGELOG.md) for per-release changes. Key migration moments:

- **0.4.0** — `presentationDefinition` (PEX) replaced by DCQL queries; `verifyPresentation` introduced.
- **0.5.0** — `trustStore` option added for RFC 5280 chain validation; `trustedCertificates` deprecated.
- **0.6.0** — DCQL surfaces specific `UnmatchedReason` values via `@openeudi/dcql@0.2.0` (BREAKING for callers reading `match.unmatched[].reason`).
- **0.7.0** — `createSignedAuthorizationRequest`, `decryptAuthorizationResponse`, `verifyAuthorizationResponse` for HAIP / 1.0 §8.1 envelopes.
- **0.8.0** — additive: ID3 `client_metadata` bridge, `trustedIssuerJwks` opt-in, transitive SD-JWT disclosure check.
- **0.9.3** — `reflect-metadata` is loaded by the package itself in both ESM and CJS builds. If you added a manual `import "reflect-metadata"` before importing this library to work around the 0.9.2 bug, you can drop it.
- **0.11.0** — **BREAKING:** `createSignedAuthorizationRequest` now rejects a self-signed leaf certificate with `SignedRequestBuildError: self_signed_leaf`, per HAIP 1.0 Final. Verifiers using a self-signed certificate for their own identity must either move to a CA-issued certificate (the correct fix) or pass `allowSelfSignedCertificate: true` to keep the previous behaviour. Verification of wallet presentations is unaffected — this concerns only the verifier's own request-signing certificate.
- **0.10.0** — `createSignedAuthorizationRequest` gains `clientIdPrefix` (`x509_san_dns` default, or `x509_hash`), and `hostname` becomes optional — required only for `x509_san_dns`, but still validated against the leaf SAN whenever supplied. **Wire change for existing callers:** the emitted `client_metadata` no longer carries the singular ID3 `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc` fields added in 0.8.0. Verifiers that read the 1.0 Final `encrypted_response_enc_values_supported` array (and `alg` from `client_metadata.jwks`) are unaffected; anything still reading the singular fields needs updating.
- **0.13.0** — **BREAKING:** SD-JWT VC issuer JWTs must carry `typ: dc+sd-jwt` (draft-ietf-oauth-sd-jwt-vc-19); `vc+sd-jwt` is rejected unless you pass `allowLegacyVcSdJwtTyp: true`, which is already deprecated and goes in 1.0.0. **BREAKING:** trust-module fetches (LOTL / national TL, CRL, OCSP) are SSRF-guarded by default — a CA, OCSP responder or trusted list on a private network now needs `fetcher: createGuardedFetcher({ allowHttp: true, allowPrivateNetworks: true })`. IACA → document-signer chain building only applies on the `trustStore` path: `trustedCertificates` is still byte-equality, so pass `trustStore: new StaticTrustStore([...])` to accept PIDs whose list publishes the IACA rather than the signer.
- **Unreleased** — **BREAKING:** the default mDOC `sessionTranscriptProfile` is now `'openid4vp-1.0'` (OpenID4VP 1.0 Final `OpenID4VPHandover`), and it is also auto-built for unencrypted `direct_post`. Verifiers that relied on the old Annex B default for draft-era wallets must pass `sessionTranscriptProfile: 'oid4vp-draft-annex-b'` (`'iso-18013-7'` still works as a deprecated alias). Encrypted `mso_mdoc` responses under the new default need `verifierEncryptionJwk`. New: [Digital Credentials API](#digital-credentials-api) support.

- **Unreleased (next minor)** — **BREAKING:** a KB-JWT needs an expected audience (`audience`, or `clientId` on `verifyAuthorizationResponse`; `MissingAudienceError` otherwise), its `aud` must be one string equal to it, and `typ: kb+jwt`, `iat` (within `kbJwtMaxAge`, default 300 s) and `sd_hash` are required. **BREAKING:** `verifyPresentation` / `verifyAuthorizationResponse` reject a bearer SD-JWT VC unless the query sets `require_cryptographic_holder_binding: false`. **BREAKING:** `trusted_authorities` `aki` values are base64url AKI key ids (hex still matches for one release, with a warning), and each value only matches its own type. **BREAKING:** certificates with unrecognised critical extensions are rejected; `createSignedAuthorizationRequest` rejects a `certificateChain` ending in the trust anchor. See [CHANGELOG](./CHANGELOG.md).
- **0.14.0** — Security release ([GHSA-3v3j-fghh-r2gg](https://github.com/openeudi/openid4vp/security/advisories/GHSA-3v3j-fghh-r2gg), [GHSA-r8q4-fcxm-v42q](https://github.com/openeudi/openid4vp/security/advisories/GHSA-r8q4-fcxm-v42q)). **BREAKING:** the KB-JWT `aud` must equal the verifier's client identifier. `verifyAuthorizationResponse` defaults `audience` to `clientId`, and with no audience available the check throws `MissingAudienceError`. **BREAKING:** the DCQL `require_cryptographic_holder_binding` (default `true`) is enforced, so bearer SD-JWT VCs fail unless the query sets it to `false`. **BREAKING:** `trusted_authorities` `aki` values are base64url (hex still matches for one release), unrecognised critical X.509 extensions are rejected, and Node.js 22 or later is required. KB-JWT `typ` and `iat` freshness (`kbJwtMaxAge`, default 300 s) are checked too.
- **0.15.0** — **BREAKING:** the auto-built mDOC SessionTranscript defaults to the OpenID4VP 1.0 Final `OpenID4VPHandover` (`sessionTranscriptProfile: 'openid4vp-1.0'`); pass `sessionTranscriptProfile: 'oid4vp-draft-annex-b'` for draft-era wallets. Additive: `verifierInfo` (`verifier_info`, ETSI TS 119 472-2), Token Status List checks (`statusPolicy`, `statusListResolver`), OpenID4VP over the Digital Credentials API (`verifyDcApiResponse`, KB-JWT `aud` = `origin:<origin>`), and the EU Age Verification fallback profile (`createAvAuthorizationRequest`, `verifyAvPresentation`).

## License

[Apache 2.0](./LICENSE)
