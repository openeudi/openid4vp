# Manual OIDF Verifier Conformance Interop

This guide runs `@openeudi/openid4vp` as a verifier against the OpenID Foundation conformance suite at [demo.certification.openid.net](https://demo.certification.openid.net). The suite acts as a mock web wallet and drives our verifier through a realistic authorization → response flow.

## Why run this

Automated unit/contract tests exercise the library in isolation; they do not prove a remote wallet will accept our signed authorization request, nor that we correctly parse a wallet-issued JWE response. A green OIDF plan provides that end-to-end confidence. A red plan with diagnosable failures is also useful — it tells us exactly which request/response fields are wrong.

The conformance suite is not part of CI. Run it manually before a release that changes the authorization-request envelope, JAR signing, response encryption, or any HAIP-facing shape.

## Scope and known gaps

Our implementation targets **OpenID4VP 1.0 Final**. The OIDF suite's most mature verifier plan is **ID3 (Implementer's Draft 3) plus draft 24**. Some `client_metadata` field names and shapes differ between the two revisions; the suite may flag `client_metadata` drift as a WARNING. That is expected and not a library defect.

## Prerequisites

- Node 20+ and this repo checked out with a clean tree on the branch you want to test.
- A public HTTPS tunnel to `localhost:8080`. Either works:
  - `ngrok http 8080` (free tier gives a rotating `*.ngrok-free.app` hostname).
  - `cloudflared tunnel --url http://localhost:8080`.
- A [demo.certification.openid.net](https://demo.certification.openid.net) account (free, GitHub OAuth login).

## One-shot procedure

### 1. Build and start the helper server

```bash
npm run build
PUBLIC_BASE=https://<your-tunnel-hostname> node scripts/manual-oidf-run.mjs
```

The script prints four values you will paste into the OIDF form:

```
client_id:     x509_san_dns:<your-tunnel-hostname>
request_uri:   https://<your-tunnel-hostname>/request.jwt
response_uri:  https://<your-tunnel-hostname>/response
Short URI:     openid4vp://authorize?client_id=...&request_uri=...
```

Leave it running. `/request.jwt` serves the signed JAR; `/response` receives and decrypts the wallet JWE.

### 2. Create a test plan

On [demo.certification.openid.net](https://demo.certification.openid.net):

1. **Create a new test plan**.
2. **Specification**: `OID4VP`.
3. **Entity Under Test**: `Test a OpenID4VP Verifier`.
4. **Version**: `ID3`.
5. **Test Plan**: `OpenID for Verifiable Presentations ID3 (plus draft 24): Test a verifier`.
6. Variants:
   - **Credential Format**: `sd_jwt_vc`
   - **Client Id Scheme**: `x509_san_dns`
   - **Request Method**: `request_uri_signed`
   - **Query Language**: `dcql`
   - **Response Mode**: `direct_post.jwt`

In the **JSON** tab, paste a config shaped like this (adjust values):

```json
{
  "alias": "openeudi-openid4vp-b-remaining",
  "description": "Manual OIDF interop for @openeudi/openid4vp vX.Y.Z",
  "publish": "no",
  "client_id": "x509_san_dns:<your-tunnel-hostname>",
  "credential": {
    "signing_jwk": { "...": "see §4 below" }
  }
}
```

> **Note**: `client_id` sits at the top level, **not** nested under a `"client"` object — OIDF's JSON schema is flatter than the Form-view section headers suggest. A nested placement silently fails with `EnsureMatchingClientId: Mismatch between Client ID in test configuration and the one in the authorization request`.

Click **Create Test Plan**. Capture the **Plan ID** (shown on the plan page) for the release PR.

### 3. Run the test

On the plan page, click **▶ Run Test** next to the `oid4vp-id3-verifier-happy-flow` module.

The test page shows **Exported Values** after setup. The key one is `authorization_endpoint` — the URL the OIDF mock-wallet listens on. The conformance suite is a web wallet, not an `openid4vp://` handler. Trigger the flow by opening this URL in a browser tab:

```
<authorization_endpoint>?client_id=<url-encoded-client_id>&request_uri=<url-encoded-request_uri>
```

(The script's "Short URI" output is the same shape with `openid4vp://authorize` swapped in; copy the query string from there.)

The mock wallet then:

1. GETs `/request.jwt` from our helper (via the tunnel) and validates the signed JAR.
2. Generates a test SD-JWT VC credential, wraps it in an encrypted JWE.
3. POSTs `response=<JWE>` (form-encoded) to `/response`.

Our helper logs the verification result. The OIDF UI updates from WAITING → SUCCESS / FAILURE.

### 4. Signing JWK for the test credential

The OIDF issues a test SD-JWT VC; it needs a signing JWK (and matching x509 cert) to do that. If you leave it out, the test interrupts with `CreateSdJwtKbCredential: Credential Signing JWK missing from configuration`.

Generate a P-256 EC JWK offline, paste the public half into the plan config's `credential.signing_jwk`, and put the matching issuer cert's DER bytes into `trustedCertificates` in `scripts/manual-oidf-run.mjs` (currently `[]` — see the TODO). Without that, our verifier rejects the test credential as untrusted.

A future improvement is to script this keypair generation inline so the plan config + script are wired together automatically.

### 5. Capture and report

For each release that runs this test, record in the release PR body:

- Plan ID (e.g. `2nlImI7uEf6sy`).
- Variant string (copied verbatim from the plan page).
- Results tally (`SUCCESS N, FAILURE N, WARNING N, REVIEW N, INFO N`).
- For each FAILURE: the check ID (e.g. `OID4VP-ID3-5.10.4`), short message, and whether it's a library bug, fixture issue, or known 1.0-final-vs-ID3 drift.

If any FAILURE indicates a library bug, stop — fix it on the same branch using the RED → GREEN test loop before merging the release.

## Failure catalog (from the 2026-04-24 run against 0.7.0)

All four failures below were fixture / harness / plan-config issues, not library defects. They are documented here so a future run does not rediscover them.

| Check ID | Message | Cause | Fix |
|---|---|---|---|
| `RFC7519-4.1.4` | Request object expired | Script builds the JAR once at startup; by the time OIDF fetches it, `exp` is stale. | Rebuild the JAR per `/request.jwt` fetch, or bump `exp` to ~10 minutes at build time. |
| `OID4VP-ID3-5.10.4` | Leaf certificate in x5c chain must not be self-signed | `scripts/manual-oidf-run.mjs` uses a self-signed leaf. ID3 §5.10.4 forbids that. | Generate a throwaway CA + leaf chain inside the script; put the CA in `x5c` above the leaf. |
| `OIDCC-3.1.2.1` | Mismatch between Client ID in test configuration and the one in the authorization request | Plan config JSON had `"client": { "client_id": ... }` nested; OIDF expects `client_id` at top level. | Re-create the plan with `client_id` at top level. |
| (no code) | CreateSdJwtKbCredential: Credential Signing JWK missing from configuration | Plan config had no credential-issuer Signing JWK; OIDF cannot sign the test credential, so the test interrupts. | Add `credential.signing_jwk` to the plan config; add the matching issuer cert DER bytes to the script's `trustedCertificates`. |

A warning of `CheckForUnexpectedParametersInVpClientMetadata` is the expected 1.0-final-vs-ID3 drift and not a defect.

## Troubleshooting

- **`tsyringe requires a reflect polyfill`** when starting the script: the `reflect-metadata` import must be the first statement. Already fixed in the script; if you see this, confirm nothing re-ordered the imports.
- **Tunnel hostname changed mid-run**: ngrok free tier rotates hostnames when the tunnel restarts. The cert in the script binds to the hostname captured at startup, so any mismatch breaks the `x509_san_dns` check. Restart the script whenever the tunnel restarts.
- **OIDF fetches `/request.jwt` but nothing happens on `/response`**: the wallet side rejected the JAR (expired, untrusted, or malformed). Check the OIDF test log — it shows exactly which validator failed.

## References

- OIDF conformance suite: https://gitlab.com/openid/conformance-suite
- OpenID4VP 1.0 Final: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OpenID4VP ID3: https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html
- HAIP (High Assurance Interoperability Profile): https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
