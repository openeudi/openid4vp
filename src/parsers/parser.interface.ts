import type { CredentialFormat, PresentationResult } from '../types/presentation.js';
import type { Cache } from '../trust/Cache.js';
import type { Fetcher } from '../trust/Fetcher.js';
import type { TrustStore } from '../trust/TrustStore.js';
import type { StatusPolicy } from '../status/credential-status.js';
import type { StatusListResolver } from '../status/StatusListResolver.js';

export interface ParseOptions {
    /**
     * DER-encoded issuer leaf certificates used for byte-equality trust check.
     * Kept for 0.4.0 compatibility. No chain building: a credential signed by a
     * document signer issued under a listed root (e.g. an IACA) is rejected on
     * this path — use `trustStore` for that.
     * @deprecated since 0.5.0. Use `trustStore: new StaticTrustStore([...])`
     * with root/intermediate CAs for RFC 5280 chain validation. Scheduled
     * for removal in 1.0.0. Optional since 0.14.0: it is ignored whenever
     * `trustStore` is set, and an omitted value counts as empty.
     */
    trustedCertificates?: Uint8Array[];

    nonce: string;

    /**
     * Expected audience of the key binding JWT: the verifier's Client
     * Identifier as sent in the request (OpenID4VP 1.0 Appendix B.3.6), e.g.
     * `x509_hash:…` or `x509_san_dns:verifier.example`.
     *
     * Required whenever a KB-JWT is verified — the parser throws
     * `MissingAudienceError` otherwise. `verifyAuthorizationResponse` defaults
     * it to `clientId`. The KB-JWT `aud` must be a single string equal to this
     * value; a missing `aud` or an array `aud` is rejected.
     */
    audience?: string;

    /**
     * Force holder-binding verification even when the issuer JWT carries no
     * `cnf` claim. When the credential IS holder-bound (`cnf` present), a
     * KB-JWT is ALWAYS required regardless of this flag — this flag only
     * extends the requirement to credentials that lack `cnf`. Default: false
     * for the parsers.
     *
     * `verifyPresentation` / `verifyAuthorizationResponse` additionally
     * require holder binding whenever the matched DCQL credential query does
     * not set `require_cryptographic_holder_binding: false` (OpenID4VP 1.0
     * §6.1 — the default is `true`).
     */
    requireKeyBinding?: boolean;

    /**
     * Largest accepted age, in seconds, of a key binding JWT judged by its
     * `iat` (RFC 9901 §7.3 step 5e). `clockSkewTolerance` is added on both
     * sides, so an `iat` up to that many seconds in the future is also
     * accepted. Default 300.
     */
    kbJwtMaxAge?: number;

    /** Allowed JWT signature algorithms. Defaults to ['ES256', 'ES384', 'ES512']. */
    allowedAlgorithms?: string[];

    /**
     * CBOR bytes of the ISO 18013-5 `SessionTranscript` data item for the current
     * OpenID4VP exchange. REQUIRED to verify mDOC device authentication — the
     * mDOC parser fails closed without it, since device proof-of-possession and
     * replay/nonce binding cannot otherwise be checked.
     *
     * Which handover to build depends on the wallet: OpenID4VP 1.0 wallets use
     * the 1.0 `OpenID4VPHandover` (Appendix B.2.6: client_id, nonce, the JWK
     * thumbprint of the verifier's encryption key, response_uri) — see
     * `buildOpenID4VPHandoverSessionTranscript`. Draft-era wallets use the
     * ISO 18013-7 Annex B `OID4VPHandover` with the `mdoc-generated-nonce` —
     * see `buildOid4vpSessionTranscript`.
     */
    mdocSessionTranscript?: Uint8Array;

    /**
     * Explicit opt-in to skip the trust check. When omitted or `false`,
     * either `trustedCertificates` must be non-empty OR `trustStore` must be
     * provided — otherwise parsing throws `MalformedCredentialError`.
     */
    skipTrustCheck?: boolean;

    /**
     * When set, the parsed credential's `docType` (mDOC) or `vct` (SD-JWT)
     * must equal this value — otherwise parsing throws `MalformedCredentialError`.
     */
    expectedDocType?: string;

    // ---- New in 0.5.0 ---------------------------------------------------

    /**
     * Trust anchor resolver. When provided, the library performs RFC 5280
     * chain validation and ignores `trustedCertificates`. When unset, the
     * library falls back to 0.4.0 byte-equality against `trustedCertificates`.
     *
     * The credential's signer certificate (`x5c[0]` / `x5chain[0]`) is trusted
     * when it either IS an anchor (byte-identical DER) or chains to one through
     * verified signatures, using the remaining `x5c` / `x5chain` entries as
     * untrusted path candidates. Anchors may be roots such as an ISO 18013-5
     * IACA, or the document-signer certificate itself. For `mso_mdoc`, built
     * chains must also satisfy the ISO 18013-5 Annex B certificate profile
     * (DS EKU `1.0.18013.5.1.2`, mandatory keyUsage). Every certificate must be
     * valid now and at the credential's issuance time (MSO `signed` / `iat`).
     */
    trustStore?: TrustStore;

    /**
     * Extended key usages accepted on an `mso_mdoc` Document Signer when a
     * chain is built through `trustStore` (at least one must be present).
     * Default `['1.0.18013.5.1.2']` (ISO 18013-5 `id-mdl-kp-mdlDS`). A signer
     * that IS a trust anchor is not EKU-checked. `verifyAvPresentation` sets
     * this for the EU Age Verification profile.
     */
    mdocDocumentSignerEkus?: readonly string[];

    /**
     * Certificate revocation (CRL / OCSP) policy for the issuer chain built
     * from `trustStore`. Default `'skip'`.
     * - `'prefer'`: check; a revoked certificate fails, an unreachable
     *   responder yields `revocationStatus: 'unknown'`.
     * - `'require'`: check; a revoked certificate fails and so does a check
     *   that cannot complete.
     */
    revocationPolicy?: 'skip' | 'prefer' | 'require';

    /**
     * HTTP transport for CRL/OCSP/LOTL fetches. Defaults to a guarded fetcher
     * (`createGuardedFetcher({ allowHttp: true })`): no private/loopback/metadata
     * targets, manual re-validated redirects (max 3), 15 s timeout, 16 MiB cap.
     * A caller-supplied fetcher replaces those guards entirely — wrap it with
     * `createGuardedFetcher({ fetch: yourFetcher })` to keep them.
     */
    fetcher?: Fetcher;

    /** Cache for CRL/OCSP/LOTL artefacts. Defaults to `new InMemoryCache()`. */
    cache?: Cache;

    /**
     * Clock-skew tolerance in seconds for certificate validity checks and for
     * the key binding JWT `iat` / `exp` / `nbf` checks. Default 60.
     */
    clockSkewTolerance?: number;

    /**
     * An explicit set of trusted issuer JWKs used as an alternate trust path when the
     * SD-JWT VC's issuer JWT lacks an `x5c` header. When the header has no `x5c`:
     *   - If this array is provided, the parser looks up the issuer key by `kid`
     *     (or by exact `kty`/`crv`/`x`/`y` match when no `kid` is present). The
     *     matched JWK is the trust anchor — cert-chain validation is skipped.
     *   - If this array is absent (or empty), the parser falls back to the existing
     *     behaviour and throws `MalformedCredentialError('Missing or invalid x5c in JWT header')`.
     *
     * **When the JWT header DOES include `x5c`** this option is ignored — the existing
     * x5c/`trustedCertificates` / `trustStore` path runs unchanged.
     *
     * **Security notice**: opting in to this path skips certificate-chain trust
     * evaluation entirely. The caller is explicitly asserting that they trust the
     * supplied JWK(s) out-of-band. This is appropriate for CI harness setups (e.g.
     * OIDF conformance suite, where the wallet signs without x5c and the verifier
     * knows the signing key from the test-plan config). It is **not recommended for
     * production verifiers** — cert-chain trust evaluation via `trustStore` is the
     * secure path.
     */
    trustedIssuerJwks?: JsonWebKey[];

    /**
     * Accept the legacy `vc+sd-jwt` media type in the SD-JWT VC issuer JWT's
     * `typ` header, in addition to `dc+sd-jwt`. Default `false`.
     *
     * @deprecated draft-ietf-oauth-sd-jwt-vc-19 removed `vc+sd-jwt`; only
     * `dc+sd-jwt` is conformant. This exists solely to keep interoperating
     * with wallets that have not migrated yet and will be removed in 1.0.0.
     */
    allowLegacyVcSdJwtTyp?: boolean;

    // ---- Token Status List (draft-ietf-oauth-status-list-21) ------------

    /**
     * How the credential's `status` claim (`status.status_list`) is checked.
     * Default `'skip'` (unchanged behaviour); intended to become `'prefer'` in 1.0.
     *
     * - `'prefer'` — a definitive INVALID / SUSPENDED / unrecognised status, an
     *   out-of-range `idx` or a malformed `status` claim yields `valid: false`.
     *   When no statement can be made (list unreachable, untrusted, expired,
     *   malformed) the credential is accepted and
     *   `credentialStatus.outcome === 'unavailable'` carries a warning.
     * - `'require'` — as `'prefer'`, but "no statement can be made" throws
     *   `StatusListError`.
     *
     * Any value other than `'skip'` requires {@link statusListResolver}.
     * Applies to SD-JWT VC only in this release; the mdoc MSO `status`
     * (`statuslist+cwt`) is not evaluated yet.
     */
    statusPolicy?: StatusPolicy;

    /**
     * Resolver for Status List Tokens. Create ONE per process and reuse it so
     * its cache spans presentations; give it the status-list signer anchors
     * (e.g. the LoTE `PID/Revocation` services), not the issuance anchors.
     */
    statusListResolver?: StatusListResolver;
}

export interface ICredentialParser {
    readonly format: CredentialFormat;
    canParse(vpToken: unknown): boolean;
    parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult>;
}
