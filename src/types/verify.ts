import type { DcqlMatchResult, DcqlSubmission } from '@openeudi/dcql';
import type { ParseOptions } from '../parsers/parser.interface.js';
import type { PresentationResult } from './presentation.js';

export type VerifyOptions = ParseOptions & {
    /**
     * Out-of-band SD-JWT VC type inheritance: maps a `vct` to the types it
     * extends, e.g. `{ 'urn:eudi:pid:de:1': ['urn:eudi:pid:1'] }`. Walked
     * transitively. A credential then matches a DCQL `vct_values` entry naming
     * any of its types (OpenID4VP 1.0 Appendix B.3.5); `parsed.vct` still
     * reports the credential's own `vct`. The issuer-signed `aka_vcts` claim
     * is honoured without configuration. Type Metadata is never fetched.
     */
    vctAncestors?: Readonly<Record<string, readonly string[]>>;
};

/**
 * Trust and status options for ONE DCQL credential query, used by the
 * `perCredential` option of `verifyAuthorizationResponse` and
 * `verifyDcApiResponse`.
 *
 * For the credential the wallet answered, these values REPLACE the
 * corresponding top-level options; nothing is merged and nothing falls back to
 * the top level. An option left out here takes its library default (for
 * example no `trustStore`, `statusPolicy: 'skip'`), not the top-level value.
 */
export interface PerCredentialVerifyOptions {
    /** Replaces {@link ParseOptions.trustStore}. */
    trustStore?: ParseOptions['trustStore'];

    /**
     * Replaces {@link ParseOptions.trustedCertificates}.
     * @deprecated as on {@link ParseOptions.trustedCertificates}: prefer `trustStore`.
     */
    trustedCertificates?: ParseOptions['trustedCertificates'];

    /** Replaces {@link ParseOptions.trustedIssuerJwks} (SD-JWT VC without `x5c`). */
    trustedIssuerJwks?: ParseOptions['trustedIssuerJwks'];

    /** Replaces {@link ParseOptions.statusPolicy}. */
    statusPolicy?: ParseOptions['statusPolicy'];

    /** Replaces {@link ParseOptions.statusListResolver}. */
    statusListResolver?: ParseOptions['statusListResolver'];

    /** Replaces {@link ParseOptions.revocationPolicy} (X.509 CRL / OCSP of the issuer chain). */
    revocationPolicy?: ParseOptions['revocationPolicy'];

    /** Replaces {@link ParseOptions.cache}. */
    cache?: ParseOptions['cache'];

    /**
     * Replaces {@link ParseOptions.mdocDocumentSignerEkus} for an `mso_mdoc`
     * credential. With `avProfile: true` it defaults to the EU Age
     * Verification Document Signer EKU plus the ISO 18013-5 DS EKU.
     */
    documentSignerEkus?: readonly string[];

    /**
     * Verify this `mso_mdoc` credential as an EU Age Verification Proof of Age
     * attestation (AV Annex A §A.4): exactly one `eu.europa.ec.av.1` document,
     * only boolean `age_over_NN` elements in namespace `eu.europa.ec.av.1`, no
     * device-signed elements, MSO docType `eu.europa.ec.av.1`, and the AV
     * Document Signer EKU default. Requires `trustStore`. Only valid on an
     * `mso_mdoc` credential query.
     */
    avProfile?: boolean;
}

/**
 * `perCredential`: per-DCQL-credential trust and status options, keyed by the
 * DCQL credential query id (the key the wallet uses in `vp_token`, OpenID4VP
 * 1.0 §8.1). Every key must be a credential id of the query.
 */
export type PerCredentialVerifyOptionsMap = Readonly<Record<string, PerCredentialVerifyOptions>>;

export interface VerifyResult {
    parsed: PresentationResult;
    match: DcqlMatchResult;
    submission: DcqlSubmission | null;
    valid: boolean;
}

export interface EncryptedResponse {
    response: string;
}

/**
 * mDOC SessionTranscript layouts that `verifyAuthorizationResponse` can
 * auto-build.
 *
 * - `'openid4vp-1.0'` — OpenID4VP 1.0 Final `OpenID4VPHandover` (§B.2.6.1).
 *   The default since the release after 0.13.0.
 * - `'oid4vp-draft-annex-b'` — the legacy ISO 18013-7 Annex B
 *   `OID4VPHandover` used by draft-era (ID2/ID3) wallets, derived from the
 *   `mdoc-generated-nonce` in the JWE `apu` header.
 * - `'iso-18013-7'` — deprecated alias of `'oid4vp-draft-annex-b'`, kept so
 *   existing configurations keep working. Removed in 1.0.0.
 */
export type SessionTranscriptProfile =
    | 'openid4vp-1.0'
    | 'oid4vp-draft-annex-b'
    /** @deprecated Use `'oid4vp-draft-annex-b'`. Removed in 1.0.0. */
    | 'iso-18013-7';

export type VerifyAuthorizationResponseOptions = VerifyOptions & {
    decryptionKey?: CryptoKey;

    /**
     * The OpenID4VP verifier's `client_id`, as sent in the authorization request
     * (including its Client Identifier Prefix). Together with
     * {@link responseUri} and {@link ParseOptions.nonce} it lets
     * `verifyAuthorizationResponse` auto-build the mDOC SessionTranscript the
     * mDOC parser requires, so callers need not construct the CBOR by hand.
     * Ignored when the caller supplies {@link ParseOptions.mdocSessionTranscript}.
     */
    clientId?: string;

    /**
     * The OpenID4VP verifier's `response_uri`, as sent in the authorization request.
     * See {@link clientId} — used to auto-build the mDOC SessionTranscript.
     */
    responseUri?: string;

    /**
     * Which mDOC SessionTranscript layout to auto-build when the presented
     * credential is `mso_mdoc`, {@link clientId}, {@link responseUri} and
     * {@link ParseOptions.nonce} are present, and the caller has not supplied
     * {@link ParseOptions.mdocSessionTranscript}:
     *
     * - `'openid4vp-1.0'` (default): the OpenID4VP 1.0 Final
     *   `OpenID4VPHandover` (§B.2.6.1). Built for both envelopes: for
     *   `direct_post.jwt` the third element is the RFC 7638 thumbprint of
     *   {@link verifierEncryptionJwk}; for unencrypted `direct_post` it is
     *   `null`, as the spec requires.
     * - `'oid4vp-draft-annex-b'`: the legacy ISO 18013-7 Annex B
     *   `OID4VPHandover`, derived from the `mdoc-generated-nonce` in the JWE
     *   `apu` header. Encrypted responses only.
     * - `'iso-18013-7'`: deprecated alias of `'oid4vp-draft-annex-b'`.
     */
    sessionTranscriptProfile?: SessionTranscriptProfile;

    /**
     * The verifier's response-encryption public JWK. Required for an encrypted
     * `mso_mdoc` response under the `'openid4vp-1.0'` profile — its RFC 7638
     * SHA-256 thumbprint is embedded in the OpenID4VPHandover SessionTranscript.
     * Ignored for unencrypted responses (the thumbprint is then `null`) and for
     * the legacy Annex B profile (which uses the JWE `apu` header instead).
     */
    verifierEncryptionJwk?: JsonWebKey;

    /**
     * Trust and status options per DCQL credential query, for a query whose
     * `credential_sets` lets the wallet answer one of several credentials that
     * need different trust (e.g. an EU AV Proof of Age attestation OR a PID).
     * Keyed by credential query id; every key must be an id of the query, or
     * `PerCredentialOptionsError('unknown_credential_id')` is thrown before
     * the response is read.
     *
     * When set, the credential the wallet answered (its `vp_token` key) MUST
     * have an entry, or `PerCredentialOptionsError('missing_credential_options')`
     * is thrown. The entry's options replace the top-level `trustStore`,
     * `trustedCertificates`, `trustedIssuerJwks`, `statusPolicy`,
     * `statusListResolver`, `revocationPolicy`, `cache` and
     * `mdocDocumentSignerEkus` — no merging, no fallback — and the presentation
     * is matched only against that credential query, so a credential trusted
     * under one entry can never satisfy another. All other options stay
     * top-level.
     */
    perCredential?: PerCredentialVerifyOptionsMap;
};
