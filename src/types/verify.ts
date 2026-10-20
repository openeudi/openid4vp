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
};
