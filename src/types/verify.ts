import type { DcqlMatchResult, DcqlSubmission } from '@openeudi/dcql';
import type { ParseOptions } from '../parsers/parser.interface.js';
import type { PresentationResult } from './presentation.js';

export type VerifyOptions = ParseOptions;

export interface VerifyResult {
    parsed: PresentationResult;
    match: DcqlMatchResult;
    submission: DcqlSubmission | null;
    valid: boolean;
}

export interface EncryptedResponse {
    response: string;
}

export type VerifyAuthorizationResponseOptions = VerifyOptions & {
    decryptionKey?: CryptoKey;

    /**
     * The OpenID4VP verifier's `client_id`, as sent in the authorization request.
     * Combined with {@link responseUri}, {@link ParseOptions.nonce} and the
     * `mdoc-generated-nonce` (carried in the JWE `apu` header, ISO 18013-7 Annex B),
     * it lets the encrypted-response path auto-build the mDOC SessionTranscript the
     * mDOC parser requires — so callers need not construct the CBOR by hand. Ignored
     * when the caller supplies {@link ParseOptions.mdocSessionTranscript} explicitly.
     */
    clientId?: string;

    /**
     * The OpenID4VP verifier's `response_uri`, as sent in the authorization request.
     * See {@link clientId} — used to auto-build the mDOC SessionTranscript.
     */
    responseUri?: string;

    /**
     * Which mDOC SessionTranscript layout to auto-build when {@link clientId},
     * {@link responseUri} and {@link ParseOptions.nonce} are present and the
     * caller has not supplied {@link ParseOptions.mdocSessionTranscript}:
     *
     * - `'iso-18013-7'` (default): the ISO 18013-7 Annex B `OID4VPHandover`,
     *   derived from the `mdoc-generated-nonce` carried in the JWE `apu` header.
     *   This is the id2/id3-era layout and is kept as the default for
     *   backwards compatibility.
     * - `'openid4vp-1.0'`: the OpenID4VP 1.0 (Final) `OpenID4VPHandover`
     *   (§B.2.6), derived from {@link verifierEncryptionJwk}'s RFC 7638
     *   thumbprint instead of an `apu` nonce.
     */
    sessionTranscriptProfile?: 'iso-18013-7' | 'openid4vp-1.0';

    /**
     * The verifier's response-encryption public JWK. Required when
     * {@link sessionTranscriptProfile} is `'openid4vp-1.0'` and the response is
     * encrypted — its RFC 7638 SHA-256 thumbprint is embedded in the
     * OpenID4VPHandover SessionTranscript. Ignored for the `'iso-18013-7'`
     * profile (which uses the JWE `apu` header instead).
     */
    verifierEncryptionJwk?: JsonWebKey;
};
