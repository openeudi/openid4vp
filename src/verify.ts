import { matchQuery, buildSubmission } from '@openeudi/dcql';
import type { DcqlQuery, DecodedCredential } from '@openeudi/dcql';
import { decodeProtectedHeader } from 'jose';

import { parsePresentation } from './presentation.js';
import { decryptAuthorizationResponse } from './decrypt-response.js';
import {
    buildOid4vpSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from './crypto/session-transcript.js';
import {
    MissingDecryptionKeyError,
    MultipleCredentialsNotSupportedError,
} from './errors.js';
import type { CredentialFormat } from './types/presentation.js';
import type { AuthorizationResponse } from './types/authorization.js';
import type {
    EncryptedResponse,
    VerifyAuthorizationResponseOptions,
    VerifyOptions,
    VerifyResult,
} from './types/verify.js';

/**
 * Maps the internal `CredentialFormat` to the DCQL wire-level format string
 * as defined by OpenID4VP 1.0 final. The internal `sd-jwt-vc` value predates
 * the DCQL `dc+sd-jwt` identifier; we translate here so the parser contract
 * stays stable.
 */
const INTERNAL_TO_DCQL_FORMAT: Record<CredentialFormat, string> = {
    'sd-jwt-vc': 'dc+sd-jwt',
    mdoc: 'mso_mdoc',
};

/**
 * Parses a VP token, then matches it against a DCQL query.
 *
 * Cryptographic / structural parser failures still throw (via `parsePresentation`).
 * Query-level mismatches are surfaced as `match.unmatched` entries so callers can
 * show per-claim diagnostics.
 *
 * @param vpToken raw VP token (SD-JWT string or mDOC Uint8Array)
 * @param query  DCQL query describing the required credential(s)
 * @param options parse + verify options (nonce, trusted issuers, etc.)
 */
export async function verifyPresentation(
    vpToken: unknown,
    query: DcqlQuery,
    options: VerifyOptions
): Promise<VerifyResult> {
    const parsed = await parsePresentation(vpToken, options);

    const dcqlFormat = INTERNAL_TO_DCQL_FORMAT[parsed.format] ?? parsed.format;

    // For mDOC, DCQL claim paths address namespace-grouped values (e.g. ['ns', 'attr']).
    // For SD-JWT, the flat claim bag is addressed directly.
    const decodedClaims: Record<string, unknown> =
        parsed.format === 'mdoc' && parsed.namespacedClaims !== undefined
            ? (parsed.namespacedClaims as Record<string, unknown>)
            : (parsed.claims as unknown as Record<string, unknown>);

    const decoded: DecodedCredential = {
        id: query.credentials[0]?.id ?? 'presented',
        format: dcqlFormat,
        claims: decodedClaims,
    };

    if (parsed.format === 'sd-jwt-vc' && typeof parsed.vct === 'string') {
        decoded.vct = parsed.vct;
    }
    if (parsed.format === 'mdoc' && typeof parsed.docType === 'string') {
        decoded.doctype = parsed.docType;
    }

    // Forward trust-evaluation authority ids into the decoded credential so
    // DCQL's trusted_authorities filter can match them. Populated by
    // TrustEvaluator when a trustStore is provided (Task 16/17).
    if (
        parsed.trust?.trustedAuthorityIds &&
        parsed.trust.trustedAuthorityIds.length > 0
    ) {
        decoded.trusted_authority_ids = [...parsed.trust.trustedAuthorityIds];
    }

    const match = matchQuery(query, [decoded]);
    const submission = match.satisfied ? buildSubmission(query, match) : null;

    return {
        parsed,
        match,
        submission,
        valid: parsed.valid && match.satisfied,
    };
}

function isEncryptedResponse(x: unknown): x is EncryptedResponse {
    return (
        typeof x === 'object' &&
        x !== null &&
        'response' in x &&
        typeof (x as Record<string, unknown>).response === 'string' &&
        Object.keys(x).length === 1
    );
}

// base64url alphabet (RFC 4648 §5): URL-safe, unpadded. Decoded here without
// Node's Buffer or the browser's atob, matching the parser layer's approach so
// the library stays runtime-agnostic.
const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function base64UrlToBytes(input: string): Uint8Array {
    const cleaned = input.replace(/=+$/, '');
    const byteLength = Math.floor((cleaned.length * 3) / 4);
    const bytes = new Uint8Array(byteLength);
    let byteIndex = 0;
    for (let i = 0; i < cleaned.length; i += 4) {
        const a = BASE64URL_CHARS.indexOf(cleaned[i]);
        const b = i + 1 < cleaned.length ? BASE64URL_CHARS.indexOf(cleaned[i + 1]) : 0;
        const c = i + 2 < cleaned.length ? BASE64URL_CHARS.indexOf(cleaned[i + 2]) : 0;
        const d = i + 3 < cleaned.length ? BASE64URL_CHARS.indexOf(cleaned[i + 3]) : 0;
        if (a === -1 || b === -1 || c === -1 || d === -1) {
            throw new TypeError('Invalid base64url character in vp_token/apu');
        }
        bytes[byteIndex++] = (a << 2) | (b >> 4);
        if (byteIndex < byteLength) bytes[byteIndex++] = ((b & 0x0f) << 4) | (c >> 2);
        if (byteIndex < byteLength) bytes[byteIndex++] = ((c & 0x03) << 6) | d;
    }
    return bytes;
}

/**
 * Extract the `mdoc-generated-nonce` from a JWE's `apu` protected header
 * (ISO 18013-7 Annex B). `apu` is a base64url string whose decoded bytes are the
 * UTF-8 nonce. Returns undefined when the header is malformed or carries no `apu`
 * (the caller then leaves the SessionTranscript unset and the mDOC parser fails
 * closed). The actual JWE validation/decryption is left to
 * {@link decryptAuthorizationResponse}, which raises the canonical errors.
 */
function extractMdocGeneratedNonce(jwe: string): string | undefined {
    let apu: unknown;
    try {
        apu = decodeProtectedHeader(jwe).apu;
    } catch {
        return undefined;
    }
    if (typeof apu !== 'string' || apu.length === 0) {
        return undefined;
    }
    // apu is an attacker-influenceable header nonce: a malformed value must fall
    // through to the documented graceful fail-closed path (transcript left unset,
    // mDOC parser rejects), NOT surface base64UrlToBytes's loud TypeError — which
    // is reserved for the vp_token DeviceResponse decode.
    try {
        return new TextDecoder().decode(base64UrlToBytes(apu));
    } catch {
        return undefined;
    }
}

function isAuthorizationResponse(x: unknown): x is AuthorizationResponse {
    return (
        typeof x === 'object' &&
        x !== null &&
        'vp_token' in x &&
        typeof (x as Record<string, unknown>).vp_token === 'object' &&
        (x as Record<string, unknown>).vp_token !== null
    );
}

/**
 * Verify an OpenID4VP 1.0 §8.1 Authorization Response envelope.
 *
 * Accepts either the unencrypted envelope (object-keyed `vp_token`) or a
 * JWE-wrapped envelope `{ response: '<JWE>' }` for response_mode =
 * direct_post.jwt. When encrypted, decrypts with `options.decryptionKey`
 * first. For this release only single-credential single-presentation is
 * supported — multi-credential envelopes throw
 * {@link MultipleCredentialsNotSupportedError}. Otherwise delegates the
 * extracted single presentation to the existing {@link verifyPresentation}.
 *
 * Callers MUST compare the envelope's `state` against the value they issued
 * themselves — library is stateless and does not track state.
 */
export async function verifyAuthorizationResponse(
    envelope: AuthorizationResponse | EncryptedResponse,
    query: DcqlQuery,
    options: VerifyAuthorizationResponseOptions,
): Promise<VerifyResult> {
    if (isEncryptedResponse(envelope)) {
        if (!options.decryptionKey) {
            throw new MissingDecryptionKeyError();
        }

        // Auto-build the mDOC SessionTranscript. A caller-supplied transcript
        // always wins. Otherwise the layout depends on `sessionTranscriptProfile`
        // (default 'iso-18013-7' preserves prior behavior):
        //  - 'iso-18013-7': ISO 18013-7 Annex B OID4VPHandover, derived from the
        //    mdoc-generated-nonce carried in the JWE `apu` header — which only
        //    exists on the encrypted response, so this is the sole place we can
        //    derive it.
        //  - 'openid4vp-1.0': OpenID4VP 1.0 (Final) OpenID4VPHandover (§B.2.6),
        //    derived from `verifierEncryptionJwk`'s thumbprint instead — no `apu`
        //    needed.
        // When the request config or apu/JWK is missing, we leave the transcript
        // unset and the mDOC parser fails closed (SD-JWT flows are unaffected
        // either way).
        const nextOptions: VerifyAuthorizationResponseOptions = { ...options };
        if (
            options.mdocSessionTranscript === undefined &&
            options.clientId !== undefined &&
            options.responseUri !== undefined &&
            options.nonce !== undefined
        ) {
            if (options.sessionTranscriptProfile === 'openid4vp-1.0') {
                nextOptions.mdocSessionTranscript = await buildOpenID4VPHandoverSessionTranscript({
                    clientId: options.clientId,
                    nonce: options.nonce,
                    responseUri: options.responseUri,
                    verifierEncryptionJwk: options.verifierEncryptionJwk,
                });
            } else {
                const mdocGeneratedNonce = extractMdocGeneratedNonce(envelope.response);
                if (mdocGeneratedNonce !== undefined) {
                    nextOptions.mdocSessionTranscript = await buildOid4vpSessionTranscript({
                        clientId: options.clientId,
                        responseUri: options.responseUri,
                        nonce: options.nonce,
                        mdocGeneratedNonce,
                    });
                }
            }
        }

        const decrypted = await decryptAuthorizationResponse(
            envelope.response,
            options.decryptionKey,
        );
        return verifyAuthorizationResponse(decrypted, query, nextOptions);
    }

    if (!isAuthorizationResponse(envelope)) {
        throw new TypeError('envelope must contain vp_token as a JSON object per OpenID4VP 1.0 §8.1');
    }

    const vpToken = envelope.vp_token;
    const queryIds = Object.keys(vpToken);

    if (queryIds.length === 0) {
        throw new TypeError('vp_token cannot be empty per OpenID4VP 1.0 §8.1');
    }

    for (const id of queryIds) {
        if (!Array.isArray(vpToken[id])) {
            throw new TypeError(
                `vp_token entry "${id}" must be an array of presentations per OpenID4VP 1.0 §8.1`,
            );
        }
    }

    const presentationCount = queryIds.reduce(
        (sum, id) => sum + vpToken[id].length,
        0,
    );
    if (queryIds.length > 1 || presentationCount > 1) {
        throw new MultipleCredentialsNotSupportedError(queryIds.length, presentationCount);
    }

    const presentation = vpToken[queryIds[0]][0];

    // OpenID4VP 1.0 / ISO 18013-7: an `mso_mdoc` VP token is a base64url-encoded
    // CBOR DeviceResponse. Once carried through a JWE-decrypted JSON envelope it is
    // a string, so decode it back to the Uint8Array the mDOC parser expects. SD-JWT
    // (string) and any already-binary presentation pass through unchanged.
    const decodedPresentation =
        query.credentials[0]?.format === 'mso_mdoc' && typeof presentation === 'string'
            ? base64UrlToBytes(presentation)
            : presentation;

    return verifyPresentation(decodedPresentation, query, options);
}
