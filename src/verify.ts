import { matchQuery, buildSubmission } from '@openeudi/dcql';
import type { DcqlQuery, DecodedCredential } from '@openeudi/dcql';
import { decodeProtectedHeader } from 'jose';

import { parsePresentation } from './presentation.js';
import {
    credentialTypes,
    hasKeyBindingJwt,
    requiresHolderBinding,
    vctForQuery,
} from './credential-types.js';
import { prepareTrustedAuthorityMatching } from './trusted-authorities.js';
import { decryptAuthorizationResponse } from './decrypt-response.js';
import {
    buildOid4vpSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from './crypto/session-transcript.js';
import {
    MissingDecryptionKeyError,
    MissingVerifierEncryptionKeyError,
    MultipleCredentialsNotSupportedError,
    WalletErrorResponseError,
} from './errors.js';
import type { CredentialFormat, PresentationResult } from './types/presentation.js';
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
    let parsed = await parsePresentation(vpToken, options);
    const types = credentialTypes(parsed, options.vctAncestors);

    const dcqlFormat = INTERNAL_TO_DCQL_FORMAT[parsed.format] ?? parsed.format;

    // For mDOC, DCQL claim paths address namespace-grouped values (e.g. ['ns', 'attr']).
    // For SD-JWT, the flat claim bag is addressed directly.
    const decodedClaims: Record<string, unknown> =
        parsed.format === 'mdoc' && parsed.namespacedClaims !== undefined
            ? (parsed.namespacedClaims as Record<string, unknown>)
            : (parsed.claims as unknown as Record<string, unknown>);

    // Resolve which query credential this presentation actually is. `decoded.id`
    // is what DCQL matching attributes the presentation to, so getting it wrong
    // reports a credential the wallet never presented.
    //
    // This entry point has no `queryIds` — unlike verifyAuthorizationResponse,
    // which reads the id the wallet keyed the vp_token with — so the credential
    // has to be identified from its own contents. Format alone is not enough: a
    // query can list several entries of the same format distinguished only by
    // vct or doctype. Narrow by format, then by credential type, and only fall
    // back to first-listed when nothing identifies it.
    const sameFormat = query.credentials.filter((c) => c.format === dcqlFormat);
    const presentedCredentialQuery =
        sameFormat.find((c) => matchesCredentialType(c, parsed, types)) ??
        sameFormat[0] ??
        query.credentials[0];

    const decoded: DecodedCredential = {
        id: presentedCredentialQuery?.id ?? 'presented',
        format: dcqlFormat,
        claims: decodedClaims,
    };

    // OpenID4VP 1.0 §6.1: holder binding is required unless the query entry
    // opts out. mdoc DeviceAuth is always verified; an SD-JWT VC without a
    // KB-JWT passed the parser only because it has no `cnf`.
    if (
        parsed.valid &&
        parsed.format === 'sd-jwt-vc' &&
        requiresHolderBinding(presentedCredentialQuery) &&
        !hasKeyBindingJwt(vpToken)
    ) {
        parsed = {
            ...parsed,
            valid: false,
            error:
                `Cryptographic holder binding is required by credential query "${presentedCredentialQuery?.id}" ` +
                'but the presentation has no key binding JWT',
        };
    }

    if (parsed.format === 'sd-jwt-vc' && typeof parsed.vct === 'string') {
        // The real vct stays on `parsed`; DCQL sees the inherited type it asked for.
        decoded.vct = vctForQuery(types, parsed.vct, presentedCredentialQuery);
    }
    if (parsed.format === 'mdoc' && typeof parsed.docType === 'string') {
        decoded.doctype = parsed.docType;
    }

    // Forward trust-evaluation authority ids into the decoded credential so
    // DCQL's trusted_authorities filter can match them, type-tagged on both
    // sides (see trusted-authorities.ts). Populated by TrustEvaluator when a
    // trustStore is provided.
    const authorities = prepareTrustedAuthorityMatching(query, parsed.trust);
    if (authorities.ids) {
        decoded.trusted_authority_ids = authorities.ids;
    }

    const match = matchQuery(authorities.query, [decoded]);
    const submission = match.satisfied ? buildSubmission(query, match) : null;

    return {
        parsed,
        match,
        submission,
        valid: parsed.valid && match.satisfied,
    };
}

/**
 * Does this query credential's type constraint match what was actually presented?
 *
 * `vct_values` / `doctype_value` are the only things distinguishing two query
 * entries of the same format, so they are what identifies the presented
 * credential when no query id is available. Returns false when the query states
 * no constraint — an unconstrained entry matches anything, which makes it useless
 * for telling two entries apart, so it should not win over a specific one.
 */
function matchesCredentialType(
    credentialQuery: DcqlQuery['credentials'][number],
    parsed: PresentationResult,
    types: readonly string[]
): boolean {
    if (parsed.format === 'sd-jwt-vc') {
        const vctValues = credentialQuery.meta?.vct_values;
        return Array.isArray(vctValues) && types.some((t) => vctValues.includes(t));
    }
    if (parsed.format === 'mdoc') {
        const doctype = credentialQuery.meta?.doctype_value;
        return typeof parsed.docType === 'string' && doctype === parsed.docType;
    }
    return false;
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
        const decrypted = await decryptAuthorizationResponse(
            envelope.response,
            options.decryptionKey,
        );
        return verifyEnvelope(decrypted, query, options, envelope.response);
    }
    return verifyEnvelope(envelope, query, options, undefined);
}

/**
 * Verify a plaintext §8.1 envelope. `jwe` is the compact JWE it was decrypted
 * from, or undefined when the response arrived unencrypted — it decides the
 * SessionTranscript's thumbprint element and carries the Annex B `apu` nonce.
 */
async function verifyEnvelope(
    envelope: unknown,
    query: DcqlQuery,
    options: VerifyAuthorizationResponseOptions,
    jwe: string | undefined,
): Promise<VerifyResult> {
    // OpenID4VP 1.0 §8.5 error response (also reachable decrypted, §8.3.1).
    const walletResponse = envelope as Record<string, unknown> | null;
    if (typeof walletResponse === 'object' && walletResponse !== null && typeof walletResponse.error === 'string') {
        throw new WalletErrorResponseError({ ...walletResponse, error: walletResponse.error });
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

    const presentedQueryId = queryIds[0];
    const presentation = vpToken[presentedQueryId][0];

    // OpenID4VP 1.0 / ISO 18013-7: an `mso_mdoc` VP token is a base64url-encoded
    // CBOR DeviceResponse. Once carried through a JWE-decrypted JSON envelope it is
    // a string, so decode it back to the Uint8Array the mDOC parser expects. SD-JWT
    // (string) and any already-binary presentation pass through unchanged.
    //
    // Dispatch on the credential the wallet actually presented (queryIds[0], per
    // §8.1) rather than query.credentials[0], the first entry in the DCQL query —
    // for a dual-format query built with credential_sets those can differ, and the
    // wrong one always decodes as if it were the first-listed format.
    const presentedCredentialQuery = query.credentials.find(
        (c) => c.id === presentedQueryId,
    );
    const isMdoc = presentedCredentialQuery?.format === 'mso_mdoc';
    const decodedPresentation =
        isMdoc && typeof presentation === 'string'
            ? base64UrlToBytes(presentation)
            : presentation;

    const mdocSessionTranscript = isMdoc
        ? await autoBuildMdocSessionTranscript(options, jwe)
        : options.mdocSessionTranscript;

    // OpenID4VP 1.0 Appendix B.3.6: the KB-JWT `aud` is the Client Identifier.
    return verifyPresentation(decodedPresentation, query, {
        ...options,
        audience: options.audience ?? options.clientId,
        mdocSessionTranscript,
    });
}

/**
 * Auto-build the mDOC SessionTranscript for an OpenID4VP redirect-flow
 * response (`direct_post` / `direct_post.jwt`). A caller-supplied transcript
 * always wins. Without `clientId`, `responseUri` and `nonce` nothing is built
 * and the mDOC parser fails closed.
 *
 * - `'openid4vp-1.0'` (default): OpenID4VP 1.0 §B.2.6.1 `OpenID4VPHandover`.
 *   The thumbprint element is the verifier encryption key's thumbprint when the
 *   response was encrypted and `null` otherwise, per the spec.
 * - `'oid4vp-draft-annex-b'` / `'iso-18013-7'`: the legacy Annex B layout,
 *   derived from the JWE `apu` header, so encrypted responses only.
 */
async function autoBuildMdocSessionTranscript(
    options: VerifyAuthorizationResponseOptions,
    jwe: string | undefined,
): Promise<Uint8Array | undefined> {
    if (
        options.mdocSessionTranscript !== undefined ||
        options.clientId === undefined ||
        options.responseUri === undefined ||
        options.nonce === undefined
    ) {
        return options.mdocSessionTranscript;
    }

    const profile = options.sessionTranscriptProfile ?? 'openid4vp-1.0';
    if (profile === 'oid4vp-draft-annex-b' || profile === 'iso-18013-7') {
        const mdocGeneratedNonce = jwe === undefined ? undefined : extractMdocGeneratedNonce(jwe);
        if (mdocGeneratedNonce === undefined) return undefined;
        return buildOid4vpSessionTranscript({
            clientId: options.clientId,
            responseUri: options.responseUri,
            nonce: options.nonce,
            mdocGeneratedNonce,
        });
    }

    // An encrypted response implies the verifier advertised an encryption JWK,
    // so a missing `verifierEncryptionJwk` is a caller misconfiguration. Fail
    // loud rather than bind a null-thumbprint transcript that would only show
    // up later as an opaque device-auth failure.
    if (jwe !== undefined && options.verifierEncryptionJwk === undefined) {
        throw new MissingVerifierEncryptionKeyError();
    }
    return buildOpenID4VPHandoverSessionTranscript({
        clientId: options.clientId,
        nonce: options.nonce,
        responseUri: options.responseUri,
        verifierEncryptionJwk: jwe === undefined ? undefined : options.verifierEncryptionJwk,
    });
}
