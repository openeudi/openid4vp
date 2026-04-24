import { matchQuery, buildSubmission } from '@openeudi/dcql';
import type { DcqlQuery, DecodedCredential } from '@openeudi/dcql';

import { parsePresentation } from './presentation.js';
import { decryptAuthorizationResponse } from './decrypt-response.js';
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
        return verifyAuthorizationResponse(decrypted, query, options);
    }

    if (!isAuthorizationResponse(envelope)) {
        throw new TypeError('envelope must contain vp_token as a JSON object per OpenID4VP 1.0 §8.1');
    }

    const vpToken = envelope.vp_token;
    const queryIds = Object.keys(vpToken);

    if (queryIds.length === 0) {
        return {
            parsed: { valid: false, error: 'No presentations in vp_token' } as unknown as VerifyResult['parsed'],
            match: { satisfied: false, matches: [], unmatched: [] },
            submission: null,
            valid: false,
        };
    }

    const presentationCount = queryIds.reduce(
        (sum, id) => sum + (vpToken[id]?.length ?? 0),
        0,
    );
    if (queryIds.length > 1 || presentationCount > 1) {
        throw new MultipleCredentialsNotSupportedError(queryIds.length, presentationCount);
    }

    const presentation = vpToken[queryIds[0]][0];
    return verifyPresentation(presentation, query, options);
}
