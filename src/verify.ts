import { matchQuery, buildSubmission } from '@openeudi/dcql';
import type { DcqlQuery, DecodedCredential } from '@openeudi/dcql';

import { parsePresentation } from './presentation.js';
import type { CredentialFormat } from './types/presentation.js';
import type { VerifyOptions, VerifyResult } from './types/verify.js';

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
