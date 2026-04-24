import { matchQuery, buildSubmission } from '@openeudi/dcql';
import type {
    DcqlQuery,
    DecodedCredential,
    DcqlMatchResult,
    CredentialQuery,
    UnmatchedReason,
} from '@openeudi/dcql';

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
 * Replicates `@openeudi/dcql@0.1.1`'s internal `matchCredentialQuery`
 * precedence to restore a specific `UnmatchedReason` that the public
 * `matchQuery` API collapses to `'no_credential_found'`.
 *
 * The outer `matchQuery` preserves the inner `detail` JSON-pointer when the
 * inner reason is `missing_claims`, which we use as the only available
 * signal to distinguish claim-path rejections from category rejections.
 *
 * TODO: remove this workaround once @openeudi/dcql surfaces specific
 * reasons at its public API.
 */
function classifyMismatch(
    query: CredentialQuery,
    decoded: DecodedCredential,
    hasDetail: boolean
): UnmatchedReason {
    if (decoded.format !== query.format) return 'format_mismatch';

    if (query.format === 'dc+sd-jwt') {
        const allowed = query.meta?.vct_values;
        if (allowed && allowed.length > 0 && !allowed.includes(decoded.vct ?? '')) {
            return 'vct_mismatch';
        }
    }

    if (query.format === 'mso_mdoc') {
        const expected = query.meta?.doctype_value;
        if (expected && expected !== decoded.doctype) return 'doctype_mismatch';
    }

    if (query.trusted_authorities && query.trusted_authorities.length > 0) {
        const decodedAuthIds = decoded.trusted_authority_ids ?? [];
        const anyMatch = query.trusted_authorities.some((ta) =>
            ta.values.some((v) => decodedAuthIds.includes(v))
        );
        if (!anyMatch) return 'trusted_authority_mismatch';
    }

    if (hasDetail) return 'missing_claims';
    return 'no_credential_found';
}

/**
 * Post-processes `DcqlMatchResult.unmatched` to replace the collapsed
 * `'no_credential_found'` reason that `@openeudi/dcql@0.1.1` returns with a
 * specific `UnmatchedReason` from {@link classifyMismatch}. Fast-path return
 * when there is nothing to refine (happy path), so this costs nothing on
 * successful verifications.
 */
function refineUnmatched(
    query: DcqlQuery,
    decoded: DecodedCredential,
    match: DcqlMatchResult
): DcqlMatchResult {
    if (match.unmatched.length === 0) return match;

    const refined = match.unmatched.map((entry) => {
        const credentialQuery = query.credentials.find((c) => c.id === entry.queryId);
        if (!credentialQuery) return entry;
        const specific = classifyMismatch(credentialQuery, decoded, entry.detail !== undefined);
        return { ...entry, reason: specific };
    });

    return { ...match, unmatched: refined };
}

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

    const rawMatch = matchQuery(query, [decoded]);
    const match = refineUnmatched(query, decoded, rawMatch);
    const submission = match.satisfied ? buildSubmission(query, match) : null;

    return {
        parsed,
        match,
        submission,
        valid: parsed.valid && match.satisfied,
    };
}
