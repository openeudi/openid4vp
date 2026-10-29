import type { DcqlMatchResult, DcqlQuery } from '@openeudi/dcql';

import { AV_DOCTYPE, AV_DOCUMENT_SIGNER_EKU } from './av/constants.js';
import { PerCredentialOptionsError } from './errors.js';
import { ISO_18013_5_DS_EKU } from './trust/ChainBuilder.js';
import type {
    PerCredentialVerifyOptions,
    PerCredentialVerifyOptionsMap,
    VerifyOptions,
} from './types/verify.js';

/**
 * Check `perCredential` against the DCQL query before anything of the response
 * is read: every key must be a credential query id, every entry an object, and
 * `avProfile` only on an `mso_mdoc` query that has a `trustStore`.
 */
export function validatePerCredentialOptions(
    query: DcqlQuery,
    perCredential: PerCredentialVerifyOptionsMap | undefined,
): void {
    if (perCredential === undefined) return;
    if (typeof perCredential !== 'object' || perCredential === null || Array.isArray(perCredential)) {
        throw new PerCredentialOptionsError(
            'invalid_per_credential_options',
            'perCredential must be an object keyed by DCQL credential query id',
        );
    }
    const keys = Object.keys(perCredential);
    if (keys.length === 0) {
        throw new PerCredentialOptionsError(
            'invalid_per_credential_options',
            'perCredential has no entries: every answered credential would be rejected',
        );
    }
    const credentials = Array.isArray(query?.credentials) ? query.credentials : [];
    for (const id of keys) {
        const credentialQuery = credentials.find((c) => c.id === id);
        if (credentialQuery === undefined) {
            throw new PerCredentialOptionsError(
                'unknown_credential_id',
                `perCredential key "${id}" is not a credential id of the DCQL query`,
                id,
            );
        }
        const entry = perCredential[id];
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
            throw new PerCredentialOptionsError(
                'invalid_per_credential_options',
                `perCredential["${id}"] must be an options object`,
                id,
            );
        }
        if (entry.avProfile === true) {
            if (credentialQuery.format !== 'mso_mdoc') {
                throw new PerCredentialOptionsError(
                    'invalid_per_credential_options',
                    `perCredential["${id}"].avProfile applies to mso_mdoc only, but the query is "${credentialQuery.format}"`,
                    id,
                );
            }
            if (!entry.trustStore) {
                throw new PerCredentialOptionsError(
                    'invalid_per_credential_options',
                    `perCredential["${id}"].avProfile requires a trustStore with the AV Attestation Provider anchors`,
                    id,
                );
            }
        }
    }
}

/**
 * The entry for the credential the wallet answered. Throws when there is none:
 * there is deliberately no fallback to the top-level trust options.
 */
export function perCredentialEntryFor(
    perCredential: PerCredentialVerifyOptionsMap,
    presentedQueryId: string,
): PerCredentialVerifyOptions {
    if (!Object.hasOwn(perCredential, presentedQueryId)) {
        throw new PerCredentialOptionsError(
            'missing_credential_options',
            `the wallet answered credential query "${presentedQueryId}", which has no perCredential entry`,
            presentedQueryId,
        );
    }
    return perCredential[presentedQueryId];
}

/**
 * The parse options for the answered credential: the entry's trust and status
 * options REPLACE the top-level ones. Each is assigned even when the entry
 * leaves it out, so a top-level value never leaks into the answered
 * credential's verification.
 */
export function applyPerCredentialOptions<T extends VerifyOptions>(
    options: T,
    entry: PerCredentialVerifyOptions,
): T {
    const avProfile = entry.avProfile === true;
    return {
        ...options,
        trustStore: entry.trustStore,
        trustedCertificates: entry.trustedCertificates,
        trustedIssuerJwks: entry.trustedIssuerJwks,
        statusPolicy: entry.statusPolicy,
        statusListResolver: entry.statusListResolver,
        revocationPolicy: entry.revocationPolicy,
        cache: entry.cache,
        mdocDocumentSignerEkus:
            entry.documentSignerEkus ?? (avProfile ? [AV_DOCUMENT_SIGNER_EKU, ISO_18013_5_DS_EKU] : undefined),
        expectedDocType: avProfile ? AV_DOCTYPE : options.expectedDocType,
    };
}

/**
 * Keep only what the presentation proves for the credential query it was
 * answered as. DCQL matches a decoded credential against every query entry,
 * so without this a credential verified under one `perCredential` entry (one
 * set of anchors) could satisfy a different entry of a `credential_sets`
 * disjunction. Matches for other entries are reported as unmatched and
 * `satisfied` is recomputed as `matchQuery` does.
 */
export function restrictMatchToQueryId(
    query: DcqlQuery,
    match: DcqlMatchResult,
    queryId: string,
): DcqlMatchResult {
    const matches = match.matches.filter((m) => m.queryId === queryId);
    const dropped = [...new Set(match.matches.filter((m) => m.queryId !== queryId).map((m) => m.queryId))];
    const unmatched = [
        ...match.unmatched,
        ...dropped.map((id) => ({
            queryId: id,
            reason: 'no_credential_found' as const,
            detail: `the presentation was answered as credential query "${queryId}"`,
        })),
    ];
    const satisfiedIds = new Set(matches.map((m) => m.queryId));
    const satisfied =
        query.credential_sets && query.credential_sets.length > 0
            ? query.credential_sets.every(
                  (set) => set.required === false || set.options.some((option) => option.every((id) => satisfiedIds.has(id))),
              )
            : unmatched.length === 0;
    return { satisfied, matches, unmatched };
}
