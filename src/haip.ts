import type { DcqlQuery, CredentialQuery, ClaimsQuery } from '@openeudi/dcql';
import { HaipValidationError } from './errors.js';
import type { HaipQueryInput } from './types/haip.js';

export const HAIP_DOCTYPE_NAMESPACES: Record<string, string> = {
    'org.iso.18013.5.1.mDL': 'org.iso.18013.5.1',
    'eu.europa.ec.eudi.pid.1': 'eu.europa.ec.eudi.pid.1',
};

export function buildHaipQuery(input: HaipQueryInput): DcqlQuery {
    if (input.claims.length === 0) {
        throw new HaipValidationError(
            'NO_CLAIMS',
            `credential '${input.credentialId}' must declare at least one claim`,
            input.credentialId,
        );
    }

    let meta: CredentialQuery['meta'];
    let claims: ClaimsQuery[];

    if (input.format === 'dc+sd-jwt') {
        if (!input.vctValues || input.vctValues.length === 0) {
            throw new HaipValidationError(
                'MISSING_SDJWT_META',
                `credential '${input.credentialId}' with format 'dc+sd-jwt' must provide non-empty vctValues`,
                input.credentialId,
            );
        }
        meta = { vct_values: input.vctValues };
        claims = input.claims.map((c) => ({ path: [c] }));
    } else {
        if (!input.doctypeValue) {
            throw new HaipValidationError(
                'MISSING_MDOC_META',
                `credential '${input.credentialId}' with format 'mso_mdoc' must provide doctypeValue`,
                input.credentialId,
            );
        }
        meta = { doctype_value: input.doctypeValue };
        const namespace = HAIP_DOCTYPE_NAMESPACES[input.doctypeValue] ?? input.doctypeValue;
        claims = input.claims.map((c) => ({ path: [namespace, c] }));
    }

    const credential: CredentialQuery = {
        id: input.credentialId,
        format: input.format,
        meta,
        claims,
    };

    if (input.trustedAuthorities && input.trustedAuthorities.length > 0) {
        credential.trusted_authorities = input.trustedAuthorities;
    }

    return { credentials: [credential] };
}

const HAIP_FORMATS = new Set<string>(['dc+sd-jwt', 'mso_mdoc']);

export function validateHaipQuery(query: DcqlQuery): void {
    if (!query.credentials || query.credentials.length === 0) {
        throw new HaipValidationError(
            'EMPTY_QUERY',
            'query.credentials must have at least one entry',
        );
    }

    if (query.credential_sets !== undefined) {
        throw new HaipValidationError(
            'CREDENTIAL_SETS_DISALLOWED',
            'credential_sets are not permitted in HAIP-minimal',
        );
    }

    for (const credential of query.credentials) {
        if (!HAIP_FORMATS.has(credential.format)) {
            throw new HaipValidationError(
                'UNSUPPORTED_FORMAT',
                `credential '${credential.id}' uses unsupported format '${credential.format}' (allowed: dc+sd-jwt, mso_mdoc)`,
                credential.id,
            );
        }

        if (credential.format === 'dc+sd-jwt') {
            const vctValues = credential.meta?.vct_values;
            if (!vctValues || vctValues.length === 0) {
                throw new HaipValidationError(
                    'MISSING_SDJWT_META',
                    `credential '${credential.id}' with format 'dc+sd-jwt' must set meta.vct_values`,
                    credential.id,
                );
            }
        }

        if (credential.format === 'mso_mdoc') {
            if (typeof credential.meta?.doctype_value !== 'string') {
                throw new HaipValidationError(
                    'MISSING_MDOC_META',
                    `credential '${credential.id}' with format 'mso_mdoc' must set meta.doctype_value`,
                    credential.id,
                );
            }
        }

        if (!credential.claims || credential.claims.length === 0) {
            throw new HaipValidationError(
                'NO_CLAIMS',
                `credential '${credential.id}' must declare at least one claim`,
                credential.id,
            );
        }

        if (credential.claim_sets !== undefined) {
            throw new HaipValidationError(
                'CLAIM_SETS_DISALLOWED',
                `credential '${credential.id}' uses claim_sets, not permitted in HAIP-minimal`,
                credential.id,
            );
        }
    }
}

export function isHaipQuery(query: DcqlQuery): boolean {
    try {
        validateHaipQuery(query);
        return true;
    } catch {
        return false;
    }
}
