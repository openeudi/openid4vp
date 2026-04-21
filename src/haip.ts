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
