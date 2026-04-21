import type { TrustedAuthoritiesQuery } from '@openeudi/dcql';

export interface HaipQueryInput {
    credentialId: string;
    format: 'dc+sd-jwt' | 'mso_mdoc';
    vctValues?: string[];
    doctypeValue?: string;
    claims: string[];
    trustedAuthorities?: TrustedAuthoritiesQuery[];
}
