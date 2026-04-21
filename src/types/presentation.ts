export type CredentialFormat = 'sd-jwt-vc' | 'mdoc';

export interface CredentialClaims {
    age_over_18?: boolean;
    age_over_21?: boolean;
    resident_country?: string;
    nationality?: string;
    family_name_birth?: string;
    [key: string]: unknown;
}

export interface PresentationResult {
    valid: boolean;
    format: CredentialFormat;
    claims: CredentialClaims;
    issuer: IssuerInfo;
    error?: string;
    /** SD-JWT type (Verifiable Credential Type URI). Populated for `sd-jwt-vc` format. */
    vct?: string;
    /** mDOC docType (ISO 18013-5). Populated for `mdoc` format. */
    docType?: string;
    /**
     * mDOC claims grouped by namespace. Populated for `mdoc` format.
     * DCQL claim paths address this shape: `['org.iso.18013.5.1', 'age_over_18']`.
     */
    namespacedClaims?: Record<string, Record<string, unknown>>;
}

import type { IssuerInfo } from './issuer.js';
export type { IssuerInfo } from './issuer.js';
