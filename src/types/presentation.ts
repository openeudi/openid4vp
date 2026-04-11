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
}

import type { IssuerInfo } from './issuer.js';
export type { IssuerInfo } from './issuer.js';
