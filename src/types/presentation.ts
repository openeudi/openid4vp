export type CredentialFormat = 'sd-jwt-vc' | 'mdoc';

/**
 * The disclosed claims of a presentation: every claim, keyed by its name as
 * the credential carries it (for example `birthdate`, `nationalities` and
 * `address` for an SD-JWT VC PID, or the mdoc element identifiers). Treat it
 * as `Record<string, unknown>`; it is assignable to that type.
 *
 * The named fields below predate that and only describe some non-PID
 * credentials: an EU PID carries neither `age_over_18` nor `age_over_21`, and
 * its SD-JWT VC form has `nationalities` (an array), not `nationality`.
 */
export interface CredentialClaims {
    /** @deprecated Not a PID claim. Read `claims['age_over_18']` (unknown) and check its type; removed in 1.0.0. */
    age_over_18?: boolean;
    /** @deprecated Not a PID claim. Read `claims['age_over_21']` and check its type; removed in 1.0.0. */
    age_over_21?: boolean;
    /** @deprecated Read `claims['resident_country']` and check its type; removed in 1.0.0. */
    resident_country?: string;
    /** @deprecated The SD-JWT VC PID uses `nationalities` (array). Removed in 1.0.0. */
    nationality?: string;
    /** @deprecated Read `claims['family_name_birth']` and check its type; removed in 1.0.0. */
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
    /**
     * Additional types the issuer declared in the issuer-signed `aka_vcts`
     * claim (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2). `sd-jwt-vc` only;
     * omitted when absent. Used by `verifyPresentation` for `vct_values`
     * matching.
     */
    akaVcts?: string[];
    /** mDOC docType (ISO 18013-5). Populated for `mdoc` format. */
    docType?: string;
    /**
     * mDOC claims grouped by namespace. Populated for `mdoc` format.
     * DCQL claim paths address this shape: `['org.iso.18013.5.1', 'age_over_18']`.
     */
    namespacedClaims?: Record<string, Record<string, unknown>>;
    /**
     * Populated when `ParseOptions.trustStore` was provided and trust
     * evaluation succeeded. Contains the validated chain, matched anchor,
     * and revocation + provenance metadata (populated incrementally across
     * 0.5.0 A.1/A.2/A.3). Omitted when `skipTrustCheck: true` or when
     * `trustStore` was not provided.
     */
    trust?: TrustEvaluationResult;
    /**
     * Token Status List outcome. Populated for SD-JWT VC when
     * `ParseOptions.statusPolicy` is `'prefer'` or `'require'`.
     */
    credentialStatus?: CredentialStatusResult;
}

import type { IssuerInfo } from './issuer.js';
import type { TrustEvaluationResult } from '../trust/TrustEvaluator.js';
import type { CredentialStatusResult } from '../status/credential-status.js';
export type { IssuerInfo } from './issuer.js';
