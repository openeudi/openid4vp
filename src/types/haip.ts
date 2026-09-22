import type { TrustedAuthoritiesQuery } from '@openeudi/dcql';

export interface HaipQueryInput {
    credentialId: string;
    format: 'dc+sd-jwt' | 'mso_mdoc';
    vctValues?: string[];
    doctypeValue?: string;
    claims: string[];
    trustedAuthorities?: TrustedAuthoritiesQuery[];
}

/**
 * Input to `buildCredentialSetQuery` — a DCQL `credential_sets` disjunction
 * offering the wallet several alternative credentials for the same question.
 */
export interface CredentialSetQueryInput {
    /**
     * The alternatives, **most-preferred first**. Option order is a privacy
     * signal, not cosmetic: list the credential that discloses least first.
     * Wallets are not obliged to honour the order.
     */
    options: HaipQueryInput[];
    /** Whether the wallet must satisfy one option. Default: `true`. */
    required?: boolean;
}
