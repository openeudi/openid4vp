/**
 * Internal types for the revocation module. NOT exported from the
 * package root. Consumed only by `RevocationChecker`, `CrlFetcher`,
 * `OcspClient`, and `TrustEvaluator`.
 */

import type { X509Certificate } from '@peculiar/x509';

export type RevocationStatus = 'good' | 'revoked' | 'unknown';

export interface RevocationResult {
    /** Definitive status from the chosen source, or 'unknown' on transient failure. */
    status: RevocationStatus;
    /** Which source produced this verdict. 'none' when no source was available. */
    source: 'ocsp' | 'crl' | 'none';
    /** Populated when status === 'revoked'. */
    revokedAt?: Date;
    /** Populated when status === 'revoked' and the source reported a reason. */
    revocationReason?: string;
    /** When this check was performed. */
    checkedAt: Date;
}

/**
 * Hints extracted from the leaf cert to drive OCSP/CRL endpoint discovery.
 * Populated by `RevocationChecker` before dispatching to sub-modules.
 */
export interface RevocationSourceHint {
    /** OCSP responder URL from `authorityInfoAccess` `id-ad-ocsp`. */
    ocspUrl?: string;
    /** CRL distribution-point URLs from `cRLDistributionPoints`. First is tried, fallbacks follow. */
    crlUrls: string[];
    /** The certificate being checked. */
    subjectCert: X509Certificate;
    /** The issuer cert that signed the subject (direct parent in the chain). */
    issuerCert: X509Certificate;
}
