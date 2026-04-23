import type { CredentialFormat, PresentationResult } from '../types/presentation.js';
import type { Cache } from '../trust/Cache.js';
import type { Fetcher } from '../trust/Fetcher.js';
import type { TrustStore } from '../trust/TrustStore.js';

export interface ParseOptions {
    /**
     * DER-encoded issuer leaf certificates used for byte-equality trust check.
     * Kept for 0.4.0 compatibility.
     * @deprecated since 0.5.0. Use `trustStore: new StaticTrustStore([...])`
     * with root/intermediate CAs for RFC 5280 chain validation. Scheduled
     * for removal in 1.0.0.
     */
    trustedCertificates: Uint8Array[];

    nonce: string;

    /** Expected audience for key binding JWT verification. Optional. */
    audience?: string;

    /** Allowed JWT signature algorithms. Defaults to ['ES256', 'ES384', 'ES512']. */
    allowedAlgorithms?: string[];

    /**
     * Explicit opt-in to skip the trust check. When omitted or `false`,
     * either `trustedCertificates` must be non-empty OR `trustStore` must be
     * provided — otherwise parsing throws `MalformedCredentialError`.
     */
    skipTrustCheck?: boolean;

    /**
     * When set, the parsed credential's `docType` (mDOC) or `vct` (SD-JWT)
     * must equal this value — otherwise parsing throws `MalformedCredentialError`.
     */
    expectedDocType?: string;

    // ---- New in 0.5.0 ---------------------------------------------------

    /**
     * Trust anchor resolver. When provided, the library performs RFC 5280
     * chain validation and ignores `trustedCertificates`. When unset, the
     * library falls back to 0.4.0 byte-equality against `trustedCertificates`.
     */
    trustStore?: TrustStore;

    /**
     * Revocation checking policy. Default `'skip'`. `'prefer'` and `'require'`
     * ship in 0.5.0 workstream A.2 — passing them today throws.
     */
    revocationPolicy?: 'skip' | 'prefer' | 'require';

    /** HTTP transport for CRL/OCSP/LOTL fetches. Defaults to `globalThis.fetch`. */
    fetcher?: Fetcher;

    /** Cache for CRL/OCSP/LOTL artefacts. Defaults to `new InMemoryCache()`. */
    cache?: Cache;

    /** Clock-skew tolerance in seconds for certificate validity checks. Default 60. */
    clockSkewTolerance?: number;
}

export interface ICredentialParser {
    readonly format: CredentialFormat;
    canParse(vpToken: unknown): boolean;
    parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult>;
}
