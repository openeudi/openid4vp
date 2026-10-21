import type { X509Certificate } from '@peculiar/x509';

/**
 * A certificate used as the root of a trust chain. `source` tracks provenance
 * so consumers can distinguish static config from LOTL-derived anchors.
 */
export interface TrustAnchor {
    readonly certificate: X509Certificate;
    readonly source: 'static' | 'lotl';
    readonly metadata?: LotlAnchorMetadata;
    /**
     * Typed authority identifiers this anchor stands for, matched against a
     * DCQL `trusted_authorities` entry of the same `type` only. Populated by
     * `LotlTrustStore` (`aki` from the service certificate's SKI, `etsi_tl`
     * from the national TL and LOTL URLs). `TrustEvaluator` always adds the
     * `aki` ids of the validated chain itself, so static anchors need none.
     */
    readonly trustedAuthorities?: readonly TrustedAuthorityId[];
    /**
     * Untyped authority identifiers.
     *
     * @deprecated since 0.14.0 — set {@link trustedAuthorities} instead. When an
     * anchor has no `trustedAuthorities`, these values still match a DCQL
     * `trusted_authorities` entry of any type, as before. Removed in 1.0.0.
     */
    readonly trustedAuthorityIds?: readonly string[];
}

/**
 * One identifier usable in DCQL `trusted_authorities` (OpenID4VP 1.0
 * §6.1.1). For `aki`, `value` is the base64url (unpadded) KeyIdentifier of an
 * AuthorityKeyIdentifier in the credential's certificate chain; for
 * `etsi_tl`, the URL of an ETSI TS 119 612 trusted list.
 */
export interface TrustedAuthorityId {
    readonly type: 'aki' | 'etsi_tl' | 'openid_federation';
    readonly value: string;
}

/**
 * Metadata attached to anchors sourced from the EU LOTL (populated by
 * `LotlTrustStore` in A.3 — left optional here so the shape is stable today).
 */
export interface LotlAnchorMetadata {
    /** ISO 3166-1 alpha-2 country code of the TL scheme operator */
    readonly country: string;
    readonly serviceName: string;
    /** e.g. `http://uri.etsi.org/TrstSvc/Svctype/CA/QC` */
    readonly serviceTypeIdentifier: string;
    readonly serviceStatus: string;
    readonly qualified: boolean;
    readonly loa?: 'substantial' | 'high';
}
