import type { X509Certificate } from '@peculiar/x509';

/**
 * A certificate used as the root of a trust chain. `source` tracks provenance
 * so consumers can distinguish static config from LOTL-derived anchors.
 */
export interface TrustAnchor {
    readonly certificate: X509Certificate;
    readonly source: 'static' | 'lotl';
    readonly metadata?: LotlAnchorMetadata;
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
