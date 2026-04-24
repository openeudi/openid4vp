/**
 * Internal types for the LOTL (List of Trusted Lists) module. NOT exported
 * from the package root. Consumed only by `LotlFetcher`, `LotlParser`,
 * `NationalTlResolver`, `LotlTrustStore`, and `ProvenanceResolver`.
 */

import type { X509Certificate } from '@peculiar/x509';

/**
 * One `OtherTSLPointer` entry in the LOTL. Identifies a national TL and
 * the cert(s) that should sign it.
 */
export interface OtherTslPointer {
    /** ISO 3166-1 alpha-2 scheme territory (`"FR"`, `"DE"`, ...). */
    readonly country: string;
    /** URL of the national TL XML (`TSLLocation`). */
    readonly tslLocation: string;
    /** Service digital identities expected to have signed the national TL. */
    readonly signingCertificates: readonly X509Certificate[];
}

/**
 * A parsed EU LOTL snapshot after XML-DSig verification. Contains only the
 * shape this module needs — not a literal TrustServiceStatusList round-trip.
 */
export interface LotlSnapshot {
    /** `SchemeInformation.ListIssueDateTime`. */
    readonly issueDate: Date;
    /** `SchemeInformation.NextUpdate.dateTime`. */
    readonly nextUpdate: Date | null;
    readonly pointers: readonly OtherTslPointer[];
}

/**
 * One `TSPService` inside a national TL, flattened with its provider's
 * `TSPInformation` and resolved certificates.
 */
export interface TspService {
    /** `TSPInformation.TSPName` of the provider that owns this service. */
    readonly providerName: string;
    /** ISO 3166-1 alpha-2 scheme territory the national TL belongs to. */
    readonly country: string;
    /** `ServiceTypeIdentifier`, e.g. `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`. */
    readonly serviceTypeIdentifier: string;
    /** `ServiceStatus`, e.g. `http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted`. */
    readonly serviceStatus: string;
    /** `ServiceName` (first language variant — English preferred). */
    readonly serviceName: string;
    /** All X.509 certs in `ServiceDigitalIdentity`. */
    readonly certificates: readonly X509Certificate[];
    /**
     * `AdditionalServiceInformation/URI` values. Used by the LoA mapping
     * in `lotl-loa-mapping.ts` to derive `'substantial' | 'high'`.
     */
    readonly additionalServiceInformationUris: readonly string[];
}

/** One national TL, parsed + verified. */
export interface NationalTlSnapshot {
    readonly country: string;
    readonly issueDate: Date;
    readonly nextUpdate: Date | null;
    readonly services: readonly TspService[];
}

/** Config for `LotlTrustStore` refresh behavior (spec §8.4). */
export interface LotlRefreshOptions {
    /** Milliseconds between snapshot refreshes. Default: 86_400_000 (24 h). */
    readonly refreshInterval?: number;
    /** Overrides the bundled `EU_LOTL_SIGNING_ANCHORS`. */
    readonly signingAnchors?: readonly X509Certificate[];
}
