import { X509Certificate } from '@peculiar/x509';
import type { NationalTlSnapshot, TspService } from './lotl-types.js';
import { deriveServiceMetadata } from './service-metadata.js';
import { getSkiHex } from './x509-utils.js';

export interface ResolvedProvenance {
    readonly provenance: {
        readonly loa?: 'substantial' | 'high';
        readonly qualified: boolean;
        readonly country: string;
        readonly serviceName: string;
    };
    readonly trustedAuthorityIds: readonly string[];
}

/**
 * Private — NOT exported from the package root. Maps a LOTL-sourced anchor
 * cert to its ETSI TS 119 612 `TSPService` entry across all national TLs.
 * Spec §8.5 qualified derivation is deterministic; loa derivation falls
 * back to `undefined` when the service's `AdditionalServiceInformation`
 * URIs don't map to a known LoA.
 */
export class ProvenanceResolver {
    resolve(
        anchor: X509Certificate,
        nationalTls: readonly NationalTlSnapshot[]
    ): ResolvedProvenance | null {
        const anchorSki = getSkiHex(anchor);
        if (!anchorSki) return null;
        for (const tl of nationalTls) {
            for (const service of tl.services) {
                if (serviceMatches(service, anchorSki)) {
                    return buildProvenance(service, anchorSki);
                }
            }
        }
        return null;
    }
}

function serviceMatches(service: TspService, anchorSki: string): boolean {
    for (const cert of service.certificates) {
        const ski = getSkiHex(cert);
        if (ski && ski === anchorSki) return true;
    }
    return false;
}

function buildProvenance(
    service: TspService,
    anchorSki: string
): ResolvedProvenance {
    const derived = deriveServiceMetadata(service);
    const provenance: ResolvedProvenance['provenance'] = {
        country: service.country,
        serviceName: service.serviceName,
        ...derived,
    };
    return {
        provenance,
        trustedAuthorityIds: [anchorSki],
    };
}
