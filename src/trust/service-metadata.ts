import { mapLoA } from './lotl-loa-mapping.js';
import type { TspService } from './lotl-types.js';

/**
 * Derive the `qualified` + `loa` fields from a `TspService` per spec §8.5.
 * Returned by `LotlTrustStore` when it builds `LotlAnchorMetadata` and by
 * `ProvenanceResolver` when it builds the provenance block — keeping the
 * derivation in one place guarantees the two views agree.
 */
export function deriveServiceMetadata(service: TspService): {
    qualified: boolean;
    loa?: 'substantial' | 'high';
} {
    const qualified =
        service.serviceTypeIdentifier.endsWith('/CA/QC') &&
        service.serviceStatus.endsWith('/granted');
    const loa = mapLoA(service.additionalServiceInformationUris);
    return loa !== undefined ? { qualified, loa } : { qualified };
}
