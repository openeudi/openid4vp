/**
 * Map ETSI `AdditionalServiceInformation` URIs to eIDAS Regulation
 * (EU 910/2014) Article 8 levels of assurance. Per spec §8.5, absence
 * of a mapping means `loa` is omitted from the provenance block
 * (NOT mapped to 'low' — we never synthesize LoAs we did not observe).
 *
 * Source: ETSI TS 119 612 v2.2.1 Annex D + Commission Implementing
 * Decision (EU) 2015/1505.
 */

export const LOA_MAPPING: Readonly<Record<string, 'substantial' | 'high'>> = Object.freeze({
    // Qualified electronic signature / seal — substantial + high are both
    // expressed via `qualified` in ETSI, not LoA. The LoA URIs below apply to
    // electronic-identification services (eIDAS Article 8 notified schemes).
    'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/eIDASnotified-substantial':
        'substantial',
    'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/eIDASnotified-high':
        'high',
    'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/eIDAS-substantial':
        'substantial',
    'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/eIDAS-high':
        'high',
});

export function mapLoA(
    uris: readonly string[]
): 'substantial' | 'high' | undefined {
    // `high` wins over `substantial` when both are present.
    let result: 'substantial' | 'high' | undefined;
    for (const uri of uris) {
        const mapped = LOA_MAPPING[uri];
        if (mapped === 'high') return 'high';
        if (mapped === 'substantial') result = 'substantial';
    }
    return result;
}
