import { describe, expect, it } from 'vitest';
import { EU_LOTL_SIGNING_ANCHORS } from '../../src/trust/lotl-signing-anchors.js';

describe('EU_LOTL_SIGNING_ANCHORS', () => {
    it('loads at least one signing anchor', () => {
        expect(EU_LOTL_SIGNING_ANCHORS.length).toBeGreaterThan(0);
    });

    it('every anchor is a well-formed X509Certificate', () => {
        for (const anchor of EU_LOTL_SIGNING_ANCHORS) {
            expect(anchor.subject).toBeDefined();
            expect(anchor.issuer).toBeDefined();
            // Signing certs are typically valid for ~2-5 years.
            expect(anchor.notAfter.getTime()).toBeGreaterThan(
                Date.now() - 365 * 24 * 3600_000
            );
        }
    });

    it('first anchor has a plausible EU Commission subject', () => {
        const anchor = EU_LOTL_SIGNING_ANCHORS[0];
        // Guards against byte-corruption in the bundled PEM (e.g. COMMESSION vs COMMISSION).
        expect(anchor.subject).toContain('EUROPEAN COMMISSION'); // must be spelled correctly
        expect(anchor.subject).toContain('DIGIT'); // DIGITal services
    });
});
