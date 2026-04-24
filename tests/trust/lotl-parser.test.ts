import { describe, expect, it } from 'vitest';
import { DOMParser } from '@xmldom/xmldom';
import { LotlParser } from '../../src/trust/LotlParser.js';
import {
    buildSignedLotlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';

describe('LotlParser — happy path', () => {
    it('extracts issueDate, nextUpdate, and pointer list', async () => {
        const signer = await createLotlSigner();
        const fr = await createLotlSigner({ name: 'CN=FR Signer' });
        const de = await createLotlSigner({ name: 'CN=DE Signer' });
        const xml = await buildSignedLotlXml(signer, {
            issueDate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-10-01T00:00:00Z'),
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://example.invalid/fr-tl.xml',
                    signingCertificates: [fr.certificate],
                },
                {
                    country: 'DE',
                    tslLocation: 'http://example.invalid/de-tl.xml',
                    signingCertificates: [de.certificate],
                },
            ],
        });
        const doc = new DOMParser().parseFromString(xml, 'application/xml');
        const parser = new LotlParser();
        const snapshot = parser.parse(doc);
        expect(snapshot.issueDate.toISOString()).toBe('2026-04-01T00:00:00.000Z');
        expect(snapshot.nextUpdate?.toISOString()).toBe('2026-10-01T00:00:00.000Z');
        expect(snapshot.pointers).toHaveLength(2);
        expect(snapshot.pointers[0].country).toBe('FR');
        expect(snapshot.pointers[0].tslLocation).toBe(
            'http://example.invalid/fr-tl.xml'
        );
        expect(snapshot.pointers[0].signingCertificates[0].subject).toBe(
            'CN=FR Signer'
        );
    });
});

describe('LotlParser — edge cases', () => {
    it('returns empty pointer list when no OtherTSLPointer elements', async () => {
        const signer = await createLotlSigner();
        const xml = await buildSignedLotlXml(signer, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        const doc = new DOMParser().parseFromString(xml, 'application/xml');
        const snapshot = new LotlParser().parse(doc);
        expect(snapshot.pointers).toEqual([]);
        expect(snapshot.nextUpdate).toBeNull();
    });

    it('throws when ListIssueDateTime is missing (malformed LOTL)', () => {
        const xml = `<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><TSLVersionIdentifier>5</TSLVersionIdentifier></SchemeInformation>
</TrustServiceStatusList>`;
        const doc = new DOMParser().parseFromString(xml, 'application/xml');
        expect(() =>
            new LotlParser().parse(doc)
        ).toThrow(/ListIssueDateTime/);
    });
});
