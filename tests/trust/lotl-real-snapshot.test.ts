import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { DOMParser } from '@xmldom/xmldom';
import { LotlParser } from '../../src/trust/LotlParser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('real EU LOTL snapshot', () => {
    it('LotlParser parses the committed snapshot without error', () => {
        const path = join(
            __dirname,
            '..',
            'fixtures',
            'lotl-snapshot-2026-04-23.xml'
        );
        const xml = readFileSync(path, 'utf8');
        const doc = new DOMParser().parseFromString(xml, 'application/xml');
        const snapshot = new LotlParser().parse(doc as unknown as Document);
        // The real LOTL currently has one pointer per active member state;
        // count fluctuates around 27-30 (EU+EEA). Keep assertion loose.
        expect(snapshot.pointers.length).toBeGreaterThan(20);
        expect(snapshot.pointers.length).toBeLessThan(50);
        // Every pointer must have a tslLocation and at least one signing cert.
        for (const p of snapshot.pointers) {
            expect(p.tslLocation).toMatch(/^https?:\/\//);
            expect(p.signingCertificates.length).toBeGreaterThan(0);
        }
    });
});
