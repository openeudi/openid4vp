import { describe, expect, it } from 'vitest';
import { CrlFetcher } from '../../src/trust/CrlFetcher.js';
import { createCa, createLeaf, createCrl } from './helpers/synthetic-ca.js';

describe('CrlFetcher — fetch + parse', () => {
    it('fetches a CRL from the given URL and parses it', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const { der } = await createCrl(root, {
            revokedSerials: [
                { serialHex: leaf.certificate.serialNumber, revokedAt: new Date('2026-01-01T00:00:00Z') },
            ],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const fetcher = async (): Promise<Response> =>
            new Response(der, { status: 200, headers: { 'content-type': 'application/pkix-crl' } });
        const fetcher2 = fetcher as unknown as (url: string, init?: RequestInit) => Promise<Response>;
        const f = new CrlFetcher({ fetcher: fetcher2 });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        expect(parsed.thisUpdate.toISOString()).toBe('2026-04-01T00:00:00.000Z');
        expect(parsed.nextUpdate.toISOString()).toBe('2026-05-01T00:00:00.000Z');
        expect(parsed.revokedSerialsHex).toContain(leaf.certificate.serialNumber.toUpperCase());
    });

    it('throws on 404 with a useful cause', async () => {
        const fetcher = async () => new Response('not found', { status: 404 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        await expect(f.fetchAndParse('http://example.com/missing.crl')).rejects.toMatchObject({
            message: /404|fetch/i,
        });
    });

    it('throws on malformed DER bytes', async () => {
        const fetcher = async () => new Response(new Uint8Array([1, 2, 3, 4]), { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        await expect(f.fetchAndParse('http://example.com/bad.crl')).rejects.toBeInstanceOf(Error);
    });
});
