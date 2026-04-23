import { describe, expect, it } from 'vitest';
import { CrlFetcher } from '../../src/trust/CrlFetcher.js';
import { InMemoryCache } from '../../src/trust/Cache.js';
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

describe('CrlFetcher — signature verification', () => {
    it('accepts a CRL signed by the issuer', async () => {
        const root = await createCa();
        const { der } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const fetcher = async () => new Response(der, { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        await expect(f.verifyCrl(parsed, root.certificate)).resolves.toBeUndefined();
    });

    it('rejects a CRL signed by a different CA', async () => {
        const realRoot = await createCa();
        const attackerRoot = await createCa();
        const { der } = await createCrl(attackerRoot, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const fetcher = async () => new Response(der, { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        await expect(f.verifyCrl(parsed, realRoot.certificate)).rejects.toThrow(/signature/i);
    });
});

describe('CrlFetcher — revoked-serial lookup', () => {
    it('returns revoked for a serial in the revokedCertificates list', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const { der } = await createCrl(root, {
            revokedSerials: [
                { serialHex: leaf.certificate.serialNumber, revokedAt: new Date('2026-01-01T00:00:00Z') },
            ],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const fetcher = async () => new Response(der, { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        const outcome = f.isRevoked(parsed, leaf.certificate.serialNumber);
        expect(outcome.status).toBe('revoked');
        if (outcome.status === 'revoked') {
            expect(outcome.revokedAt.toISOString()).toBe('2026-01-01T00:00:00.000Z');
        }
    });

    it('returns good for a serial not in the list', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const { der } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const fetcher = async () => new Response(der, { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        expect(f.isRevoked(parsed, leaf.certificate.serialNumber).status).toBe('good');
    });

    it('normalizes hex comparison case-insensitively and ignores leading zeros', async () => {
        const root = await createCa();
        const { der } = await createCrl(root, {
            revokedSerials: [{ serialHex: '00AF01', revokedAt: new Date('2026-01-01') }],
            thisUpdate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-05-01'),
        });
        const fetcher = async () => new Response(der, { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        expect(f.isRevoked(parsed, 'af01').status).toBe('revoked');
        expect(f.isRevoked(parsed, 'AF01').status).toBe('revoked');
    });
});

describe('CrlFetcher — staleness', () => {
    it('reports stale when now > nextUpdate', async () => {
        const root = await createCa();
        const { der } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-01-01'),
            nextUpdate: new Date('2026-02-01'),
        });
        const fetcher = async () => new Response(der, { status: 200 });
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response> });
        const parsed = await f.fetchAndParse('http://crl.example.com/a.crl');
        expect(f.isStale(parsed, new Date('2026-04-23'))).toBe(true);
        expect(f.isStale(parsed, new Date('2026-01-15'))).toBe(false);
    });
});

describe('CrlFetcher — caching', () => {
    it('caches a fetched CRL by URL and reuses it on the next call', async () => {
        const root = await createCa();
        const { der } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-05-01'),
        });
        let fetchCalls = 0;
        const fetcher = async () => {
            fetchCalls++;
            return new Response(der, { status: 200 });
        };
        const cache = new InMemoryCache();
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response>, cache });
        await f.fetchAndParseCached('http://crl.example.com/a.crl');
        await f.fetchAndParseCached('http://crl.example.com/a.crl');
        expect(fetchCalls).toBe(1);
    });

    it('re-fetches when the cache entry is absent', async () => {
        const root = await createCa();
        const { der } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-05-01'),
        });
        let fetchCalls = 0;
        const fetcher = async () => {
            fetchCalls++;
            return new Response(der, { status: 200 });
        };
        const f = new CrlFetcher({ fetcher: fetcher as (url: string) => Promise<Response>, cache: new InMemoryCache() });
        await f.fetchAndParseCached('http://crl.example.com/a.crl');
        await f.fetchAndParseCached('http://crl.example.com/b.crl');
        expect(fetchCalls).toBe(2);
    });
});
