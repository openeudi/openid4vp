import { describe, expect, it } from 'vitest';
import { RevocationChecker } from '../../src/trust/RevocationChecker.js';
import { RevocationCheckFailedError } from '../../src/errors.js';
import {
    createCa,
    createLeaf,
    createCrl,
    signOcspResponse,
} from './helpers/synthetic-ca.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';

describe('RevocationChecker — policy=skip', () => {
    it('returns status=good without any I/O when policy is skip', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://should-not-be-called',
            crlUrls: ['http://should-not-be-called'],
        });
        let fetched = false;
        const fetcher: Fetcher = async () => {
            fetched = true;
            return new Response(new Uint8Array(), { status: 200 });
        };
        const checker = new RevocationChecker({ policy: 'skip', fetcher });
        const result = await checker.check(leaf.certificate, root.certificate);
        expect(result.status).toBe('good');
        expect(result.source).toBe('none');
        expect(fetched).toBe(false);
    });
});

describe('RevocationChecker — OCSP first, CRL fallback', () => {
    it('uses OCSP when both URLs are present and OCSP succeeds', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://ocsp.example.com',
            crlUrls: ['http://crl.example.com/a.crl'],
        });
        const client = new (await import('../../src/trust/OcspClient.js')).OcspClient();
        const reqDer = await client.buildRequest(leaf.certificate, root.certificate);
        const ocspDer = await signOcspResponse(root, reqDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher: Fetcher = async (url) => {
            if (url.startsWith('http://ocsp')) return new Response(ocspDer, { status: 200 });
            throw new Error('CRL should not be called when OCSP succeeds');
        };
        const checker = new RevocationChecker({ policy: 'prefer', fetcher });
        const result = await checker.check(leaf.certificate, root.certificate);
        expect(result.source).toBe('ocsp');
        expect(result.status).toBe('good');
    });

    it('falls back to CRL when OCSP transiently fails and policy is prefer', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://ocsp.example.com',
            crlUrls: ['http://crl.example.com/a.crl'],
        });
        const { der: crlDer } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-05-01'),
        });
        const fetcher: Fetcher = async (url) => {
            if (url.startsWith('http://ocsp')) return new Response('', { status: 500 });
            return new Response(crlDer, { status: 200 });
        };
        const checker = new RevocationChecker({ policy: 'prefer', fetcher });
        const result = await checker.check(leaf.certificate, root.certificate);
        expect(result.source).toBe('crl');
        expect(result.status).toBe('good');
    });
});

describe('RevocationChecker — policy=prefer on all-sources-transient-fail → unknown + pass', () => {
    it('returns unknown + source=none when both OCSP and CRL fail transiently', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://ocsp.example.com',
            crlUrls: ['http://crl.example.com/a.crl'],
        });
        const fetcher: Fetcher = async () => new Response('', { status: 500 });
        const checker = new RevocationChecker({ policy: 'prefer', fetcher });
        const result = await checker.check(leaf.certificate, root.certificate);
        expect(result.status).toBe('unknown');
        expect(result.source).toBe('none');
    });
});

describe('RevocationChecker — policy=require', () => {
    it('throws RevocationCheckFailedError when all sources fail', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://ocsp.example.com',
            crlUrls: ['http://crl.example.com/a.crl'],
        });
        const fetcher: Fetcher = async () => new Response('', { status: 500 });
        const checker = new RevocationChecker({ policy: 'require', fetcher });
        await expect(checker.check(leaf.certificate, root.certificate)).rejects.toBeInstanceOf(
            RevocationCheckFailedError
        );
    });

    it('throws RevocationCheckFailedError when neither OCSP nor CRL URL is present', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root); // no URLs
        const fetcher: Fetcher = async () => new Response('', { status: 500 });
        const checker = new RevocationChecker({ policy: 'require', fetcher });
        await expect(checker.check(leaf.certificate, root.certificate)).rejects.toBeInstanceOf(
            RevocationCheckFailedError
        );
    });
});
