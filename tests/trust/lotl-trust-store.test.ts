import { describe, expect, it, vi } from 'vitest';
import { LotlTrustStore } from '../../src/trust/LotlTrustStore.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import {
    buildSignedLotlXml,
    buildSignedNationalTlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';
import { createCa } from './helpers/synthetic-ca.js';

describe('LotlTrustStore — basic resolution', () => {
    it('returns LOTL-sourced anchors matching the issuer DN', async () => {
        const lotlSigner = await createLotlSigner();
        const frSigner = await createLotlSigner({ name: 'CN=FR TL Signer' });
        const tspRoot = await createCa({ name: 'CN=ANTS Root, C=FR' });
        const frXml = await buildSignedNationalTlXml(frSigner, {
            country: 'FR',
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            services: [
                {
                    providerName: 'ANTS',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'ANTS Qualified CA',
                    certificates: [tspRoot.certificate],
                    additionalServiceInformationUris: [],
                },
            ],
        });
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://fr.test/tl.xml',
                    signingCertificates: [frSigner.certificate],
                },
            ],
        });
        const fetcher: Fetcher = async (url) => {
            if (url.includes('eu-lotl')) {
                return new Response(lotlXml, { status: 200 });
            }
            if (url.includes('fr')) {
                return new Response(frXml, { status: 200 });
            }
            return new Response('', { status: 404 });
        };
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
        });
        const anchors = await store.getAnchors({
            issuer: tspRoot.certificate.subject,
        });
        expect(anchors).toHaveLength(1);
        expect(anchors[0].source).toBe('lotl');
        expect(anchors[0].metadata?.country).toBe('FR');
        expect(anchors[0].metadata?.qualified).toBe(true);
        expect(anchors[0].trustedAuthorityIds).toHaveLength(1);
    });

    it('returns empty when no service matches the hint', async () => {
        const lotlSigner = await createLotlSigner();
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        const fetcher: Fetcher = async () =>
            new Response(lotlXml, { status: 200 });
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
        });
        const anchors = await store.getAnchors({ issuer: 'CN=nobody' });
        expect(anchors).toEqual([]);
    });
});

describe('LotlTrustStore — single-flight refresh', () => {
    it('concurrent getAnchors triggers only one LOTL fetch', async () => {
        const lotlSigner = await createLotlSigner();
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        let fetchCount = 0;
        const fetcher: Fetcher = async (url) => {
            if (url.includes('eu-lotl')) {
                fetchCount++;
                // Artificial delay so all callers overlap.
                await new Promise((r) => setTimeout(r, 30));
                return new Response(lotlXml, { status: 200 });
            }
            return new Response('', { status: 404 });
        };
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
        });
        await Promise.all([
            store.getAnchors({ issuer: 'CN=anyone' }),
            store.getAnchors({ issuer: 'CN=anyone' }),
            store.getAnchors({ issuer: 'CN=anyone' }),
        ]);
        expect(fetchCount).toBe(1);
    });

    it('subsequent calls within refreshInterval hit the cached snapshot', async () => {
        const lotlSigner = await createLotlSigner();
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        let fetchCount = 0;
        const fetcher: Fetcher = async () => {
            fetchCount++;
            return new Response(lotlXml, { status: 200 });
        };
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
            refreshInterval: 60_000,
        });
        await store.getAnchors({ issuer: 'CN=a' });
        await store.getAnchors({ issuer: 'CN=b' });
        expect(fetchCount).toBe(1);
    });

    it('refreshes after refreshInterval expires', async () => {
        const lotlSigner = await createLotlSigner();
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        let fetchCount = 0;
        const fetcher: Fetcher = async () => {
            fetchCount++;
            return new Response(lotlXml, { status: 200 });
        };
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
            refreshInterval: 1, // 1 ms → every call refreshes
        });
        await store.getAnchors({ issuer: 'CN=a' });
        await new Promise((r) => setTimeout(r, 5));
        await store.getAnchors({ issuer: 'CN=b' });
        expect(fetchCount).toBe(2);
    });
});

describe('LotlTrustStore — graceful degradation', () => {
    it('serves the cached snapshot with console.warn when a refresh fails', async () => {
        const lotlSigner = await createLotlSigner();
        const xmlV1 = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        let fetchCount = 0;
        const fetcher: Fetcher = async () => {
            fetchCount++;
            if (fetchCount === 1) return new Response(xmlV1, { status: 200 });
            return new Response('', { status: 500 });
        };
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
            refreshInterval: 1,
        });
        await store.getAnchors({ issuer: 'CN=a' });
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        await new Promise((r) => setTimeout(r, 5));
        const anchors = await store.getAnchors({ issuer: 'CN=a' });
        expect(anchors).toEqual([]); // the pointerless cached snapshot
        expect(warnSpy).toHaveBeenCalled();
        warnSpy.mockRestore();
    });

    it('propagates the error when the very first fetch fails', async () => {
        const lotlSigner = await createLotlSigner();
        const fetcher: Fetcher = async () => new Response('', { status: 500 });
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
        });
        await expect(store.getAnchors({ issuer: 'CN=a' })).rejects.toThrow();
    });
});
