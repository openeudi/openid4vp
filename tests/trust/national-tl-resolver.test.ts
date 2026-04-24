import { describe, expect, it, vi } from 'vitest';
import { NationalTlResolver } from '../../src/trust/NationalTlResolver.js';
import { LotlFetcher } from '../../src/trust/LotlFetcher.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import type { LotlSnapshot } from '../../src/trust/lotl-types.js';
import {
    buildSignedNationalTlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';
import { createCa } from './helpers/synthetic-ca.js';

describe('NationalTlResolver — happy path', () => {
    it('fetches + parses each national TL and returns a snapshot array', async () => {
        const frSigner = await createLotlSigner({ name: 'CN=FR TL Signer' });
        const tspRoot = await createCa({ name: 'CN=ANTS Root' });
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
        const fetcher: Fetcher = async (url) => {
            if (url === 'http://fr.test/tl.xml') {
                return new Response(frXml, { status: 200 });
            }
            return new Response('', { status: 404 });
        };
        const snapshot: LotlSnapshot = {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://fr.test/tl.xml',
                    signingCertificates: [frSigner.certificate],
                },
            ],
        };
        const resolver = new NationalTlResolver({
            fetcher: new LotlFetcher({ fetcher }),
        });
        const results = await resolver.resolve(snapshot);
        expect(results).toHaveLength(1);
        expect(results[0].country).toBe('FR');
        expect(results[0].services).toHaveLength(1);
        expect(results[0].services[0].providerName).toBe('ANTS');
        expect(results[0].services[0].serviceTypeIdentifier).toBe(
            'http://uri.etsi.org/TrstSvc/Svctype/CA/QC'
        );
        expect(results[0].services[0].certificates).toHaveLength(1);
    });

    it('fetches national TLs in parallel', async () => {
        const signer = await createLotlSigner();
        const xml = await buildSignedNationalTlXml(signer, {
            country: 'FR',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [],
        });
        const calls: number[] = [];
        const fetcher: Fetcher = async () => {
            const callStart = Date.now();
            calls.push(callStart);
            await new Promise((r) => setTimeout(r, 30));
            return new Response(xml, { status: 200 });
        };
        const snapshot: LotlSnapshot = {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://a.test',
                    signingCertificates: [signer.certificate],
                },
                {
                    country: 'DE',
                    tslLocation: 'http://b.test',
                    signingCertificates: [signer.certificate],
                },
                {
                    country: 'IT',
                    tslLocation: 'http://c.test',
                    signingCertificates: [signer.certificate],
                },
            ],
        };
        const resolver = new NationalTlResolver({
            fetcher: new LotlFetcher({ fetcher }),
        });
        const start = Date.now();
        const results = await resolver.resolve(snapshot);
        const elapsed = Date.now() - start;
        expect(results).toHaveLength(3);
        // Parallel: elapsed < 3 * 30 ms. Allow 100ms for scheduling slop.
        expect(elapsed).toBeLessThan(100);
    });
});

describe('NationalTlResolver — graceful degradation', () => {
    it('skips a pointer that fails to fetch without aborting the whole resolve', async () => {
        const frSigner = await createLotlSigner({ name: 'CN=FR' });
        const deSigner = await createLotlSigner({ name: 'CN=DE' });
        const deXml = await buildSignedNationalTlXml(deSigner, {
            country: 'DE',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [],
        });
        const warnings: unknown[] = [];
        const warnSpy = vi
            .spyOn(console, 'warn')
            .mockImplementation((...args) => warnings.push(args));

        const fetcher: Fetcher = async (url) => {
            if (url.includes('fr')) return new Response('', { status: 500 });
            return new Response(deXml, { status: 200 });
        };
        const snapshot: LotlSnapshot = {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://fr.test/tl.xml',
                    signingCertificates: [frSigner.certificate],
                },
                {
                    country: 'DE',
                    tslLocation: 'http://de.test/tl.xml',
                    signingCertificates: [deSigner.certificate],
                },
            ],
        };
        const resolver = new NationalTlResolver({
            fetcher: new LotlFetcher({ fetcher }),
        });
        const results = await resolver.resolve(snapshot);
        expect(results).toHaveLength(1);
        expect(results[0].country).toBe('DE');
        expect(warnings.length).toBeGreaterThan(0);
        warnSpy.mockRestore();
    });
});
