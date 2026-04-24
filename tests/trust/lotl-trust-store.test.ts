import { describe, expect, it } from 'vitest';
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
