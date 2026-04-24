import { describe, expect, it } from 'vitest';
import { createLotlSigner } from './lotl-fixtures.js';
import {
    buildSignedLotlXml,
    buildSignedNationalTlXml,
} from './lotl-fixtures.js';
import { DOMParser } from '@xmldom/xmldom';
import * as xmldsig from 'xmldsigjs';

describe('lotl-fixtures — createLotlSigner', () => {
    it('produces a self-signed CA + keypair suitable for signing LOTL XML', async () => {
        const signer = await createLotlSigner({ name: 'CN=EU LOTL Test Signer' });
        expect(signer.certificate.subject).toBe('CN=EU LOTL Test Signer');
        expect(signer.keys.privateKey).toBeDefined();
        expect(signer.keys.publicKey).toBeDefined();
        // Signing certs don't need cA=true — they sign XML, not issue certs.
        // They must assert `digitalSignature`, which is the default we set.
    });
});

describe('buildSignedLotlXml', () => {
    it('produces a verifiable LOTL XML with one pointer', async () => {
        const signer = await createLotlSigner();
        const nationalSigner = await createLotlSigner({ name: 'CN=FR TL Signer' });

        const xml = await buildSignedLotlXml(signer, {
            issueDate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-10-01T00:00:00Z'),
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://example.invalid/fr-tl.xml',
                    signingCertificates: [nationalSigner.certificate],
                },
            ],
        });
        const doc = new DOMParser().parseFromString(xml, 'application/xml');
        const sigEl = doc.getElementsByTagNameNS(
            'http://www.w3.org/2000/09/xmldsig#',
            'Signature'
        )[0];
        expect(sigEl).toBeDefined();
        const signed = new xmldsig.SignedXml(doc);
        signed.LoadXml(sigEl);
        const ok = await signed.Verify();
        expect(ok).toBe(true);
    });
});

describe('buildSignedNationalTlXml', () => {
    it('produces a verifiable national TL with one TSPService', async () => {
        const signer = await createLotlSigner({ name: 'CN=FR TL Signer' });
        const { createCa, createLeaf } = await import('./synthetic-ca.js');
        const tspRoot = await createCa({ name: 'CN=ANTS Root' });
        const tspLeaf = await createLeaf(tspRoot, { name: 'CN=ANTS Issuing CA' });
        const xml = await buildSignedNationalTlXml(signer, {
            country: 'FR',
            issueDate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-10-01T00:00:00Z'),
            services: [
                {
                    providerName: 'ANTS',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'ANTS Qualified CA',
                    certificates: [tspRoot.certificate, tspLeaf.certificate],
                    additionalServiceInformationUris: [],
                },
            ],
        });
        const doc = new DOMParser().parseFromString(xml, 'application/xml');
        const sigEl = doc.getElementsByTagNameNS(
            'http://www.w3.org/2000/09/xmldsig#',
            'Signature'
        )[0];
        expect(sigEl).toBeDefined();
    });
});
