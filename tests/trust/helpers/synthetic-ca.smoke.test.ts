import { describe, expect, it } from 'vitest';
import { createCa, createIntermediate, createLeaf, createCrl } from './synthetic-ca.js';
import { AsnConvert } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';

describe('synthetic-ca smoke', () => {
    it('builds root → intermediate → leaf chain', async () => {
        const root = await createCa();
        const intermediate = await createIntermediate(root);
        const leaf = await createLeaf(intermediate);
        expect(root.certificate.subject).toBe('CN=Test Root CA');
        expect(intermediate.certificate.issuer).toBe(root.certificate.subject);
        expect(leaf.certificate.issuer).toBe(intermediate.certificate.subject);
    });

    it('builds leaf with DNS SAN', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            subjectAlternativeName: [{ type: 'dns', value: 'api.example.com' }],
        });
        expect(leaf.certificate.issuer).toBe(root.certificate.subject);
    });

    it('builds intermediate with DNS name constraints', async () => {
        const root = await createCa();
        const intermediate = await createIntermediate(root, {
            nameConstraintsPermitted: [{ type: 'dns', value: 'example.com' }],
        });
        expect(intermediate.certificate.issuer).toBe(root.certificate.subject);
    });

    it('builds intermediate with DN name constraints', async () => {
        const root = await createCa();
        const intermediate = await createIntermediate(root, {
            nameConstraintsPermitted: [{ type: 'dn', value: 'O=Acme Corp' }],
        });
        expect(intermediate.certificate.issuer).toBe(root.certificate.subject);
    });

    it('builds intermediate with email + URI name constraints', async () => {
        const root = await createCa();
        const intermediate = await createIntermediate(root, {
            nameConstraintsPermitted: [
                { type: 'email', value: 'acme.com' },
                { type: 'uri', value: 'example.com' },
            ],
            nameConstraintsExcluded: [{ type: 'dns', value: 'banned.com' }],
        });
        expect(intermediate.certificate.issuer).toBe(root.certificate.subject);
    });
});

describe('createCrl (helper smoke test)', () => {
    it('produces a DER-encoded CRL with the given revoked serials', async () => {
        const root = await createCa({ name: 'CN=Test CRL Root' });
        const leaf = await createLeaf(root);
        const serialHex = leaf.certificate.serialNumber;
        const { der } = await createCrl(root, {
            revokedSerials: [{ serialHex, revokedAt: new Date('2026-01-01T00:00:00Z') }],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const crl = AsnConvert.parse(der, CertificateList);
        expect(crl.tbsCertList.revokedCertificates).toBeDefined();
        expect(crl.tbsCertList.revokedCertificates).toHaveLength(1);
    });

    it('produces an empty CRL when no serials are revoked', async () => {
        const root = await createCa();
        const { der } = await createCrl(root, {
            revokedSerials: [],
            thisUpdate: new Date('2026-04-01T00:00:00Z'),
            nextUpdate: new Date('2026-05-01T00:00:00Z'),
        });
        const crl = AsnConvert.parse(der, CertificateList);
        // ASN.1 SEQUENCE OF may be absent OR present-but-empty, both are valid.
        const revoked = crl.tbsCertList.revokedCertificates;
        expect(revoked === undefined || revoked.length === 0).toBe(true);
    });
});
