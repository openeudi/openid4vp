import { describe, expect, it } from 'vitest';
import { createCa, createIntermediate, createLeaf } from './synthetic-ca.js';

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
