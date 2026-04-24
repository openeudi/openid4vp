import { describe, expect, it } from 'vitest';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import { createCa } from './helpers/synthetic-ca.js';

describe('StaticTrustStore', () => {
    it('returns [] when no hint matches', async () => {
        const ca = await createCa();
        const store = new StaticTrustStore([ca.certificate]);
        const result = await store.getAnchors({ issuer: 'CN=Other' });
        expect(result).toEqual([]);
    });

    it('matches by issuer DN string', async () => {
        const ca = await createCa({ name: 'CN=Match Me' });
        const store = new StaticTrustStore([ca.certificate]);
        const result = await store.getAnchors({ issuer: 'CN=Match Me' });
        expect(result).toHaveLength(1);
        expect(result[0].source).toBe('static');
        expect(result[0].certificate.subject).toBe('CN=Match Me');
    });

    it('matches by Authority Key Identifier bytes', async () => {
        const ca = await createCa();
        const store = new StaticTrustStore([ca.certificate]);
        // Locate the CA's SubjectKeyIdentifier extension via its @peculiar/x509 class.
        const { SubjectKeyIdentifierExtension } = await import('@peculiar/x509');
        const skiExt = ca.certificate.getExtension(SubjectKeyIdentifierExtension);
        expect(skiExt).toBeTruthy();
        // SKI extension exposes keyId as a hex string.
        const skiHex = skiExt!.keyId;
        const skiBytes = new Uint8Array(
            skiHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16))
        );
        const result = await store.getAnchors({ aki: skiBytes });
        expect(result).toHaveLength(1);
    });

    it('accepts Uint8Array DER inputs', async () => {
        const ca = await createCa({ name: 'CN=DER Input' });
        const der = new Uint8Array(ca.certificate.rawData);
        const store = new StaticTrustStore([der]);
        const result = await store.getAnchors({ issuer: 'CN=DER Input' });
        expect(result).toHaveLength(1);
    });

    it('accepts PEM string inputs', async () => {
        const ca = await createCa({ name: 'CN=PEM Input' });
        const pem = ca.certificate.toString('pem');
        const store = new StaticTrustStore([pem]);
        const result = await store.getAnchors({ issuer: 'CN=PEM Input' });
        expect(result).toHaveLength(1);
    });

    it('returns multiple anchors when hints match several', async () => {
        const ca1 = await createCa({ name: 'CN=Same DN' });
        const ca2 = await createCa({ name: 'CN=Same DN' });
        const store = new StaticTrustStore([ca1.certificate, ca2.certificate]);
        const result = await store.getAnchors({ issuer: 'CN=Same DN' });
        expect(result).toHaveLength(2);
    });

    it('getAnchors is safe to call concurrently', async () => {
        const ca = await createCa();
        const store = new StaticTrustStore([ca.certificate]);
        const results = await Promise.all([
            store.getAnchors({ issuer: ca.certificate.subject }),
            store.getAnchors({ issuer: ca.certificate.subject }),
            store.getAnchors({ issuer: ca.certificate.subject }),
        ]);
        for (const r of results) expect(r).toHaveLength(1);
    });
});

describe('StaticTrustStore — trustedAuthorityIds field shape', () => {
    it('anchors may carry an optional trustedAuthorityIds list', async () => {
        const root = await createCa();
        const store = new StaticTrustStore([root.certificate]);
        const anchors = await store.getAnchors({ issuer: root.certificate.subject });
        expect(anchors).toHaveLength(1);
        // Field is optional; A.1 StaticTrustStore does not populate it. A.3
        // TrustEvaluator will synthesize a value from the anchor's SKI so
        // consumers see a non-empty list either way.
        expect(anchors[0].trustedAuthorityIds).toBeUndefined();
    });
});
