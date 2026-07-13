import { describe, it, expect } from 'vitest';
import { Encoder as CborEncoder } from 'cbor-x';

import {
    buildOid4vpSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from '../../src/crypto/session-transcript.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

describe('buildOid4vpSessionTranscript', () => {
    it('produces [null,null,[clientIdHash(32),responseUriHash(32),nonce]]', async () => {
        const st = await buildOid4vpSessionTranscript({
            clientId: 'x509_san_dns:v.example',
            responseUri: 'https://v.example/response',
            nonce: 'nonce-abc',
            mdocGeneratedNonce: 'mgn-xyz',
        });
        const d = cbor.decode(st) as unknown[];
        expect(d.length).toBe(3);
        expect(d[0]).toBeNull();
        expect(d[1]).toBeNull();
        const h = d[2] as unknown[];
        expect(h.length).toBe(3);
        expect((h[0] as Uint8Array).length).toBe(32);
        expect((h[1] as Uint8Array).length).toBe(32);
        expect(h[2]).toBe('nonce-abc');
    });

    it('is deterministic and nonce-sensitive', async () => {
        const base = { clientId: 'c', responseUri: 'r', nonce: 'n', mdocGeneratedNonce: 'm' };
        const a = await buildOid4vpSessionTranscript(base);
        const b = await buildOid4vpSessionTranscript(base);
        const c = await buildOid4vpSessionTranscript({ ...base, nonce: 'different' });
        expect(Buffer.compare(Buffer.from(a), Buffer.from(b))).toBe(0);
        expect(Buffer.compare(Buffer.from(a), Buffer.from(c))).not.toBe(0);
    });
});

describe('buildOpenID4VPHandoverSessionTranscript', () => {
    // Self-consistency / determinism only; interop correctness is proven by the
    // OIDF conformance happy-flow run, not by these unit tests.
    const P256_JWK = {
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };

    it('produces [null,null,["OpenID4VPHandover", hash(32)]] with encryption thumbprint', async () => {
        const st = await buildOpenID4VPHandoverSessionTranscript({
            clientId: 'x509_san_dns:v.example',
            nonce: 'n-1',
            responseUri: 'https://v.example/response',
            verifierEncryptionJwk: P256_JWK,
        });
        const d = cbor.decode(st) as unknown[];
        expect(d.length).toBe(3);
        expect(d[0]).toBeNull();
        expect(d[1]).toBeNull();
        const ho = d[2] as unknown[];
        expect(ho[0]).toBe('OpenID4VPHandover');
        expect((ho[1] as Uint8Array).length).toBe(32);
    });

    it('is deterministic; nonce-sensitive; thumbprint-sensitive; null-thumbprint when no jwk', async () => {
        const base = { clientId: 'c', nonce: 'n', responseUri: 'r', verifierEncryptionJwk: P256_JWK };
        const a = await buildOpenID4VPHandoverSessionTranscript(base);
        const b = await buildOpenID4VPHandoverSessionTranscript(base);
        const diffNonce = await buildOpenID4VPHandoverSessionTranscript({ ...base, nonce: 'other' });
        const noJwk = await buildOpenID4VPHandoverSessionTranscript({ clientId: 'c', nonce: 'n', responseUri: 'r' });
        expect(Buffer.compare(Buffer.from(a), Buffer.from(b))).toBe(0);
        expect(Buffer.compare(Buffer.from(a), Buffer.from(diffNonce))).not.toBe(0);
        expect(Buffer.compare(Buffer.from(a), Buffer.from(noJwk))).not.toBe(0);
    });

    // Regression guard: the self-consistency tests above only ever exercise ONE
    // concrete JWK (or none at all), so a canonicalization bug that ignores the
    // JWK's actual key bytes (e.g. hashing a constant placeholder instead of the
    // real x/y) would pass every test above yet silently break the binding this
    // transcript exists to provide. Two genuinely different P-256 public keys
    // MUST produce different thumbprints/output.
    it('produces different output for two different verifierEncryptionJwk key bytes (thumbprint truly key-dependent)', async () => {
        const kp1 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const kp2 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const jwk1 = (await crypto.subtle.exportKey('jwk', kp1.publicKey)) as JsonWebKey;
        const jwk2 = (await crypto.subtle.exportKey('jwk', kp2.publicKey)) as JsonWebKey;
        // Sanity: the two generated keys are actually distinct, otherwise this
        // test would pass vacuously.
        expect(jwk1.x).not.toBe(jwk2.x);

        const base = { clientId: 'c', nonce: 'n', responseUri: 'r' };
        const a = await buildOpenID4VPHandoverSessionTranscript({ ...base, verifierEncryptionJwk: jwk1 });
        const b = await buildOpenID4VPHandoverSessionTranscript({ ...base, verifierEncryptionJwk: jwk2 });
        expect(Buffer.compare(Buffer.from(a), Buffer.from(b))).not.toBe(0);
    });

    it('throws when verifierEncryptionJwk is missing a required EC member (x, y, or crv)', async () => {
        const base = { clientId: 'c', nonce: 'n', responseUri: 'r' };
        const missingX = { kty: 'EC', crv: P256_JWK.crv, y: P256_JWK.y };
        const missingY = { kty: 'EC', crv: P256_JWK.crv, x: P256_JWK.x };
        const missingCrv = { kty: 'EC', x: P256_JWK.x, y: P256_JWK.y };

        await expect(
            buildOpenID4VPHandoverSessionTranscript({ ...base, verifierEncryptionJwk: missingX }),
        ).rejects.toThrow();
        await expect(
            buildOpenID4VPHandoverSessionTranscript({ ...base, verifierEncryptionJwk: missingY }),
        ).rejects.toThrow();
        await expect(
            buildOpenID4VPHandoverSessionTranscript({ ...base, verifierEncryptionJwk: missingCrv }),
        ).rejects.toThrow();
    });
});
