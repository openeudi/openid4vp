/**
 * HAIP 1.0 §6.1.1: "The X.509 certificate of the trust anchor MUST NOT be
 * included in the x5c JOSE header of the SD-JWT VC."
 */

import * as jose from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';
import { StaticTrustStore } from '../src/trust/TrustStore.js';

import { b64u, digest, encodeDisclosure } from './fixtures/sd-jwt-builder.js';

const parser = new SdJwtParser();

type Ca = { certificate: { rawData: ArrayBuffer }; keys: CryptoKeyPair };
let root: Ca;
let intermediate: Ca;
let leaf: Ca;

beforeAll(async () => {
    // Dynamic import: synthetic-ca sets a global x509 crypto provider.
    const { createCa, createIntermediate, createLeaf } = await import('./trust/helpers/synthetic-ca.js');
    root = (await createCa({ name: 'CN=HAIP Root' })) as unknown as Ca;
    intermediate = (await createIntermediate(root as never, { name: 'CN=HAIP Intermediate' })) as unknown as Ca;
    leaf = (await createLeaf(intermediate as never, { name: 'CN=HAIP Issuer' })) as unknown as Ca;
});

/** Re-import a @peculiar/webcrypto key into Node's WebCrypto so jose can sign with it. */
async function nodeSigningKey(key: CryptoKey): Promise<CryptoKey> {
    const { Crypto } = await import('@peculiar/webcrypto');
    const jwk = await new Crypto().subtle.exportKey('jwk', key);
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

const der = (c: Ca): string => Buffer.from(c.certificate.rawData).toString('base64');

async function present(x5c: string[]): Promise<{ valid: boolean; error?: string }> {
    const disclosure = encodeDisclosure('given_name', 'Erika');
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new jose.SignJWT({
        iss: 'https://issuer.example',
        vct: 'urn:eudi:pid:1',
        iat: now,
        exp: now + 3600,
        _sd: [await digest('sha-256', disclosure)],
        _sd_alg: 'sha-256',
    })
        .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c })
        .sign(await nodeSigningKey(leaf.keys.privateKey));
    try {
        const r = await parser.parse(`${jwt}~${disclosure}~`, {
            trustStore: new StaticTrustStore([new Uint8Array(root.certificate.rawData)]),
            nonce: 'n',
            audience: `x509_hash:${b64u(new Uint8Array(32))}`,
        });
        return { valid: r.valid, error: r.error };
    } catch (err) {
        return { valid: false, error: (err as Error).message };
    }
}

describe('x5c and the trust anchor (HAIP 1.0 §6.1.1)', () => {
    it('accepts leaf + intermediate', async () => {
        expect(await present([der(leaf), der(intermediate)])).toEqual({ valid: true, error: undefined });
    });

    it('refuses an x5c that also carries the trust anchor certificate', async () => {
        const r = await present([der(leaf), der(intermediate), der(root)]);
        expect(r.valid).toBe(false);
        expect(r.error).toMatch(/trust anchor/);
    });
});
