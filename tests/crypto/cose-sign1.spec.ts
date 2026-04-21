import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { importX509 } from 'jose';
import { describe, it, expect } from 'vitest';

import { decodeCoseSign1, verifyCoseSign1 } from '../../src/crypto/cose-sign1.js';
import { MalformedCredentialError } from '../../src/errors.js';
import { generateTestKeyMaterial, derToPem } from '../fixtures/crypto-helpers.js';
import { buildSignedMdoc } from '../fixtures/mdoc-helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false });

describe('decodeCoseSign1', () => {
    it('decodes a valid COSE_Sign1 produced by our signer', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const cose = decodeCoseSign1(issuerAuth);
        expect(cose.alg).toBe('ES256');
        expect(cose.x5chain.length).toBe(1);
        expect(cose.x5chain[0]).toBeInstanceOf(Uint8Array);
        expect(cose.signature.length).toBeGreaterThan(0);
    });

    it('handles COSE_Sign1 wrapped in CBOR tag 18', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        // Decode the raw issuerAuth array (it's a CBOR-encoded 4-tuple), then re-encode
        // with an outer tag 18 so the decoder must unwrap the tag before processing.
        const coseArray = cbor.decode(issuerAuth);
        const wrapped = cbor.encode(new Tag(coseArray, 18));
        const cose = decodeCoseSign1(wrapped);
        expect(cose.alg).toBe('ES256');
    });

    it('throws MalformedCredentialError on non-array CBOR', () => {
        const notAnArray = cbor.encode('not a cose_sign1');
        expect(() => decodeCoseSign1(notAnArray)).toThrow(MalformedCredentialError);
    });

    it('throws MalformedCredentialError on wrong array length', () => {
        const wrongLen = cbor.encode([cbor.encode(new Map()), new Map(), new Uint8Array(1)]); // only 3
        expect(() => decodeCoseSign1(wrongLen)).toThrow(MalformedCredentialError);
    });

    it('throws MalformedCredentialError on unknown algorithm label', () => {
        // Build a structurally-valid COSE_Sign1 with alg = -999 (unknown)
        const protHeader = cbor.encode(new Map<number, unknown>([[1, -999]]));
        const unprot = new Map<number, unknown>([[33, new Uint8Array([0x30, 0x01, 0x00])]]);
        const payload = cbor.encode('x');
        const sig = new Uint8Array(64);
        const bad = cbor.encode([protHeader, unprot, payload, sig]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });
});

describe('decodeCoseSign1 — structural errors', () => {
    it('throws when protected header is not a bstr', () => {
        const aMap = new Map<number, unknown>([[1, -7]]);
        const bad = cbor.encode([aMap, aMap, new Uint8Array(4), new Uint8Array(64)]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });

    it('throws when unprotected header is not a Map', () => {
        const protBytes = cbor.encode(new Map<number, unknown>([[1, -7]]));
        const bad = cbor.encode([protBytes, 'not a map', new Uint8Array(4), new Uint8Array(64)]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });

    it('throws when signature is not a bstr', () => {
        const protBytes = cbor.encode(new Map<number, unknown>([[1, -7]]));
        const unprot = new Map<number, unknown>([[33, new Uint8Array([0x30, 0x01, 0x00])]]);
        const bad = cbor.encode([protBytes, unprot, new Uint8Array(4), 42]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });

    it('throws when protected header bytes are not decodable CBOR as a Map', () => {
        const protBytes = cbor.encode('string-not-a-map');
        const unprot = new Map<number, unknown>([[33, new Uint8Array([0x30, 0x01, 0x00])]]);
        const bad = cbor.encode([protBytes, unprot, new Uint8Array(4), new Uint8Array(64)]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });

    it('throws when payload is not a byte string', () => {
        const protBytes = cbor.encode(new Map<number, unknown>([[1, -7]]));
        const unprot = new Map<number, unknown>([[33, new Uint8Array([0x30, 0x01, 0x00])]]);
        const bad = cbor.encode([protBytes, unprot, 42, new Uint8Array(64)]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });

    it('throws when x5chain is present but not a bstr or array of bstr', () => {
        const protBytes = cbor.encode(new Map<number, unknown>([[1, -7]]));
        const unprot = new Map<number, unknown>([[33, 'not a cert']]);
        const bad = cbor.encode([protBytes, unprot, new Uint8Array(4), new Uint8Array(64)]);
        expect(() => decodeCoseSign1(bad)).toThrow(MalformedCredentialError);
    });
});

describe('verifyCoseSign1', () => {
    it('verifies a signature produced by our signer', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const cose = decodeCoseSign1(issuerAuth);
        const publicKey = await importX509(derToPem(key.x5cBase64), 'ES256');
        await expect(verifyCoseSign1(cose, publicKey, ['ES256'])).resolves.toBeUndefined();
    });

    it('rejects an algorithm not in the allowlist', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const cose = decodeCoseSign1(issuerAuth);
        const publicKey = await importX509(derToPem(key.x5cBase64), 'ES256');
        await expect(verifyCoseSign1(cose, publicKey, ['ES384'])).rejects.toThrow(/not in allowlist/i);
    });

    it('rejects a tampered signature', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const cose = decodeCoseSign1(issuerAuth);
        cose.signature[0] ^= 0xff; // flip one byte
        const publicKey = await importX509(derToPem(key.x5cBase64), 'ES256');
        await expect(verifyCoseSign1(cose, publicKey, ['ES256'])).rejects.toThrow(/signature/i);
    });

    it('rejects when verified against the wrong public key', async () => {
        const issuer = await generateTestKeyMaterial();
        const other = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: issuer,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const cose = decodeCoseSign1(issuerAuth);
        const otherPub = await importX509(derToPem(other.x5cBase64), 'ES256');
        await expect(verifyCoseSign1(cose, otherPub, ['ES256'])).rejects.toThrow(/signature/i);
    });

    it('verifies ES384 and ES512 signatures', async () => {
        for (const alg of ['ES384', 'ES512'] as const) {
            const key = await generateTestKeyMaterial(alg);
            const { issuerAuth } = await buildSignedMdoc({
                issuerKey: key,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
                alg,
            });
            const cose = decodeCoseSign1(issuerAuth);
            const pub = await importX509(derToPem(key.x5cBase64), alg);
            await expect(verifyCoseSign1(cose, pub, [alg])).resolves.toBeUndefined();
        }
    });
});
