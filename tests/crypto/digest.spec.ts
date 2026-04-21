import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { describe, it, expect } from 'vitest';

import { decodeCoseSign1 } from '../../src/crypto/cose-sign1.js';
import { computeItemDigest, verifyAllDigests } from '../../src/crypto/digest.js';
import { decodeMso } from '../../src/crypto/mso.js';
import { MalformedCredentialError } from '../../src/errors.js';
import { generateTestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { buildSignedMdoc } from '../fixtures/mdoc-helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false });

describe('computeItemDigest', () => {
    it('produces a 32-byte SHA-256 digest', async () => {
        const d = await computeItemDigest(new Uint8Array([1, 2, 3]), 'SHA-256');
        expect(d).toBeInstanceOf(Uint8Array);
        expect(d.length).toBe(32);
    });

    it('produces a 48-byte SHA-384 digest', async () => {
        const d = await computeItemDigest(new Uint8Array([1]), 'SHA-384');
        expect(d.length).toBe(48);
    });

    it('produces a 64-byte SHA-512 digest', async () => {
        const d = await computeItemDigest(new Uint8Array([1]), 'SHA-512');
        expect(d.length).toBe(64);
    });

    it('throws on unknown algorithm', async () => {
        await expect(computeItemDigest(new Uint8Array(), 'MD5' as unknown as 'SHA-256')).rejects.toThrow();
    });
});

describe('verifyAllDigests', () => {
    it('accepts every item in a freshly built mDOC', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth, itemBytesByNamespace } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: {
                'eu.europa.ec.eudi.pid.1': { age_over_18: true, family_name: 'Doe' },
            },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        const ns = new Map<string, Uint8Array[]>(Object.entries(itemBytesByNamespace));
        await expect(verifyAllDigests(ns, mso)).resolves.toBeUndefined();
    });

    it('throws when namespace has no valueDigests entry in MSO', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth, itemBytesByNamespace } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        // Pass a namespace not present in the MSO valueDigests
        const ns = new Map<string, Uint8Array[]>([
            ['unknown.namespace', itemBytesByNamespace['eu.europa.ec.eudi.pid.1']!],
        ]);
        await expect(verifyAllDigests(ns, mso)).rejects.toThrow(MalformedCredentialError);
    });

    it('throws when digestID is missing from MSO valueDigests for that namespace', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth, itemBytesByNamespace } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        // Clear the valueDigests for the namespace so no digestID matches
        mso.valueDigests.set('eu.europa.ec.eudi.pid.1', new Map());
        const ns = new Map<string, Uint8Array[]>(Object.entries(itemBytesByNamespace) as [string, Uint8Array[]][]);
        await expect(verifyAllDigests(ns, mso)).rejects.toThrow(MalformedCredentialError);
    });

    it('throws when IssuerSignedItem bytes are not decodable CBOR', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        const garbage = new Uint8Array([0xff, 0xfe, 0xfd]);
        const ns = new Map<string, Uint8Array[]>([['eu.europa.ec.eudi.pid.1', [garbage]]]);
        await expect(verifyAllDigests(ns, mso)).rejects.toThrow(MalformedCredentialError);
    });

    it('throws when IssuerSignedItem is a tag-24 wrapping a Map without digestID', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        // Build a tag-24 wrapped Map that has no digestID key
        const itemMap = new Map<string, unknown>([
            ['elementIdentifier', 'x'],
            ['elementValue', 1],
        ]);
        const innerBytes = cbor.encode(itemMap);
        const wrapped = cbor.encode(new Tag(innerBytes, 24));
        const ns = new Map<string, Uint8Array[]>([['eu.europa.ec.eudi.pid.1', [wrapped]]]);
        await expect(verifyAllDigests(ns, mso)).rejects.toThrow(MalformedCredentialError);
    });

    it('rejects when an item is tampered', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth, itemBytesByNamespace } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: {
                'eu.europa.ec.eudi.pid.1': { age_over_18: true, family_name: 'Doe' },
            },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        const items = [...itemBytesByNamespace['eu.europa.ec.eudi.pid.1']!];
        items[0]![0] ^= 0xff; // flip a byte in the first item
        const ns = new Map([['eu.europa.ec.eudi.pid.1', items]]);
        await expect(verifyAllDigests(ns, mso)).rejects.toThrow(MalformedCredentialError);
    });
});
