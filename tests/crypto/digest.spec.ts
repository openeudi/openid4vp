import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { describe, it, expect } from 'vitest';

import { decodeCoseSign1 } from '../../src/crypto/cose-sign1.js';
import { computeItemDigest, verifyAllDigests } from '../../src/crypto/digest.js';
import { decodeMso } from '../../src/crypto/mso.js';
import { MalformedCredentialError } from '../../src/errors.js';
import { wrapIssuerSignedItemBytes } from '../../src/parsers/mdoc.parser.js';
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

    // Regression guard for the ISO 18013-5 §9.1.2.4 interop bug: the ValueDigests
    // digest is computed over IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
    // — the FULL tag-24 encoding — NOT the inner IssuerSignedItem CBOR. Hashing the inner
    // bytes rejected every genuine single-wrapped wallet mdoc (caught by the OIDF suite).
    describe('IssuerSignedItemBytes tag-24 hashing (ISO 18013-5 §9.1.2.4)', () => {
        const buildInner = (): Uint8Array =>
            cbor.encode(
                new Map<string, unknown>([
                    ['digestID', 7],
                    ['random', crypto.getRandomValues(new Uint8Array(16))],
                    ['elementIdentifier', 'family_name'],
                    ['elementValue', 'Doe'],
                ])
            );

        it('wrapIssuerSignedItemBytes reproduces the exact on-wire #6.24(bstr) bytes', () => {
            const inner = buildInner();
            // Canonical wire form an issuer/wallet serializes: 0xD8 0x18 ++ bstr(inner).
            // Compare via Array.from — cbor-x returns a Node Buffer and toEqual treats
            // Buffer/Uint8Array as distinct types even when the bytes are identical.
            const wire = cbor.encode(new Tag(inner, 24));
            expect([wire[0], wire[1]]).toEqual([0xd8, 0x18]);

            // cbor-x hands the decoder the inner bstr content verbatim (Tag(24,·) in prod,
            // EmbeddedCbor(·) under the fixture's global tag-24 addExtension — both via .value).
            const decoded = cbor.decode(wire) as { value: Uint8Array };
            expect(Array.from(decoded.value)).toEqual(Array.from(inner));

            // Re-wrapping that inner content must reproduce the original wire bytes exactly:
            // only the tag+length header is prepended; inner is copied verbatim (no re-encode).
            expect(Array.from(wrapIssuerSignedItemBytes(decoded.value))).toEqual(Array.from(wire));
        });

        it('digest is taken over the FULL tag-24 bytes, never the inner CBOR', async () => {
            const inner = buildInner();
            const wire = cbor.encode(new Tag(inner, 24));

            const overFull = await computeItemDigest(wire, 'SHA-256');
            const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', wire));
            expect(overFull).toEqual(expected);

            // The pre-fix behaviour (hashing inner CBOR) must NOT collide with the spec digest.
            const overInner = await computeItemDigest(inner, 'SHA-256');
            expect(overInner).not.toEqual(expected);
        });
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

    // The test above flips byte 0 of the tag-24 wire — the 0xD8 tag byte itself —
    // which breaks CBOR decodability and is caught by unwrapItemMap's "not
    // decodable" guard. That pins malformed-input rejection, but NOT the
    // security-relevant direction: an item whose INNER content (elementValue) was
    // tampered while remaining perfectly valid, decodable CBOR must still be
    // rejected, because its hash no longer matches the digest the issuer signed
    // over. This regression-guards that verifyAllDigests actually recomputes and
    // compares the digest rather than trusting a structurally-valid item.
    it('rejects when an IssuerSignedItem\'s inner elementValue is tampered but remains valid, decodable CBOR (digest mismatch, not decode failure)', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth, itemBytesByNamespace } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { family_name: 'Doe' } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        const originalItemBytes = itemBytesByNamespace['eu.europa.ec.eudi.pid.1']![0]!;

        // Unwrap the tag-24 item (Path B: EmbeddedCbor-like `{ value }`, since
        // mdoc-helpers.ts registers a global tag-24 extension), decode the inner
        // Map, tamper ONLY elementValue's content, and re-wrap — producing bytes
        // that are still valid tag-24 CBOR decoding to a Map with the original
        // digestID, but whose hash no longer matches the signed digest.
        const decoded = cbor.decode(originalItemBytes) as { value: Uint8Array };
        const innerMap = cbor.decode(decoded.value) as Map<string, unknown>;
        expect(innerMap.get('elementValue')).toBe('Doe');
        innerMap.set('elementValue', 'Eve');
        const tamperedInner = cbor.encode(innerMap);
        const tamperedItemBytes = cbor.encode(new Tag(tamperedInner, 24));

        const ns = new Map<string, Uint8Array[]>([['eu.europa.ec.eudi.pid.1', [tamperedItemBytes]]]);
        await expect(verifyAllDigests(ns, mso)).rejects.toThrow(/digest mismatch/);
    });
});
