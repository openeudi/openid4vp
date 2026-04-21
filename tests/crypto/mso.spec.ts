import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { describe, it, expect } from 'vitest';

import { decodeCoseSign1 } from '../../src/crypto/cose-sign1.js';
import { decodeMso, validateMsoValidity, validateMsoDocType } from '../../src/crypto/mso.js';
import { MalformedCredentialError, ExpiredCredentialError } from '../../src/errors.js';
import { generateTestKeyMaterial } from '../fixtures/crypto-helpers.js';
import {
    buildSignedMdoc,
    buildMdocWithExpiredValidity,
    buildMdocWithFutureValidFrom,
    buildMdocWithFutureSigned,
} from '../fixtures/mdoc-helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false });

describe('decodeMso', () => {
    it('decodes a valid MSO from a fresh mDOC', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            docType: 'eu.europa.ec.eudi.pid.1',
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const cose = decodeCoseSign1(issuerAuth);
        const mso = decodeMso(cose.payload);
        expect(mso.version).toBe('1.0');
        expect(mso.digestAlgorithm).toBe('SHA-256');
        expect(mso.docType).toBe('eu.europa.ec.eudi.pid.1');
        expect(mso.validityInfo.signed).toBeInstanceOf(Date);
        expect(mso.validityInfo.validFrom).toBeInstanceOf(Date);
        expect(mso.validityInfo.validUntil).toBeInstanceOf(Date);
        expect(mso.valueDigests.get('eu.europa.ec.eudi.pid.1')?.size).toBe(1);
    });

    it('throws on payload that is not a CBOR Map', () => {
        const notAMap = new Uint8Array([0x82, 0x01, 0x02]); // CBOR array [1, 2]
        expect(() => decodeMso(notAMap)).toThrow(MalformedCredentialError);
    });
});

describe('validateMsoValidity', () => {
    it('accepts a freshly built mDOC', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildSignedMdoc({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        expect(() => validateMsoValidity(mso, new Date())).not.toThrow();
    });

    it('rejects an expired mDOC with ExpiredCredentialError', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildMdocWithExpiredValidity({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        expect(() => validateMsoValidity(mso, new Date())).toThrow(ExpiredCredentialError);
    });

    it('rejects a not-yet-valid mDOC with MalformedCredentialError', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildMdocWithFutureValidFrom({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        expect(() => validateMsoValidity(mso, new Date())).toThrow(MalformedCredentialError);
    });

    it('rejects a future-signed mDOC with MalformedCredentialError', async () => {
        const key = await generateTestKeyMaterial();
        const { issuerAuth } = await buildMdocWithFutureSigned({
            issuerKey: key,
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
        });
        const mso = decodeMso(decodeCoseSign1(issuerAuth).payload);
        expect(() => validateMsoValidity(mso, new Date())).toThrow(MalformedCredentialError);
    });
});

describe('validateMsoDocType', () => {
    it('passes when docType matches', () => {
        const mso = fakeMso('eu.europa.ec.eudi.pid.1');
        expect(() => validateMsoDocType(mso, 'eu.europa.ec.eudi.pid.1')).not.toThrow();
    });

    it('throws MalformedCredentialError on mismatch', () => {
        const mso = fakeMso('eu.europa.ec.eudi.pid.1');
        expect(() => validateMsoDocType(mso, 'org.iso.18013.5.1.mDL')).toThrow(MalformedCredentialError);
    });
});

// ----------------------------------------------------------------
// Helper: build a minimal valid MSO Map and encode as raw CBOR bytes
// (NOT tag-24 wrapped — decodeMso receives the raw payload bstr)
// ----------------------------------------------------------------
function buildRawMsoBytes(overrides: Record<string, unknown> = {}): Uint8Array {
    const validityInfo = new Map<string, unknown>([
        ['signed', new Date()],
        ['validFrom', new Date(Date.now() - 3600_000)],
        ['validUntil', new Date(Date.now() + 3600_000)],
    ]);
    const valueDigests = new Map<string, Map<number, Uint8Array>>();
    const base = new Map<string, unknown>([
        ['version', '1.0'],
        ['digestAlgorithm', 'SHA-256'],
        ['docType', 'eu.europa.ec.eudi.pid.1'],
        ['valueDigests', valueDigests],
        ['validityInfo', validityInfo],
    ]);
    for (const [k, v] of Object.entries(overrides)) {
        base.set(k, v);
    }
    return cbor.encode(base);
}

describe('decodeMso — structural errors', () => {
    it('throws when version is not a string', () => {
        const bytes = buildRawMsoBytes({ version: 123 });
        expect(() => decodeMso(bytes)).toThrow(MalformedCredentialError);
    });

    it('throws when digestAlgorithm is not a string', () => {
        const bytes = buildRawMsoBytes({ digestAlgorithm: 99 });
        expect(() => decodeMso(bytes)).toThrow(MalformedCredentialError);
    });

    it('throws when docType is not a string', () => {
        const bytes = buildRawMsoBytes({ docType: 42 });
        expect(() => decodeMso(bytes)).toThrow(MalformedCredentialError);
    });

    it('throws when valueDigests is not a Map', () => {
        const bytes = buildRawMsoBytes({ valueDigests: 'not a map' });
        expect(() => decodeMso(bytes)).toThrow(MalformedCredentialError);
    });

    it('throws when validityInfo is not a Map', () => {
        const bytes = buildRawMsoBytes({ validityInfo: [] });
        expect(() => decodeMso(bytes)).toThrow(MalformedCredentialError);
    });

    it('throws on unsupported date encoding in validityInfo.signed', () => {
        const badValidityInfo = new Map<string, unknown>([
            ['signed', 99999],
            ['validFrom', new Date(Date.now() - 3600_000)],
            ['validUntil', new Date(Date.now() + 3600_000)],
        ]);
        const bytes = buildRawMsoBytes({ validityInfo: badValidityInfo });
        expect(() => decodeMso(bytes)).toThrow(MalformedCredentialError);
    });

    it('decodes expectedUpdate when present', () => {
        const validityInfo = new Map<string, unknown>([
            ['signed', new Date()],
            ['validFrom', new Date(Date.now() - 3600_000)],
            ['validUntil', new Date(Date.now() + 3600_000)],
            ['expectedUpdate', new Date(Date.now() + 7200_000)],
        ]);
        const bytes = buildRawMsoBytes({ validityInfo });
        const mso = decodeMso(bytes);
        expect(mso.validityInfo.expectedUpdate).toBeInstanceOf(Date);
    });

    it('decodeDateLike accepts Tag(1, epochSeconds) via validityInfo', () => {
        const epochSecs = Math.floor(Date.now() / 1000);
        const validityInfo = new Map<string, unknown>([
            ['signed', new Tag(epochSecs, 1)],
            ['validFrom', new Tag(epochSecs - 3600, 1)],
            ['validUntil', new Tag(epochSecs + 3600, 1)],
        ]);
        const bytes = buildRawMsoBytes({ validityInfo });
        const mso = decodeMso(bytes);
        expect(mso.validityInfo.signed).toBeInstanceOf(Date);
    });

    it('decodeDateLike accepts Tag(1004, "2025-01-01") via validityInfo', () => {
        const validityInfo = new Map<string, unknown>([
            ['signed', new Tag('2025-01-01', 1004)],
            ['validFrom', new Tag('2025-01-01', 1004)],
            ['validUntil', new Tag('2026-01-01', 1004)],
        ]);
        const bytes = buildRawMsoBytes({ validityInfo });
        const mso = decodeMso(bytes);
        expect(mso.validityInfo.signed).toBeInstanceOf(Date);
    });
});

function fakeMso(docType: string) {
    return {
        version: '1.0',
        digestAlgorithm: 'SHA-256',
        valueDigests: new Map(),
        docType,
        validityInfo: {
            signed: new Date(),
            validFrom: new Date(Date.now() - 3600_000),
            validUntil: new Date(Date.now() + 3600_000),
        },
    } as import('../../src/crypto/mso.js').MobileSecurityObject;
}
