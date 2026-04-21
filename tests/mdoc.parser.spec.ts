import { Encoder as CborEncoder } from 'cbor-x';
import { describe, it, expect, beforeAll } from 'vitest';

import { MalformedCredentialError } from '../src/errors.js';
import { MdocParser } from '../src/parsers/mdoc.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import { generateTestKeyMaterial, type TestKeyMaterial } from './fixtures/crypto-helpers.js';
import {
    buildSignedMdoc,
    buildMdocWithExpiredValidity,
    buildMdocWithFutureValidFrom,
    buildMdocWithFutureSigned,
    stripCoseSignature,
} from './fixtures/mdoc-helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false });

let issuerKey: TestKeyMaterial;
let altKey: TestKeyMaterial;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial();
    altKey = await generateTestKeyMaterial();
});

function trustedOptions(overrides: Partial<ParseOptions> = {}): ParseOptions {
    return {
        trustedCertificates: [issuerKey.certDerBytes],
        nonce: 'n',
        ...overrides,
    };
}

describe('MdocParser', () => {
    const parser = new MdocParser();

    it('has format "mdoc"', () => {
        expect(parser.format).toBe('mdoc');
    });

    // ------------------------------------------------------------------
    // canParse
    // ------------------------------------------------------------------

    describe('canParse', () => {
        it('returns true for Uint8Array', () => {
            expect(parser.canParse(new Uint8Array([0x01, 0x02]))).toBe(true);
        });

        it('returns true for Buffer', () => {
            expect(parser.canParse(Buffer.from([0x01, 0x02]))).toBe(true);
        });

        it('returns false for string', () => {
            expect(parser.canParse('not mdoc')).toBe(false);
        });

        it('returns false for number', () => {
            expect(parser.canParse(42)).toBe(false);
        });

        it('returns false for null', () => {
            expect(parser.canParse(null)).toBe(false);
        });

        it('returns false for undefined', () => {
            expect(parser.canParse(undefined)).toBe(false);
        });

        it('returns false for object', () => {
            expect(parser.canParse({ data: new Uint8Array() })).toBe(false);
        });
    });

    // ------------------------------------------------------------------
    // parse — happy path
    // ------------------------------------------------------------------

    describe('parse — happy path', () => {
        it('parses a valid signed mDOC and extracts claims', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                docType: 'eu.europa.ec.eudi.pid.1',
                namespaces: {
                    'eu.europa.ec.eudi.pid.1': { age_over_18: true, family_name: 'Doe' },
                },
            });
            const result = await parser.parse(built.mdocBytes, trustedOptions());
            expect(result.valid).toBe(true);
            expect(result.claims.age_over_18).toBe(true);
            expect((result.claims as Record<string, unknown>).family_name).toBe('Doe');
        });

        it('handles multi-namespace mDOCs', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                namespaces: {
                    'eu.europa.ec.eudi.pid.1': { age_over_18: true },
                    'org.iso.18013.5.1': { family_name: 'Doe' },
                },
            });
            const result = await parser.parse(built.mdocBytes, trustedOptions());
            expect(result.valid).toBe(true);
            expect(result.claims.age_over_18).toBe(true);
        });
    });

    // ------------------------------------------------------------------
    // parse — signature verification
    // ------------------------------------------------------------------

    describe('parse — signature verification', () => {
        it('rejects a credential with zeroed signature', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            const stripped = await stripCoseSignature(built.mdocBytes);
            const result = await parser.parse(stripped, trustedOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toMatch(/signature/i);
        });

        it('rejects when signed with a different key', async () => {
            const built = await buildSignedMdoc({
                issuerKey: altKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            // Trust only issuerKey; altKey's cert is untrusted
            const result = await parser.parse(built.mdocBytes, trustedOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toMatch(/not trusted/i);
        });
    });

    // ------------------------------------------------------------------
    // parse — validity
    // ------------------------------------------------------------------

    describe('parse — validity', () => {
        it('rejects an expired credential', async () => {
            const built = await buildMdocWithExpiredValidity({
                issuerKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            const result = await parser.parse(built.mdocBytes, trustedOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toMatch(/expired/i);
        });

        it('throws on a not-yet-valid credential (structural)', async () => {
            const built = await buildMdocWithFutureValidFrom({
                issuerKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            await expect(parser.parse(built.mdocBytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws on a future-signed credential', async () => {
            const built = await buildMdocWithFutureSigned({
                issuerKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            await expect(parser.parse(built.mdocBytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });

    // ------------------------------------------------------------------
    // parse — expectedDocType
    // ------------------------------------------------------------------

    describe('parse — expectedDocType', () => {
        it('accepts matching docType', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                docType: 'eu.europa.ec.eudi.pid.1',
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            const result = await parser.parse(
                built.mdocBytes,
                trustedOptions({ expectedDocType: 'eu.europa.ec.eudi.pid.1' })
            );
            expect(result.valid).toBe(true);
        });

        it('rejects mismatched docType', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                docType: 'eu.europa.ec.eudi.pid.1',
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            const result = await parser.parse(
                built.mdocBytes,
                trustedOptions({ expectedDocType: 'org.iso.18013.5.1.mDL' })
            );
            expect(result.valid).toBe(false);
            expect(result.error).toMatch(/docType/);
        });

        it('accepts any docType when expectedDocType is undefined', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                docType: 'custom.doc.type',
                namespaces: { ns: { k: 1 } },
            });
            const result = await parser.parse(built.mdocBytes, trustedOptions());
            expect(result.valid).toBe(true);
        });
    });

    // ------------------------------------------------------------------
    // parse — algorithm allowlist
    // ------------------------------------------------------------------

    describe('parse — algorithm allowlist', () => {
        it('rejects alg not in allowlist', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
                alg: 'ES256',
            });
            const result = await parser.parse(built.mdocBytes, trustedOptions({ allowedAlgorithms: ['ES384'] }));
            expect(result.valid).toBe(false);
            expect(result.error).toMatch(/algorithm/i);
        });
    });

    // ------------------------------------------------------------------
    // parse — structural
    // ------------------------------------------------------------------

    describe('parse — structural', () => {
        it('throws on corrupt CBOR', async () => {
            const corrupt = new Uint8Array([0xff, 0x01]);
            await expect(parser.parse(corrupt, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws when vpToken is not a Uint8Array', async () => {
            await expect(parser.parse('not-bytes' as unknown, trustedOptions())).rejects.toThrow(
                MalformedCredentialError
            );
        });
    });

    // ------------------------------------------------------------------
    // parse — DeviceResponse structural errors
    // ------------------------------------------------------------------

    describe('parse — DeviceResponse structural errors', () => {
        it('throws when vpToken is not a CBOR DeviceResponse Map (CBOR array)', async () => {
            // CBOR array [0] — not a Map
            const notAMap = new Uint8Array([0x81, 0x00]);
            await expect(parser.parse(notAMap, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws when DeviceResponse has no documents key', async () => {
            const dr = new Map<string, unknown>([
                ['version', '1.0'],
                ['status', 0],
            ]);
            const bytes = cbor.encode(dr);
            await expect(parser.parse(bytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws when DeviceResponse documents array is empty', async () => {
            const dr = new Map<string, unknown>([
                ['version', '1.0'],
                ['documents', []],
                ['status', 0],
            ]);
            const bytes = cbor.encode(dr);
            await expect(parser.parse(bytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws when document is not a Map', async () => {
            const dr = new Map<string, unknown>([
                ['version', '1.0'],
                ['documents', ['not a map']],
                ['status', 0],
            ]);
            const bytes = cbor.encode(dr);
            await expect(parser.parse(bytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws when issuerSigned is not a Map', async () => {
            const doc = new Map<string, unknown>([
                ['docType', 'eu.europa.ec.eudi.pid.1'],
                ['issuerSigned', 'not a map'],
            ]);
            const dr = new Map<string, unknown>([
                ['version', '1.0'],
                ['documents', [doc]],
                ['status', 0],
            ]);
            const bytes = cbor.encode(dr);
            await expect(parser.parse(bytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws when issuerAuth is not an array', async () => {
            const issuerSigned = new Map<string, unknown>([['issuerAuth', 'not an array']]);
            const doc = new Map<string, unknown>([
                ['docType', 'eu.europa.ec.eudi.pid.1'],
                ['issuerSigned', issuerSigned],
            ]);
            const dr = new Map<string, unknown>([
                ['version', '1.0'],
                ['documents', [doc]],
                ['status', 0],
            ]);
            const bytes = cbor.encode(dr);
            await expect(parser.parse(bytes, trustedOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });

    // ------------------------------------------------------------------
    // parse — trust check opt-out
    // ------------------------------------------------------------------

    describe('parse — trust check opt-out', () => {
        it('throws MalformedCredentialError when trustedCertificates is empty and skipTrustCheck is not set', async () => {
            const built = await buildSignedMdoc({
                issuerKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            await expect(parser.parse(built.mdocBytes, trustedOptions({ trustedCertificates: [] }))).rejects.toThrow(
                MalformedCredentialError
            );
        });

        it('accepts any cert when skipTrustCheck: true', async () => {
            const built = await buildSignedMdoc({
                issuerKey: altKey,
                namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            });
            const result = await parser.parse(
                built.mdocBytes,
                trustedOptions({ trustedCertificates: [], skipTrustCheck: true })
            );
            expect(result.valid).toBe(true);
        });
    });
});
