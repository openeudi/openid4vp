import { describe, it, expect } from 'vitest';

import { MalformedCredentialError } from '../src/errors.js';
import { MdocParser } from '../src/parsers/mdoc.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import { VALID_MDOC, EXPIRED_MDOC, UNTRUSTED_MDOC, MALFORMED_MDOC, FAKE_MDOC_CERT } from './fixtures/mdoc-samples.js';

function buildOptions(overrides: Partial<ParseOptions> = {}): ParseOptions {
    return {
        trustedCertificates: [FAKE_MDOC_CERT],
        nonce: 'test-nonce-mdoc',
        ...overrides,
    };
}

describe('MdocParser', () => {
    const parser = new MdocParser();

    // ------------------------------------------------------------------
    // Format identity
    // ------------------------------------------------------------------

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

        it('returns false for string input', () => {
            expect(parser.canParse('not-binary-data')).toBe(false);
        });

        it('returns false for number input', () => {
            expect(parser.canParse(42)).toBe(false);
        });

        it('returns false for null', () => {
            expect(parser.canParse(null)).toBe(false);
        });

        it('returns false for undefined', () => {
            expect(parser.canParse(undefined)).toBe(false);
        });

        it('returns false for object input', () => {
            expect(parser.canParse({ data: new Uint8Array() })).toBe(false);
        });
    });

    // ------------------------------------------------------------------
    // parse -- valid credential
    // ------------------------------------------------------------------

    describe('parse -- valid credential', () => {
        it('parses valid mDOC and extracts claims', async () => {
            const result = await parser.parse(VALID_MDOC, buildOptions());

            expect(result.valid).toBe(true);
            expect(result.format).toBe('mdoc');
            expect(result.claims.age_over_18).toBe(true);
            expect(result.claims.resident_country).toBe('DE');
            expect(result.error).toBeUndefined();
        });

        it('extracts issuer info with certificate bytes', async () => {
            const result = await parser.parse(VALID_MDOC, buildOptions());

            expect(result.issuer.certificate).toBeInstanceOf(Uint8Array);
            expect(result.issuer.certificate.length).toBeGreaterThan(0);
        });

        it('derives country from resident_country claim', async () => {
            const result = await parser.parse(VALID_MDOC, buildOptions());

            expect(result.issuer.country).toBe('DE');
        });
    });

    // ------------------------------------------------------------------
    // parse -- expired credential
    // ------------------------------------------------------------------

    describe('parse -- expired credential', () => {
        it('returns invalid for an expired mDOC', async () => {
            const result = await parser.parse(EXPIRED_MDOC, buildOptions());

            expect(result.valid).toBe(false);
            expect(result.error).toContain('expired');
        });
    });

    // ------------------------------------------------------------------
    // parse -- untrusted certificate
    // ------------------------------------------------------------------

    describe('parse -- untrusted certificate', () => {
        it('returns invalid when issuer certificate is not trusted', async () => {
            const result = await parser.parse(UNTRUSTED_MDOC, buildOptions());

            expect(result.valid).toBe(false);
            expect(result.error).toContain('not trusted');
        });
    });

    // ------------------------------------------------------------------
    // parse -- malformed CBOR
    // ------------------------------------------------------------------

    describe('parse -- malformed structure', () => {
        it('throws MalformedCredentialError for invalid CBOR data', async () => {
            await expect(parser.parse(MALFORMED_MDOC, buildOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws MalformedCredentialError for non-binary input', async () => {
            await expect(parser.parse('string-input', buildOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });
});
