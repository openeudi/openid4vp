import { describe, it, expect } from 'vitest';

import { MalformedCredentialError } from '../src/errors.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';
import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';

import {
    VALID_SD_JWT,
    VALID_SD_JWT_NONCE,
    EXPIRED_SD_JWT,
    UNTRUSTED_SD_JWT,
    PLAIN_JWT_NO_TILDE,
    MALFORMED_SD_JWT,
    WRONG_NONCE_SD_JWT,
    FAKE_CERT_UINT8,
} from './fixtures/sd-jwt-samples.js';

function buildOptions(overrides: Partial<ParseOptions> = {}): ParseOptions {
    return {
        trustedCertificates: [FAKE_CERT_UINT8],
        nonce: VALID_SD_JWT_NONCE,
        ...overrides,
    };
}

describe('SdJwtParser', () => {
    const parser = new SdJwtParser();

    // ------------------------------------------------------------------
    // Format identity
    // ------------------------------------------------------------------

    it('has format "sd-jwt-vc"', () => {
        expect(parser.format).toBe('sd-jwt-vc');
    });

    // ------------------------------------------------------------------
    // canParse
    // ------------------------------------------------------------------

    describe('canParse', () => {
        it('returns true for an SD-JWT string containing tildes', () => {
            expect(parser.canParse(VALID_SD_JWT)).toBe(true);
        });

        it('returns false for a non-string input (number)', () => {
            expect(parser.canParse(12345)).toBe(false);
        });

        it('returns false for a non-string input (object)', () => {
            expect(parser.canParse({ token: 'abc~def' })).toBe(false);
        });

        it('returns false for null', () => {
            expect(parser.canParse(null)).toBe(false);
        });

        it('returns false for undefined', () => {
            expect(parser.canParse(undefined)).toBe(false);
        });

        it('returns false for a plain JWT without tildes', () => {
            expect(parser.canParse(PLAIN_JWT_NO_TILDE)).toBe(false);
        });
    });

    // ------------------------------------------------------------------
    // parse — valid credential
    // ------------------------------------------------------------------

    describe('parse — valid credential', () => {
        it('parses valid SD-JWT and extracts claims', async () => {
            const result = await parser.parse(VALID_SD_JWT, buildOptions());

            expect(result.valid).toBe(true);
            expect(result.format).toBe('sd-jwt-vc');
            expect(result.claims.age_over_18).toBe(true);
            expect(result.claims.resident_country).toBe('DE');
            expect(result.error).toBeUndefined();
        });

        it('extracts issuer info with certificate bytes', async () => {
            const result = await parser.parse(VALID_SD_JWT, buildOptions());

            expect(result.issuer.certificate).toBeInstanceOf(Uint8Array);
            expect(result.issuer.certificate.length).toBeGreaterThan(0);
        });

        it('derives country hint from issuer URL TLD', async () => {
            const result = await parser.parse(VALID_SD_JWT, buildOptions());

            expect(result.issuer.country).toBe('DE');
        });
    });

    // ------------------------------------------------------------------
    // parse — expired credential
    // ------------------------------------------------------------------

    describe('parse — expired credential', () => {
        it('returns invalid for an expired credential', async () => {
            const result = await parser.parse(EXPIRED_SD_JWT, buildOptions());

            expect(result.valid).toBe(false);
            expect(result.error).toContain('expired');
        });
    });

    // ------------------------------------------------------------------
    // parse — untrusted certificate
    // ------------------------------------------------------------------

    describe('parse — untrusted certificate', () => {
        it('returns invalid when issuer certificate is not trusted', async () => {
            const result = await parser.parse(UNTRUSTED_SD_JWT, buildOptions());

            expect(result.valid).toBe(false);
            expect(result.error).toContain('not trusted');
        });
    });

    // ------------------------------------------------------------------
    // parse — nonce mismatch
    // ------------------------------------------------------------------

    describe('parse — nonce mismatch', () => {
        it('returns invalid when key binding JWT nonce does not match', async () => {
            const result = await parser.parse(WRONG_NONCE_SD_JWT, buildOptions());

            expect(result.valid).toBe(false);
            expect(result.error).toContain('nonce');
        });
    });

    // ------------------------------------------------------------------
    // parse — malformed structure
    // ------------------------------------------------------------------

    describe('parse — malformed structure', () => {
        it('throws MalformedCredentialError for completely invalid input', async () => {
            await expect(parser.parse(MALFORMED_SD_JWT, buildOptions())).rejects.toThrow(MalformedCredentialError);
        });

        it('throws MalformedCredentialError for non-string input', async () => {
            await expect(parser.parse(42, buildOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });
});
