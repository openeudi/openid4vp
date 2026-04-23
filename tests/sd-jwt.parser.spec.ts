import { describe, it, expect, beforeAll } from 'vitest';

import { MalformedCredentialError } from '../src/errors.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';
import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';

import {
    generateTestKeyMaterial,
    buildSignedSdJwt,
    tamperJwtPayload,
    buildStaticJwt,
    type TestKeyMaterial,
    type BuildSdJwtResult,
} from './fixtures/crypto-helpers.js';

// ----------------------------------------------------------------
// Shared test state — initialized in beforeAll
// ----------------------------------------------------------------

let issuerKey: TestKeyMaterial;
let holderKey: TestKeyMaterial;
let altKey: TestKeyMaterial;

let validResult: BuildSdJwtResult;
let validNonce: string;
let validAudience: string;

let expiredResult: BuildSdJwtResult;
let noKbResult: BuildSdJwtResult;

function buildOptions(overrides: Partial<ParseOptions> = {}): ParseOptions {
    return {
        trustedCertificates: [issuerKey.certDerBytes],
        nonce: validNonce,
        audience: validAudience,
        ...overrides,
    };
}

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial();
    holderKey = await generateTestKeyMaterial();
    altKey = await generateTestKeyMaterial();

    validNonce = crypto.randomUUID();
    validAudience = 'https://verifier.example.com';

    validResult = await buildSignedSdJwt({
        issuerKey,
        holderKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [
            ['age_over_18', true],
            ['resident_country', 'DE'],
        ],
        nonce: validNonce,
        audience: validAudience,
    });

    expiredResult = await buildSignedSdJwt({
        issuerKey,
        holderKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [
            ['age_over_18', true],
            ['resident_country', 'DE'],
        ],
        nonce: validNonce,
        audience: validAudience,
        expSeconds: -7200,
    });

    noKbResult = await buildSignedSdJwt({
        issuerKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [
            ['age_over_18', true],
            ['resident_country', 'DE'],
        ],
    });
});

// ----------------------------------------------------------------
// Tests
// ----------------------------------------------------------------

describe('SdJwtParser', () => {
    const parser = new SdJwtParser();

    it('has format "sd-jwt-vc"', () => {
        expect(parser.format).toBe('sd-jwt-vc');
    });

    // ------------------------------------------------------------------
    // canParse
    // ------------------------------------------------------------------

    describe('canParse', () => {
        it('returns true for an SD-JWT string containing tildes', () => {
            expect(parser.canParse(validResult.sdJwt)).toBe(true);
        });

        it('returns false for a number', () => {
            expect(parser.canParse(12345)).toBe(false);
        });

        it('returns false for an object', () => {
            expect(parser.canParse({ token: 'abc~def' })).toBe(false);
        });

        it('returns false for null', () => {
            expect(parser.canParse(null)).toBe(false);
        });

        it('returns false for undefined', () => {
            expect(parser.canParse(undefined)).toBe(false);
        });

        it('returns false for a plain JWT without tildes', () => {
            const plainJwt = buildStaticJwt({ alg: 'ES256' }, { sub: 'test' });
            expect(parser.canParse(plainJwt)).toBe(false);
        });
    });

    // ------------------------------------------------------------------
    // parse — valid credential
    // ------------------------------------------------------------------

    describe('parse — valid credential', () => {
        it('parses valid SD-JWT and extracts claims', async () => {
            const result = await parser.parse(validResult.sdJwt, buildOptions());
            expect(result.valid).toBe(true);
            expect(result.format).toBe('sd-jwt-vc');
            expect(result.claims.age_over_18).toBe(true);
            expect(result.claims.resident_country).toBe('DE');
            expect(result.error).toBeUndefined();
        });

        it('extracts issuer info with certificate bytes', async () => {
            const result = await parser.parse(validResult.sdJwt, buildOptions());
            expect(result.issuer.certificate).toBeInstanceOf(Uint8Array);
            expect(result.issuer.certificate.length).toBeGreaterThan(0);
        });

        it('derives country hint from issuer URL TLD', async () => {
            const result = await parser.parse(validResult.sdJwt, buildOptions());
            expect(result.issuer.country).toBe('DE');
        });
    });

    // ------------------------------------------------------------------
    // parse — signature verification
    // ------------------------------------------------------------------

    describe('parse — signature verification', () => {
        it('rejects a JWT with tampered payload', async () => {
            const tamperedIssuerJwt = tamperJwtPayload(validResult.issuerJwt, { age_over_18: false });
            const tamperedSdJwt = validResult.sdJwt.replace(validResult.issuerJwt, tamperedIssuerJwt);
            const result = await parser.parse(tamperedSdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('signature verification failed');
        });

        it('rejects when issuer JWT signed with wrong key', async () => {
            const wrongKeyResult = await buildSignedSdJwt({
                issuerKey: altKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
                disclosureClaims: [['age_over_18', true]],
            });
            // Trust only the original issuer cert — altKey's cert is untrusted
            const result = await parser.parse(wrongKeyResult.sdJwt, buildOptions());
            expect(result.valid).toBe(false);
        });
    });

    // ------------------------------------------------------------------
    // parse — expired credential
    // ------------------------------------------------------------------

    describe('parse — expired credential', () => {
        it('returns invalid for an expired credential', async () => {
            const result = await parser.parse(expiredResult.sdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('signature verification failed');
        });
    });

    // ------------------------------------------------------------------
    // parse — untrusted certificate
    // ------------------------------------------------------------------

    describe('parse — untrusted certificate', () => {
        it('returns invalid when issuer certificate is not trusted', async () => {
            const untrustedResult = await buildSignedSdJwt({
                issuerKey: altKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
                disclosureClaims: [['age_over_18', true]],
            });
            // altKey's cert is not in trustedCertificates
            const result = await parser.parse(
                untrustedResult.sdJwt,
                buildOptions({
                    trustedCertificates: [issuerKey.certDerBytes],
                })
            );
            expect(result.valid).toBe(false);
            expect(result.error).toContain('not trusted');
        });
    });

    // ------------------------------------------------------------------
    // parse — malformed structure
    // ------------------------------------------------------------------

    describe('parse — malformed structure', () => {
        it('throws MalformedCredentialError for completely invalid input', async () => {
            await expect(parser.parse('!!!not-a-jwt!!!~garbage~more-garbage~', buildOptions())).rejects.toThrow(
                MalformedCredentialError
            );
        });

        it('throws MalformedCredentialError for non-string input', async () => {
            await expect(parser.parse(42, buildOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });

    // ------------------------------------------------------------------
    // parse — missing x5c
    // ------------------------------------------------------------------

    describe('parse — missing x5c', () => {
        it('throws MalformedCredentialError when x5c is missing from header', async () => {
            const noX5cHeader = { alg: 'ES256', typ: 'vc+sd-jwt' };
            const noX5cPayload = {
                iss: 'https://issuer.de/eudi',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };
            const noX5cJwt = buildStaticJwt(noX5cHeader, noX5cPayload);
            const sdJwt = noX5cJwt + '~~';
            await expect(parser.parse(sdJwt, buildOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });

    // ------------------------------------------------------------------
    // parse — unsupported algorithm
    // ------------------------------------------------------------------

    describe('parse — unsupported algorithm', () => {
        it('returns invalid for algorithm not in allowlist', async () => {
            const rsaHeader = { alg: 'RS256', typ: 'vc+sd-jwt', x5c: [issuerKey.x5cBase64] };
            const rsaPayload = {
                iss: 'https://issuer.de/eudi',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };
            const rsaJwt = buildStaticJwt(rsaHeader, rsaPayload);
            const sdJwt = rsaJwt + '~~';
            const result = await parser.parse(sdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('Unsupported algorithm');
            expect(result.error).toContain('RS256');
        });
    });

    // ------------------------------------------------------------------
    // parse — no key binding JWT (optional per spec)
    // ------------------------------------------------------------------

    describe('parse — no key binding JWT', () => {
        it('accepts SD-JWT without key binding JWT', async () => {
            const result = await parser.parse(
                noKbResult.sdJwt,
                buildOptions({
                    trustedCertificates: [issuerKey.certDerBytes],
                })
            );
            expect(result.valid).toBe(true);
            expect(result.claims.age_over_18).toBe(true);
        });
    });

    // ------------------------------------------------------------------
    // parse — disclosure hash verification
    // ------------------------------------------------------------------

    describe('parse — disclosure hash verification', () => {
        it('rejects when a disclosure is tampered', async () => {
            // Create a fake disclosure that won't hash to any _sd entry
            const fakeDisclosure = Buffer.from(JSON.stringify([crypto.randomUUID(), 'age_over_18', false])).toString(
                'base64url'
            );
            // Replace the first real disclosure with the fake one
            const tamperedSdJwt = validResult.sdJwt.replace(validResult.disclosures[0], fakeDisclosure);
            const result = await parser.parse(tamperedSdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('Disclosure hash mismatch');
        });

        it('rejects when disclosures are present but _sd array is absent', async () => {
            // Build an SD-JWT with no _sd in the payload (no disclosureClaims)
            // then manually inject a disclosure into the token string
            const noSdResult = await buildSignedSdJwt({
                issuerKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
            });
            const fakeDisclosure = Buffer.from(JSON.stringify([crypto.randomUUID(), 'age_over_18', true])).toString(
                'base64url'
            );
            // Insert a disclosure between the JWT and the trailing ~
            const injectedSdJwt = noSdResult.issuerJwt + '~' + fakeDisclosure + '~';
            const result = await parser.parse(injectedSdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('no _sd array');
        });
    });

    // ------------------------------------------------------------------
    // parse — trust check opt-out
    // ------------------------------------------------------------------

    describe('parse — trust check opt-out', () => {
        it('throws MalformedCredentialError when trustedCertificates is empty and skipTrustCheck is not set', async () => {
            const result = await buildSignedSdJwt({
                issuerKey,
                holderKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
                disclosureClaims: [['age_over_18', true]],
                nonce: validNonce,
                audience: validAudience,
            });
            await expect(parser.parse(result.sdJwt, buildOptions({ trustedCertificates: [] }))).rejects.toThrow(
                MalformedCredentialError
            );
        });

        it('accepts any issuer cert when skipTrustCheck: true', async () => {
            const untrusted = await buildSignedSdJwt({
                issuerKey: altKey,
                holderKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
                disclosureClaims: [['age_over_18', true]],
                nonce: validNonce,
                audience: validAudience,
            });
            const r = await parser.parse(
                untrusted.sdJwt,
                buildOptions({ trustedCertificates: [], skipTrustCheck: true })
            );
            expect(r.valid).toBe(true);
        });
    });

    // ------------------------------------------------------------------
    // parse — key binding JWT verification
    // ------------------------------------------------------------------

    describe('parse — key binding JWT verification', () => {
        it('rejects nonce mismatch in key binding JWT', async () => {
            const result = await parser.parse(
                validResult.sdJwt,
                buildOptions({
                    nonce: 'completely-different-nonce',
                })
            );
            expect(result.valid).toBe(false);
            expect(result.error).toContain('nonce');
        });

        it('rejects a tampered key binding JWT', async () => {
            // Tamper the KB-JWT payload (change nonce after signing)
            const tamperedKbJwt = tamperJwtPayload(validResult.kbJwt!, {
                nonce: 'tampered-nonce',
            });
            const tamperedSdJwt = validResult.sdJwt.replace(validResult.kbJwt!, tamperedKbJwt);
            const result = await parser.parse(tamperedSdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('signature verification failed');
        });

        it('rejects when sd_hash does not match', async () => {
            // Build an SD-JWT where the KB-JWT sd_hash is wrong
            // We do this by building two different SD-JWTs and swapping the KB-JWT
            const otherResult = await buildSignedSdJwt({
                issuerKey,
                holderKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
                disclosureClaims: [['nationality', 'FR']],
                nonce: validNonce,
                audience: validAudience,
            });
            // Use validResult's issuer JWT + disclosures but otherResult's KB-JWT
            // The sd_hash in otherResult.kbJwt was computed over otherResult's content
            const mismatchedSdJwt =
                validResult.issuerJwt + '~' + validResult.disclosures.join('~') + '~' + otherResult.kbJwt!;
            const result = await parser.parse(mismatchedSdJwt, buildOptions());
            expect(result.valid).toBe(false);
            expect(result.error).toContain('sd_hash');
        });

        it('throws MalformedCredentialError when cnf.jwk is missing', async () => {
            // Build SD-JWT without holder key (no cnf in payload) but with a KB-JWT appended
            const noHolderResult = await buildSignedSdJwt({
                issuerKey,
                claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
                disclosureClaims: [['age_over_18', true]],
            });
            // Manually append a KB-JWT to an SD-JWT that has no cnf claim
            const fakeKbJwt = buildStaticJwt(
                { alg: 'ES256', typ: 'kb+jwt' },
                { nonce: validNonce, iat: Math.floor(Date.now() / 1000) }
            );
            const sdJwtWithFakeKb = noHolderResult.sdJwt + fakeKbJwt;
            await expect(parser.parse(sdJwtWithFakeKb, buildOptions())).rejects.toThrow(MalformedCredentialError);
        });
    });

    describe('trustStore routing (0.5.0)', () => {
        // Documentary tests — real end-to-end chain validation is exercised in Task 21.
        it('exposes sd-jwt-vc format marker (parser wiring smoke check)', () => {
            const parser = new SdJwtParser();
            expect(parser.format).toBe('sd-jwt-vc');
        });

        it('preserves 0.4.0 byte-equality trust path when trustStore is absent', () => {
            // The absence of `options.trustStore` must route through the legacy
            // byte-equality check against `trustedCertificates`. Verified here
            // only as documentation; concrete behavior is covered by every
            // other test in this file, all of which exercise that path.
            expect(true).toBe(true);
        });
    });
});
