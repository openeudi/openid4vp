/**
 * SD-JWT VC verification rules from RFC 9901 and OpenID4VP 1.0 Appendix B.3:
 * KB-JWT audience, typ and claim checks, `_sd_alg`, repeated disclosures and
 * digests, and strict base64url disclosure decoding.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { MissingAudienceError } from '../src/errors.js';
import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import {
    b64u,
    digest,
    encodeDisclosure,
    generateKeys,
    issue,
    randomBirthdate,
    withKbJwt,
    type TestKeys,
} from './fixtures/sd-jwt-builder.js';

const parser = new SdJwtParser();
let keys: TestKeys;

beforeAll(async () => {
    keys = await generateKeys();
});

function context(): { nonce: string; audience: string; options: ParseOptions } {
    const nonce = crypto.randomUUID();
    const audience = `x509_hash:${b64u(crypto.getRandomValues(new Uint8Array(32)))}`;
    return { nonce, audience, options: { trustedIssuerJwks: [keys.issuerJwk], nonce, audience } };
}

describe('KB-JWT audience (OpenID4VP 1.0 B.3.6, RFC 9901 §7.3)', () => {
    it('accepts a KB-JWT whose aud equals the configured audience', async () => {
        const { nonce, audience, options } = context();
        const birthdate = randomBirthdate();
        const { presentation } = await issue(keys, { claims: { birthdate } });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        expect(result.error).toBeUndefined();
        expect(result.valid).toBe(true);
        expect(result.claims.birthdate).toBe(birthdate);
    });

    it('throws MissingAudienceError when a KB-JWT is presented and no audience is configured', async () => {
        const { nonce, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: crypto.randomUUID() });
        await expect(parser.parse(token, { ...options, audience: undefined })).rejects.toBeInstanceOf(
            MissingAudienceError
        );
    });

    it('rejects a KB-JWT without aud', async () => {
        const { nonce, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/aud/);
    });

    it('rejects a KB-JWT made out to another verifier', async () => {
        const { nonce, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: `x509_san_dns:${crypto.randomUUID()}.example` });
        const result = await parser.parse(token, options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Key binding JWT aud does not match the expected audience');
    });

    it('rejects an array aud even when it contains the expected audience', async () => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: [audience, crypto.randomUUID()] });
        const result = await parser.parse(token, options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Key binding JWT aud must be a single string');
    });
});

describe('KB-JWT typ and claims (RFC 9901 §4.3, §7.3 step 5)', () => {
    it.each([
        ['JWT', 'JWT'],
        ['missing', null],
        ['dc+sd-jwt', 'dc+sd-jwt'],
    ])('rejects typ %s', async (_label, typ) => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience, typ }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/KB-JWT typ/);
    });

    it('accepts typ application/kb+jwt (RFC 7515 §4.1.9)', async () => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: audience, typ: 'application/kb+jwt' });
        expect((await parser.parse(token, options)).valid).toBe(true);
    });

    it.each([
        ['one year old', -365 * 86400],
        ['one year in the future', 365 * 86400],
        ['older than 300 s plus the default 60 s tolerance', -(300 + 60 + 30)],
        ['more than the default tolerance in the future', 60 + 30],
    ])('rejects an iat %s', async (_label, offset) => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const iat = Math.floor(Date.now() / 1000) + offset;
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience, iat }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/claim validation failed.*iat/);
    });

    it('accepts an iat inside the window and slightly ahead within the clock tolerance', async () => {
        const { nonce, audience, options } = context();
        for (const offset of [-250, 30]) {
            const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
            const iat = Math.floor(Date.now() / 1000) + offset;
            const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience, iat }), options);
            expect(result.valid).toBe(true);
        }
    });

    it('honours kbJwtMaxAge and clockSkewTolerance', async () => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: audience, iat: Math.floor(Date.now() / 1000) - 120 });
        expect((await parser.parse(token, { ...options, kbJwtMaxAge: 30, clockSkewTolerance: 0 })).valid).toBe(false);
        expect((await parser.parse(token, { ...options, kbJwtMaxAge: 600 })).valid).toBe(true);
    });

    it.each(['iat', 'sd_hash'] as const)('rejects a KB-JWT without %s', async (claim) => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, {
            nonce,
            aud: audience,
            ...(claim === 'iat' ? { iat: null } : { sdHash: null }),
        });
        const result = await parser.parse(token, options);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(new RegExp(claim));
    });

    it('rejects a KB-JWT without nonce', async () => {
        const { audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const result = await parser.parse(await withKbJwt(keys, presentation, { aud: audience }), options);
        expect(result.valid).toBe(false);
    });
});

describe('_sd_alg (RFC 9901 §4.1.1)', () => {
    it.each(['sha-256', 'sha-384', 'sha-512'] as const)('verifies disclosures and sd_hash hashed with %s', async (sdAlg) => {
        const { nonce, audience, options } = context();
        const birthdate = randomBirthdate();
        const { presentation } = await issue(keys, { claims: { birthdate }, sdAlg });
        const token = await withKbJwt(keys, presentation, { nonce, aud: audience, sdAlg });
        const result = await parser.parse(token, options);
        expect(result.error).toBeUndefined();
        expect(result.claims.birthdate).toBe(birthdate);
    });

    it('defaults to sha-256 when _sd_alg is absent', async () => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, sdAlg: null });
        expect((await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options)).valid).toBe(true);
    });

    it('rejects an unsupported _sd_alg instead of hashing with SHA-256', async () => {
        const { nonce, audience, options } = context();
        const disclosures = [encodeDisclosure('birthdate', randomBirthdate())];
        const { presentation } = await issue(keys, {
            disclosures,
            sdDigests: [await digest('sha-256', disclosures[0])],
            sdAlg: 'sha3-256',
        });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Unsupported _sd_alg: sha3-256');
    });

    it('rejects sd_hash computed with another algorithm than _sd_alg', async () => {
        const { nonce, audience, options } = context();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, sdAlg: 'sha-384' });
        const token = await withKbJwt(keys, presentation, { nonce, aud: audience, sdAlg: 'sha-256' });
        const result = await parser.parse(token, options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Key binding JWT sd_hash does not match');
    });
});

describe('repeated disclosures and digests (RFC 9901 §4.2, §7.1)', () => {
    it('rejects a disclosure presented twice', async () => {
        const { nonce, audience, options } = context();
        const disclosure = encodeDisclosure('birthdate', randomBirthdate());
        const issued = await issue(keys, { disclosures: [disclosure] });
        const doubled = `${issued.presentation}${disclosure}~`;
        const result = await parser.parse(await withKbJwt(keys, doubled, { nonce, aud: audience }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Disclosure presented more than once');
    });

    it('rejects a digest listed twice in _sd', async () => {
        const { nonce, audience, options } = context();
        const disclosure = encodeDisclosure('birthdate', randomBirthdate());
        const d = await digest('sha-256', disclosure);
        const { presentation } = await issue(keys, { disclosures: [disclosure], sdDigests: [d, d] });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('A disclosure digest appears more than once in the SD-JWT');
    });

    it('rejects a digest repeated inside a disclosed value', async () => {
        const { nonce, audience, options } = context();
        const inner = encodeDisclosure('country', 'DE');
        const innerDigest = await digest('sha-256', inner);
        // The outer disclosure's value repeats a digest the payload already lists.
        const outer = encodeDisclosure('place_of_birth', { _sd: [innerDigest] });
        const { presentation } = await issue(keys, {
            disclosures: [outer, inner],
            sdDigests: [await digest('sha-256', outer), innerDigest],
        });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('A disclosure digest appears more than once in the SD-JWT');
    });
});

describe('base64url disclosure decoding', () => {
    it('rejects a disclosure written in the standard base64 alphabet', async () => {
        const { nonce, audience, options } = context();
        // Find a disclosure whose base64url form uses '-' or '_' so the
        // standard-alphabet form differs ('+' or '/').
        let urlForm = '';
        do {
            urlForm = encodeDisclosure('family_name', `Ö${crypto.randomUUID()}ß?>~`);
        } while (!/[-_]/.test(urlForm));
        const standardForm = urlForm.replace(/-/g, '+').replace(/_/g, '/');
        const { presentation } = await issue(keys, {
            disclosures: [standardForm],
            sdDigests: [await digest('sha-256', standardForm)],
        });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Disclosure is not valid base64url-encoded JSON');
    });

    it('accepts disclosures that use the URL-safe characters', async () => {
        const { nonce, audience, options } = context();
        let disclosure = '';
        let value = '';
        do {
            value = `Hauptstraße ${crypto.randomUUID()} ?>`;
            disclosure = encodeDisclosure('street_address', value);
        } while (!/[-_]/.test(disclosure));
        const { presentation } = await issue(keys, { disclosures: [disclosure] });
        const result = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        expect(result.valid).toBe(true);
        expect(result.claims.street_address).toBe(value);
    });
});

describe('aka_vcts', () => {
    it('reports issuer-signed aka_vcts and ignores a disclosed one', async () => {
        const { nonce, audience, options } = context();
        const alias = `urn:eudi:pid:${crypto.randomUUID()}`;
        const signed = await issue(keys, { claims: { birthdate: randomBirthdate() }, payload: { aka_vcts: [alias] } });
        const r1 = await parser.parse(await withKbJwt(keys, signed.presentation, { nonce, aud: audience }), options);
        expect(r1.akaVcts).toEqual([alias]);

        const disclosed = await issue(keys, { claims: { aka_vcts: [alias] } });
        const r2 = await parser.parse(await withKbJwt(keys, disclosed.presentation, { nonce, aud: audience }), options);
        expect(r2.valid).toBe(true);
        expect(r2.akaVcts).toBeUndefined();
    });
});
