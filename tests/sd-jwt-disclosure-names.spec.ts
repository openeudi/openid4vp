/**
 * Disclosure claim names a verifier must refuse although every digest is
 * anchored and every signature verifies: RFC 9901 §7.1 step 3.c.ii (a name
 * that is `_sd` or `...`, or that already exists at the level of its `_sd`
 * key) and SD-JWT VC draft-19 §2.2.2.3 (registered claims that MUST NOT be
 * selectively disclosed).
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import {
    b64u,
    digest,
    encodeDisclosure,
    generateKeys,
    issue,
    withKbJwt,
    type IssueOptions,
    type TestKeys,
} from './fixtures/sd-jwt-builder.js';

const parser = new SdJwtParser();
let keys: TestKeys;

beforeAll(async () => {
    keys = await generateKeys();
});

/** Encodes a raw disclosure array (any shape). */
function rawDisclosure(arr: unknown[]): string {
    return b64u(new TextEncoder().encode(JSON.stringify(arr)));
}
const salt = (): string => b64u(crypto.getRandomValues(new Uint8Array(16)));

async function parse(opts: IssueOptions): Promise<{ valid: boolean; error?: string; claims: Record<string, unknown> }> {
    const nonce = crypto.randomUUID();
    const audience = `x509_hash:${b64u(crypto.getRandomValues(new Uint8Array(32)))}`;
    const options: ParseOptions = { trustedIssuerJwks: [keys.issuerJwk], nonce, audience };
    const { presentation } = await issue(keys, opts);
    try {
        const r = await parser.parse(await withKbJwt(keys, presentation, { nonce, aud: audience }), options);
        return { valid: r.valid, error: r.error, claims: r.claims as Record<string, unknown> };
    } catch (err) {
        return { valid: false, error: (err as Error).message, claims: {} };
    }
}

async function expectRefused(opts: IssueOptions, reason: RegExp): Promise<void> {
    const r = await parse(opts);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(reason);
}

describe('control', () => {
    it('accepts ordinary disclosures', async () => {
        const r = await parse({ claims: { given_name: 'Erika', family_name: 'Mustermann' } });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
        expect(r.claims.given_name).toBe('Erika');
    });

    it('accepts sub and iat as Disclosures, which SD-JWT VC allows', async () => {
        const r = await parse({ claims: { sub: 'user-1', iat: 1_700_000_000 }, payload: { iat: undefined } });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
    });

    it('accepts the same claim name disclosed at two different levels', async () => {
        const inner = encodeDisclosure('country', 'DE');
        const outer = encodeDisclosure('address', { _sd: [await digest('sha-256', inner)] });
        const top = encodeDisclosure('country', 'AT');
        const r = await parse({ disclosures: [outer, inner, top], sdDigests: [await digest('sha-256', outer), await digest('sha-256', top)] });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
    });

    it('accepts a registered claim name disclosed below the top level', async () => {
        const inner = encodeDisclosure('exp', '2030-01-01');
        const r = await parse({
            disclosures: [inner],
            sdDigests: [],
            payload: { document: { _sd: [await digest('sha-256', inner)] } },
        });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
    });
});

describe('RFC 9901 §7.1 step 3.c.ii', () => {
    it('refuses a Disclosure that names a claim the payload holds in the clear', async () => {
        await expectRefused(
            { claims: { given_name: 'Erika' }, payload: { given_name: 'Max' } },
            /given_name.*already/
        );
    });

    it('refuses a nested Disclosure that names a claim its object holds in the clear', async () => {
        const inner = encodeDisclosure('locality', 'Berlin');
        await expectRefused(
            {
                disclosures: [inner],
                sdDigests: [],
                payload: { address: { locality: 'Köln', _sd: [await digest('sha-256', inner)] } },
            },
            /locality.*already/
        );
    });

    it('refuses two Disclosures with the same claim name at the same level', async () => {
        await expectRefused(
            { disclosures: [encodeDisclosure('given_name', 'A'), encodeDisclosure('given_name', 'B')] },
            /given_name.*already/
        );
    });

    it.each(['_sd', '...'])('refuses a Disclosure whose claim name is %s', async (name) => {
        await expectRefused({ disclosures: [encodeDisclosure(name, ['x'])] }, /claim name/);
    });

    it('refuses a Disclosure whose claim name is not a string', async () => {
        await expectRefused({ disclosures: [rawDisclosure([salt(), 7, 'x'])] }, /claim name/);
    });
});

describe('SD-JWT VC draft-19 §2.2.2.3: registered claims that MUST NOT be disclosed', () => {
    it.each([
        ['iss', 'https://issuer.example'],
        ['nbf', 1_700_000_000],
        ['exp', 4_102_444_800],
        ['cnf', { jwk: { kty: 'EC' } }],
        ['vct', 'urn:eudi:pid:1'],
        ['vct#integrity', 'sha256-abc'],
        ['status', { status_list: { idx: 0, uri: 'https://status.example' } }],
    ])('refuses a top-level Disclosure of %s', async (name, value) => {
        // Drop the claim from the signed payload so only the Disclosure carries it.
        // cnf stays in the payload: a clash would be refused for the other reason too,
        // and the name check runs first.
        const payload = name === 'cnf' ? {} : { [name]: undefined };
        await expectRefused({ claims: { [name]: value }, payload }, new RegExp(`${name.replace('#', '#')}.*(must not|MUST NOT)`, 'i'));
    });

    it('refuses an expired credential whose exp travels in a Disclosure', async () => {
        await expectRefused({ claims: { exp: 1 }, payload: { exp: undefined } }, /exp/);
    });

    // "including any of their sub-claims"
    it('refuses a Disclosure of a sub-claim of status', async () => {
        const idx = encodeDisclosure('idx', 5);
        await expectRefused(
            {
                disclosures: [idx],
                sdDigests: [],
                payload: {
                    status: { status_list: { uri: 'https://status.example', _sd: [await digest('sha-256', idx)] } },
                },
            },
            /Claim idx inside status MUST NOT be selectively disclosed/
        );
    });

    it('refuses a Disclosure of a sub-claim of cnf', async () => {
        const kid = encodeDisclosure('kid', 'holder-key-1');
        await expectRefused(
            {
                disclosures: [kid],
                sdDigests: [],
                payload: { cnf: { jwk: keys.holderJwk, _sd: [await digest('sha-256', kid)] } },
            },
            /Claim kid inside cnf MUST NOT be selectively disclosed/
        );
    });

    it('refuses an array-element Disclosure inside status', async () => {
        const element = rawDisclosure([salt(), 'https://status.example/2']);
        await expectRefused(
            {
                disclosures: [element],
                sdDigests: [],
                payload: {
                    status: {
                        status_list: { idx: 0, uri: 'https://status.example' },
                        extra: [{ '...': await digest('sha-256', element) }],
                    },
                },
            },
            /array element inside status MUST NOT be selectively disclosed/
        );
    });

    it('accepts an undisclosed digest inside status, which may be a decoy', async () => {
        const r = await parse({
            claims: { given_name: 'Erika' },
            payload: {
                status: {
                    status_list: { idx: 0, uri: 'https://status.example', _sd: [await digest('sha-256', encodeDisclosure('x', 1))] },
                },
            },
        });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
    });
});
