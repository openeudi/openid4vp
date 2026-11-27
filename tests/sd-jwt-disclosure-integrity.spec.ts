/**
 * Every Disclosure in a presentation must hash, with the issuer's `_sd_alg`,
 * to a digest in the issuer-signed payload or in another anchored Disclosure
 * (RFC 9901 §7.1). A Disclosure that does not is refused, never dropped: it
 * shows that the presentation was altered after issuance.
 *
 * Each presentation here carries a valid KB-JWT over the altered token, so the
 * holder signature cannot be what refuses it.
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
    type SdAlg,
    type TestKeys,
} from './fixtures/sd-jwt-builder.js';

const parser = new SdJwtParser();
let keys: TestKeys;

beforeAll(async () => {
    keys = await generateKeys();
});

const salt = (): string => b64u(crypto.getRandomValues(new Uint8Array(16)));
const randomWord = (): string => b64u(crypto.getRandomValues(new Uint8Array(9)));
const rawDisclosure = (arr: unknown[]): string => b64u(new TextEncoder().encode(JSON.stringify(arr)));
const arrayDisclosure = (value: unknown): string => rawDisclosure([salt(), value]);

type Outcome = { valid: boolean; error?: string; claims: Record<string, unknown> };

/**
 * Issues a credential, lets `alter` change the list of presented Disclosures,
 * and presents the result with a fresh, valid KB-JWT.
 */
async function present(opts: IssueOptions, alter?: (disclosures: string[]) => string[]): Promise<Outcome> {
    const nonce = crypto.randomUUID();
    const audience = `x509_hash:${b64u(crypto.getRandomValues(new Uint8Array(32)))}`;
    const options: ParseOptions = { trustedIssuerJwks: [keys.issuerJwk], nonce, audience };
    const { jwt, disclosures } = await issue(keys, opts);
    const presented = alter ? alter([...disclosures]) : disclosures;
    const sdJwt = `${jwt}~${presented.map((d) => `${d}~`).join('')}`;
    const r = await parser.parse(await withKbJwt(keys, sdJwt, { nonce, aud: audience, sdAlg: opts.sdAlg ?? 'sha-256' }), options);
    return { valid: r.valid, error: r.error, claims: r.claims as Record<string, unknown> };
}

/** Changes one character of the disclosed value and re-encodes the Disclosure. */
function tamperOneByte(disclosure: string): string {
    const arr = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf8')) as unknown[];
    const value = arr[arr.length - 1] as string;
    const last = value.charCodeAt(value.length - 1);
    arr[arr.length - 1] = value.slice(0, -1) + String.fromCharCode(last === 0x41 ? 0x42 : 0x41);
    return rawDisclosure(arr);
}

describe('valid presentations', () => {
    it('accepts flat Disclosures and returns exactly the disclosed claims', async () => {
        const givenName = randomWord();
        const familyName = randomWord();
        const r = await present({ claims: { given_name: givenName, family_name: familyName } });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
        expect(r.claims.given_name).toBe(givenName);
        expect(r.claims.family_name).toBe(familyName);
        expect(r.claims).not.toHaveProperty('_sd');
        expect(r.claims).not.toHaveProperty('_sd_alg');
    });

    it('accepts a withheld Disclosure and leaves its claim out', async () => {
        const shown = encodeDisclosure('given_name', randomWord());
        const withheld = encodeDisclosure('family_name', randomWord());
        const r = await present({ disclosures: [shown, withheld] }, (d) => d.filter((x) => x !== withheld));
        expect(r.valid).toBe(true);
        expect(r.claims).toHaveProperty('given_name');
        expect(r.claims).not.toHaveProperty('family_name');
    });

    it('accepts a Disclosure nested in another Disclosure (recursive selective disclosure)', async () => {
        const country = randomWord();
        const locality = randomWord();
        const inner = encodeDisclosure('country', country);
        const outer = encodeDisclosure('address', { locality, _sd: [await digest('sha-256', inner)] });
        const r = await present({ disclosures: [outer, inner], sdDigests: [await digest('sha-256', outer)] });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
        expect(r.claims.address).toEqual({ locality, country });
    });

    it('accepts a nested Disclosure presented before the one that references it', async () => {
        const country = randomWord();
        const inner = encodeDisclosure('country', country);
        const outer = encodeDisclosure('address', { _sd: [await digest('sha-256', inner)] });
        const r = await present({ disclosures: [inner, outer], sdDigests: [await digest('sha-256', outer)] });
        expect(r.valid).toBe(true);
        expect(r.claims.address).toEqual({ country });
    });

    it('accepts array-element Disclosures and drops withheld elements and decoys', async () => {
        const first = randomWord();
        const clear = randomWord();
        const shown = arrayDisclosure(first);
        const withheld = arrayDisclosure(randomWord());
        const decoy = await digest('sha-256', salt());
        const r = await present(
            {
                disclosures: [shown, withheld],
                sdDigests: [],
                payload: {
                    nationalities: [
                        { '...': await digest('sha-256', shown) },
                        clear,
                        { '...': await digest('sha-256', withheld) },
                        { '...': decoy },
                    ],
                },
            },
            (d) => d.filter((x) => x !== withheld)
        );
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
        expect(r.claims.nationalities).toEqual([first, clear]);
    });

    it('accepts an object Disclosure inside an array-element Disclosure', async () => {
        const country = randomWord();
        const inner = encodeDisclosure('country', country);
        const element = arrayDisclosure({ _sd: [await digest('sha-256', inner)] });
        const outer = encodeDisclosure('places', [{ '...': await digest('sha-256', element) }]);
        const r = await present({ disclosures: [outer, element, inner], sdDigests: [await digest('sha-256', outer)] });
        expect(r.error).toBeUndefined();
        expect(r.valid).toBe(true);
        expect(r.claims.places).toEqual([{ country }]);
    });

    it.each(['sha-384', 'sha-512'] as const)('accepts Disclosures hashed with _sd_alg %s', async (sdAlg) => {
        const value = randomWord();
        const r = await present({ claims: { given_name: value }, sdAlg });
        expect(r.valid).toBe(true);
        expect(r.claims.given_name).toBe(value);
    });

    it('does not let a Disclosure named __proto__ pose as other claims', async () => {
        const disclosure = rawDisclosure([salt(), '__proto__', { age_over_18: true }]);
        const r = await present({ disclosures: [disclosure] });
        expect(r.valid).toBe(true);
        expect(Object.getPrototypeOf(r.claims)).toBe(Object.prototype);
        expect(r.claims.age_over_18).toBeUndefined();
    });
});

describe('altered presentations are refused', () => {
    it('refuses a Disclosure with one byte of its value changed', async () => {
        const r = await present({ claims: { given_name: randomWord(), family_name: randomWord() } }, (d) => {
            d[0] = tamperOneByte(d[0]!);
            return d;
        });
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
        expect(r.claims).toEqual({});
    });

    it('refuses an extra Disclosure that no digest references', async () => {
        const r = await present({ claims: { given_name: randomWord() } }, (d) => [
            ...d,
            encodeDisclosure('age_over_18', true),
        ]);
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses an extra Disclosure when the payload has no digests at all', async () => {
        const r = await present({ disclosures: [], sdDigests: [] }, () => [encodeDisclosure('age_over_18', true)]);
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses the same Disclosure presented twice', async () => {
        const r = await present({ claims: { given_name: randomWord() } }, (d) => [d[0]!, d[0]!]);
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure presented more than once');
    });

    it('refuses a nested Disclosure whose parent Disclosure was withheld', async () => {
        const inner = encodeDisclosure('country', randomWord());
        const outer = encodeDisclosure('address', { _sd: [await digest('sha-256', inner)] });
        const r = await present({ disclosures: [outer, inner], sdDigests: [await digest('sha-256', outer)] }, (d) =>
            d.filter((x) => x !== outer)
        );
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses a nested Disclosure with one byte changed', async () => {
        const inner = encodeDisclosure('country', randomWord());
        const outer = encodeDisclosure('address', { _sd: [await digest('sha-256', inner)] });
        const r = await present({ disclosures: [outer, inner], sdDigests: [await digest('sha-256', outer)] }, (d) => [
            d[0]!,
            tamperOneByte(d[1]!),
        ]);
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses an array-element Disclosure with one byte changed', async () => {
        const shown = arrayDisclosure(randomWord());
        const r = await present(
            { disclosures: [shown], sdDigests: [], payload: { nationalities: [{ '...': await digest('sha-256', shown) }] } },
            (d) => [tamperOneByte(d[0]!)]
        );
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses an array-element Disclosure whose digest sits in _sd', async () => {
        const element = arrayDisclosure(randomWord());
        const r = await present({ disclosures: [element] });
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses an object-property Disclosure whose digest sits in an array element', async () => {
        const property = encodeDisclosure('nationality', randomWord());
        const r = await present({
            disclosures: [property],
            sdDigests: [],
            payload: { nationalities: [{ '...': await digest('sha-256', property) }] },
        });
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });

    it('refuses a Disclosure hashed with another algorithm than the issuer _sd_alg', async () => {
        const disclosure = encodeDisclosure('given_name', randomWord());
        const sdAlg: SdAlg = 'sha-384';
        const r = await present({ disclosures: [disclosure], sdDigests: [await digest('sha-256', disclosure)], sdAlg });
        expect(r.valid).toBe(false);
        expect(r.error).toBe('Disclosure hash mismatch');
    });
});
