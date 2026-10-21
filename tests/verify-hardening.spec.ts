/**
 * Query-level verification rules: the KB-JWT audience defaults to client_id,
 * `require_cryptographic_holder_binding` (OpenID4VP 1.0 §6.1), SD-JWT VC type
 * inheritance (B.3.5, `aka_vcts`, `vctAncestors`), typed
 * `trusted_authorities` matching (§6.1.1) and wallet error responses (§8.5).
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { DcqlQuery } from '@openeudi/dcql';

import { MissingAudienceError, WalletErrorResponseError } from '../src/errors.js';
import { prepareTrustedAuthorityMatching } from '../src/trusted-authorities.js';
import type { TrustEvaluationResult } from '../src/trust/TrustEvaluator.js';
import { verifyAuthorizationResponse, verifyPresentation } from '../src/verify.js';

import { createEncryptionKeypair, encryptAuthorizationResponseJwe } from './fixtures/crypto-helpers.js';
import { b64u, generateKeys, issue, randomBirthdate, withKbJwt, type TestKeys } from './fixtures/sd-jwt-builder.js';

let keys: TestKeys;

beforeAll(async () => {
    keys = await generateKeys();
});

function pidQuery(overrides: Partial<DcqlQuery['credentials'][number]> = {}): DcqlQuery {
    return {
        credentials: [
            {
                id: 'pid',
                format: 'dc+sd-jwt',
                meta: { vct_values: ['urn:eudi:pid:1'] },
                claims: [{ path: ['birthdate'] }],
                ...overrides,
            },
        ],
    };
}

function randomClientId(): string {
    return `x509_hash:${b64u(crypto.getRandomValues(new Uint8Array(32)))}`;
}

describe('verifyAuthorizationResponse — KB-JWT audience defaults to clientId', () => {
    it('accepts a KB-JWT made out to clientId without an explicit audience', async () => {
        const nonce = crypto.randomUUID();
        const clientId = randomClientId();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: clientId });
        const result = await verifyAuthorizationResponse({ vp_token: { pid: [token] } }, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            clientId,
        });
        expect(result.parsed.error).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    it('rejects a KB-JWT made out to another verifier', async () => {
        const nonce = crypto.randomUUID();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: randomClientId() });
        const result = await verifyAuthorizationResponse({ vp_token: { pid: [token] } }, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            clientId: randomClientId(),
        });
        expect(result.valid).toBe(false);
    });

    it('lets an explicit audience win over clientId', async () => {
        const nonce = crypto.randomUUID();
        const audience = randomClientId();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: audience });
        const result = await verifyAuthorizationResponse({ vp_token: { pid: [token] } }, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            audience,
            clientId: randomClientId(),
        });
        expect(result.valid).toBe(true);
    });

    it('throws MissingAudienceError when neither audience nor clientId is set', async () => {
        const nonce = crypto.randomUUID();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const token = await withKbJwt(keys, presentation, { nonce, aud: randomClientId() });
        await expect(
            verifyAuthorizationResponse({ vp_token: { pid: [token] } }, pidQuery(), {
                trustedIssuerJwks: [keys.issuerJwk],
                nonce,
            })
        ).rejects.toBeInstanceOf(MissingAudienceError);
    });
});

describe('require_cryptographic_holder_binding (OpenID4VP 1.0 §6.1)', () => {
    it('rejects a bearer SD-JWT (no cnf, no KB-JWT) by default', async () => {
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, holderBound: false });
        const result = await verifyPresentation(presentation, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce: crypto.randomUUID(),
        });
        expect(result.valid).toBe(false);
        expect(result.parsed.valid).toBe(false);
        expect(result.parsed.error).toMatch(/holder binding is required by credential query "pid"/);
    });

    it('accepts a bearer SD-JWT when the query sets require_cryptographic_holder_binding: false', async () => {
        const birthdate = randomBirthdate();
        const { presentation } = await issue(keys, { claims: { birthdate }, holderBound: false });
        const result = await verifyPresentation(
            presentation,
            pidQuery({ require_cryptographic_holder_binding: false }),
            { trustedIssuerJwks: [keys.issuerJwk], nonce: crypto.randomUUID() }
        );
        expect(result.valid).toBe(true);
        expect(result.parsed.claims.birthdate).toBe(birthdate);
    });

    it('accepts a holder-bound SD-JWT with a valid KB-JWT', async () => {
        const nonce = crypto.randomUUID();
        const audience = randomClientId();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() } });
        const result = await verifyPresentation(await withKbJwt(keys, presentation, { nonce, aud: audience }), pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            audience,
        });
        expect(result.valid).toBe(true);
    });

    it('applies the opt-out of the entry the presentation matched, not of another entry', async () => {
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, holderBound: false });
        const query: DcqlQuery = {
            credentials: [
                {
                    id: 'other',
                    format: 'dc+sd-jwt',
                    meta: { vct_values: [`urn:example:${crypto.randomUUID()}`] },
                    require_cryptographic_holder_binding: false,
                },
                { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] } },
            ],
        };
        const result = await verifyPresentation(presentation, query, {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce: crypto.randomUUID(),
        });
        expect(result.valid).toBe(false);
    });
});

describe('SD-JWT VC type inheritance (B.3.5)', () => {
    async function nationalPid(payload: Record<string, unknown> = {}): Promise<{ token: string; nonce: string; audience: string }> {
        const nonce = crypto.randomUUID();
        const audience = randomClientId();
        const { presentation } = await issue(keys, {
            claims: { birthdate: randomBirthdate() },
            payload: { vct: 'urn:eudi:pid:de:1', ...payload },
        });
        return { token: await withKbJwt(keys, presentation, { nonce, aud: audience }), nonce, audience };
    }

    it('matches urn:eudi:pid:de:1 against vct_values [urn:eudi:pid:1] via vctAncestors', async () => {
        const { token, nonce, audience } = await nationalPid();
        const result = await verifyPresentation(token, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            audience,
            vctAncestors: { 'urn:eudi:pid:de:1': ['urn:eudi:pid:1'] },
        });
        expect(result.valid).toBe(true);
        expect(result.parsed.vct).toBe('urn:eudi:pid:de:1');
    });

    it('walks vctAncestors transitively', async () => {
        const middle = `urn:example:${crypto.randomUUID()}`;
        const { token, nonce, audience } = await nationalPid();
        const result = await verifyPresentation(token, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            audience,
            vctAncestors: { 'urn:eudi:pid:de:1': [middle], [middle]: ['urn:eudi:pid:1'], 'urn:eudi:pid:1': [middle] },
        });
        expect(result.valid).toBe(true);
    });

    it('matches via issuer-signed aka_vcts without configuration', async () => {
        const { token, nonce, audience } = await nationalPid({ aka_vcts: ['urn:eudi:pid:1'] });
        const result = await verifyPresentation(token, pidQuery(), { trustedIssuerJwks: [keys.issuerJwk], nonce, audience });
        expect(result.valid).toBe(true);
        expect(result.parsed.vct).toBe('urn:eudi:pid:de:1');
        expect(result.parsed.akaVcts).toEqual(['urn:eudi:pid:1']);
    });

    it('still reports vct_mismatch for an unrelated vct', async () => {
        const { token, nonce, audience } = await nationalPid();
        const result = await verifyPresentation(token, pidQuery(), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            audience,
            vctAncestors: { [`urn:example:${crypto.randomUUID()}`]: ['urn:eudi:pid:1'] },
        });
        expect(result.valid).toBe(false);
        expect(result.match.unmatched[0]?.reason).toBe('vct_mismatch');
    });
});

describe('typed trusted_authorities matching (§6.1.1)', () => {
    const akiValue = b64u(crypto.getRandomValues(new Uint8Array(20)));
    const trust = {
        trustedAuthorities: [
            { type: 'aki', value: akiValue },
            { type: 'etsi_tl', value: 'https://tl.example/tl.xml' },
        ],
    } as unknown as TrustEvaluationResult;
    const queryWith = (type: string, values: string[]): DcqlQuery =>
        pidQuery({ trusted_authorities: [{ type, values }] });
    const hex = Buffer.from(akiValue, 'base64url').toString('hex');

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('tags credential ids and query values by type', () => {
        const prepared = prepareTrustedAuthorityMatching(queryWith('aki', [akiValue]), trust);
        expect(prepared.ids).toEqual([`aki:${akiValue}`, 'etsi_tl:https://tl.example/tl.xml']);
        expect(prepared.query.credentials[0].trusted_authorities?.[0].values).toEqual([`aki:${akiValue}`]);
    });

    it('does not let an aki id satisfy an etsi_tl entry', () => {
        const prepared = prepareTrustedAuthorityMatching(queryWith('etsi_tl', [akiValue]), trust);
        expect(prepared.ids).not.toContain(prepared.query.credentials[0].trusted_authorities?.[0].values[0]);
    });

    it('still matches the deprecated hex form, warning once', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        const first = prepareTrustedAuthorityMatching(queryWith('aki', [hex.toUpperCase()]), trust);
        prepareTrustedAuthorityMatching(queryWith('aki', [hex]), trust);
        expect(first.query.credentials[0].trusted_authorities?.[0].values).toEqual([`aki:${akiValue}`]);
        expect(warn.mock.calls.filter(([m]) => String(m).includes('deprecated hex')).length).toBe(1);
    });

    it('leaves a query without trusted_authorities untouched', () => {
        const query = pidQuery();
        expect(prepareTrustedAuthorityMatching(query, trust).query).toBe(query);
    });
});

describe('wallet error responses (§8.5)', () => {
    it('throws WalletErrorResponseError for an unencrypted error response', async () => {
        const state = crypto.randomUUID();
        const description = `declined ${crypto.randomUUID()}`;
        const err = await verifyAuthorizationResponse(
            { error: 'access_denied', error_description: description, state } as never,
            pidQuery(),
            { nonce: crypto.randomUUID() }
        ).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(WalletErrorResponseError);
        expect(err).toMatchObject({ code: 'access_denied', description, state });
    });

    it('throws WalletErrorResponseError for an encrypted error response', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const state = crypto.randomUUID();
        const jwe = await encryptAuthorizationResponseJwe({ error: 'wallet_unavailable', state }, publicJwk);
        const err = await verifyAuthorizationResponse({ response: jwe }, pidQuery(), {
            nonce: crypto.randomUUID(),
            decryptionKey: privateKey,
        }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(WalletErrorResponseError);
        expect(err).toMatchObject({ code: 'wallet_unavailable', state });
        expect((err as WalletErrorResponseError).description).toBeUndefined();
    });
});
