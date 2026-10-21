/**
 * @openeudi/dcql 0.3: the DecodedCredential fields openid4vp fills for
 * matchQuery (vct_aliases, holder_bound, typed trusted_authorities), and the
 * stricter validateQuery rules applied to every query openid4vp emits.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
    DcqlValidationError,
    matchQuery,
    validateQuery,
    type DcqlQuery,
    type DecodedCredential,
} from '@openeudi/dcql';

vi.mock('@openeudi/dcql', async (importOriginal) => {
    const actual = await importOriginal<typeof import('@openeudi/dcql')>();
    return { ...actual, matchQuery: vi.fn(actual.matchQuery) };
});

import { createAuthorizationRequest } from '../src/authorization.js';
import { createAvAuthorizationRequest } from '../src/av/request.js';
import { createDcApiRequest } from '../src/dc-api/request.js';
import { HaipValidationError } from '../src/errors.js';
import { buildCredentialSetQuery, buildHaipQuery, validateCredentialSetQuery, validateHaipQuery } from '../src/haip.js';
import { createSignedAuthorizationRequest } from '../src/signed-authorization.js';
import { prepareTrustedAuthorityMatching } from '../src/trusted-authorities.js';
import type { TrustEvaluationResult } from '../src/trust/TrustEvaluator.js';
import { verifyPresentation } from '../src/verify.js';

import {
    createEncryptionKeypair,
    createVerifierKeypairAndCert,
    createVpFormatsSupported,
    generateTestKeyMaterial,
} from './fixtures/crypto-helpers.js';
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';
import { b64u, generateKeys, issue, randomBirthdate, withKbJwt, type TestKeys } from './fixtures/sd-jwt-builder.js';

let keys: TestKeys;

beforeAll(async () => {
    keys = await generateKeys();
});

afterEach(() => {
    vi.mocked(matchQuery).mockClear();
});

const randomVct = (): string => `urn:example:${crypto.randomUUID()}`;
const randomId = (): string => `q_${b64u(crypto.getRandomValues(new Uint8Array(9)))}`;
const randomClientId = (): string => `x509_hash:${b64u(crypto.getRandomValues(new Uint8Array(32)))}`;

function lastDecoded(): DecodedCredential {
    const call = vi.mocked(matchQuery).mock.calls.at(-1);
    if (!call) throw new Error('matchQuery was not called');
    return call[1][0];
}

function sdJwtQuery(vctValues: string[], overrides: Partial<DcqlQuery['credentials'][number]> = {}): DcqlQuery {
    return {
        credentials: [
            { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: vctValues }, claims: [{ path: ['birthdate'] }], ...overrides },
        ],
    };
}

async function boundPresentation(payload: Record<string, unknown>) {
    const nonce = crypto.randomUUID();
    const audience = randomClientId();
    const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, payload });
    return { token: await withKbJwt(keys, presentation, { nonce, aud: audience }), nonce, audience };
}

describe('DecodedCredential.vct_aliases', () => {
    it('carries aka_vcts and the vctAncestors chain transitively, with the real vct', async () => {
        const [vct, aka, middle, root] = [randomVct(), randomVct(), randomVct(), randomVct()];
        const { token, nonce, audience } = await boundPresentation({ vct, aka_vcts: [aka] });
        const result = await verifyPresentation(token, sdJwtQuery([root]), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce,
            audience,
            vctAncestors: { [aka]: [middle], [middle]: [root], [root]: [aka] },
        });
        expect(result.valid).toBe(true);
        const decoded = lastDecoded();
        expect(decoded.vct).toBe(vct);
        expect(decoded.vct_aliases).toEqual([aka, middle, root]);
    });

    it('is omitted when the credential has no other type', async () => {
        const vct = randomVct();
        const { token, nonce, audience } = await boundPresentation({ vct });
        await verifyPresentation(token, sdJwtQuery([vct]), { trustedIssuerJwks: [keys.issuerJwk], nonce, audience });
        expect(lastDecoded().vct).toBe(vct);
        expect(lastDecoded()).not.toHaveProperty('vct_aliases');
    });
});

describe('DecodedCredential.holder_bound', () => {
    it('is true for a verified KB-JWT and for a verified mdoc', async () => {
        const vct = randomVct();
        const { token, nonce, audience } = await boundPresentation({ vct });
        await verifyPresentation(token, sdJwtQuery([vct]), { trustedIssuerJwks: [keys.issuerJwk], nonce, audience });
        expect(lastDecoded().holder_bound).toBe(true);

        const issuerKey = await generateTestKeyMaterial('ES256');
        const doctype = `org.example.${crypto.randomUUID()}`;
        const element = `e_${crypto.randomUUID().slice(0, 8)}`;
        const mdoc = await buildSignedMdoc({ issuerKey, docType: doctype, namespaces: { [doctype]: { [element]: true } } });
        const result = await verifyPresentation(
            mdoc.mdocBytes,
            { credentials: [{ id: 'm', format: 'mso_mdoc', meta: { doctype_value: doctype }, claims: [{ path: [doctype, element] }] }] },
            { trustedCertificates: [issuerKey.certDerBytes], nonce: crypto.randomUUID(), mdocSessionTranscript: mdoc.sessionTranscript },
        );
        expect(result.valid).toBe(true);
        expect(lastDecoded().holder_bound).toBe(true);
    });

    it('is false for a bearer SD-JWT VC, and unset when the parser rejected the presentation', async () => {
        const vct = randomVct();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, payload: { vct }, holderBound: false });
        await verifyPresentation(presentation, sdJwtQuery([vct], { require_cryptographic_holder_binding: false }), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce: crypto.randomUUID(),
        });
        expect(lastDecoded().holder_bound).toBe(false);

        const bound = await boundPresentation({ vct });
        const rejected = await verifyPresentation(bound.token, sdJwtQuery([vct]), {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce: crypto.randomUUID(),
            audience: bound.audience,
        });
        expect(rejected.parsed.valid).toBe(false);
        expect(lastDecoded()).not.toHaveProperty('holder_bound');
    });

    it('a bearer presentation no longer satisfies a second entry that requires binding', async () => {
        const vct = randomVct();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, payload: { vct }, holderBound: false });
        const query: DcqlQuery = {
            credentials: [
                { id: 'optout', format: 'dc+sd-jwt', meta: { vct_values: [vct] }, require_cryptographic_holder_binding: false },
                { id: 'bound', format: 'dc+sd-jwt', meta: { vct_values: [vct] } },
            ],
        };
        const result = await verifyPresentation(presentation, query, {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce: crypto.randomUUID(),
        });
        expect(result.parsed.valid).toBe(true);
        expect(result.valid).toBe(false);
        expect(result.match.unmatched).toEqual([{ queryId: 'bound', reason: 'holder_binding_required' }]);
    });

    it('an optional credential set cannot turn a bearer presentation into a valid result', async () => {
        const vct = randomVct();
        const { presentation } = await issue(keys, { claims: { birthdate: randomBirthdate() }, payload: { vct }, holderBound: false });
        const query: DcqlQuery = { ...sdJwtQuery([vct]), credential_sets: [{ options: [['pid']], required: false }] };
        const result = await verifyPresentation(presentation, query, {
            trustedIssuerJwks: [keys.issuerJwk],
            nonce: crypto.randomUUID(),
        });
        // dcql alone would call this query satisfied; the presentation itself is rejected.
        expect(result.match.satisfied).toBe(true);
        expect(result.parsed.valid).toBe(false);
        expect(result.valid).toBe(false);
    });
});

describe('DecodedCredential.trusted_authorities (typed)', () => {
    const akiValue = b64u(crypto.getRandomValues(new Uint8Array(20)));
    const tlValue = `https://tl-${crypto.randomUUID()}.example/tl.xml`;
    const trust = {
        trustedAuthorities: [
            { type: 'aki', value: akiValue },
            { type: 'etsi_tl', value: tlValue },
        ],
    } as unknown as TrustEvaluationResult;
    const query = (type: string, values: string[]): DcqlQuery =>
        sdJwtQuery([randomVct()], { claims: undefined, trusted_authorities: [{ type, values }] });

    function matches(q: DcqlQuery): boolean {
        const prepared = prepareTrustedAuthorityMatching(q, trust);
        const vct = q.credentials[0].meta?.vct_values?.[0];
        const decoded: DecodedCredential = {
            id: 'pid',
            format: 'dc+sd-jwt',
            vct,
            claims: {},
            trusted_authorities: prepared.trustedAuthorities,
        };
        return matchQuery(prepared.query, [decoded]).satisfied;
    }

    it('groups the trust evaluation authorities by type', () => {
        expect(prepareTrustedAuthorityMatching(query('aki', [akiValue]), trust).trustedAuthorities).toEqual([
            { type: 'aki', values: [`aki:${akiValue}`] },
            { type: 'etsi_tl', values: [`etsi_tl:${tlValue}`] },
        ]);
        expect(prepareTrustedAuthorityMatching(query('aki', [akiValue]), undefined).trustedAuthorities).toBeUndefined();
    });

    it('matches per type through dcql, also for the deprecated hex aki form', () => {
        vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        expect(matches(query('aki', [akiValue]))).toBe(true);
        expect(matches(query('etsi_tl', [tlValue]))).toBe(true);
        expect(matches(query('etsi_tl', [akiValue]))).toBe(false);
        expect(matches(query('aki', [tlValue]))).toBe(false);
        expect(matches(query('aki', [Buffer.from(akiValue, 'base64url').toString('hex')]))).toBe(true);
        vi.restoreAllMocks();
    });
});

describe('every query openid4vp emits passes dcql 0.3 validateQuery', () => {
    const element = (): string => `e_${crypto.randomUUID().slice(0, 8)}`;

    it('buildHaipQuery, buildCredentialSetQuery and createAvAuthorizationRequest', () => {
        const queries: DcqlQuery[] = [
            buildHaipQuery({ credentialId: randomId(), format: 'dc+sd-jwt', vctValues: [randomVct()], claims: [element()] }),
            buildHaipQuery({ credentialId: randomId(), format: 'mso_mdoc', doctypeValue: 'org.iso.18013.5.1.mDL', claims: [element()] }),
            buildHaipQuery({
                credentialId: randomId(),
                format: 'mso_mdoc',
                doctypeValue: `org.example.${crypto.randomUUID()}`,
                claims: [element(), element()],
                trustedAuthorities: [{ type: 'aki', values: [b64u(crypto.getRandomValues(new Uint8Array(20)))] }],
            }),
            buildCredentialSetQuery({
                options: [
                    { credentialId: randomId(), format: 'mso_mdoc', doctypeValue: 'eu.europa.ec.av.1', claims: ['age_over_18'] },
                    { credentialId: randomId(), format: 'dc+sd-jwt', vctValues: ['urn:eudi:pid:1'], claims: ['birthdate'] },
                ],
                required: false,
            }),
            createAvAuthorizationRequest({ responseUri: `https://rp-${crypto.randomUUID()}.example/av` }).dcqlQuery,
        ];
        for (const q of queries) expect(() => validateQuery(q)).not.toThrow();
    });

    it('buildHaipQuery refuses an id outside [A-Za-z0-9_-] and malformed trusted authorities', () => {
        const badId = `${randomId()}.${randomId()}`;
        expect(() => buildHaipQuery({ credentialId: badId, format: 'dc+sd-jwt', vctValues: [randomVct()], claims: [element()] }))
            .toThrow(expect.objectContaining({ code: 'INVALID_CREDENTIAL_ID', credentialId: badId }));
        const id = randomId();
        expect(() =>
            buildHaipQuery({
                credentialId: id,
                format: 'dc+sd-jwt',
                vctValues: [randomVct()],
                claims: [element()],
                trustedAuthorities: [{ type: 'aki', values: [] }],
            }),
        ).toThrow(expect.objectContaining({ code: 'INVALID_DCQL', credentialId: id }));
        expect(() =>
            buildCredentialSetQuery({
                options: [{ credentialId: badId, format: 'dc+sd-jwt', vctValues: [randomVct()], claims: [element()] }],
            }),
        ).toThrow(HaipValidationError);
    });

    it('validateHaipQuery and validateCredentialSetQuery apply the dcql rules after the profile rules', () => {
        const doctype = `org.example.${crypto.randomUUID()}`;
        const id = randomId();
        const threeSegment: DcqlQuery = {
            credentials: [{ id, format: 'mso_mdoc', meta: { doctype_value: doctype }, claims: [{ path: [doctype, element(), element()] }] }],
        };
        expect(() => validateHaipQuery(threeSegment)).toThrow(expect.objectContaining({ code: 'INVALID_DCQL', credentialId: id }));
        expect(() => validateHaipQuery({ ...threeSegment, credentials: [{ ...threeSegment.credentials[0], id: `${id} x` }] }))
            .toThrow(expect.objectContaining({ code: 'INVALID_CREDENTIAL_ID' }));
        const emptyValues: DcqlQuery = {
            credentials: [{ id, format: 'dc+sd-jwt', meta: { vct_values: [randomVct()] }, claims: [{ path: [element()], values: [] }] }],
            credential_sets: [{ options: [[id]] }],
        };
        expect(() => validateCredentialSetQuery(emptyValues)).toThrow(expect.objectContaining({ code: 'INVALID_DCQL' }));
    });

    describe('the request builders refuse a query a wallet must reject', () => {
        const noMeta = (): DcqlQuery => ({ credentials: [{ id: randomId(), format: 'dc+sd-jwt', claims: [{ path: [element()] }] }] });
        const isMissingMeta = (err: unknown) =>
            err instanceof DcqlValidationError && err.code === 'missing_field' && err.path === '/credentials/0/meta';

        it('createAuthorizationRequest', () => {
            let thrown: unknown;
            try {
                createAuthorizationRequest(
                    { clientId: randomClientId(), nonce: crypto.randomUUID(), responseUri: `https://rp-${crypto.randomUUID()}.example/cb` },
                    noMeta(),
                );
            } catch (err) {
                thrown = err;
            }
            expect(isMissingMeta(thrown)).toBe(true);
        });

        it('createSignedAuthorizationRequest', async () => {
            const hostname = `verifier-${crypto.randomUUID()}.example`;
            const { signer, certificateChain } = await createVerifierKeypairAndCert(hostname);
            const { publicJwk } = await createEncryptionKeypair();
            await expect(
                createSignedAuthorizationRequest(
                    {
                        hostname,
                        requestUri: `https://${hostname}/request.jwt`,
                        responseUri: `https://${hostname}/response`,
                        nonce: crypto.randomUUID(),
                        signer,
                        certificateChain,
                        encryptionKey: { publicJwk },
                        vpFormatsSupported: createVpFormatsSupported(),
                    },
                    noMeta(),
                ),
            ).rejects.toSatisfy(isMissingMeta);
        });

        it('createDcApiRequest', async () => {
            await expect(
                createDcApiRequest(
                    {
                        protocol: 'openid4vp-v1-unsigned',
                        nonce: crypto.randomUUID(),
                        responseMode: 'dc_api',
                        vpFormatsSupported: createVpFormatsSupported(),
                    },
                    noMeta(),
                ),
            ).rejects.toSatisfy(isMissingMeta);
        });
    });
});
