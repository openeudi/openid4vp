import { randomInt, randomUUID } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import type { DcqlQuery } from '@openeudi/dcql';

import { StatusListError } from '../../src/errors.js';
import type { ParseOptions } from '../../src/parsers/parser.interface.js';
import { SdJwtParser } from '../../src/parsers/sd-jwt.parser.js';
import { StatusListResolver } from '../../src/status/StatusListResolver.js';
import { verifyPresentation } from '../../src/verify.js';
import { buildSignedSdJwt, type TestKeyMaterial } from '../fixtures/crypto-helpers.js';

import {
    buildStatusListJwt,
    createHolderKeyMaterial,
    createIssuerKeyMaterial,
    createStatusListSigner,
    createStubFetcher,
    randomStatusUri,
    type StatusListSigner,
    type StubFetcher,
} from './helpers.js';

const VALID = 0;
const INVALID = 1;
const SUSPENDED = 2;
const APPLICATION_SPECIFIC = 3;

// Since 0.14.0 a KB-JWT must carry the verifier's client identifier as `aud`.
const AUDIENCE = `x509_hash:${randomUUID()}`;

let issuerKey: TestKeyMaterial;
let holderKey: TestKeyMaterial;
let listSigner: StatusListSigner;
let otherSigner: StatusListSigner;

beforeAll(async () => {
    issuerKey = await createIssuerKeyMaterial();
    holderKey = await createHolderKeyMaterial();
    listSigner = await createStatusListSigner();
    otherSigner = await createStatusListSigner();
});

interface Fixture {
    uri: string;
    idxByStatus: Record<'valid' | 'invalid' | 'suspended' | 'appSpecific', number>;
    stub: StubFetcher;
    resolver: StatusListResolver;
}

/** One 2-bit list holding a VALID, INVALID, SUSPENDED and 0x03 entry at random positions. */
async function createFixture(): Promise<Fixture> {
    const uri = randomStatusUri();
    const size = 4 * randomInt(4, 64);
    const statuses = new Array<number>(size).fill(VALID);
    const positions = new Set<number>();
    while (positions.size < 4) positions.add(randomInt(0, size));
    const [valid, invalid, suspended, appSpecific] = [...positions];
    statuses[invalid] = INVALID;
    statuses[suspended] = SUSPENDED;
    statuses[appSpecific] = APPLICATION_SPECIFIC;
    const stub = createStubFetcher({
        [uri]: { body: await buildStatusListJwt({ signer: listSigner, uri, bits: 2, statuses }) },
    });
    const resolver = new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher });
    return { uri, idxByStatus: { valid, invalid, suspended, appSpecific }, stub, resolver };
}

async function credential(status: unknown): Promise<{ sdJwt: string; nonce: string }> {
    const nonce = randomUUID();
    const { sdJwt } = await buildSignedSdJwt({
        issuerKey,
        holderKey,
        nonce,
        audience: AUDIENCE,
        claims: status === undefined ? {} : { status },
        disclosureClaims: [['age_over_18', true]],
    });
    return { sdJwt, nonce };
}

function options(nonce: string, extra: Partial<ParseOptions>): ParseOptions {
    return { trustedCertificates: [issuerKey.certDerBytes], nonce, audience: AUDIENCE, ...extra };
}

const parser = new SdJwtParser();

describe('SD-JWT VC + Token Status List — policy matrix', () => {
    let fx: Fixture;
    beforeAll(async () => {
        fx = await createFixture();
    });

    for (const policy of ['prefer', 'require'] as const) {
        describe(`statusPolicy: '${policy}'`, () => {
            it('VALID → accepted, outcome exposed', async () => {
                const idx = fx.idxByStatus.valid;
                const { sdJwt, nonce } = await credential({ status_list: { idx, uri: fx.uri } });
                const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: policy, statusListResolver: fx.resolver }));
                expect(result.valid).toBe(true);
                expect(result.credentialStatus).toMatchObject({
                    policy,
                    outcome: 'checked',
                    status: 'valid',
                    value: VALID,
                    uri: fx.uri,
                    idx,
                });
            });

            it.each([
                ['invalid', 'invalid', INVALID],
                ['suspended', 'suspended', SUSPENDED],
                ['appSpecific', 'unknown', APPLICATION_SPECIFIC],
            ] as const)('%s → rejected', async (key, status, value) => {
                const idx = fx.idxByStatus[key];
                const { sdJwt, nonce } = await credential({ status_list: { idx, uri: fx.uri } });
                const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: policy, statusListResolver: fx.resolver }));
                expect(result.valid).toBe(false);
                expect(result.error).toMatch(/^Credential status is /);
                expect(result.credentialStatus).toMatchObject({ outcome: 'checked', status, value });
            });

            it('index out of range → rejected', async () => {
                const list = await fx.resolver.getStatusList(fx.uri);
                const { sdJwt, nonce } = await credential({ status_list: { idx: list.size + randomInt(0, 50), uri: fx.uri } });
                const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: policy, statusListResolver: fx.resolver }));
                expect(result.valid).toBe(false);
                expect(result.credentialStatus).toMatchObject({ outcome: 'rejected', reason: 'index_out_of_range' });
            });

            it.each([
                ['not an object', 'revoked'],
                ['no status_list (HAIP 1.0 §6.1)', { other_mechanism: { foo: 1 } }],
                ['status_list without uri', { status_list: { idx: 0 } }],
                ['negative idx', { status_list: { idx: -1, uri: 'https://status.example.eu/x' } }],
            ])('malformed status claim (%s) → rejected', async (_label, status) => {
                const { sdJwt, nonce } = await credential(status);
                const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: policy, statusListResolver: fx.resolver }));
                expect(result.valid).toBe(false);
                expect(result.credentialStatus).toMatchObject({ outcome: 'rejected', reason: 'invalid_reference' });
            });

            it('no status claim → accepted, outcome absent', async () => {
                const { sdJwt, nonce } = await credential(undefined);
                const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: policy, statusListResolver: fx.resolver }));
                expect(result.valid).toBe(true);
                expect(result.credentialStatus).toMatchObject({ outcome: 'absent' });
            });
        });
    }

    describe('list unreachable / unverifiable', () => {
        const unreachable = async () => {
            const uri = randomStatusUri();
            const stub = createStubFetcher({ [uri]: { status: 503, body: 'maintenance' } });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };
        const untrusted = async () => {
            const uri = randomStatusUri();
            const stub = createStubFetcher({
                [uri]: { body: await buildStatusListJwt({ signer: otherSigner, uri, statuses: [INVALID, INVALID, INVALID, INVALID] }) },
            });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };

        it.each([
            ['unreachable', unreachable, 'fetch_failed'],
            ['signed by an untrusted key', untrusted, 'untrusted_signer'],
        ] as const)("'prefer': %s → accepted with a warning", async (_label, make, reason) => {
            const { uri, resolver } = await make();
            const { sdJwt, nonce } = await credential({ status_list: { idx: 0, uri } });
            const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: 'prefer', statusListResolver: resolver }));
            expect(result.valid).toBe(true);
            expect(result.credentialStatus).toMatchObject({ outcome: 'unavailable', reason, uri, idx: 0 });
            expect(result.credentialStatus?.warning).toMatch(/could not be determined/);
        });

        it.each([
            ['unreachable', unreachable, 'fetch_failed'],
            ['signed by an untrusted key', untrusted, 'untrusted_signer'],
        ] as const)("'require': %s → throws StatusListError", async (_label, make, reason) => {
            const { uri, resolver } = await make();
            const { sdJwt, nonce } = await credential({ status_list: { idx: 0, uri } });
            await expect(
                parser.parse(sdJwt, options(nonce, { statusPolicy: 'require', statusListResolver: resolver })),
            ).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === reason);
        });
    });

    describe("statusPolicy: 'skip' (default)", () => {
        it('does not fetch and does not reject a revoked credential', async () => {
            const { sdJwt, nonce } = await credential({ status_list: { idx: fx.idxByStatus.invalid, uri: fx.uri } });
            const calls = fx.stub.calls.length;
            for (const extra of [{}, { statusPolicy: 'skip' as const, statusListResolver: fx.resolver }]) {
                const result = await parser.parse(sdJwt, options(nonce, extra));
                expect(result.valid).toBe(true);
                expect(result.credentialStatus).toBeUndefined();
            }
            expect(fx.stub.calls.length).toBe(calls);
        });

        it('a malformed status claim is ignored', async () => {
            const { sdJwt, nonce } = await credential('revoked');
            expect((await parser.parse(sdJwt, options(nonce, {}))).valid).toBe(true);
        });
    });

    describe('ordering and configuration', () => {
        it('does not fetch the list for a credential that already failed validation (§8.3)', async () => {
            const fresh = await createFixture();
            const { sdJwt } = await credential({ status_list: { idx: fresh.idxByStatus.valid, uri: fresh.uri } });
            const result = await parser.parse(
                sdJwt,
                options(randomUUID(), { statusPolicy: 'require', statusListResolver: fresh.resolver }),
            );
            expect(result.valid).toBe(false);
            expect(result.error).toMatch(/nonce/);
            expect(fresh.stub.calls).toHaveLength(0);
        });

        it('statusPolicy without a resolver is a configuration error', async () => {
            const { sdJwt, nonce } = await credential(undefined);
            await expect(parser.parse(sdJwt, options(nonce, { statusPolicy: 'prefer' }))).rejects.toSatisfy(
                (err: unknown) => err instanceof StatusListError && err.reason === 'configuration',
            );
        });

        it('an unknown statusPolicy is a configuration error', async () => {
            const { sdJwt, nonce } = await credential(undefined);
            await expect(
                parser.parse(sdJwt, options(nonce, { statusPolicy: 'always' as never, statusListResolver: fx.resolver })),
            ).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === 'configuration');
        });

        it('reuses the cached list across presentations', async () => {
            const fresh = await createFixture();
            for (let i = 0; i < 3; i++) {
                const { sdJwt, nonce } = await credential({ status_list: { idx: fresh.idxByStatus.valid, uri: fresh.uri } });
                const result = await parser.parse(sdJwt, options(nonce, { statusPolicy: 'require', statusListResolver: fresh.resolver }));
                expect(result.credentialStatus?.fromCache).toBe(i > 0);
            }
            expect(fresh.stub.calls).toHaveLength(1);
        });
    });
});

describe('verifyPresentation surfaces the status outcome', () => {
    const query: DcqlQuery = {
        credentials: [
            {
                id: 'pid',
                format: 'dc+sd-jwt',
                meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] },
                claims: [{ path: ['age_over_18'], values: [true] }],
            },
        ],
    };

    it('valid only when the status is VALID', async () => {
        const fx = await createFixture();
        const ok = await credential({ status_list: { idx: fx.idxByStatus.valid, uri: fx.uri } });
        const okResult = await verifyPresentation(
            ok.sdJwt,
            query,
            options(ok.nonce, { statusPolicy: 'require', statusListResolver: fx.resolver }),
        );
        expect(okResult.valid).toBe(true);
        expect(okResult.parsed.credentialStatus?.status).toBe('valid');

        const revoked = await credential({ status_list: { idx: fx.idxByStatus.invalid, uri: fx.uri } });
        const revokedResult = await verifyPresentation(
            revoked.sdJwt,
            query,
            options(revoked.nonce, { statusPolicy: 'require', statusListResolver: fx.resolver }),
        );
        expect(revokedResult.valid).toBe(false);
        expect(revokedResult.parsed.credentialStatus?.status).toBe('invalid');
    });
});
