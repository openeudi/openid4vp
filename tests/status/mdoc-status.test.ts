import { randomInt, randomUUID } from 'node:crypto';

import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import { beforeAll, describe, expect, it } from 'vitest';

import { AV_DOCUMENT_SIGNER_EKU } from '../../src/av/constants.js';
import { createAvAuthorizationRequest } from '../../src/av/request.js';
import { verifyAvPresentation } from '../../src/av/verify.js';
import { buildOpenID4VPDCAPIHandoverSessionTranscript, buildOpenID4VPHandoverSessionTranscript } from '../../src/crypto/session-transcript.js';
import { verifyDcApiResponse } from '../../src/dc-api/response.js';
import { StatusListError } from '../../src/errors.js';
import { buildHaipQuery } from '../../src/haip.js';
import type { ParseOptions } from '../../src/parsers/parser.interface.js';
import { MdocParser } from '../../src/parsers/mdoc.parser.js';
import { StatusListResolver } from '../../src/status/StatusListResolver.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import { verifyAuthorizationResponse, verifyPresentation } from '../../src/verify.js';
import type { TestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { buildSignedMdoc } from '../fixtures/mdoc-helpers.js';
import { createCa, createLeaf, type GeneratedCa } from '../trust/helpers/synthetic-ca.js';

import {
    buildStatusListCwt,
    buildStatusListJwt,
    createHolderKeyMaterial,
    createIssuerKeyMaterial,
    createStatusListSigner,
    createStubFetcher,
    msoStatus,
    randomStatusUri,
    type StatusListSigner,
    type StubFetcher,
} from './helpers.js';

const VALID = 0;
const INVALID = 1;
const SUSPENDED = 2;
const APPLICATION_SPECIFIC = 3;

const PID = 'eu.europa.ec.eudi.pid.1';
const AV = 'eu.europa.ec.av.1';

let issuerKey: TestKeyMaterial;
let listSigner: StatusListSigner;
let otherSigner: StatusListSigner;

beforeAll(async () => {
    issuerKey = await createIssuerKeyMaterial();
    listSigner = await createStatusListSigner();
    otherSigner = await createStatusListSigner();
});

interface Fixture {
    uri: string;
    size: number;
    idxByStatus: Record<'valid' | 'invalid' | 'suspended' | 'appSpecific', number>;
    stub: StubFetcher;
    resolver: StatusListResolver;
}

/** One 2-bit CWT list holding a VALID, INVALID, SUSPENDED and 0x03 entry at random positions. */
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
        [uri]: { body: await buildStatusListCwt({ signer: listSigner, uri, bits: 2, statuses }) },
    });
    const resolver = new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher });
    return { uri, size, idxByStatus: { valid, invalid, suspended, appSpecific }, stub, resolver };
}

async function mdoc(status: unknown, overrides: { sessionTranscript?: Uint8Array } = {}) {
    return buildSignedMdoc({
        issuerKey,
        deviceKey: await createHolderKeyMaterial(),
        docType: PID,
        namespaces: { [PID]: { age_over_18: true } },
        msoStatus: status,
        ...overrides,
    });
}

function options(sessionTranscript: Uint8Array, extra: Partial<ParseOptions>): ParseOptions {
    return {
        trustedCertificates: [issuerKey.certDerBytes],
        nonce: randomUUID(),
        mdocSessionTranscript: sessionTranscript,
        ...extra,
    };
}

const parser = new MdocParser();

describe('mdoc MSO status + Token Status List (statuslist+cwt) — policy matrix', () => {
    let fx: Fixture;
    beforeAll(async () => {
        fx = await createFixture();
    });

    for (const policy of ['prefer', 'require'] as const) {
        describe(`statusPolicy: '${policy}'`, () => {
            it('VALID → accepted, outcome exposed', async () => {
                const idx = fx.idxByStatus.valid;
                const built = await mdoc(msoStatus(idx, fx.uri));
                const result = await parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: policy, statusListResolver: fx.resolver }),
                );
                expect(result.error).toBeUndefined();
                expect(result.valid).toBe(true);
                expect(result.namespacedClaims?.[PID]?.['age_over_18']).toBe(true);
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
                ['INVALID', 'invalid', INVALID, /status is invalid/],
                ['SUSPENDED', 'suspended', SUSPENDED, /status is suspended/],
                ['application-specific 0x03', 'appSpecific', APPLICATION_SPECIFIC, /unrecognised \(0x03\)/],
            ] as const)('%s → rejected', async (_label, key, value, message) => {
                const idx = fx.idxByStatus[key];
                const built = await mdoc(msoStatus(idx, fx.uri));
                const result = await parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: policy, statusListResolver: fx.resolver }),
                );
                expect(result.valid).toBe(false);
                expect(result.error).toMatch(message);
                expect(result.credentialStatus).toMatchObject({ outcome: 'checked', value, idx, uri: fx.uri });
            });

            it('index out of range → rejected', async () => {
                const idx = fx.size + randomInt(0, 1000);
                const built = await mdoc(msoStatus(idx, fx.uri));
                const result = await parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: policy, statusListResolver: fx.resolver }),
                );
                expect(result.valid).toBe(false);
                expect(result.credentialStatus).toMatchObject({ outcome: 'rejected', reason: 'index_out_of_range' });
            });

            it.each([
                ['not a map', () => randomUUID()],
                ['no status_list', () => new Map([[randomUUID(), randomInt(0, 9)]])],
                ['negative idx', () => msoStatus(-randomInt(1, 100), randomStatusUri())],
                ['non-string uri', () => msoStatus(randomInt(0, 100), randomInt(0, 100))],
                ['integer-keyed map', () => new Map([[randomInt(0, 9), msoStatus(0, randomStatusUri())]])],
            ])('malformed MSO status (%s) → rejected', async (_label, make) => {
                const built = await mdoc(make());
                const result = await parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: policy, statusListResolver: fx.resolver }),
                );
                expect(result.valid).toBe(false);
                expect(result.credentialStatus).toMatchObject({ outcome: 'rejected', reason: 'invalid_reference' });
            });

            it('no MSO status → accepted, outcome absent', async () => {
                const built = await mdoc(undefined);
                const calls = fx.stub.calls.length;
                const result = await parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: policy, statusListResolver: fx.resolver }),
                );
                expect(result.valid).toBe(true);
                expect(result.credentialStatus).toMatchObject({ policy, outcome: 'absent' });
                expect(fx.stub.calls.length).toBe(calls);
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
                [uri]: { body: await buildStatusListCwt({ signer: otherSigner, uri, statuses: [INVALID, INVALID, INVALID, INVALID] }) },
            });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };
        const anchorInChain = async () => {
            const uri = randomStatusUri();
            const x5chain = [listSigner.leafDer, new Uint8Array(listSigner.root.certificate.rawData)];
            const stub = createStubFetcher({
                [uri]: { body: await buildStatusListCwt({ signer: listSigner, uri, x5chain, statuses: [VALID, VALID, VALID, VALID] }) },
            });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };
        const expired = async () => {
            const uri = randomStatusUri();
            const now = Math.floor(Date.now() / 1000);
            const stub = createStubFetcher({
                [uri]: { body: await buildStatusListCwt({ signer: listSigner, uri, claims: { exp: now - randomInt(120, 3600) } }) },
            });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };
        const wrongTyp = async () => {
            const uri = randomStatusUri();
            const stub = createStubFetcher({
                [uri]: {
                    body: await buildStatusListCwt({
                        signer: listSigner,
                        uri,
                        protectedHeader: new Map([[16, 'application/cwt']]),
                    }),
                },
            });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };
        const subMismatch = async () => {
            const uri = randomStatusUri();
            const stub = createStubFetcher({
                [uri]: { body: await buildStatusListCwt({ signer: listSigner, uri, claims: { sub: randomStatusUri() } }) },
            });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };
        const jwtOnly = async () => {
            // A JWT list must not satisfy an mdoc reference: the mdoc path asks for, and verifies, a CWT.
            const uri = randomStatusUri();
            const stub = createStubFetcher({ [uri]: { body: await buildStatusListJwt({ signer: listSigner, uri }) } });
            return { uri, resolver: new StatusListResolver({ trustStore: listSigner.trustStore, fetcher: stub.fetcher }) };
        };

        const cases = [
            ['unreachable', unreachable, 'fetch_failed'],
            ['signed by an untrusted key', untrusted, 'untrusted_signer'],
            ['trust anchor inside x5chain', anchorInChain, 'untrusted_signer'],
            ['expired list', expired, 'expired'],
            ['wrong typ', wrongTyp, 'invalid_token'],
            ['sub mismatch', subMismatch, 'subject_mismatch'],
            ['JWT served for a CWT reference', jwtOnly, 'invalid_token'],
        ] as const;

        it.each(cases)("'prefer': %s → accepted with a warning", async (_label, make, reason) => {
            const { uri, resolver } = await make();
            const built = await mdoc(msoStatus(0, uri));
            const result = await parser.parse(
                built.mdocBytes,
                options(built.sessionTranscript, { statusPolicy: 'prefer', statusListResolver: resolver }),
            );
            expect(result.valid).toBe(true);
            expect(result.credentialStatus).toMatchObject({ outcome: 'unavailable', reason, uri, idx: 0 });
            expect(result.credentialStatus?.warning).toMatch(/could not be determined/);
        });

        it.each(cases)("'require': %s → throws StatusListError", async (_label, make, reason) => {
            const { uri, resolver } = await make();
            const built = await mdoc(msoStatus(0, uri));
            await expect(
                parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: 'require', statusListResolver: resolver }),
                ),
            ).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === reason);
        });
    });

    describe("statusPolicy: 'skip' (default)", () => {
        it('does not fetch and does not reject a revoked credential', async () => {
            const built = await mdoc(msoStatus(fx.idxByStatus.invalid, fx.uri));
            const calls = fx.stub.calls.length;
            for (const extra of [{}, { statusPolicy: 'skip' as const, statusListResolver: fx.resolver }]) {
                const result = await parser.parse(built.mdocBytes, options(built.sessionTranscript, extra));
                expect(result.valid).toBe(true);
                expect(result.credentialStatus).toBeUndefined();
            }
            expect(fx.stub.calls.length).toBe(calls);
        });

        it('a malformed MSO status is ignored', async () => {
            const built = await mdoc(randomUUID());
            expect((await parser.parse(built.mdocBytes, options(built.sessionTranscript, {}))).valid).toBe(true);
        });
    });

    describe('ordering and configuration', () => {
        it('does not fetch the list for an mdoc that failed device authentication (§8.3)', async () => {
            const fresh = await createFixture();
            const built = await mdoc(msoStatus(fresh.idxByStatus.valid, fresh.uri));
            const otherTranscript = new Uint8Array(built.sessionTranscript);
            otherTranscript[otherTranscript.length - 1] ^= 0xff;
            const result = await parser.parse(
                built.mdocBytes,
                options(otherTranscript, { statusPolicy: 'require', statusListResolver: fresh.resolver }),
            );
            expect(result.valid).toBe(false);
            expect(result.credentialStatus).toBeUndefined();
            expect(fresh.stub.calls).toHaveLength(0);
        });

        it('does not fetch the list for an untrusted issuer', async () => {
            const fresh = await createFixture();
            const built = await mdoc(msoStatus(fresh.idxByStatus.valid, fresh.uri));
            const result = await parser.parse(
                built.mdocBytes,
                options(built.sessionTranscript, {
                    trustedCertificates: [listSigner.leafDer],
                    statusPolicy: 'require',
                    statusListResolver: fresh.resolver,
                }),
            );
            expect(result.valid).toBe(false);
            expect(fresh.stub.calls).toHaveLength(0);
        });

        it('statusPolicy without a resolver is a configuration error', async () => {
            const built = await mdoc(undefined);
            await expect(
                parser.parse(built.mdocBytes, options(built.sessionTranscript, { statusPolicy: 'prefer' })),
            ).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === 'configuration');
        });

        it('reuses the cached list across presentations', async () => {
            const fresh = await createFixture();
            for (let i = 0; i < 3; i++) {
                const built = await mdoc(msoStatus(fresh.idxByStatus.valid, fresh.uri));
                const result = await parser.parse(
                    built.mdocBytes,
                    options(built.sessionTranscript, { statusPolicy: 'require', statusListResolver: fresh.resolver }),
                );
                expect(result.credentialStatus?.fromCache).toBe(i > 0);
            }
            expect(fresh.stub.calls).toHaveLength(1);
        });
    });
});

describe('mdoc status through every verify entry point', () => {
    const mdocQuery = buildHaipQuery({
        credentialId: 'pid',
        format: 'mso_mdoc',
        doctypeValue: PID,
        claims: ['age_over_18'],
    });

    it('verifyPresentation: valid only when the status is VALID', async () => {
        const fx = await createFixture();
        const ok = await mdoc(msoStatus(fx.idxByStatus.valid, fx.uri));
        const okResult = await verifyPresentation(
            ok.mdocBytes,
            mdocQuery,
            options(ok.sessionTranscript, { statusPolicy: 'require', statusListResolver: fx.resolver }),
        );
        expect(okResult.valid).toBe(true);
        expect(okResult.parsed.credentialStatus?.status).toBe('valid');

        const revoked = await mdoc(msoStatus(fx.idxByStatus.invalid, fx.uri));
        const revokedResult = await verifyPresentation(
            revoked.mdocBytes,
            mdocQuery,
            options(revoked.sessionTranscript, { statusPolicy: 'require', statusListResolver: fx.resolver }),
        );
        expect(revokedResult.valid).toBe(false);
        expect(revokedResult.parsed.credentialStatus?.status).toBe('invalid');
    });

    it('verifyAuthorizationResponse (direct_post): rejects a suspended mdoc', async () => {
        const fx = await createFixture();
        const clientId = `x509_hash:${randomUUID()}`;
        const responseUri = `https://rp-${randomUUID()}.example/cb`;
        const nonce = randomUUID();
        const sessionTranscript = await buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri });
        const optionsFor = { trustedCertificates: [issuerKey.certDerBytes], nonce, clientId, responseUri };

        for (const [key, valid] of [['valid', true], ['suspended', false]] as const) {
            const built = await mdoc(msoStatus(fx.idxByStatus[key], fx.uri), { sessionTranscript });
            const result = await verifyAuthorizationResponse(
                { vp_token: { pid: [Buffer.from(built.mdocBytes).toString('base64url')] } },
                mdocQuery,
                { ...optionsFor, statusPolicy: 'prefer', statusListResolver: fx.resolver },
            );
            expect(result.valid).toBe(valid);
            expect(result.parsed.credentialStatus?.status).toBe(key);
        }
    });

    it('verifyDcApiResponse (dc_api): rejects a revoked mdoc', async () => {
        const fx = await createFixture();
        const origin = `https://shop-${randomUUID()}.example`;
        const nonce = randomUUID();
        const sessionTranscript = await buildOpenID4VPDCAPIHandoverSessionTranscript({ origin, nonce });

        for (const [key, valid] of [['valid', true], ['invalid', false]] as const) {
            const built = await mdoc(msoStatus(fx.idxByStatus[key], fx.uri), { sessionTranscript });
            const result = await verifyDcApiResponse(
                { protocol: 'openid4vp-v1-unsigned', data: { vp_token: { pid: [Buffer.from(built.mdocBytes).toString('base64url')] } } },
                mdocQuery,
                {
                    origin,
                    nonce,
                    responseMode: 'dc_api',
                    trustedCertificates: [issuerKey.certDerBytes],
                    statusPolicy: 'require',
                    statusListResolver: fx.resolver,
                },
            );
            expect(result.valid).toBe(valid);
            expect(result.parsed.credentialStatus?.status).toBe(key);
        }
    });
});

describe('verifyAvPresentation and the MSO status', () => {
    const peculiar = new PeculiarCrypto();
    let avCa: GeneratedCa;
    let avDs: TestKeyMaterial;

    beforeAll(async () => {
        avCa = await createCa({
            name: `CN=AV IACA ${randomUUID()},O=Test,C=EU`,
            pathLenConstraint: 0,
            notBefore: new Date(Date.now() - 365 * 86_400_000),
        });
        const leaf = await createLeaf(avCa, {
            name: `CN=AV DS ${randomUUID()},O=Test,C=EU`,
            extendedKeyUsages: [AV_DOCUMENT_SIGNER_EKU],
        });
        const algo = { name: 'ECDSA', namedCurve: 'P-256' };
        const der = new Uint8Array(leaf.certificate.rawData);
        avDs = {
            privateKey: await crypto.subtle.importKey(
                'jwk',
                await peculiar.subtle.exportKey('jwk', leaf.keys.privateKey),
                algo,
                true,
                ['sign'],
            ),
            publicKey: await crypto.subtle.importKey(
                'jwk',
                await peculiar.subtle.exportKey('jwk', leaf.keys.publicKey),
                algo,
                true,
                ['verify'],
            ),
            x5cBase64: Buffer.from(der).toString('base64'),
            certDerBytes: der,
        };
    });

    async function avPresentation(status: unknown) {
        const request = createAvAuthorizationRequest({
            responseUri: `https://rp-${randomUUID()}.example/av/${randomUUID()}`,
        });
        const sessionTranscript = await buildOpenID4VPHandoverSessionTranscript({
            clientId: request.clientId,
            nonce: request.nonce,
            responseUri: request.responseUri,
        });
        const built = await buildSignedMdoc({
            issuerKey: avDs,
            deviceKey: await createHolderKeyMaterial(),
            docType: AV,
            namespaces: { [AV]: { age_over_18: true } },
            sessionTranscript,
            msoStatus: status,
        });
        const body = { vp_token: { proof_of_age: [Buffer.from(built.mdocBytes).toString('base64url')] } };
        return { request, body };
    }

    it('an attestation without status verifies under every policy', async () => {
        const fx = await createFixture();
        for (const policy of [undefined, 'prefer', 'require'] as const) {
            const { request, body } = await avPresentation(undefined);
            const result = await verifyAvPresentation(body, {
                request,
                trustStore: new StaticTrustStore([avCa.certificate]),
                statusPolicy: policy,
                statusListResolver: fx.resolver,
            });
            expect(result.valid).toBe(true);
            expect(result.ageVerified).toBe(true);
            expect(result.credentialStatus?.outcome).toBe(policy === undefined ? undefined : 'absent');
        }
        expect(fx.stub.calls).toHaveLength(0);
    });

    it('a revoked attestation fails with credential_status under a policy, and passes under skip', async () => {
        const fx = await createFixture();
        const { request, body } = await avPresentation(msoStatus(fx.idxByStatus.invalid, fx.uri));
        const trustStore = new StaticTrustStore([avCa.certificate]);

        const checked = await verifyAvPresentation(body, {
            request,
            trustStore,
            statusPolicy: 'prefer',
            statusListResolver: fx.resolver,
        });
        expect(checked).toMatchObject({ valid: false, ageVerified: false, failure: 'credential_status' });
        expect(checked.credentialStatus).toMatchObject({ outcome: 'checked', status: 'invalid' });

        const skipped = await verifyAvPresentation(body, { request, trustStore });
        expect(skipped.valid).toBe(true);
        expect(skipped.credentialStatus).toBeUndefined();
    });

    it('a VALID attestation exposes the outcome', async () => {
        const fx = await createFixture();
        const { request, body } = await avPresentation(msoStatus(fx.idxByStatus.valid, fx.uri));
        const result = await verifyAvPresentation(body, {
            request,
            trustStore: new StaticTrustStore([avCa.certificate]),
            statusPolicy: 'require',
            statusListResolver: fx.resolver,
        });
        expect(result.valid).toBe(true);
        expect(result.credentialStatus).toMatchObject({ outcome: 'checked', status: 'valid', uri: fx.uri });
    });
});
