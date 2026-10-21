import { describe, it, expect } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, decodeJwt, generateKeyPair } from 'jose';
import type { DcqlQuery } from '@openeudi/dcql';

import { registrarDatasetVerifierInfo, registrationCertVerifierInfo } from '../src/verifier-info.js';
import { createSignedAuthorizationRequest } from '../src/signed-authorization.js';
import { createAuthorizationRequest } from '../src/authorization.js';
import { buildHaipQuery } from '../src/haip.js';
import { SignedRequestBuildError } from '../src/errors.js';
import type { RegistrarDataset, VerifierInfo } from '../src/types/verifier-info.js';
import {
    createVerifierKeypairAndCert,
    createEncryptionKeypair,
    createVpFormatsSupported,
} from './fixtures/crypto-helpers.js';

const randomToken = (bytes = 12) => randomBytes(bytes).toString('base64url');
const randomLang = () => ['en', 'de', 'fr', 'nl', 'lb'][randomBytes(1)[0] % 5];

function randomDataset(overrides: Partial<RegistrarDataset> = {}): RegistrarDataset {
    return {
        identifier: [{ type: 'http://data.europa.eu/eudi/id/LEI', identifier: `LEIXG-${randomToken(10)}` }],
        srvDescription: [{ lang: randomLang(), content: `Service ${randomToken()}` }],
        registryURI: `https://registrar-${randomToken(4).toLowerCase()}.example/api`,
        intendedUseIdentifier: randomUUID(),
        purpose: [{ lang: randomLang(), content: `Purpose ${randomToken()}` }],
        policyURI: `https://shop-${randomToken(4).toLowerCase()}.example/privacy`,
        ...overrides,
    };
}

async function randomWrprc(typ = 'rc-wrp+jwt'): Promise<string> {
    const { privateKey } = await generateKeyPair('ES256');
    return new SignJWT({ sub: `VATLU-${randomToken(6)}`, name: randomToken() })
        .setProtectedHeader({ alg: 'ES256', typ })
        .setIssuedAt()
        .sign(privateKey);
}

function base64UrlToText(value: string): string {
    return Buffer.from(value, 'base64url').toString('utf8');
}

const credentialId = `pid_${randomToken(4)}`;
const query: DcqlQuery = buildHaipQuery({
    credentialId,
    format: 'dc+sd-jwt',
    vctValues: ['urn:eudi:pid:1'],
    claims: ['birthdate'],
});

describe('registrarDatasetVerifierInfo', () => {
    it('builds a registrar_dataset element with the ETSI member names', () => {
        const dataset = randomDataset();
        const info = registrarDatasetVerifierInfo(dataset);

        expect(info.format).toBe('registrar_dataset');
        expect(info.credential_ids).toBeUndefined();
        expect(info.data).toEqual({
            identifier: dataset.identifier,
            srvDescription: dataset.srvDescription,
            registryURI: dataset.registryURI,
            intendedUseIdentifier: dataset.intendedUseIdentifier,
            purpose: dataset.purpose,
            policyURI: dataset.policyURI,
        });
    });

    it('includes the registered credential set when given', () => {
        const credential = [
            { format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claim: [{ path: ['birthdate'] }] },
        ];
        const info = registrarDatasetVerifierInfo(randomDataset({ credential }));
        expect((info.data as Record<string, unknown>).credential).toEqual(credential);
    });

    it('drops members the ETSI data model does not define', () => {
        const dataset = {
            ...randomDataset(),
            [randomToken(4)]: randomToken(),
        } as RegistrarDataset;
        const info = registrarDatasetVerifierInfo(dataset);
        expect(Object.keys(info.data).sort()).toEqual(
            ['identifier', 'intendedUseIdentifier', 'policyURI', 'purpose', 'registryURI', 'srvDescription'],
        );
    });

    it.each([
        ['identifier', { identifier: [] }],
        ['identifier[0].identifier', { identifier: [{ type: 'http://data.europa.eu/eudi/id/LEI', identifier: '' }] }],
        ['srvDescription', { srvDescription: [] }],
        ['srvDescription[0].lang', { srvDescription: [{ lang: '', content: 'x' }] }],
        ['registryURI', { registryURI: 'not a uri' }],
        ['intendedUseIdentifier', { intendedUseIdentifier: '' }],
        ['purpose[0].content', { purpose: [{ lang: 'en', content: '' }] }],
        ['policyURI', { policyURI: '' }],
        ['credential', { credential: [] }],
        ['credential[0].format', { credential: [{ format: '', meta: {} }] }],
        ['credential[0].claim[0].path', { credential: [{ format: 'dc+sd-jwt', meta: {}, claim: [{ path: [] }] }] }],
    ])('rejects an invalid %s', (member, overrides) => {
        expect(() => registrarDatasetVerifierInfo(randomDataset(overrides as Partial<RegistrarDataset>))).toThrow(
            new RegExp(member.replace(/[[\].]/g, '\\$&')),
        );
    });
});

describe('registrationCertVerifierInfo', () => {
    it('base64url-encodes the compact JWS of a JWT WRPRC (RO-16)', async () => {
        const wrprc = await randomWrprc();
        const info = registrationCertVerifierInfo(wrprc);

        expect(info.format).toBe('registration_cert');
        expect(info.credential_ids).toBeUndefined();
        expect(typeof info.data).toBe('string');
        expect(info.data as string).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(base64UrlToText(info.data as string)).toBe(wrprc);
    });

    it('base64url-encodes the bytes of a CWT WRPRC', () => {
        const cwt = new Uint8Array(randomBytes(64));
        const info = registrationCertVerifierInfo(cwt);
        expect(new Uint8Array(Buffer.from(info.data as string, 'base64url'))).toEqual(cwt);
    });

    it('rejects a JWT whose typ is not rc-wrp+jwt', async () => {
        const wrong = await randomWrprc('JWT');
        expect(() => registrationCertVerifierInfo(wrong)).toThrow(/rc-wrp\+jwt/);
    });

    it('rejects a string that is not a compact JWS', () => {
        expect(() => registrationCertVerifierInfo(randomToken())).toThrow(/compact JWS/);
        expect(() => registrationCertVerifierInfo(`${randomToken()}.${randomToken()}.a+b`)).toThrow(/compact JWS/);
    });

    it('rejects empty CWT bytes', () => {
        expect(() => registrationCertVerifierInfo(new Uint8Array())).toThrow(/must not be empty/);
    });
});

describe('createSignedAuthorizationRequest with verifierInfo', () => {
    const hostname = 'verifier.example.com';

    async function baseInput(verifierInfo?: unknown) {
        const { signer, certificateChain } = await createVerifierKeypairAndCert(hostname);
        const { publicJwk } = await createEncryptionKeypair();
        return {
            hostname,
            requestUri: `https://${hostname}/${randomToken()}/request.jwt`,
            responseUri: `https://${hostname}/${randomToken()}/response`,
            nonce: randomToken(),
            signer,
            certificateChain,
            encryptionKey: { publicJwk },
            vpFormatsSupported: createVpFormatsSupported(),
            ...(verifierInfo !== undefined ? { verifierInfo: verifierInfo as VerifierInfo[] } : {}),
        };
    }

    async function buildError(verifierInfo: unknown): Promise<SignedRequestBuildError> {
        const err = await createSignedAuthorizationRequest(await baseInput(verifierInfo), query).catch((e) => e);
        expect(err).toBeInstanceOf(SignedRequestBuildError);
        expect(err.code).toBe('invalid_verifier_info');
        return err;
    }

    it('omits verifier_info when none is given', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), query);
        expect(decodeJwt(req.requestObject).verifier_info).toBeUndefined();
    });

    it('emits registrar_dataset and registration_cert in the request object', async () => {
        const dataset = registrarDatasetVerifierInfo(randomDataset());
        const cert = registrationCertVerifierInfo(await randomWrprc());
        const req = await createSignedAuthorizationRequest(await baseInput([dataset, cert]), query);
        expect(decodeJwt(req.requestObject).verifier_info).toEqual([dataset, cert]);
    });

    it('passes other formats through, with credential_ids that match the DCQL query', async () => {
        const entry = { format: `example_${randomToken(4)}`, data: randomToken(), credential_ids: [credentialId] };
        const req = await createSignedAuthorizationRequest(await baseInput([entry]), query);
        expect(decodeJwt(req.requestObject).verifier_info).toEqual([entry]);
    });

    it('emits only the members OpenID4VP defines', async () => {
        const entry = { format: `example_${randomToken(4)}`, data: { value: randomToken() }, extra: randomToken() };
        const req = await createSignedAuthorizationRequest(await baseInput([entry]), query);
        expect(decodeJwt(req.requestObject).verifier_info).toEqual([{ format: entry.format, data: entry.data }]);
    });

    it('rejects an empty array', async () => {
        expect((await buildError([])).message).toMatch(/non-empty array/);
    });

    it('rejects an empty format', async () => {
        expect((await buildError([{ format: '', data: randomToken() }])).message).toMatch(/format/);
    });

    it('rejects missing or empty data', async () => {
        expect((await buildError([{ format: randomToken() }])).message).toMatch(/data/);
        expect((await buildError([{ format: randomToken(), data: '' }])).message).toMatch(/data/);
    });

    it('rejects empty credential_ids', async () => {
        const err = await buildError([{ format: randomToken(), data: randomToken(), credential_ids: [] }]);
        expect(err.message).toMatch(/credential_ids/);
    });

    it('rejects credential_ids that are not in the DCQL query', async () => {
        const unknownId = `unknown_${randomToken(4)}`;
        const err = await buildError([{ format: randomToken(), data: randomToken(), credential_ids: [unknownId] }]);
        expect(err.message).toContain(unknownId);
    });

    it.each(['registrar_dataset', 'registration_cert'])('rejects credential_ids on %s', async (format) => {
        const data = format === 'registrar_dataset' ? { identifier: randomToken() } : randomToken();
        const err = await buildError([{ format, data, credential_ids: [credentialId] }]);
        expect(err.message).toMatch(/must not carry credential_ids/);
    });

    it('rejects a second registration_cert', async () => {
        const cert = registrationCertVerifierInfo(await randomWrprc());
        expect((await buildError([cert, cert])).message).toMatch(/only one "registration_cert"/);
    });

    it('rejects a registrar_dataset whose data is not a non-empty object', async () => {
        expect((await buildError([{ format: 'registrar_dataset', data: randomToken() }])).message).toMatch(/RO-05/);
        expect((await buildError([{ format: 'registrar_dataset', data: {} }])).message).toMatch(/RO-05/);
    });

    it('rejects a registration_cert whose data is not a string', async () => {
        const err = await buildError([{ format: 'registration_cert', data: { jws: randomToken() } }]);
        expect(err.message).toMatch(/RO-16/);
    });
});

describe('createAuthorizationRequest with verifierInfo', () => {
    const baseInput = () => ({
        clientId: `x509_hash:${randomToken(32)}`,
        responseUri: `https://verifier.example.com/${randomToken()}`,
        nonce: randomToken(),
    });

    it('emits verifier_info as a JSON-encoded parameter', () => {
        const entry = registrarDatasetVerifierInfo(randomDataset());
        const req = createAuthorizationRequest({ ...baseInput(), verifierInfo: [entry] }, query);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;
        expect(JSON.parse(params.get('verifier_info')!)).toEqual([entry]);
    });

    it('omits verifier_info when none is given', () => {
        const req = createAuthorizationRequest(baseInput(), query);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;
        expect(params.get('verifier_info')).toBeNull();
    });

    it('throws TypeError on invalid verifierInfo', () => {
        expect(() => createAuthorizationRequest({ ...baseInput(), verifierInfo: [] }, query)).toThrow(TypeError);
    });
});
