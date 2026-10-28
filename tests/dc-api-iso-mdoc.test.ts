/**
 * `org-iso-mdoc` over the W3C Digital Credentials API (ISO/IEC 18013-7
 * Annex C): request building and response verification through
 * `createDcApiRequest` / `verifyDcApiResponse`.
 */
import { Encoder as CborEncoder } from 'cbor-x';
import type { DcqlQuery } from '@openeudi/dcql';
import { beforeAll, describe, expect, it } from 'vitest';

import { createDcApiRequest } from '../src/dc-api/request.js';
import { verifyDcApiResponse } from '../src/dc-api/response.js';
import { DcApiRequestBuildError, DcApiResponseError, WalletErrorResponseError } from '../src/dc-api/errors.js';
import { encodeEncryptionInfo } from '../src/dc-api/iso-mdoc.js';
import type { DcApiIsoMdocRequest } from '../src/dc-api/types.js';
import { DecryptionFailedError, MultipleCredentialsNotSupportedError } from '../src/errors.js';
import * as publicApi from '../src/index.js';
import { generateTestKeyMaterial, type TestKeyMaterial } from './fixtures/crypto-helpers.js';
import {
    answerIsoMdocRequest,
    dcapiSessionTranscript,
    recipientKeyOf,
    sealDeviceResponse,
} from './fixtures/iso-mdoc-wallet.js';
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';

const PID = 'eu.europa.ec.eudi.pid.1';
const MDL = 'org.iso.18013.5.1.mDL';
const MDL_NS = 'org.iso.18013.5.1';
const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

function randomOrigin(): string {
    return `https://shop-${crypto.randomUUID()}.example`;
}

function randomBirthDate(): string {
    const year = 1950 + Math.floor(Math.random() * 50);
    const month = String(1 + Math.floor(Math.random() * 12)).padStart(2, '0');
    const day = String(1 + Math.floor(Math.random() * 28)).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

function pidQuery(overrides: Partial<DcqlQuery['credentials'][number]> = {}): DcqlQuery {
    return {
        credentials: [
            {
                id: `pid_${crypto.randomUUID().slice(0, 8)}`,
                format: 'mso_mdoc',
                meta: { doctype_value: PID },
                claims: [{ path: [PID, 'birth_date'] }],
                ...overrides,
            },
        ],
    };
}

function decodeB64Cbor(value: string): unknown {
    return cbor.decode(Buffer.from(value, 'base64url'));
}

/** The tag-24 `itemsRequest` of the first DocRequest; checks the raw tag byte, since cbor-x unwraps it. */
function itemsRequestOf(deviceRequestB64: string): Map<string, unknown> {
    const raw = Buffer.from(deviceRequestB64, 'base64url');
    const itemsRequestKey = Buffer.from(cbor.encode('itemsRequest'));
    const at = raw.indexOf(itemsRequestKey) + itemsRequestKey.length;
    expect(raw.subarray(at, at + 2).toString('hex')).toBe('d818'); // #6.24
    const deviceRequest = cbor.decode(raw) as Map<string, unknown>;
    const embedded = (deviceRequest.get('docRequests') as Map<string, unknown>[])[0].get('itemsRequest') as {
        value: Uint8Array;
    };
    return cbor.decode(embedded.value) as Map<string, unknown>;
}

let issuer: TestKeyMaterial;

beforeAll(async () => {
    issuer = await generateTestKeyMaterial('ES256');
});

async function isoRequest(query: DcqlQuery = pidQuery()): Promise<DcApiIsoMdocRequest> {
    return createDcApiRequest({ protocol: 'org-iso-mdoc' }, query);
}

function verifyOptions(req: DcApiIsoMdocRequest, origin: string) {
    return {
        protocol: 'org-iso-mdoc' as const,
        origin,
        encryptionInfo: req.encryptionInfo,
        decryptionKey: req.recipientPrivateJwk,
        nonce: req.nonce,
        trustedCertificates: [issuer.certDerBytes],
    };
}

describe('createDcApiRequest — org-iso-mdoc', () => {
    it('builds DeviceRequest 1.0 + EncryptionInfo as the only two data members', async () => {
        const query = pidQuery();
        const req = await isoRequest(query);

        expect(req.request.protocol).toBe('org-iso-mdoc');
        expect(Object.keys(req.request.data).sort()).toEqual(['deviceRequest', 'encryptionInfo']);
        expect(req.request.data.deviceRequest).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(req.encryptionInfo).toBe(req.request.data.encryptionInfo);
        expect(req.dcqlQuery).toBe(query);

        const deviceRequest = decodeB64Cbor(req.request.data.deviceRequest) as Map<string, unknown>;
        expect([...deviceRequest.keys()]).toEqual(['version', 'docRequests']);
        expect(deviceRequest.get('version')).toBe('1.0');
        const docRequests = deviceRequest.get('docRequests') as Map<string, unknown>[];
        expect(docRequests).toHaveLength(1);
        expect([...docRequests[0].keys()]).toEqual(['itemsRequest']); // no readerAuth
        const items = itemsRequestOf(req.request.data.deviceRequest);
        expect(items.get('docType')).toBe(PID);
        expect(items.get('nameSpaces')).toEqual(new Map([[PID, new Map([['birth_date', false]])]]));
    });

    it('puts a fresh 16-byte nonce and the returned P-256 recipient key in EncryptionInfo', async () => {
        const req = await isoRequest();

        const [type, params] = decodeB64Cbor(req.encryptionInfo) as [string, Map<string, unknown>];
        expect(type).toBe('dcapi');
        const nonce = params.get('nonce') as Uint8Array;
        expect(nonce).toHaveLength(16);
        expect(Buffer.from(nonce).toString('base64url')).toBe(req.nonce);
        const key = params.get('recipientPublicKey') as Map<number, unknown>;
        expect(key.get(1)).toBe(2);
        expect(key.get(-1)).toBe(1);
        expect(Buffer.from(key.get(-2) as Uint8Array).toString('base64url')).toBe(req.recipientPrivateJwk.x);
        expect(Buffer.from(key.get(-3) as Uint8Array).toString('base64url')).toBe(req.recipientPrivateJwk.y);
        expect(typeof req.recipientPrivateJwk.d).toBe('string');
    });

    it('uses a new key and nonce for every request', async () => {
        const a = await isoRequest();
        const b = await isoRequest();

        expect(a.nonce).not.toBe(b.nonce);
        expect(a.recipientPrivateJwk.d).not.toBe(b.recipientPrivateJwk.d);
    });

    it('uses a supplied nonce and carries intent_to_retain', async () => {
        const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
        const req = await createDcApiRequest(
            { protocol: 'org-iso-mdoc', nonce },
            pidQuery({ claims: [{ path: [PID, 'birth_date'], intent_to_retain: true }] }),
        );

        expect(req.nonce).toBe(nonce);
        const items = itemsRequestOf(req.request.data.deviceRequest);
        expect(items.get('nameSpaces')).toEqual(new Map([[PID, new Map([['birth_date', true]])]]));
    });

    it.each([
        ['too short', Buffer.from(crypto.getRandomValues(new Uint8Array(15))).toString('base64url')],
        ['not base64url', `${crypto.randomUUID()}+/=`],
        ['empty', ''],
    ])('rejects a nonce that is %s', async (_label, nonce) => {
        const err = await createDcApiRequest({ protocol: 'org-iso-mdoc', nonce }, pidQuery()).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(DcApiRequestBuildError);
        expect((err as DcApiRequestBuildError).code).toBe('invalid_nonce');
    });

    it.each<[string, DcqlQuery]>([
        [
            'an SD-JWT credential',
            { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claims: [{ path: ['birthdate'] }] }] },
        ],
        ['two credentials', { credentials: [...pidQuery().credentials, { ...pidQuery().credentials[0], id: 'second' }] }],
        [
            'credential_sets',
            ((query: DcqlQuery): DcqlQuery => ({ ...query, credential_sets: [{ options: [[query.credentials[0].id]] }] }))(
                pidQuery(),
            ),
        ],
        ['no claims', pidQuery({ claims: undefined })],
        ['a claim with values', pidQuery({ claims: [{ path: [PID, 'birth_date'], values: [randomBirthDate()] }] })],
        ['multiple: true', pidQuery({ multiple: true })],
    ])('rejects a query with %s as unsupported_query', async (_label, query) => {
        const err = await createDcApiRequest({ protocol: 'org-iso-mdoc' }, query).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(DcApiRequestBuildError);
        expect((err as DcApiRequestBuildError).code).toBe('unsupported_query');
    });

    it('rejects claim_sets as unsupported_query', async () => {
        const query = pidQuery({
            claims: [
                { id: 'a', path: [PID, 'birth_date'] },
                { id: 'b', path: [PID, 'age_over_18'] },
            ],
            claim_sets: [['a'], ['b']],
        });
        const err = await createDcApiRequest({ protocol: 'org-iso-mdoc' }, query).catch((e: unknown) => e);
        expect((err as DcApiRequestBuildError).code).toBe('unsupported_query');
    });

    it('sends an eu.europa.ec.av.1 query to the AV profile builder', async () => {
        const query: DcqlQuery = {
            credentials: [
                {
                    id: 'proof_of_age',
                    format: 'mso_mdoc',
                    meta: { doctype_value: 'eu.europa.ec.av.1' },
                    claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'] }],
                },
            ],
        };
        const err = await createDcApiRequest({ protocol: 'org-iso-mdoc' }, query).catch((e: unknown) => e);
        expect((err as DcApiRequestBuildError).code).toBe('av_profile_required');
    });
});

describe('verifyDcApiResponse — org-iso-mdoc round trip', () => {
    it('verifies an HPKE-encrypted DeviceResponse bound to the dcapi SessionTranscript', async () => {
        const origin = randomOrigin();
        const birthDate = randomBirthDate();
        const req = await isoRequest();
        const credential = await answerIsoMdocRequest({
            data: req.request.data,
            origin,
            issuerKey: issuer,
            namespaces: { [PID]: { birth_date: birthDate } },
        });

        const result = await verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin));

        expect(result.parsed.error).toBeUndefined();
        expect(result.valid).toBe(true);
        expect(result.parsed.docType).toBe(PID);
        expect(result.parsed.namespacedClaims?.[PID]?.birth_date).toBe(birthDate);
        expect(result.submission).not.toBeNull();
    });

    it('accepts the recipient key as a CryptoKey and data as a JSON string', async () => {
        const origin = randomOrigin();
        const req = await isoRequest();
        const credential = await answerIsoMdocRequest({
            data: req.request.data,
            origin,
            issuerKey: issuer,
            namespaces: { [PID]: { birth_date: randomBirthDate() } },
        });
        const decryptionKey = await crypto.subtle.importKey(
            'jwk',
            req.recipientPrivateJwk,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );

        const result = await verifyDcApiResponse(
            { protocol: credential.protocol, data: JSON.stringify(credential.data) },
            req.dcqlQuery,
            { ...verifyOptions(req, origin), decryptionKey, nonce: undefined },
        );

        expect(result.valid).toBe(true);
    });

    it('exposes the transcript builder and the new types from the package entry point', () => {
        expect(typeof publicApi.buildDCAPIHandoverSessionTranscript).toBe('function');
    });
});

describe('verifyDcApiResponse — org-iso-mdoc negative cases', () => {
    async function answered(origin = randomOrigin()) {
        const req = await isoRequest();
        const credential = await answerIsoMdocRequest({
            data: req.request.data,
            origin,
            issuerKey: issuer,
            namespaces: { [PID]: { birth_date: randomBirthDate() } },
        });
        return { req, credential, origin };
    }

    it('fails to decrypt a response the browser bound to another origin', async () => {
        const { req, credential } = await answered();

        await expect(
            verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, randomOrigin())),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('rejects a device signature over another origin even when HPKE opens', async () => {
        const origin = randomOrigin();
        const req = await isoRequest();
        const credential = await answerIsoMdocRequest({
            data: req.request.data,
            origin,
            signingOrigin: randomOrigin(),
            issuerKey: issuer,
            namespaces: { [PID]: { birth_date: randomBirthDate() } },
        });

        const result = await verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin));

        expect(result.valid).toBe(false);
        expect(result.parsed.error).toMatch(/device/i);
    });

    it('fails when the wallet bound an EncryptionInfo with another nonce', async () => {
        const origin = randomOrigin();
        const req = await isoRequest();
        const recipient = recipientKeyOf(req.encryptionInfo);
        const replayedInfo = encodeEncryptionInfo(
            crypto.getRandomValues(new Uint8Array(16)),
            recipient.slice(1, 33),
            recipient.slice(33, 65),
        );
        const credential = await answerIsoMdocRequest({
            data: req.request.data,
            boundEncryptionInfo: replayedInfo,
            origin,
            issuerKey: issuer,
            namespaces: { [PID]: { birth_date: randomBirthDate() } },
        });

        await expect(verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin))).rejects.toBeInstanceOf(
            DecryptionFailedError,
        );
    });

    it('refuses a nonce option that is not the EncryptionInfo nonce', async () => {
        const { req, credential, origin } = await answered();
        const otherNonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url');

        await expect(
            verifyDcApiResponse(credential, req.dcqlQuery, { ...verifyOptions(req, origin), nonce: otherNonce }),
        ).rejects.toMatchObject({ name: 'DcApiResponseError', code: 'nonce_mismatch' });
    });

    it('fails on a tampered ciphertext', async () => {
        const { req, credential, origin } = await answered();
        const [type, params] = decodeB64Cbor(credential.data.response) as [string, Map<string, Uint8Array>];
        const cipherText = new Uint8Array(params.get('cipherText')!);
        cipherText[Math.floor(Math.random() * cipherText.length)] ^= 1 + Math.floor(Math.random() * 255);
        params.set('cipherText', cipherText);
        const tampered = { protocol: 'org-iso-mdoc', data: { response: Buffer.from(cbor.encode([type, params])).toString('base64url') } };

        await expect(verifyDcApiResponse(tampered, req.dcqlQuery, verifyOptions(req, origin))).rejects.toBeInstanceOf(
            DecryptionFailedError,
        );
    });

    it('refuses a private key that is not the recipient key', async () => {
        const { req, credential, origin } = await answered();
        const other = await isoRequest();

        await expect(
            verifyDcApiResponse(credential, req.dcqlQuery, {
                ...verifyOptions(req, origin),
                decryptionKey: other.recipientPrivateJwk,
            }),
        ).rejects.toMatchObject({ code: 'decryption_key_mismatch' });
    });

    it('does not match a document of another docType', async () => {
        const origin = randomOrigin();
        const req = await isoRequest();
        const credential = await answerIsoMdocRequest({
            data: req.request.data,
            origin,
            issuerKey: issuer,
            docType: MDL,
            namespaces: { [MDL_NS]: { birth_date: randomBirthDate() } },
        });

        const result = await verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin));

        expect(result.valid).toBe(false);
        expect(result.match.satisfied).toBe(false);
    });

    it('does not trust an unknown issuer', async () => {
        const { req, credential, origin } = await answered();
        const stranger = await generateTestKeyMaterial('ES256');

        const result = await verifyDcApiResponse(credential, req.dcqlQuery, {
            ...verifyOptions(req, origin),
            trustedCertificates: [stranger.certDerBytes],
        });

        expect(result.valid).toBe(false);
        expect(result.parsed.error).toMatch(/not trusted/);
    });

    it.each([
        ['an OpenID4VP response with org-iso-mdoc options', 'openid4vp-v1-unsigned', true],
        ['an org-iso-mdoc response with OpenID4VP options', 'org-iso-mdoc', false],
    ])('rejects %s as protocol_mismatch', async (_label, protocol, isoOptions) => {
        const { req, credential, origin } = await answered();
        const options = isoOptions
            ? verifyOptions(req, origin)
            : { origin, nonce: req.nonce, trustedCertificates: [issuer.certDerBytes] };

        await expect(
            verifyDcApiResponse({ protocol, data: credential.data }, req.dcqlQuery, options),
        ).rejects.toMatchObject({ name: 'DcApiResponseError', code: 'protocol_mismatch' });
    });

    it.each<[string, unknown]>([
        ['extra members', { response: 'AA', vp_token: {} }],
        ['a non-base64url response', { response: `${crypto.randomUUID()}+/` }],
        ['a response that is not ["dcapi", {...}]', { response: Buffer.from(cbor.encode(['x', new Map()])).toString('base64url') }],
        ['no response', {}],
    ])('rejects data with %s as malformed_response', async (_label, data) => {
        const req = await isoRequest();

        await expect(
            verifyDcApiResponse({ protocol: 'org-iso-mdoc', data }, req.dcqlQuery, verifyOptions(req, randomOrigin())),
        ).rejects.toMatchObject({ code: 'malformed_response' });
    });

    it('surfaces a wallet error object as WalletErrorResponseError', async () => {
        const req = await isoRequest();

        await expect(
            verifyDcApiResponse(
                { protocol: 'org-iso-mdoc', data: { error: 'access_denied' } },
                req.dcqlQuery,
                verifyOptions(req, randomOrigin()),
            ),
        ).rejects.toBeInstanceOf(WalletErrorResponseError);
    });

    it.each(['https://shop.example/', 'origin:https://shop.example', 'http://shop.example'])(
        'rejects a misconfigured origin option %s',
        async (origin) => {
            const { req, credential } = await answered();
            await expect(
                verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin)),
            ).rejects.toMatchObject({ code: 'invalid_origin' });
        },
    );

    it('rejects a stored encryptionInfo that does not decode', async () => {
        const { req, credential, origin } = await answered();

        await expect(
            verifyDcApiResponse(credential, req.dcqlQuery, {
                ...verifyOptions(req, origin),
                encryptionInfo: Buffer.from(cbor.encode(['dcapi', new Map([['nonce', 1]])])).toString('base64url'),
            }),
        ).rejects.toMatchObject({ code: 'invalid_encryption_info' });
    });

    describe('DeviceResponse shape', () => {
        async function sealed(deviceResponse: unknown) {
            const origin = randomOrigin();
            const req = await isoRequest();
            const credential = await sealDeviceResponse(
                new Uint8Array(cbor.encode(deviceResponse)),
                recipientKeyOf(req.encryptionInfo),
                await dcapiSessionTranscript(req.encryptionInfo, origin),
            );
            return { req, credential, origin };
        }

        async function documentFor(req: DcApiIsoMdocRequest, origin: string, docType = PID) {
            const mdoc = await buildSignedMdoc({
                issuerKey: issuer,
                docType,
                namespaces: { [docType]: { birth_date: randomBirthDate() } },
                sessionTranscript: await dcapiSessionTranscript(req.encryptionInfo, origin),
            });
            const response = cbor.decode(mdoc.mdocBytes) as Map<string, unknown>;
            return (response.get('documents') as unknown[])[0];
        }

        it('rejects a non-zero status as device_response_error', async () => {
            const { req, credential, origin } = await sealed(new Map<string, unknown>([['version', '1.0'], ['status', 10]]));

            await expect(verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin))).rejects.toMatchObject({
                code: 'device_response_error',
            });
        });

        it('rejects a DeviceResponse without documents as malformed_response', async () => {
            const { req, credential, origin } = await sealed(new Map<string, unknown>([['version', '1.0'], ['status', 0]]));

            await expect(verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin))).rejects.toMatchObject({
                code: 'malformed_response',
            });
        });

        it('rejects two documents with MultipleCredentialsNotSupportedError', async () => {
            const origin = randomOrigin();
            const req = await isoRequest();
            const doc = await documentFor(req, origin);
            const credential = await sealDeviceResponse(
                new Uint8Array(cbor.encode(new Map<string, unknown>([['version', '1.0'], ['documents', [doc, doc]], ['status', 0]]))),
                recipientKeyOf(req.encryptionInfo),
                await dcapiSessionTranscript(req.encryptionInfo, origin),
            );

            await expect(verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin))).rejects.toBeInstanceOf(
                MultipleCredentialsNotSupportedError,
            );
        });

        it('sends an eu.europa.ec.av.1 document to the AV profile verifier', async () => {
            const origin = randomOrigin();
            const req = await isoRequest();
            const credential = await answerIsoMdocRequest({
                data: req.request.data,
                origin,
                issuerKey: issuer,
                docType: 'eu.europa.ec.av.1',
                namespaces: { 'eu.europa.ec.av.1': { age_over_18: true } },
            });

            const err = await verifyDcApiResponse(credential, req.dcqlQuery, verifyOptions(req, origin)).catch(
                (e: unknown) => e,
            );
            expect(err).toBeInstanceOf(DcApiResponseError);
            expect((err as DcApiResponseError).code).toBe('av_profile_required');
        });
    });
});
