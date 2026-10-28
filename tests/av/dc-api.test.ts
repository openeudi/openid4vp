/**
 * EU Age Verification profile over the W3C Digital Credentials API
 * (AV Annex A §A.6 "W3C Digital Credentials API", ISO/IEC 18013-7 Annex C):
 * `createAvDcApiRequest` / `verifyAvDcApiResponse`.
 */
import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { AV_DOCUMENT_SIGNER_EKU } from '../../src/av/constants.js';
import { createAvDcApiRequest, verifyAvDcApiResponse } from '../../src/av/dc-api.js';
import { AvRequestBuildError, AvResponseError } from '../../src/av/errors.js';
import type { AvDcApiRequest } from '../../src/av/types.js';
import { verifyAvDeviceResponse } from '../../src/av/verify.js';
import { buildDCAPIHandoverSessionTranscript } from '../../src/crypto/session-transcript.js';
import { DcApiResponseError } from '../../src/dc-api/errors.js';
import { encodeEncryptionInfo } from '../../src/dc-api/iso-mdoc.js';
import {
    CertificateChainError,
    DecryptionFailedError,
    TrustAnchorNotFoundError,
    WalletErrorResponseError,
} from '../../src/errors.js';
import * as publicApi from '../../src/index.js';
import { ISO_18013_5_DS_EKU } from '../../src/trust/ChainBuilder.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import {
    ANNEX_A_DCAPI_DEVICE_REQUEST,
    ANNEX_A_DCAPI_DEVICE_RESPONSE,
    ANNEX_A_DCAPI_ENCRYPTION_INFO,
    ANNEX_A_DCAPI_SESSION_TRANSCRIPT_HEX,
} from '../fixtures/av-annex-a-dcapi-example.js';
import { ANNEX_A_VERIFICATION_TIME } from '../fixtures/av-annex-a-example.js';
import { AV_REFERENCE_ISSUER_CA_DER_BASE64 } from '../fixtures/av-reference-issuer-ca.js';
import type { TestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { answerIsoMdocRequest, recipientKeyOf } from '../fixtures/iso-mdoc-wallet.js';
import type { GeneratedCa } from '../trust/helpers/synthetic-ca.js';
import { createIssuer, nodeDeviceKey, storeOf } from './helpers.js';

const AV = 'eu.europa.ec.av.1';
const PID = 'eu.europa.ec.eudi.pid.1';
const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

function randomOrigin(): string {
    return `https://shop-${crypto.randomUUID()}.example`;
}

let av: { ca: GeneratedCa; ds: TestKeyMaterial };
let pidProvider: { ca: GeneratedCa; ds: TestKeyMaterial };

beforeAll(async () => {
    av = await createIssuer('AV', [AV_DOCUMENT_SIGNER_EKU]);
    pidProvider = await createIssuer('PID', [ISO_18013_5_DS_EKU]);
});

afterEach(() => {
    vi.useRealTimers();
});

interface AnswerOptions {
    issuer?: TestKeyMaterial;
    docType?: string;
    namespaces?: Record<string, Record<string, unknown>>;
    signingOrigin?: string;
}

async function answer(request: AvDcApiRequest, origin: string, opts: AnswerOptions = {}) {
    return answerIsoMdocRequest({
        data: request.request.data,
        origin,
        issuerKey: opts.issuer ?? av.ds,
        deviceKey: await nodeDeviceKey(),
        docType: opts.docType,
        namespaces: opts.namespaces ?? { [AV]: { age_over_18: true } },
        signingOrigin: opts.signingOrigin,
    });
}

function options(request: AvDcApiRequest, origin: string) {
    return { request, origin, decryptionKey: request.recipientPrivateJwk, trustStore: storeOf(av.ca) };
}

describe('createAvDcApiRequest', () => {
    it('builds the org-iso-mdoc request of AV Annex A, byte-identical to the §A.11 example DeviceRequest', async () => {
        const request = await createAvDcApiRequest();

        expect(request.request.protocol).toBe('org-iso-mdoc');
        expect(Object.keys(request.request.data).sort()).toEqual(['deviceRequest', 'encryptionInfo']);
        expect(request.request.data.deviceRequest).toBe(ANNEX_A_DCAPI_DEVICE_REQUEST);
        expect(request.encryptionInfo).toBe(request.request.data.encryptionInfo);
        expect(request).toMatchObject({ ageThreshold: 18, ageOverAttribute: 'age_over_18' });
        expect(typeof request.recipientPrivateJwk.d).toBe('string');
    });

    it('requests another age_over_NN', async () => {
        const threshold = 10 + Math.floor(Math.random() * 80);
        const request = await createAvDcApiRequest({ ageThreshold: threshold });

        const deviceRequest = cbor.decode(Buffer.from(request.request.data.deviceRequest, 'base64url')) as Map<string, unknown>;
        const tagged = (deviceRequest.get('docRequests') as Map<string, unknown>[])[0].get('itemsRequest') as Tag;
        const items = cbor.decode(tagged.value as Uint8Array) as Map<string, unknown>;
        expect(items.get('nameSpaces')).toEqual(new Map([[AV, new Map([[`age_over_${threshold}`, false]])]]));
        expect(request.ageOverAttribute).toBe(`age_over_${threshold}`);
    });

    it.each([-1, 100, 1.5])('rejects age threshold %s', async (ageThreshold) => {
        const err = await createAvDcApiRequest({ ageThreshold }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(AvRequestBuildError);
        expect((err as AvRequestBuildError).code).toBe('invalid_age_threshold');
    });

    it('rejects a nonce shorter than 16 bytes', async () => {
        const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString('base64url');
        const err = await createAvDcApiRequest({ nonce }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(AvRequestBuildError);
        expect((err as AvRequestBuildError).code).toBe('invalid_nonce');
    });

    it('is exported from the package entry point', () => {
        expect(publicApi.createAvDcApiRequest).toBe(createAvDcApiRequest);
        expect(publicApi.verifyAvDcApiResponse).toBe(verifyAvDcApiResponse);
    });
});

describe('verifyAvDcApiResponse — round trip', () => {
    it('verifies an HPKE-encrypted Proof of Age attestation bound to the page origin', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        const result = await verifyAvDcApiResponse(await answer(request, origin), options(request, origin));

        expect(result.error).toBeUndefined();
        expect(result).toMatchObject({ valid: true, ageVerified: true, ageOver: true, ageThreshold: 18 });
        expect(result.trust).toBeDefined();
    });

    it('returns valid with ageVerified false for age_over_18: false', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        const result = await verifyAvDcApiResponse(
            await answer(request, origin, { namespaces: { [AV]: { age_over_18: false } } }),
            options(request, origin),
        );

        expect(result).toMatchObject({ valid: true, ageVerified: false, ageOver: false });
    });

    it('needs only the persisted subset and accepts data as a JSON string', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest({ ageThreshold: 21 });
        const credential = await answer(request, origin, { namespaces: { [AV]: { age_over_21: true } } });

        const result = await verifyAvDcApiResponse(
            { protocol: credential.protocol, data: JSON.stringify(credential.data) },
            {
                request: { encryptionInfo: request.encryptionInfo, ageThreshold: 21 },
                origin,
                decryptionKey: request.recipientPrivateJwk,
                trustStore: storeOf(av.ca),
            },
        );

        expect(result).toMatchObject({ valid: true, ageVerified: true, ageOverAttribute: 'age_over_21' });
    });
});

describe('verifyAvDcApiResponse — rejections', () => {
    it('fails to decrypt a response the browser bound to another origin', async () => {
        const request = await createAvDcApiRequest();
        const credential = await answer(request, randomOrigin());

        await expect(verifyAvDcApiResponse(credential, options(request, randomOrigin()))).rejects.toBeInstanceOf(
            DecryptionFailedError,
        );
    });

    it('rejects a device signature over another origin even when HPKE opens', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        const result = await verifyAvDcApiResponse(
            await answer(request, origin, { signingOrigin: randomOrigin() }),
            options(request, origin),
        );

        expect(result).toMatchObject({ valid: false, ageVerified: false, failure: 'invalid_credential' });
    });

    it('fails when the wallet bound an EncryptionInfo with another nonce', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();
        const recipient = recipientKeyOf(request.encryptionInfo);
        const credential = await answerIsoMdocRequest({
            data: request.request.data,
            boundEncryptionInfo: encodeEncryptionInfo(
                crypto.getRandomValues(new Uint8Array(16)),
                recipient.slice(1, 33),
                recipient.slice(33, 65),
            ),
            origin,
            issuerKey: av.ds,
            deviceKey: await nodeDeviceKey(),
            namespaces: { [AV]: { age_over_18: true } },
        });

        await expect(verifyAvDcApiResponse(credential, options(request, origin))).rejects.toBeInstanceOf(
            DecryptionFailedError,
        );
    });

    it('refuses a persisted nonce that is not the EncryptionInfo nonce', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();
        const other = await createAvDcApiRequest();

        await expect(
            verifyAvDcApiResponse(await answer(request, origin), {
                ...options(request, origin),
                request: { ...request, nonce: other.nonce },
            }),
        ).rejects.toMatchObject({ code: 'nonce_mismatch' });
    });

    it('fails on a tampered ciphertext', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();
        const credential = await answer(request, origin);
        const [type, params] = cbor.decode(Buffer.from(credential.data.response, 'base64url')) as [string, Map<string, Uint8Array>];
        const cipherText = new Uint8Array(params.get('cipherText')!);
        cipherText[Math.floor(Math.random() * cipherText.length)] ^= 1 + Math.floor(Math.random() * 255);
        params.set('cipherText', cipherText);
        const tampered = { protocol: 'org-iso-mdoc', data: { response: Buffer.from(cbor.encode([type, params])).toString('base64url') } };

        await expect(verifyAvDcApiResponse(tampered, options(request, origin))).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('rejects an attestation that carries any attribute besides age_over_NN', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        const result = await verifyAvDcApiResponse(
            await answer(request, origin, { namespaces: { [AV]: { age_over_18: true, birth_date: '2000-01-01' } } }),
            options(request, origin),
        );

        expect(result).toMatchObject({ valid: false, ageVerified: false, failure: 'unexpected_attribute' });
    });

    it('rejects an attribute in another namespace', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        const result = await verifyAvDcApiResponse(
            await answer(request, origin, { namespaces: { [AV]: { age_over_18: true }, [PID]: { age_over_18: true } } }),
            options(request, origin),
        );

        expect(result).toMatchObject({ valid: false, failure: 'unexpected_attribute' });
    });

    it('rejects a document whose docType is not eu.europa.ec.av.1', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        const result = await verifyAvDcApiResponse(
            await answer(request, origin, { docType: PID, namespaces: { [PID]: { age_over_18: true } } }),
            options(request, origin),
        );

        expect(result).toMatchObject({ valid: false, failure: 'wrong_doctype' });
    });

    it('rejects a presentation that lacks the requested age_over_NN', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest({ ageThreshold: 21 });

        const result = await verifyAvDcApiResponse(await answer(request, origin), options(request, origin));

        expect(result).toMatchObject({ valid: false, failure: 'missing_attribute' });
    });

    it('does not trust an issuer that is only a PID provider', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();

        await expect(
            verifyAvDcApiResponse(await answer(request, origin, { issuer: pidProvider.ds }), options(request, origin)),
        ).rejects.toBeInstanceOf(TrustAnchorNotFoundError);
    });

    it('rejects a Document Signer with neither AV nor ISO EKU', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();
        const other = await createIssuer('Other', ['1.3.6.1.5.5.7.3.2']);

        await expect(
            verifyAvDcApiResponse(await answer(request, origin, { issuer: other.ds }), {
                ...options(request, origin),
                trustStore: storeOf(other.ca),
            }),
        ).rejects.toBeInstanceOf(CertificateChainError);
    });

    it('throws WalletErrorResponseError for a wallet error object', async () => {
        const request = await createAvDcApiRequest();

        await expect(
            verifyAvDcApiResponse({ protocol: 'org-iso-mdoc', data: { error: 'access_denied' } }, options(request, randomOrigin())),
        ).rejects.toBeInstanceOf(WalletErrorResponseError);
    });

    it('rejects an OpenID4VP protocol response', async () => {
        const origin = randomOrigin();
        const request = await createAvDcApiRequest();
        const credential = await answer(request, origin);

        await expect(
            verifyAvDcApiResponse({ protocol: 'openid4vp-v1-unsigned', data: credential.data }, options(request, origin)),
        ).rejects.toMatchObject({ name: 'DcApiResponseError', code: 'protocol_mismatch' });
    });

    it('rejects a misconfigured origin and a missing verification context', async () => {
        const request = await createAvDcApiRequest();
        const credential = await answer(request, randomOrigin());

        await expect(
            verifyAvDcApiResponse(credential, options(request, 'https://shop.example/')),
        ).rejects.toBeInstanceOf(DcApiResponseError);
        await expect(
            verifyAvDcApiResponse(credential, { ...options(request, randomOrigin()), trustStore: undefined as never }),
        ).rejects.toBeInstanceOf(AvResponseError);
        await expect(
            verifyAvDcApiResponse(credential, { ...options(request, randomOrigin()), request: {} as never }),
        ).rejects.toBeInstanceOf(AvResponseError);
    });
});

describe('AV Annex A §A.11 "W3C Digital Credentials API" example (AV reference implementation)', () => {
    const transcript = new Uint8Array(Buffer.from(ANNEX_A_DCAPI_SESSION_TRANSCRIPT_HEX, 'hex'));
    const deviceResponse = new Uint8Array(Buffer.from(ANNEX_A_DCAPI_DEVICE_RESPONSE, 'base64url'));
    const referenceStore = () => new StaticTrustStore([new Uint8Array(Buffer.from(AV_REFERENCE_ISSUER_CA_DER_BASE64, 'base64'))]);

    it('has the dcapi SessionTranscript layout this library builds', async () => {
        const [first, second, handover] = cbor.decode(transcript) as [null, null, [string, Uint8Array]];
        expect(first).toBeNull();
        expect(second).toBeNull();
        expect(handover[0]).toBe('dcapi');
        expect(handover[1]).toHaveLength(32);
        expect(Buffer.from(cbor.encode([null, null, ['dcapi', handover[1]]])).toString('hex')).toBe(
            ANNEX_A_DCAPI_SESSION_TRANSCRIPT_HEX,
        );
        const ours = await buildDCAPIHandoverSessionTranscript({
            encryptionInfo: ANNEX_A_DCAPI_ENCRYPTION_INFO,
            origin: randomOrigin(),
        });
        expect(ours).toHaveLength(transcript.length);
        expect(Buffer.from(ours.subarray(0, ours.length - 32)).toString('hex')).toBe(
            ANNEX_A_DCAPI_SESSION_TRANSCRIPT_HEX.slice(0, (transcript.length - 32) * 2),
        );
    });

    it('re-encodes the example EncryptionInfo byte for byte', () => {
        const [, params] = cbor.decode(Buffer.from(ANNEX_A_DCAPI_ENCRYPTION_INFO, 'base64url')) as [string, Map<string, unknown>];
        const key = params.get('recipientPublicKey') as Map<number, Uint8Array>;

        expect(
            encodeEncryptionInfo(new Uint8Array(params.get('nonce') as Uint8Array), new Uint8Array(key.get(-2)!), new Uint8Array(key.get(-3)!)),
        ).toBe(ANNEX_A_DCAPI_ENCRYPTION_INFO);
    });

    it("verifies the AV app's DeviceResponse and its device signature over the dcapi transcript", async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(ANNEX_A_VERIFICATION_TIME);

        const result = await verifyAvDeviceResponse(
            deviceResponse,
            { sessionTranscript: transcript, nonce: crypto.randomUUID(), ageThreshold: 18 },
            { trustStore: referenceStore() },
        );

        expect(result).toMatchObject({ valid: true, ageVerified: true, ageThreshold: 18 });
    });

    it('rejects the example DeviceResponse under any other dcapi transcript', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(ANNEX_A_VERIFICATION_TIME);
        const other = await buildDCAPIHandoverSessionTranscript({
            encryptionInfo: ANNEX_A_DCAPI_ENCRYPTION_INFO,
            origin: randomOrigin(),
        });

        const result = await verifyAvDeviceResponse(
            deviceResponse,
            { sessionTranscript: other, nonce: crypto.randomUUID(), ageThreshold: 18 },
            { trustStore: referenceStore() },
        );

        expect(result).toMatchObject({ valid: false, failure: 'invalid_credential' });
        expect(result.error).toMatch(/device/i);
    });
});
