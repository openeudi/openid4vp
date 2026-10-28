import { describe, it, expect, beforeAll } from 'vitest';
import { decodeJwt, decodeProtectedHeader, jwtVerify, calculateJwkThumbprint, type JWK } from 'jose';
import type { DcqlQuery } from '@openeudi/dcql';

import { createDcApiRequest } from '../src/dc-api/request.js';
import { verifyDcApiResponse } from '../src/dc-api/response.js';
import { DC_API_PRESENTATION_PROTOCOLS } from '../src/dc-api/protocols.js';
import {
    DcApiRequestBuildError,
    DcApiResponseError,
    WalletErrorResponseError,
} from '../src/dc-api/errors.js';
import {
    MissingDecryptionKeyError,
    MissingVerifierEncryptionKeyError,
    SignedRequestBuildError,
    StatusListError,
} from '../src/errors.js';
import { buildHaipQuery } from '../src/haip.js';
import {
    buildOpenID4VPDCAPIHandoverSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from '../src/crypto/session-transcript.js';
import * as publicApi from '../src/index.js';
import {
    buildSignedSdJwt,
    createEncryptionKeypair,
    createVerifierKeypairAndCert,
    createVpFormatsSupported,
    encryptAuthorizationResponseJwe,
    generateTestKeyMaterial,
    type EncryptionKeypair,
    type TestKeyMaterial,
    type VerifierKeyMaterial,
} from './fixtures/crypto-helpers.js';
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';

const PID_VCT = 'urn:eudi:pid:1';
const PID_DOCTYPE = 'eu.europa.ec.eudi.pid.1';

const sdJwtQuery: DcqlQuery = buildHaipQuery({
    credentialId: 'pid',
    format: 'dc+sd-jwt',
    vctValues: [PID_VCT],
    claims: ['birthdate'],
});
const mdocQuery: DcqlQuery = buildHaipQuery({
    credentialId: 'pid',
    format: 'mso_mdoc',
    doctypeValue: PID_DOCTYPE,
    claims: ['birth_date'],
});

function randomOrigin(): string {
    return `https://shop-${crypto.randomUUID()}.example`;
}

function randomBirthDate(): string {
    const year = 1950 + Math.floor(Math.random() * 50);
    const month = String(1 + Math.floor(Math.random() * 12)).padStart(2, '0');
    const day = String(1 + Math.floor(Math.random() * 28)).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

function bytesToBase64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

let issuerKey: TestKeyMaterial;
let holderKey: TestKeyMaterial;
let verifier: VerifierKeyMaterial;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial('ES256');
    holderKey = await generateTestKeyMaterial('ES256');
    verifier = await createVerifierKeypairAndCert(`verifier-${crypto.randomUUID()}.example`);
});

async function sdJwtPresentation(params: { nonce: string; audience?: string; withHolderKey?: boolean }) {
    const built = await buildSignedSdJwt({
        issuerKey,
        holderKey: params.withHolderKey === false ? undefined : holderKey,
        claims: { vct: PID_VCT },
        disclosureClaims: [['birthdate', randomBirthDate()]],
        nonce: params.nonce,
        audience: params.audience,
    });
    return built.sdJwt;
}

async function mdocPresentation(sessionTranscript: Uint8Array): Promise<string> {
    const mdoc = await buildSignedMdoc({
        issuerKey,
        docType: PID_DOCTYPE,
        namespaces: { [PID_DOCTYPE]: { birth_date: randomBirthDate() } },
        sessionTranscript,
    });
    return bytesToBase64url(mdoc.mdocBytes);
}

// ---------------------------------------------------------------------------
// Request builder
// ---------------------------------------------------------------------------

describe('createDcApiRequest — openid4vp-v1-unsigned', () => {
    it('builds a dc_api.jwt request without client_id, with an encryption key in client_metadata', async () => {
        const nonce = crypto.randomUUID();
        const { publicJwk } = await createEncryptionKeypair();

        const req = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-unsigned',
                nonce,
                encryptionKey: { publicJwk },
                vpFormatsSupported: createVpFormatsSupported(),
            },
            sdJwtQuery,
        );

        expect(req.request.protocol).toBe('openid4vp-v1-unsigned');
        expect(req.responseMode).toBe('dc_api.jwt');
        const data = req.request.data;
        expect(data).not.toHaveProperty('client_id');
        expect(data).not.toHaveProperty('state');
        expect(data).not.toHaveProperty('response_uri');
        expect(data).not.toHaveProperty('expected_origins');
        expect(data.response_type).toBe('vp_token');
        expect(data.response_mode).toBe('dc_api.jwt');
        expect(data.nonce).toBe(nonce);
        expect(data.dcql_query).toEqual(sdJwtQuery);

        const metadata = data.client_metadata as Record<string, unknown>;
        expect(metadata.vp_formats_supported).toEqual(createVpFormatsSupported());
        expect(metadata.encrypted_response_enc_values_supported).toEqual(['A128GCM', 'A256GCM']);
        const [jwk] = (metadata.jwks as { keys: Array<Record<string, unknown>> }).keys;
        expect(jwk.use).toBe('enc');
        expect(jwk.alg).toBe('ECDH-ES');
        expect(jwk.x).toBe(publicJwk.x);
        // OpenID4VP 1.0 §5.1: every JWK needs a kid — defaults to the thumbprint.
        expect(jwk.kid).toBe(await calculateJwkThumbprint(publicJwk as JWK, 'sha256'));

        // Serializable as-is for the browser.
        expect(JSON.parse(JSON.stringify(req.request))).toEqual(req.request);
    });

    it('keeps a caller-supplied kid', async () => {
        const { publicJwk } = await createEncryptionKeypair();
        const kid = crypto.randomUUID();
        const req = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-unsigned',
                nonce: crypto.randomUUID(),
                encryptionKey: { publicJwk: { ...publicJwk, kid } as JsonWebKey },
                vpFormatsSupported: createVpFormatsSupported(),
            },
            sdJwtQuery,
        );
        const metadata = req.request.data.client_metadata as { jwks: { keys: Array<{ kid: string }> } };
        expect(metadata.jwks.keys[0].kid).toBe(kid);
    });

    it('builds a dc_api request without encryption metadata', async () => {
        const req = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-unsigned',
                nonce: crypto.randomUUID(),
                responseMode: 'dc_api',
                vpFormatsSupported: createVpFormatsSupported(),
            },
            mdocQuery,
        );
        expect(req.request.data.response_mode).toBe('dc_api');
        const metadata = req.request.data.client_metadata as Record<string, unknown>;
        expect(metadata).not.toHaveProperty('jwks');
        expect(metadata).not.toHaveProperty('encrypted_response_enc_values_supported');
    });

    it.each([
        ['missing_encryption_jwk', {}],
        ['private_key_in_jwk', { leakPrivate: true }],
        ['missing_encryption_alg', { dropAlg: true }],
        ['unsupported_enc_value', { enc: ['A192GCM'] }],
        ['empty_supported_enc_values', { enc: [] as string[] }],
    ] as const)('rejects dc_api.jwt input with %s', async (code, variant) => {
        const keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
        const publicJwk = (await crypto.subtle.exportKey('jwk', keys.publicKey)) as JsonWebKey;
        const privateJwk = (await crypto.subtle.exportKey('jwk', keys.privateKey)) as JsonWebKey;
        let encryptionKey: { publicJwk: JsonWebKey; supportedEncValues?: string[] } | undefined;
        if ('leakPrivate' in variant) encryptionKey = { publicJwk: { ...privateJwk, alg: 'ECDH-ES' } };
        else if ('dropAlg' in variant) encryptionKey = { publicJwk };
        else if ('enc' in variant)
            encryptionKey = { publicJwk: { ...publicJwk, alg: 'ECDH-ES' }, supportedEncValues: [...variant.enc] };

        await expect(
            createDcApiRequest(
                {
                    protocol: 'openid4vp-v1-unsigned',
                    nonce: crypto.randomUUID(),
                    encryptionKey,
                    vpFormatsSupported: createVpFormatsSupported(),
                },
                sdJwtQuery,
            ),
        ).rejects.toMatchObject({ name: 'DcApiRequestBuildError', code });
    });

    it('rejects a missing nonce and empty vp_formats_supported', async () => {
        await expect(
            createDcApiRequest(
                {
                    protocol: 'openid4vp-v1-unsigned',
                    nonce: '',
                    responseMode: 'dc_api',
                    vpFormatsSupported: createVpFormatsSupported(),
                },
                sdJwtQuery,
            ),
        ).rejects.toMatchObject({ code: 'missing_nonce' });
        await expect(
            createDcApiRequest(
                { protocol: 'openid4vp-v1-unsigned', nonce: crypto.randomUUID(), responseMode: 'dc_api', vpFormatsSupported: {} },
                sdJwtQuery,
            ),
        ).rejects.toMatchObject({ code: 'missing_vp_formats' });
    });

    it.each(['openid4vp-v1-multisigned', 'openid4vp', `x-${crypto.randomUUID()}`])(
        'rejects protocol "%s"',
        async (protocol) => {
            const err = await createDcApiRequest(
                {
                    protocol: protocol as 'openid4vp-v1-unsigned',
                    nonce: crypto.randomUUID(),
                    responseMode: 'dc_api',
                    vpFormatsSupported: createVpFormatsSupported(),
                },
                sdJwtQuery,
            ).catch((e: unknown) => e);
            expect(err).toBeInstanceOf(DcApiRequestBuildError);
            expect((err as DcApiRequestBuildError).code).toBe('unsupported_protocol');
        },
    );

    it('only ever names protocols from the W3C closed set', () => {
        expect([...DC_API_PRESENTATION_PROTOCOLS].sort()).toEqual(
            ['openid4vp-v1-multisigned', 'openid4vp-v1-signed', 'openid4vp-v1-unsigned', 'org-iso-mdoc'],
        );
    });
});

describe('createDcApiRequest — verifier_info (unsigned)', () => {
    it('emits verifier_info as a plain data member', async () => {
        const verifierInfo = [{ format: `x-${crypto.randomUUID()}`, data: crypto.randomUUID() }];
        const req = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-unsigned',
                nonce: crypto.randomUUID(),
                responseMode: 'dc_api',
                vpFormatsSupported: createVpFormatsSupported(),
                verifierInfo,
            },
            sdJwtQuery,
        );
        expect(req.request.data.verifier_info).toEqual(verifierInfo);
    });

    it('rejects verifierInfo whose credential_ids name no DCQL credential', async () => {
        const err = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-unsigned',
                nonce: crypto.randomUUID(),
                responseMode: 'dc_api',
                vpFormatsSupported: createVpFormatsSupported(),
                verifierInfo: [
                    {
                        format: `x-${crypto.randomUUID()}`,
                        data: crypto.randomUUID(),
                        credential_ids: [crypto.randomUUID()],
                    },
                ],
            },
            sdJwtQuery,
        ).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(DcApiRequestBuildError);
        expect((err as DcApiRequestBuildError).code).toBe('invalid_verifier_info');
    });
});

describe('createDcApiRequest — openid4vp-v1-signed', () => {
    async function signedRequest(overrides: Record<string, unknown> = {}) {
        const { publicJwk } = await createEncryptionKeypair();
        const expectedOrigins = [randomOrigin(), randomOrigin()];
        const nonce = crypto.randomUUID();
        const req = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-signed',
                nonce,
                expectedOrigins,
                encryptionKey: { publicJwk },
                vpFormatsSupported: createVpFormatsSupported(),
                signer: verifier.signer,
                certificateChain: verifier.certificateChain,
                ...overrides,
            },
            sdJwtQuery,
        );
        return { req, expectedOrigins, nonce };
    }

    it('wraps the parameters in a signed Request Object with x509_hash client_id and expected_origins', async () => {
        const { req, expectedOrigins, nonce } = await signedRequest();

        expect(req.request.protocol).toBe('openid4vp-v1-signed');
        expect(Object.keys(req.request.data)).toEqual(['request']);
        const jws = req.request.data.request as string;

        const header = decodeProtectedHeader(jws);
        expect(header.typ).toBe('oauth-authz-req+jwt');
        expect(header.alg).toBe('ES256');
        expect(header.x5c).toEqual(verifier.certificateChain.map((d) => Buffer.from(d).toString('base64')));

        const { payload } = await jwtVerify(jws, verifier.signer.publicKey);
        const leafHash = Buffer.from(
            await crypto.subtle.digest('SHA-256', verifier.certificateChain[0] as Uint8Array<ArrayBuffer>),
        ).toString('base64url');
        expect(payload.client_id).toBe(`x509_hash:${leafHash}`);
        expect(req.clientId).toBe(payload.client_id);
        expect(payload.expected_origins).toEqual(expectedOrigins);
        expect(req.expectedOrigins).toEqual(expectedOrigins);
        expect(payload.response_mode).toBe('dc_api.jwt');
        expect(payload.response_type).toBe('vp_token');
        expect(payload.nonce).toBe(nonce);
        expect(payload.dcql_query).toEqual(sdJwtQuery);
        expect(payload).not.toHaveProperty('state');
        expect(payload).not.toHaveProperty('response_uri');
        expect(payload).not.toHaveProperty('request');
        expect((payload.exp as number) - (payload.iat as number)).toBe(300);
    });

    it('supports x509_san_dns when a hostname is given', async () => {
        const { req } = await signedRequest({ clientIdPrefix: 'x509_san_dns', hostname: verifier.hostname });
        expect(decodeJwt(req.request.data.request as string).client_id).toBe(`x509_san_dns:${verifier.hostname}`);
    });

    it.each([
        ['missing_expected_origins', []],
        ['invalid_origin', ['https://shop.example/']],
        ['invalid_origin', ['https://shop.example/checkout']],
        ['invalid_origin', ['http://shop.example']],
        ['invalid_origin', ['origin:https://shop.example']],
    ])('rejects expectedOrigins with %s (%j)', async (code, expectedOrigins) => {
        await expect(signedRequest({ expectedOrigins })).rejects.toMatchObject({ code });
    });

    it('accepts an http loopback origin for local development', async () => {
        const { req } = await signedRequest({ expectedOrigins: ['http://localhost:3000'] });
        expect(req.expectedOrigins).toEqual(['http://localhost:3000']);
    });

    it('reuses the signed-request certificate checks (self-signed leaf rejected)', async () => {
        const selfSigned = await createVerifierKeypairAndCert(verifier.hostname, { selfSigned: true });
        const err = await signedRequest({
            signer: selfSigned.signer,
            certificateChain: selfSigned.certificateChain,
        }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(SignedRequestBuildError);
        expect((err as SignedRequestBuildError).code).toBe('self_signed_leaf');
    });

    it('reuses the signed-request certificate checks (trust anchor in the chain rejected)', async () => {
        const err = await signedRequest({
            certificateChain: [...verifier.certificateChain, verifier.anchorCertDer!],
        }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(SignedRequestBuildError);
        expect((err as SignedRequestBuildError).code).toBe('trust_anchor_in_chain');
    });

    it('carries verifier_info inside the signed Request Object', async () => {
        const verifierInfo = [{ format: `x-${crypto.randomUUID()}`, data: crypto.randomUUID() }];
        const { req } = await signedRequest({ verifierInfo });
        expect(decodeJwt(req.request.data.request as string).verifier_info).toEqual(verifierInfo);
    });

    it('rejects invalid verifierInfo before signing', async () => {
        const err = await signedRequest({ verifierInfo: [] }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(DcApiRequestBuildError);
        expect((err as DcApiRequestBuildError).code).toBe('invalid_verifier_info');
    });
});

// ---------------------------------------------------------------------------
// Response verification
// ---------------------------------------------------------------------------

describe('verifyDcApiResponse — SD-JWT VC', () => {
    let enc: EncryptionKeypair;
    beforeAll(async () => {
        enc = await createEncryptionKeypair();
    });

    async function encryptedResponse(vpToken: string, protocol = 'openid4vp-v1-unsigned') {
        return {
            protocol,
            data: { response: await encryptAuthorizationResponseJwe({ vp_token: { pid: [vpToken] } }, enc.publicJwk) },
        };
    }

    it('round-trips a dc_api.jwt request and response bound to origin:<origin>', async () => {
        const origin = randomOrigin();
        const req = await createDcApiRequest(
            {
                protocol: 'openid4vp-v1-unsigned',
                nonce: crypto.randomUUID(),
                encryptionKey: { publicJwk: enc.publicJwk },
                vpFormatsSupported: createVpFormatsSupported(),
            },
            sdJwtQuery,
        );
        const vp = await sdJwtPresentation({ nonce: req.nonce, audience: `origin:${origin}` });

        const result = await verifyDcApiResponse(await encryptedResponse(vp), req.dcqlQuery, {
            origin,
            nonce: req.nonce,
            responseMode: req.responseMode,
            protocol: req.request.protocol,
            decryptionKey: enc.privateKey,
            trustedCertificates: [issuerKey.certDerBytes],
        });

        expect(result.parsed.error).toBeUndefined();
        expect(result.valid).toBe(true);
        expect(result.parsed.claims).toHaveProperty('birthdate');
    });

    it('passes statusPolicy through to the credential parser', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const vp = await sdJwtPresentation({ nonce, audience: `origin:${origin}` });
        // 'require' without a statusListResolver is a configuration fault the
        // parser throws on — reaching it proves the option was forwarded.
        const err = await verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, {
            origin,
            nonce,
            decryptionKey: enc.privateKey,
            trustedCertificates: [issuerKey.certDerBytes],
            statusPolicy: 'require',
        }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(StatusListError);
        expect((err as StatusListError).reason).toBe('configuration');
    });

    it('rejects a KB-JWT whose aud is a different origin', async () => {
        const nonce = crypto.randomUUID();
        const vp = await sdJwtPresentation({ nonce, audience: `origin:${randomOrigin()}` });
        const result = await verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, {
            origin: randomOrigin(),
            nonce,
            decryptionKey: enc.privateKey,
            trustedCertificates: [issuerKey.certDerBytes],
        });
        expect(result.valid).toBe(false);
        expect(result.parsed.error).toBe('Key binding JWT aud does not match the expected audience');
    });

    it('rejects a KB-JWT whose aud is the bare origin or the client_id (signed requests still use origin:)', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        for (const audience of [origin, `x509_hash:${crypto.randomUUID()}`]) {
            const vp = await sdJwtPresentation({ nonce, audience });
            const result = await verifyDcApiResponse(
                await encryptedResponse(vp, 'openid4vp-v1-signed'),
                sdJwtQuery,
                { origin, nonce, decryptionKey: enc.privateKey, trustedCertificates: [issuerKey.certDerBytes] },
            );
            expect(result.valid).toBe(false);
            expect(result.parsed.error).toBe('Key binding JWT aud does not match the expected audience');
        }
    });

    it('rejects a wrong nonce', async () => {
        const origin = randomOrigin();
        const vp = await sdJwtPresentation({ nonce: crypto.randomUUID(), audience: `origin:${origin}` });
        const result = await verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, {
            origin,
            nonce: crypto.randomUUID(),
            decryptionKey: enc.privateKey,
            trustedCertificates: [issuerKey.certDerBytes],
        });
        expect(result.valid).toBe(false);
        expect(result.parsed.error).toBe('Key binding JWT nonce does not match');
    });

    it('requires a KB-JWT by default, even for a credential without cnf', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const vp = await sdJwtPresentation({ nonce, withHolderKey: false });
        const result = await verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, {
            origin,
            nonce,
            decryptionKey: enc.privateKey,
            trustedCertificates: [issuerKey.certDerBytes],
        });
        expect(result.valid).toBe(false);
        expect(result.parsed.error).toMatch(/Key binding JWT is required/);
    });

    it('rejects an unencrypted response when dc_api.jwt was requested', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const vp = await sdJwtPresentation({ nonce, audience: `origin:${origin}` });
        const err = await verifyDcApiResponse(
            { protocol: 'openid4vp-v1-unsigned', data: { vp_token: { pid: [vp] } } },
            sdJwtQuery,
            { origin, nonce, decryptionKey: enc.privateKey, trustedCertificates: [issuerKey.certDerBytes] },
        ).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(DcApiResponseError);
        expect((err as DcApiResponseError).code).toBe('unencrypted_response');
    });

    it('requires decryptionKey for dc_api.jwt', async () => {
        const vp = await sdJwtPresentation({ nonce: crypto.randomUUID() });
        await expect(
            verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, {
                origin: randomOrigin(),
                nonce: crypto.randomUUID(),
                trustedCertificates: [issuerKey.certDerBytes],
            }),
        ).rejects.toBeInstanceOf(MissingDecryptionKeyError);
    });

    it('verifies an unencrypted dc_api response, and rejects an encrypted one in that mode', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const vp = await sdJwtPresentation({ nonce, audience: `origin:${origin}` });
        const options = {
            origin,
            nonce,
            responseMode: 'dc_api' as const,
            trustedCertificates: [issuerKey.certDerBytes],
        };

        const ok = await verifyDcApiResponse(
            // Some integrations forward data as a JSON string; accept it.
            { protocol: 'openid4vp-v1-unsigned', data: JSON.stringify({ vp_token: { pid: [vp] } }) },
            sdJwtQuery,
            options,
        );
        expect(ok.valid).toBe(true);

        await expect(verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, options)).rejects.toMatchObject({
            code: 'unexpected_encrypted_response',
        });
    });

    it('surfaces a wallet error object as WalletErrorResponseError', async () => {
        const description = crypto.randomUUID();
        const err = await verifyDcApiResponse(
            { protocol: 'openid4vp-v1-unsigned', data: { error: 'access_denied', error_description: description } },
            sdJwtQuery,
            { origin: randomOrigin(), nonce: crypto.randomUUID(), trustedCertificates: [issuerKey.certDerBytes] },
        ).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(WalletErrorResponseError);
        expect((err as WalletErrorResponseError).code).toBe('access_denied');
        expect((err as WalletErrorResponseError).description).toBe(description);
    });

    it.each([
        ['protocol_mismatch', 'org-iso-mdoc', undefined],
        ['unsupported_protocol', 'openid4vp-v1-multisigned', undefined],
        ['unsupported_protocol', `x-${crypto.randomUUID()}`, undefined],
        ['protocol_mismatch', 'openid4vp-v1-unsigned', 'openid4vp-v1-signed'],
    ] as const)('rejects with %s for protocol %s', async (code, protocol, expectedProtocol) => {
        const vp = await sdJwtPresentation({ nonce: crypto.randomUUID() });
        await expect(
            verifyDcApiResponse(await encryptedResponse(vp, protocol), sdJwtQuery, {
                origin: randomOrigin(),
                nonce: crypto.randomUUID(),
                protocol: expectedProtocol,
                decryptionKey: enc.privateKey,
                trustedCertificates: [issuerKey.certDerBytes],
            }),
        ).rejects.toMatchObject({ name: 'DcApiResponseError', code });
    });

    it.each(['https://shop.example/', 'origin:https://shop.example', 'shop.example', 'http://shop.example'])(
        'rejects a misconfigured origin option %s',
        async (origin) => {
            const vp = await sdJwtPresentation({ nonce: crypto.randomUUID() });
            await expect(
                verifyDcApiResponse(await encryptedResponse(vp), sdJwtQuery, {
                    origin,
                    nonce: crypto.randomUUID(),
                    decryptionKey: enc.privateKey,
                    trustedCertificates: [issuerKey.certDerBytes],
                }),
            ).rejects.toMatchObject({ code: 'invalid_origin' });
        },
    );
});

describe('verifyDcApiResponse — mso_mdoc', () => {
    let enc: EncryptionKeypair;
    beforeAll(async () => {
        enc = await createEncryptionKeypair();
    });

    async function encryptedMdocResponse(transcript: Uint8Array) {
        const jwe = await encryptAuthorizationResponseJwe(
            { vp_token: { pid: [await mdocPresentation(transcript)] } },
            enc.publicJwk,
        );
        return { protocol: 'openid4vp-v1-unsigned', data: { response: jwe } };
    }

    it('verifies a dc_api.jwt DeviceResponse bound to OpenID4VPDCAPIHandover with the key thumbprint', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const transcript = await buildOpenID4VPDCAPIHandoverSessionTranscript({
            origin,
            nonce,
            verifierEncryptionJwk: enc.publicJwk,
        });

        const result = await verifyDcApiResponse(await encryptedMdocResponse(transcript), mdocQuery, {
            origin,
            nonce,
            decryptionKey: enc.privateKey,
            verifierEncryptionJwk: enc.publicJwk,
            trustedCertificates: [issuerKey.certDerBytes],
        });

        expect(result.parsed.error).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    it.each([
        ['wrong origin', { origin: true }],
        ['wrong nonce', { nonce: true }],
        ['null thumbprint under dc_api.jwt', { dropJwk: true }],
    ])('rejects a DeviceResponse with a %s', async (_label, wrong) => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const transcript = await buildOpenID4VPDCAPIHandoverSessionTranscript({
            origin: 'origin' in wrong ? randomOrigin() : origin,
            nonce: 'nonce' in wrong ? crypto.randomUUID() : nonce,
            verifierEncryptionJwk: 'dropJwk' in wrong ? undefined : enc.publicJwk,
        });

        const result = await verifyDcApiResponse(await encryptedMdocResponse(transcript), mdocQuery, {
            origin,
            nonce,
            decryptionKey: enc.privateKey,
            verifierEncryptionJwk: enc.publicJwk,
            trustedCertificates: [issuerKey.certDerBytes],
        });

        expect(result.valid).toBe(false);
        expect(result.parsed.error).toMatch(/device authentication \(DeviceSignature\) failed/);
    });

    it('rejects a DeviceResponse bound to the redirect-flow OpenID4VPHandover instead', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const transcript = await buildOpenID4VPHandoverSessionTranscript({
            clientId: `origin:${origin}`,
            nonce,
            responseUri: origin,
            verifierEncryptionJwk: enc.publicJwk,
        });
        const result = await verifyDcApiResponse(await encryptedMdocResponse(transcript), mdocQuery, {
            origin,
            nonce,
            decryptionKey: enc.privateKey,
            verifierEncryptionJwk: enc.publicJwk,
            trustedCertificates: [issuerKey.certDerBytes],
        });
        expect(result.valid).toBe(false);
        expect(result.parsed.error).toMatch(/device authentication \(DeviceSignature\) failed/);
    });

    it('verifies an unencrypted dc_api DeviceResponse with a null thumbprint', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const transcript = await buildOpenID4VPDCAPIHandoverSessionTranscript({ origin, nonce });

        const result = await verifyDcApiResponse(
            { protocol: 'openid4vp-v1-signed', data: { vp_token: { pid: [await mdocPresentation(transcript)] } } },
            mdocQuery,
            { origin, nonce, responseMode: 'dc_api', trustedCertificates: [issuerKey.certDerBytes] },
        );

        expect(result.valid).toBe(true);
    });

    it('fails loud when verifierEncryptionJwk is missing for dc_api.jwt', async () => {
        const origin = randomOrigin();
        const nonce = crypto.randomUUID();
        const transcript = await buildOpenID4VPDCAPIHandoverSessionTranscript({
            origin,
            nonce,
            verifierEncryptionJwk: enc.publicJwk,
        });
        await expect(
            verifyDcApiResponse(await encryptedMdocResponse(transcript), mdocQuery, {
                origin,
                nonce,
                decryptionKey: enc.privateKey,
                trustedCertificates: [issuerKey.certDerBytes],
            }),
        ).rejects.toBeInstanceOf(MissingVerifierEncryptionKeyError);
    });
});

describe('buildOpenID4VPDCAPIHandoverSessionTranscript', () => {
    it('matches the OpenID4VP 1.0 §B.2.6.2 example', async () => {
        // Test vector copied from the spec's non-normative example.
        const transcript = await buildOpenID4VPDCAPIHandoverSessionTranscript({
            origin: 'https://example.com',
            nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
            verifierEncryptionJwk: {
                kty: 'EC',
                crv: 'P-256',
                x: 'DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0',
                y: 'XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc',
                use: 'enc',
                alg: 'ECDH-ES',
                kid: '1',
            } as JsonWebKey,
        });
        expect(Buffer.from(transcript).toString('hex')).toBe(
            '83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4' +
                '212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a',
        );
    });

    it('refuses an origin: prefixed origin', async () => {
        await expect(
            buildOpenID4VPDCAPIHandoverSessionTranscript({ origin: `origin:${randomOrigin()}`, nonce: crypto.randomUUID() }),
        ).rejects.toThrow(TypeError);
    });
});

describe('public API', () => {
    it('exports the DC API surface from the package entry point', () => {
        expect(typeof publicApi.createDcApiRequest).toBe('function');
        expect(typeof publicApi.verifyDcApiResponse).toBe('function');
        expect(typeof publicApi.buildOpenID4VPDCAPIHandoverSessionTranscript).toBe('function');
        expect(publicApi.DcApiRequestBuildError).toBe(DcApiRequestBuildError);
        expect(publicApi.DcApiResponseError).toBe(DcApiResponseError);
        expect(publicApi.WalletErrorResponseError).toBe(WalletErrorResponseError);
        expect(publicApi.DC_API_PRESENTATION_PROTOCOLS).toBe(DC_API_PRESENTATION_PROTOCOLS);
    });
});
