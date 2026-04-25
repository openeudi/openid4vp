import { describe, it, expect } from 'vitest';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import { createSignedAuthorizationRequest } from '../src/signed-authorization.js';
import { buildHaipQuery } from '../src/haip.js';
import { SignedRequestBuildError } from '../src/errors.js';
import type { DcqlQuery } from '@openeudi/dcql';
import {
    createVerifierKeypairAndCert,
    createEncryptionKeypair,
    createVpFormatsSupported,
} from './fixtures/crypto-helpers.js';

const pidQuery: DcqlQuery = buildHaipQuery({
    credentialId: 'pid',
    format: 'dc+sd-jwt',
    vctValues: ['urn:eudi:pid:1'],
    claims: ['given_name'],
});

describe('createSignedAuthorizationRequest', () => {
    const hostname = 'verifier.example.com';

    async function baseInput(overrides: Record<string, unknown> = {}) {
        const { signer, certificateChain } = await createVerifierKeypairAndCert(hostname);
        const { publicJwk } = await createEncryptionKeypair();
        return {
            hostname,
            requestUri: 'https://verifier.example.com/request.jwt',
            responseUri: 'https://verifier.example.com/response',
            nonce: 'test-nonce-abc',
            signer,
            certificateChain,
            encryptionKey: { publicJwk },
            vpFormatsSupported: createVpFormatsSupported(),
            ...overrides,
        };
    }

    it('emits the short URI with only client_id and request_uri', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;
        expect(req.uri.startsWith('openid4vp://authorize?')).toBe(true);
        expect(params.get('client_id')).toBe(`x509_san_dns:${hostname}`);
        expect(params.get('request_uri')).toBe('https://verifier.example.com/request.jwt');
        expect([...params.keys()].sort()).toEqual(['client_id', 'request_uri']);
    });

    it('returns a JWS requestObject with typ oauth-authz-req+jwt and x5c header', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        const header = decodeProtectedHeader(req.requestObject);
        expect(header.typ).toBe('oauth-authz-req+jwt');
        expect(header.alg).toBe('ES256');
        expect(Array.isArray(header.x5c)).toBe(true);
        expect((header.x5c as string[]).length).toBeGreaterThan(0);
    });

    it('payload has required OpenID4VP 1.0 claims', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        const payload = decodeJwt(req.requestObject);
        expect(payload.response_type).toBe('vp_token');
        expect(payload.client_id).toBe(`x509_san_dns:${hostname}`);
        expect(payload.response_uri).toBe('https://verifier.example.com/response');
        expect(payload.nonce).toBe('test-nonce-abc');
        expect(payload.aud).toBe('https://self-issued.me/v2');
        expect(payload.dcql_query).toEqual(pidQuery);
        expect(typeof payload.iat).toBe('number');
        expect(typeof payload.exp).toBe('number');
    });

    it('payload does NOT include client_id_scheme (derived from client_id prefix per 1.0 §5.9.1)', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        const payload = decodeJwt(req.requestObject);
        expect(payload.client_id_scheme).toBeUndefined();
    });

    it('defaults responseMode to direct_post.jwt', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        const payload = decodeJwt(req.requestObject);
        expect(payload.response_mode).toBe('direct_post.jwt');
    });

    it('direct_post.jwt payload includes client_metadata with jwks + encrypted_response_enc_values_supported', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        const payload = decodeJwt(req.requestObject);
        const cm = payload.client_metadata as Record<string, unknown>;
        expect(cm.vp_formats_supported).toBeDefined();
        expect(cm.jwks).toBeDefined();
        expect(cm.encrypted_response_enc_values_supported).toEqual(['A128GCM', 'A256GCM']);
        const keys = (cm.jwks as { keys: JsonWebKey[] }).keys;
        expect(keys[0].use).toBe('enc');
        expect(keys[0].alg).toBe('ECDH-ES');
    });

    it('direct_post payload has vp_formats_supported but NO jwks or encrypted_response_enc_values_supported', async () => {
        const req = await createSignedAuthorizationRequest(
            await baseInput({ responseMode: 'direct_post', encryptionKey: undefined }),
            pidQuery
        );
        const payload = decodeJwt(req.requestObject);
        const cm = payload.client_metadata as Record<string, unknown>;
        expect(cm.vp_formats_supported).toBeDefined();
        expect(cm.jwks).toBeUndefined();
        expect(cm.encrypted_response_enc_values_supported).toBeUndefined();
    });

    it('honors a caller-supplied state', async () => {
        const req = await createSignedAuthorizationRequest(
            await baseInput({ state: 'provided-state-xyz' }),
            pidQuery
        );
        expect(req.state).toBe('provided-state-xyz');
        const payload = decodeJwt(req.requestObject);
        expect(payload.state).toBe('provided-state-xyz');
    });

    it('generates a state when caller omits it', async () => {
        const req = await createSignedAuthorizationRequest(await baseInput(), pidQuery);
        expect(typeof req.state).toBe('string');
        expect(req.state.length).toBeGreaterThan(0);
    });

    it('rejects empty cert chain with empty_cert_chain', async () => {
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({ certificateChain: [] }),
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'empty_cert_chain',
        });
    });

    it('rejects hostname not in leaf cert SAN with hostname_cert_mismatch', async () => {
        const { signer, certificateChain } = await createVerifierKeypairAndCert('other.example.com');
        const { publicJwk } = await createEncryptionKeypair();
        await expect(
            createSignedAuthorizationRequest(
                {
                    hostname: 'verifier.example.com', // does NOT match cert SAN
                    requestUri: 'https://verifier.example.com/request.jwt',
                    responseUri: 'https://verifier.example.com/response',
                    nonce: 'n',
                    signer,
                    certificateChain,
                    encryptionKey: { publicJwk },
                    vpFormatsSupported: createVpFormatsSupported(),
                },
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'hostname_cert_mismatch',
        });
    });

    it('rejects signing key whose public SPKI does not match leaf cert with signing_key_cert_mismatch', async () => {
        const { certificateChain } = await createVerifierKeypairAndCert(hostname);
        // Generate a DIFFERENT keypair — public SPKI will not match certificateChain[0].
        const mismatchedSigner = (await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        )) as CryptoKeyPair;
        const { publicJwk } = await createEncryptionKeypair();
        await expect(
            createSignedAuthorizationRequest(
                {
                    hostname,
                    requestUri: 'https://verifier.example.com/request.jwt',
                    responseUri: 'https://verifier.example.com/response',
                    nonce: 'n',
                    signer: mismatchedSigner,
                    certificateChain,
                    encryptionKey: { publicJwk },
                    vpFormatsSupported: createVpFormatsSupported(),
                },
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'signing_key_cert_mismatch',
        });
    });

    it('rejects direct_post.jwt without encryption key with missing_encryption_jwk', async () => {
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({ responseMode: 'direct_post.jwt', encryptionKey: undefined }),
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'missing_encryption_jwk',
        });
    });

    it('rejects encryption JWK without alg with missing_encryption_alg', async () => {
        const { publicJwk } = await createEncryptionKeypair();
        delete publicJwk.alg;
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({ encryptionKey: { publicJwk } }),
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'missing_encryption_alg',
        });
    });

    it('rejects unsupported signing algorithm with unsupported_signing_alg', async () => {
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({ signingAlgorithm: 'PS512' as unknown as 'ES256' }),
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'unsupported_signing_alg',
        });
    });

    it('rejects empty vpFormatsSupported with missing_vp_formats', async () => {
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({ vpFormatsSupported: {} }),
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'missing_vp_formats',
        });
    });

    it('allows caller to override supportedEncValues', async () => {
        const { publicJwk } = await createEncryptionKeypair();
        const req = await createSignedAuthorizationRequest(
            await baseInput({
                encryptionKey: { publicJwk, supportedEncValues: ['A256GCM'] },
            }),
            pidQuery
        );
        const payload = decodeJwt(req.requestObject);
        const cm = payload.client_metadata as { encrypted_response_enc_values_supported: string[] };
        expect(cm.encrypted_response_enc_values_supported).toEqual(['A256GCM']);
    });

    it('rejects empty supportedEncValues array with empty_supported_enc_values', async () => {
        const { publicJwk } = await createEncryptionKeypair();
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({
                    encryptionKey: { publicJwk, supportedEncValues: [] },
                }),
                pidQuery
            )
        ).rejects.toMatchObject({
            name: 'SignedRequestBuildError',
            code: 'empty_supported_enc_values',
        });
    });

    it('exposes error as instanceof SignedRequestBuildError', async () => {
        await expect(
            createSignedAuthorizationRequest(
                await baseInput({ certificateChain: [] }),
                pidQuery
            )
        ).rejects.toBeInstanceOf(SignedRequestBuildError);
    });
});
