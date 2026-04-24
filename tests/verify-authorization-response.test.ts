import { describe, it, expect, beforeAll } from 'vitest';

import { verifyAuthorizationResponse } from '../src/verify.js';
import { buildHaipQuery } from '../src/haip.js';
import {
    MissingDecryptionKeyError,
    MultipleCredentialsNotSupportedError,
    DecryptionFailedError,
} from '../src/errors.js';
import {
    buildSignedSdJwt,
    generateTestKeyMaterial,
    createEncryptionKeypair,
    encryptAuthorizationResponseJwe,
    type BuildSdJwtResult,
    type TestKeyMaterial,
} from './fixtures/crypto-helpers.js';
import type { DcqlQuery } from '@openeudi/dcql';

const pidQuery: DcqlQuery = buildHaipQuery({
    credentialId: 'pid',
    format: 'dc+sd-jwt',
    vctValues: ['urn:eudi:pid:1'],
    claims: ['given_name'],
});
const vpNonce = 'nonce-abc';

let issuerKey: TestKeyMaterial;
let signedSdJwtVp: BuildSdJwtResult;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial('ES256');
    signedSdJwtVp = await buildSignedSdJwt({
        issuerKey,
        issuer: 'https://issuer.example.com',
        vct: 'urn:eudi:pid:1',
        disclosureClaims: [['given_name', 'Ada']],
        nonce: vpNonce,
        audience: 'https://verifier.example.com/response',
        kb: true,
    });
});

describe('verifyAuthorizationResponse', () => {
    it('verifies an unencrypted envelope with single-credential single-presentation', async () => {
        const envelope = { vp_token: { pid: [signedSdJwtVp.sdJwt] } };
        const result = await verifyAuthorizationResponse(envelope, pidQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });
        expect(result.valid).toBe(true);
    });

    it('verifies an encrypted envelope (direct_post.jwt path)', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const inner = { vp_token: { pid: [signedSdJwtVp.sdJwt] } };
        const jwe = await encryptAuthorizationResponseJwe(inner, publicJwk, 'A256GCM');
        const result = await verifyAuthorizationResponse({ response: jwe }, pidQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
            decryptionKey: privateKey,
        });
        expect(result.valid).toBe(true);
    });

    it('throws MissingDecryptionKeyError when encrypted envelope arrives without decryptionKey', async () => {
        const { publicJwk } = await createEncryptionKeypair();
        const jwe = await encryptAuthorizationResponseJwe(
            { vp_token: { pid: [signedSdJwtVp.sdJwt] } },
            publicJwk,
        );
        await expect(
            verifyAuthorizationResponse({ response: jwe }, pidQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
            }),
        ).rejects.toBeInstanceOf(MissingDecryptionKeyError);
    });

    it('throws DecryptionFailedError on tampered JWE', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const jwe = await encryptAuthorizationResponseJwe(
            { vp_token: { pid: [signedSdJwtVp.sdJwt] } },
            publicJwk,
        );
        const parts = jwe.split('.');
        parts[3] = parts[3].slice(0, -4) + 'AAAA';
        await expect(
            verifyAuthorizationResponse({ response: parts.join('.') }, pidQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
                decryptionKey: privateKey,
            }),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('throws MultipleCredentialsNotSupportedError when envelope has multiple query ids', async () => {
        const envelope = {
            vp_token: {
                pid: [signedSdJwtVp.sdJwt],
                other: [signedSdJwtVp.sdJwt],
            },
        };
        await expect(
            verifyAuthorizationResponse(envelope, pidQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
            }),
        ).rejects.toMatchObject({
            name: 'MultipleCredentialsNotSupportedError',
            entryCount: 2,
        });
    });

    it('throws MultipleCredentialsNotSupportedError when one queryId has multiple presentations', async () => {
        const envelope = {
            vp_token: { pid: [signedSdJwtVp.sdJwt, signedSdJwtVp.sdJwt] },
        };
        await expect(
            verifyAuthorizationResponse(envelope, pidQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
            }),
        ).rejects.toMatchObject({
            name: 'MultipleCredentialsNotSupportedError',
            entryCount: 1,
            presentationCount: 2,
        });
    });

    it('throws on envelope missing vp_token (structural error)', async () => {
        await expect(
            verifyAuthorizationResponse(
                { state: 's' } as unknown as { vp_token: Record<string, string[]> },
                pidQuery,
                { trustedCertificates: [issuerKey.certDerBytes], nonce: vpNonce },
            ),
        ).rejects.toThrow();
    });

    it('empty vp_token object → valid:false, does not throw', async () => {
        const result = await verifyAuthorizationResponse({ vp_token: {} }, pidQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });
        expect(result.valid).toBe(false);
        expect(result.match.satisfied).toBe(false);
    });
});
