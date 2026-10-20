import { describe, it, expect, beforeAll } from 'vitest';
import type { DcqlQuery } from '@openeudi/dcql';

import { verifyAuthorizationResponse } from '../src/verify.js';
import { buildHaipQuery } from '../src/haip.js';
import {
    buildOid4vpSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from '../src/crypto/session-transcript.js';
import {
    generateTestKeyMaterial,
    createEncryptionKeypair,
    encryptAuthorizationResponseJwe,
    buildSignedSdJwt,
    type TestKeyMaterial,
} from './fixtures/crypto-helpers.js';
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';

// OV-5: OpenID4VP 1.0 Final §B.2.6.1 OpenID4VPHandover is the default mDOC
// SessionTranscript profile, and it is auto-built for unencrypted direct_post
// envelopes too (with a null thumbprint).

function bytesToBase64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

const DOCTYPE = 'eu.europa.ec.eudi.pid.1';

let issuerKey: TestKeyMaterial;
let mdocQuery: DcqlQuery;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial('ES256');
    mdocQuery = buildHaipQuery({
        credentialId: 'pid',
        format: 'mso_mdoc',
        doctypeValue: DOCTYPE,
        claims: ['age_over_18'],
    });
});

function randomRequestConfig() {
    return {
        clientId: `x509_hash:${crypto.randomUUID()}`,
        responseUri: `https://verifier-${crypto.randomUUID()}.example/response`,
        nonce: crypto.randomUUID(),
    };
}

async function mdocBoundTo(sessionTranscript: Uint8Array): Promise<string> {
    const mdoc = await buildSignedMdoc({
        issuerKey,
        docType: DOCTYPE,
        namespaces: { [DOCTYPE]: { age_over_18: true } },
        sessionTranscript,
    });
    return bytesToBase64url(mdoc.mdocBytes);
}

describe('mDOC SessionTranscript default profile (OpenID4VP 1.0)', () => {
    it('verifies an encrypted response bound to the 1.0 OpenID4VPHandover without naming a profile', async () => {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const transcript = await buildOpenID4VPHandoverSessionTranscript({
            clientId,
            nonce,
            responseUri,
            verifierEncryptionJwk: publicJwk,
        });
        const jwe = await encryptAuthorizationResponseJwe(
            { vp_token: { pid: [await mdocBoundTo(transcript)] } },
            publicJwk,
        );

        const result = await verifyAuthorizationResponse({ response: jwe }, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            decryptionKey: privateKey,
            clientId,
            responseUri,
            verifierEncryptionJwk: publicJwk,
        });

        expect(result.parsed.error).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    it('auto-builds the null-thumbprint 1.0 transcript for an unencrypted direct_post envelope', async () => {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const transcript = await buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri });
        const envelope = { vp_token: { pid: [await mdocBoundTo(transcript)] } };

        const result = await verifyAuthorizationResponse(envelope, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            clientId,
            responseUri,
        });

        expect(result.parsed.error).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    it('ignores verifierEncryptionJwk for an unencrypted envelope (the spec requires a null thumbprint)', async () => {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const { publicJwk } = await createEncryptionKeypair();
        const transcript = await buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri });
        const envelope = { vp_token: { pid: [await mdocBoundTo(transcript)] } };

        const result = await verifyAuthorizationResponse(envelope, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            clientId,
            responseUri,
            verifierEncryptionJwk: publicJwk,
        });

        expect(result.valid).toBe(true);
    });

    it('rejects an unencrypted response whose device signature covers a different response_uri', async () => {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const transcript = await buildOpenID4VPHandoverSessionTranscript({
            clientId,
            nonce,
            responseUri: `https://attacker-${crypto.randomUUID()}.example/response`,
        });
        const envelope = { vp_token: { pid: [await mdocBoundTo(transcript)] } };

        const result = await verifyAuthorizationResponse(envelope, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            clientId,
            responseUri,
        });

        expect(result.valid).toBe(false);
    });

    it('does not require verifierEncryptionJwk for an encrypted SD-JWT VC response under the default profile', async () => {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const sdJwtQuery = buildHaipQuery({
            credentialId: 'pid',
            format: 'dc+sd-jwt',
            vctValues: ['urn:eu.europa.ec.eudi:pid:1'],
            claims: ['given_name'],
        });
        // 0.14.0 enforces holder binding and the KB-JWT `aud` (= clientId).
        const holderKey = await generateTestKeyMaterial('ES256');
        const sdJwt = await buildSignedSdJwt({
            issuerKey,
            holderKey,
            nonce,
            audience: clientId,
            claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
            disclosureClaims: [['given_name', crypto.randomUUID()]],
        });
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const jwe = await encryptAuthorizationResponseJwe({ vp_token: { pid: [sdJwt.sdJwt] } }, publicJwk);

        const result = await verifyAuthorizationResponse({ response: jwe }, sdJwtQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            decryptionKey: privateKey,
            clientId,
            responseUri,
        });

        expect(result.valid).toBe(true);
    });
});

describe('legacy Annex B SessionTranscript profile', () => {
    async function legacyEncryptedResponse() {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const mdocGeneratedNonce = crypto.randomUUID();
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const transcript = await buildOid4vpSessionTranscript({
            clientId,
            responseUri,
            nonce,
            mdocGeneratedNonce,
        });
        const jwe = await encryptAuthorizationResponseJwe(
            { vp_token: { pid: [await mdocBoundTo(transcript)] } },
            publicJwk,
            'A256GCM',
            mdocGeneratedNonce,
        );
        return { clientId, responseUri, nonce, publicJwk, privateKey, jwe };
    }

    it('fails a DeviceResponse built against the legacy handover under the default profile', async () => {
        const { clientId, responseUri, nonce, publicJwk, privateKey, jwe } = await legacyEncryptedResponse();

        const result = await verifyAuthorizationResponse({ response: jwe }, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            decryptionKey: privateKey,
            clientId,
            responseUri,
            verifierEncryptionJwk: publicJwk,
        });

        expect(result.valid).toBe(false);
        expect(result.parsed.valid).toBe(false);
    });

    it.each(['oid4vp-draft-annex-b', 'iso-18013-7'] as const)(
        'passes the same DeviceResponse with sessionTranscriptProfile "%s"',
        async (sessionTranscriptProfile) => {
            const { clientId, responseUri, nonce, privateKey, jwe } = await legacyEncryptedResponse();

            const result = await verifyAuthorizationResponse({ response: jwe }, mdocQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce,
                decryptionKey: privateKey,
                clientId,
                responseUri,
                sessionTranscriptProfile,
            });

            expect(result.valid).toBe(true);
        },
    );

    it('builds nothing for an unencrypted envelope (no apu), so the mDOC parser fails closed', async () => {
        const { clientId, responseUri, nonce } = randomRequestConfig();
        const transcript = await buildOpenID4VPHandoverSessionTranscript({ clientId, nonce, responseUri });
        const envelope = { vp_token: { pid: [await mdocBoundTo(transcript)] } };

        const result = await verifyAuthorizationResponse(envelope, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            clientId,
            responseUri,
            sessionTranscriptProfile: 'oid4vp-draft-annex-b',
        });

        expect(result.valid).toBe(false);
        expect(result.parsed.error).toMatch(/mdocSessionTranscript is required/);
    });
});
