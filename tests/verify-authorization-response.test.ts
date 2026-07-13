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
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';
import {
    buildOid4vpSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from '../src/crypto/session-transcript.js';
import type { DcqlQuery } from '@openeudi/dcql';

function bytesToBase64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

const pidQuery: DcqlQuery = buildHaipQuery({
    credentialId: 'pid',
    format: 'dc+sd-jwt',
    vctValues: ['urn:eu.europa.ec.eudi:pid:1'],
    claims: ['given_name'],
});

let issuerKey: TestKeyMaterial;
let signedSdJwtVp: BuildSdJwtResult;
let vpNonce: string;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial('ES256');
    vpNonce = crypto.randomUUID();
    signedSdJwtVp = await buildSignedSdJwt({
        issuerKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [['given_name', 'Ada']],
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

    it('auto-builds the mDOC SessionTranscript from the JWE apu header (encrypted mso_mdoc, no caller transcript)', async () => {
        // Verifier request config that both sides agree on.
        const clientId = `x509_san_dns:verifier.${crypto.randomUUID()}.example`;
        const responseUri = `https://verifier.example/${crypto.randomUUID()}/response`;
        const nonce = crypto.randomUUID();
        const mdocGeneratedNonce = crypto.randomUUID();

        // Device-signed mDOC bound to EXACTLY the transcript the verifier will
        // re-derive from (clientId, responseUri, nonce, mdocGeneratedNonce).
        // Self-consistent: proves the wiring binds the right transcript, NOT CBOR
        // interop with an external wallet.
        const transcript = await buildOid4vpSessionTranscript({
            clientId,
            responseUri,
            nonce,
            mdocGeneratedNonce,
        });
        const mdoc = await buildSignedMdoc({
            issuerKey,
            docType: 'eu.europa.ec.eudi.pid.1',
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            sessionTranscript: transcript,
        });

        const mdocQuery = buildHaipQuery({
            credentialId: 'pid',
            format: 'mso_mdoc',
            doctypeValue: 'eu.europa.ec.eudi.pid.1',
            claims: ['age_over_18'],
        });

        // mso_mdoc VP tokens travel as base64url-encoded DeviceResponse.
        const inner = { vp_token: { pid: [bytesToBase64url(mdoc.mdocBytes)] } };
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const jwe = await encryptAuthorizationResponseJwe(
            inner,
            publicJwk,
            'A256GCM',
            mdocGeneratedNonce,
        );

        const result = await verifyAuthorizationResponse({ response: jwe }, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            decryptionKey: privateKey,
            clientId,
            responseUri,
            // NB: no mdocSessionTranscript — the library must build it from apu.
        });

        expect(result.parsed.valid).toBe(true);
        expect(result.valid).toBe(true);
    });

    it('auto-builds the OpenID4VP 1.0-Final OpenID4VPHandover SessionTranscript when sessionTranscriptProfile is "openid4vp-1.0" (encrypted mso_mdoc, no caller transcript)', async () => {
        // Verifier request config that both sides agree on.
        const clientId = `x509_san_dns:verifier.${crypto.randomUUID()}.example`;
        const responseUri = `https://verifier.example/${crypto.randomUUID()}/response`;
        const nonce = crypto.randomUUID();

        // Same keypair on both sides: the mdoc is bound to the thumbprint of
        // `publicJwk`, and the verifier passes that SAME public JWK back in as
        // `verifierEncryptionJwk` so the thumbprints match. `privateKey` is the
        // `decryptionKey` used to open the JWE.
        const { publicJwk, privateKey } = await createEncryptionKeypair();

        // Device-signed mDOC bound to EXACTLY the OpenID4VP 1.0-Final
        // OpenID4VPHandover transcript the verifier will re-derive from
        // (clientId, nonce, verifierEncryptionJwk thumbprint, responseUri).
        // Self-consistent: proves the profile selection + wiring binds the right
        // transcript, NOT CBOR interop with an external wallet/OIDF suite.
        const transcript = await buildOpenID4VPHandoverSessionTranscript({
            clientId,
            nonce,
            responseUri,
            verifierEncryptionJwk: publicJwk,
        });
        const mdoc = await buildSignedMdoc({
            issuerKey,
            docType: 'eu.europa.ec.eudi.pid.1',
            namespaces: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } },
            sessionTranscript: transcript,
        });

        const mdocQuery = buildHaipQuery({
            credentialId: 'pid',
            format: 'mso_mdoc',
            doctypeValue: 'eu.europa.ec.eudi.pid.1',
            claims: ['age_over_18'],
        });

        // mso_mdoc VP tokens travel as base64url-encoded DeviceResponse.
        const inner = { vp_token: { pid: [bytesToBase64url(mdoc.mdocBytes)] } };
        // No mdocGeneratedNonce/apu here — the 1.0-Final profile doesn't need one.
        const jwe = await encryptAuthorizationResponseJwe(inner, publicJwk, 'A256GCM');

        const result = await verifyAuthorizationResponse({ response: jwe }, mdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce,
            decryptionKey: privateKey,
            clientId,
            responseUri,
            sessionTranscriptProfile: 'openid4vp-1.0',
            verifierEncryptionJwk: publicJwk,
            // NB: no mdocSessionTranscript — the library must build it.
        });

        expect(result.parsed.valid).toBe(true);
        expect(result.valid).toBe(true);
    });

    it('rejects a malformed base64url mso_mdoc vp_token entry with a TypeError instead of silently decoding garbage', async () => {
        const mdocQuery = buildHaipQuery({
            credentialId: 'pid',
            format: 'mso_mdoc',
            doctypeValue: 'eu.europa.ec.eudi.pid.1',
            claims: ['age_over_18'],
        });
        // crypto.randomUUID() segments are valid base64url; '$' is not in the
        // base64url alphabet, so this string must fail loudly rather than decode.
        const invalidPresentation = `${crypto.randomUUID()}$${crypto.randomUUID()}`;
        const envelope = { vp_token: { pid: [invalidPresentation] } };

        await expect(
            verifyAuthorizationResponse(envelope, mdocQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: crypto.randomUUID(),
            }),
        ).rejects.toThrow(TypeError);
    });

    it('does not surface a base64url TypeError when the JWE apu header is malformed (graceful fail-closed, not a loud throw)', async () => {
        // apu is an attacker-influenceable header nonce. A malformed value must
        // stay on the documented fail-closed path (transcript left unset → mDOC
        // parser rejects), NOT raise base64UrlToBytes's loud TypeError, which is
        // reserved for the vp_token DeviceResponse decode.
        const mdocQuery = buildHaipQuery({
            credentialId: 'pid',
            format: 'mso_mdoc',
            doctypeValue: 'eu.europa.ec.eudi.pid.1',
            claims: ['age_over_18'],
        });
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        // Well-formed JWE first (jose always emits valid base64url apu), then
        // tamper the protected header so apu carries an out-of-alphabet char.
        const jwe = await encryptAuthorizationResponseJwe(
            { vp_token: { pid: ['ignored-after-tamper'] } },
            publicJwk,
            'A256GCM',
            crypto.randomUUID(),
        );
        const parts = jwe.split('.');
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        header.apu = `${crypto.randomUUID()}$${crypto.randomUUID()}`;
        parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
        const tamperedJwe = parts.join('.');

        // It still rejects (tampering breaks GCM AAD → decryption fails), but the
        // rejection must NOT be the "Invalid base64url" TypeError — that would mean
        // extractMdocGeneratedNonce threw instead of swallowing the bad apu.
        await expect(
            verifyAuthorizationResponse({ response: tamperedJwe }, mdocQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: crypto.randomUUID(),
                decryptionKey: privateKey,
                clientId: `x509_san_dns:verifier.${crypto.randomUUID()}.example`,
                responseUri: `https://verifier.example/${crypto.randomUUID()}/response`,
            }),
        ).rejects.not.toThrow(/Invalid base64url/);
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

    it('throws when vp_token entries are not arrays (structural error)', async () => {
        const malformed = { vp_token: { pid: signedSdJwtVp.sdJwt } } as unknown as {
            vp_token: Record<string, string[]>;
        };
        await expect(
            verifyAuthorizationResponse(malformed, pidQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
            }),
        ).rejects.toThrow(/must be an array/i);
    });

    it('throws on empty vp_token object (structural error)', async () => {
        await expect(
            verifyAuthorizationResponse({ vp_token: {} }, pidQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
            }),
        ).rejects.toThrow(/empty|no presentations/i);
    });
});
