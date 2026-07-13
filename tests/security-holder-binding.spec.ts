/**
 * Security regression — holder-binding / nonce replay protection
 * (GHSA-h548-cr7v-4v97)
 * ============================================================================
 * Before the fix, key-binding verification for SD-JWT VC was gated behind
 * `if (parts.kbJwt)`, so an attacker could strip the trailing KB-JWT to bypass
 * holder proof-of-possession AND the nonce/replay check and still get
 * `valid: true`. These tests assert the SECURE (post-fix) behaviour.
 *
 * The mDOC leg of the advisory (DeviceAuth never verified) is covered by the
 * second describe block: the parser now fails closed unless a valid
 * DeviceSignature over the caller-supplied SessionTranscript is present.
 */

import { describe, it, expect } from 'vitest';

import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';
import { MdocParser } from '../src/parsers/mdoc.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import { generateTestKeyMaterial, buildSignedSdJwt } from './fixtures/crypto-helpers.js';
import { buildSignedMdoc, DEFAULT_TEST_SESSION_TRANSCRIPT } from './fixtures/mdoc-helpers.js';

describe('SD-JWT VC holder binding is enforced (GHSA-h548-cr7v-4v97)', () => {
    it('A1: rejects a holder-bound credential presented WITHOUT a KB-JWT (strip attack)', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const holderKey = await generateTestKeyMaterial();

        const built = await buildSignedSdJwt({
            issuerKey,
            holderKey, // -> issuer JWT carries cnf.jwk (holder-bound)
            disclosureClaims: [['age_over_18', true]],
            nonce: 'verifier-A-nonce',
            typ: 'vc+sd-jwt',
        });

        // Attacker drops the KB-JWT and replays to a fresh verifier/nonce.
        const strippedNoKb = `${built.issuerJwt}~${built.disclosures.join('~')}~`;

        const res = await new SdJwtParser().parse(strippedNoKb, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'verifier-B-FRESH-nonce',
        } as ParseOptions);

        expect(res.valid).toBe(false);
    });

    it('A2: still accepts a genuine, KB-bound presentation with the matching nonce (no regression)', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const holderKey = await generateTestKeyMaterial();

        const built = await buildSignedSdJwt({
            issuerKey,
            holderKey,
            disclosureClaims: [['age_over_18', true]],
            nonce: 'verifier-A-nonce',
            typ: 'vc+sd-jwt',
        });

        const res = await new SdJwtParser().parse(built.sdJwt, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'verifier-A-nonce',
        } as ParseOptions);

        expect(res.valid).toBe(true);
        expect(res.claims.age_over_18).toBe(true);
    });

    it('A3: rejects replay of a KB-bound presentation to a different nonce', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const holderKey = await generateTestKeyMaterial();

        // KB-JWT is bound to nonce A ...
        const built = await buildSignedSdJwt({
            issuerKey,
            holderKey,
            disclosureClaims: [['age_over_18', true]],
            nonce: 'verifier-A-nonce',
            typ: 'vc+sd-jwt',
        });

        // ... replayed verbatim to verifier B which challenged with nonce B.
        const res = await new SdJwtParser().parse(built.sdJwt, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'verifier-B-nonce',
        } as ParseOptions);

        expect(res.valid).toBe(false);
    });

    it('A4: requireKeyBinding forces rejection of a non-holder-bound credential lacking a KB-JWT', async () => {
        const issuerKey = await generateTestKeyMaterial();

        // No holderKey -> issuer JWT has no cnf -> not holder-bound.
        const built = await buildSignedSdJwt({
            issuerKey,
            disclosureClaims: [['age_over_18', true]],
            typ: 'vc+sd-jwt',
        });

        const res = await new SdJwtParser().parse(built.sdJwt, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'verifier-nonce',
            requireKeyBinding: true,
        } as ParseOptions);

        expect(res.valid).toBe(false);
    });

});

describe('mDOC device authentication is enforced (GHSA-h548-cr7v-4v97 Finding B)', () => {
    const ns = { 'eu.europa.ec.eudi.pid.1': { age_over_18: true } };

    it('B1: rejects a DeviceResponse with NO deviceSigned/DeviceAuth (strip attack)', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const built = await buildSignedMdoc({ issuerKey, namespaces: ns, omitDeviceAuth: true });

        const res = await new MdocParser().parse(built.mdocBytes, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'n',
            mdocSessionTranscript: DEFAULT_TEST_SESSION_TRANSCRIPT,
        } as ParseOptions);

        expect(res.valid).toBe(false);
    });

    it('B2: accepts a genuine DeviceResponse with a valid DeviceSignature (no regression)', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const built = await buildSignedMdoc({ issuerKey, namespaces: ns });

        const res = await new MdocParser().parse(built.mdocBytes, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'n',
            mdocSessionTranscript: built.sessionTranscript,
        } as ParseOptions);

        expect(res.valid).toBe(true);
        expect(res.claims.age_over_18).toBe(true);
    });

    it('B3: rejects replay of a DeviceResponse to a different SessionTranscript', async () => {
        const issuerKey = await generateTestKeyMaterial();
        // DeviceSignature is bound to the default SessionTranscript ...
        const built = await buildSignedMdoc({ issuerKey, namespaces: ns });

        // ... but the verifier's session used a different transcript.
        const res = await new MdocParser().parse(built.mdocBytes, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'n',
            mdocSessionTranscript: new Uint8Array([0xf6]), // CBOR null — a different, valid item
        } as ParseOptions);

        expect(res.valid).toBe(false);
    });

    it('B4: rejects when no SessionTranscript is supplied (cannot verify device auth)', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const built = await buildSignedMdoc({ issuerKey, namespaces: ns });

        const res = await new MdocParser().parse(built.mdocBytes, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'n',
            // mdocSessionTranscript intentionally omitted
        } as ParseOptions);

        expect(res.valid).toBe(false);
    });
});
