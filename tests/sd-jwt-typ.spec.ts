/**
 * SD-JWT VC `typ` header — draft-ietf-oauth-sd-jwt-vc-19 alignment.
 *
 * Draft 19 (2026-09-15) removed the transitional `vc+sd-jwt` media type; the
 * issuer-signed JWT's `typ` MUST be `dc+sd-jwt`. Legacy `vc+sd-jwt` is only
 * accepted behind the deprecated `allowLegacyVcSdJwtTyp` opt-in.
 */

import { describe, it, expect } from 'vitest';

import { SdJwtParser } from '../src/parsers/sd-jwt.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import { generateTestKeyMaterial, buildSignedSdJwt, type TestKeyMaterial } from './fixtures/crypto-helpers.js';

async function build(issuerKey: TestKeyMaterial, typ: string | undefined): Promise<string> {
    const built = await buildSignedSdJwt({
        issuerKey,
        claims: { vct: `urn:test:${crypto.randomUUID()}` },
        disclosureClaims: [['age_over_18', true]],
        typ,
    });
    return built.sdJwt;
}

function options(issuerKey: TestKeyMaterial, extra: Partial<ParseOptions> = {}): ParseOptions {
    return {
        trustedCertificates: [issuerKey.certDerBytes],
        nonce: crypto.randomUUID(),
        ...extra,
    };
}

describe('SD-JWT VC typ header (draft-19)', () => {
    const parser = new SdJwtParser();

    it('accepts typ dc+sd-jwt', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const result = await parser.parse(await build(issuerKey, 'dc+sd-jwt'), options(issuerKey));
        expect(result.valid).toBe(true);
    });

    it('accepts the application/ prefixed, case-insensitive form (RFC 7515 §4.1.9)', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const result = await parser.parse(await build(issuerKey, 'application/DC+SD-JWT'), options(issuerKey));
        expect(result.valid).toBe(true);
    });

    it('rejects legacy typ vc+sd-jwt by default', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const result = await parser.parse(await build(issuerKey, 'vc+sd-jwt'), options(issuerKey));
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/vc\+sd-jwt/);
        expect(result.error).toMatch(/allowLegacyVcSdJwtTyp/);
    });

    it('accepts legacy typ vc+sd-jwt only with allowLegacyVcSdJwtTyp', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const result = await parser.parse(
            await build(issuerKey, 'vc+sd-jwt'),
            options(issuerKey, { allowLegacyVcSdJwtTyp: true }),
        );
        expect(result.valid).toBe(true);
    });

    it('rejects a missing typ', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const built = await buildSignedSdJwt({ issuerKey, claims: { vct: 'urn:test' } });
        // Re-sign without a typ header by stripping it from a fresh token.
        const { SignJWT } = await import('jose');
        const payload = JSON.parse(atob(built.issuerJwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        const jwt = await new SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256', x5c: [issuerKey.x5cBase64] })
            .sign(issuerKey.privateKey);
        const result = await parser.parse(`${jwt}~`, options(issuerKey));
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/typ/);
    });

    it('rejects an unrelated typ even with the legacy opt-in', async () => {
        const issuerKey = await generateTestKeyMaterial();
        const result = await parser.parse(
            await build(issuerKey, 'JWT'),
            options(issuerKey, { allowLegacyVcSdJwtTyp: true }),
        );
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/typ/);
    });
});
