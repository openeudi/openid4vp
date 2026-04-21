import { describe, it, expect, beforeAll } from 'vitest';

import type { ParseOptions } from '../src/parsers/parser.interface.js';
import { parsePresentation } from '../src/presentation.js';

import {
    generateTestKeyMaterial,
    buildSignedSdJwt,
    type TestKeyMaterial,
    type BuildSdJwtResult,
} from './fixtures/crypto-helpers.js';
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';

let issuerKey: TestKeyMaterial;
let validSdJwt: BuildSdJwtResult;
let validNonce: string;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial();
    validNonce = crypto.randomUUID();

    validSdJwt = await buildSignedSdJwt({
        issuerKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [['age_over_18', true]],
    });
});

describe('parsePresentation', () => {
    it('auto-detects and parses SD-JWT format', async () => {
        const options: ParseOptions = {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: validNonce,
        };
        const result = await parsePresentation(validSdJwt.sdJwt, options);
        expect(result.format).toBe('sd-jwt-vc');
        expect(result.valid).toBe(true);
        // 0.4.0: parsers now expose `vct` for sd-jwt-vc (used by DCQL matcher).
        expect(result.vct).toBe('urn:eu.europa.ec.eudi:pid:1');
    });

    it('auto-detects and parses mDOC format', async () => {
        const mdocNamespace = 'eu.europa.ec.eudi.pid.1';
        const { mdocBytes } = await buildSignedMdoc({
            issuerKey,
            namespaces: {
                [mdocNamespace]: { age_over_18: true },
            },
        });
        const result = await parsePresentation(mdocBytes, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: 'n',
        });
        expect(result.format).toBe('mdoc');
        expect(result.valid).toBe(true);
        // 0.4.0: parsers now expose `docType` and `namespacedClaims` for mdoc
        // (used by DCQL matcher with path shape ['namespace', 'attribute']).
        expect(typeof result.docType).toBe('string');
        expect(result.docType?.length ?? 0).toBeGreaterThan(0);
        expect(result.namespacedClaims).toBeDefined();
        expect(result.namespacedClaims).toHaveProperty(mdocNamespace);
        expect(result.namespacedClaims?.[mdocNamespace]).toMatchObject({
            age_over_18: true,
        });
    });

    it('returns invalid for unrecognized format', async () => {
        const result = await parsePresentation(12345, {
            trustedCertificates: [],
            skipTrustCheck: true,
            nonce: 'test',
        });
        expect(result.valid).toBe(false);
        expect(result.error).toContain('Unsupported');
    });
});
