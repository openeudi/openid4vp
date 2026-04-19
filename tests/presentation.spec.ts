import { describe, it, expect, beforeAll } from 'vitest';

import type { ParseOptions } from '../src/parsers/parser.interface.js';
import { parsePresentation } from '../src/presentation.js';

import {
    generateTestKeyMaterial,
    buildSignedSdJwt,
    type TestKeyMaterial,
    type BuildSdJwtResult,
} from './fixtures/crypto-helpers.js';
import { VALID_MDOC, FAKE_MDOC_CERT } from './fixtures/mdoc-samples.js';

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
    });

    it('auto-detects and parses mDOC format', async () => {
        const result = await parsePresentation(VALID_MDOC, {
            trustedCertificates: [FAKE_MDOC_CERT],
            nonce: 'test-nonce-456',
        });
        expect(result.format).toBe('mdoc');
        expect(result.valid).toBe(true);
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
