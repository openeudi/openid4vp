import { describe, it, expect } from 'vitest';

import { parsePresentation } from '../src/presentation.js';

import { VALID_MDOC, FAKE_MDOC_CERT } from './fixtures/mdoc-samples.js';
import { VALID_SD_JWT, VALID_SD_JWT_NONCE, FAKE_CERT_UINT8 } from './fixtures/sd-jwt-samples.js';

describe('parsePresentation', () => {
    it('auto-detects and parses SD-JWT format', async () => {
        const result = await parsePresentation(VALID_SD_JWT, {
            trustedCertificates: [FAKE_CERT_UINT8],
            nonce: VALID_SD_JWT_NONCE,
        });
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
            nonce: 'test',
        });
        expect(result.valid).toBe(false);
        expect(result.error).toContain('Unsupported');
    });
});
