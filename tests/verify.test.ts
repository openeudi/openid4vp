import { describe, it, expect, beforeAll } from 'vitest';

import { verifyPresentation } from '../src/verify.js';

import { pidSdJwtQuery, pidAgeOnlyQuery } from './fixtures/dcql-queries/pid-sd-jwt.js';
import { mdlMdocQuery } from './fixtures/dcql-queries/mdl-mdoc.js';
import {
    generateTestKeyMaterial,
    buildSignedSdJwt,
    type TestKeyMaterial,
    type BuildSdJwtResult,
} from './fixtures/crypto-helpers.js';
import { buildSignedMdoc, type BuildSignedMdocResult } from './fixtures/mdoc-helpers.js';

let issuerKey: TestKeyMaterial;
let signedSdJwtVp: BuildSdJwtResult;
let signedMdocVp: BuildSignedMdocResult;
let vpNonce: string;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial();
    vpNonce = crypto.randomUUID();

    signedSdJwtVp = await buildSignedSdJwt({
        issuerKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [
            ['age_over_18', true],
            ['given_name', 'Ada'],
        ],
    });

    signedMdocVp = await buildSignedMdoc({
        issuerKey,
        namespaces: {
            'eu.europa.ec.eudi.pid.1': { age_over_18: true },
        },
    });
});

describe('verifyPresentation — happy paths', () => {
    it('matches an SD-JWT VP against a single-claim query', async () => {
        const result = await verifyPresentation(signedSdJwtVp.sdJwt, pidAgeOnlyQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.parsed.valid).toBe(true);
        expect(result.match.satisfied).toBe(true);
        expect(result.submission).not.toBeNull();
        expect(result.valid).toBe(true);
    });

    it('matches an SD-JWT VP against a multi-claim query', async () => {
        const result = await verifyPresentation(signedSdJwtVp.sdJwt, pidSdJwtQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.valid).toBe(true);
        expect(result.match.matches).toHaveLength(1);
        expect(result.match.matches[0].queryId).toBe('pid');
    });

    it('matches an mDOC VP against an mso_mdoc query', async () => {
        const result = await verifyPresentation(signedMdocVp.mdocBytes, mdlMdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.parsed.valid).toBe(true);
        expect(result.match.satisfied).toBe(true);
        expect(result.valid).toBe(true);
    });
});
