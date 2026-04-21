import { describe, it, expect, beforeAll } from 'vitest';

import type { DcqlQuery } from '@openeudi/dcql';

import { MalformedCredentialError } from '../src/errors.js';
import { verifyPresentation } from '../src/verify.js';

import {
    pidSdJwtQuery,
    pidAgeOnlyQuery,
    pidWithTrustedAuthorities,
} from './fixtures/dcql-queries/pid-sd-jwt.js';
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

describe('verifyPresentation — mismatch paths (valid: false)', () => {
    // NOTE on reasons: @openeudi/dcql@0.1.1 `matchQuery` wraps every per-credential
    // rejection in an outer `no_credential_found` entry — the specific cause
    // (format_mismatch / missing_claims / trusted_authority_mismatch / etc.) is
    // *not* surfaced in `match.unmatched[*].reason`. Claim-path rejections leave
    // a JSON-pointer in `detail`; category rejections like format and
    // trusted_authority leave `detail` undefined. We assert what the library
    // actually exposes rather than the internal precedence documented in
    // `UnmatchedReason`.

    it('reports no_credential_found for format_mismatch (SD-JWT vs mso_mdoc query)', async () => {
        const result = await verifyPresentation(signedSdJwtVp.sdJwt, mdlMdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.valid).toBe(false);
        expect(result.submission).toBeNull();
        expect(result.match.satisfied).toBe(false);
        expect(result.match.matches).toHaveLength(0);
        expect(result.match.unmatched).toHaveLength(1);
        // Format mismatch: library reports no_credential_found with no detail
        // (matchCredentialQuery returns { reason: 'format_mismatch' } without
        // a `detail`, so lastDetail stays undefined in the outer loop).
        expect(result.match.unmatched[0]).toEqual({
            queryId: 'mdl',
            reason: 'no_credential_found',
        });
    });

    it('reports no_credential_found with claim-path detail for missing_claims', async () => {
        const missingClaimQuery: DcqlQuery = {
            credentials: [
                {
                    id: 'pid',
                    format: 'dc+sd-jwt',
                    meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] },
                    claims: [{ path: ['definitely_not_present_in_fixture_xyz'] }],
                },
            ],
        };

        const result = await verifyPresentation(signedSdJwtVp.sdJwt, missingClaimQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.valid).toBe(false);
        expect(result.submission).toBeNull();
        expect(result.match.satisfied).toBe(false);
        expect(result.match.unmatched).toHaveLength(1);
        expect(result.match.unmatched[0].queryId).toBe('pid');
        expect(result.match.unmatched[0].reason).toBe('no_credential_found');
        // Claim-path rejections propagate the JSON pointer via `detail`.
        expect(result.match.unmatched[0].detail).toBe(
            '/definitely_not_present_in_fixture_xyz'
        );
    });

    it('reports no_credential_found for trusted_authority_mismatch', async () => {
        // 0.4.0 limitation: DecodedCredential.trusted_authority_ids is always
        // empty (parsers do not yet extract trusted-list identifiers), so any
        // query with a non-empty trusted_authorities clause fails this check
        // inside matchCredentialQuery. The outer matchQuery wraps that as
        // no_credential_found with no detail (trusted_authority_mismatch does
        // not populate a `detail` field).
        const result = await verifyPresentation(signedSdJwtVp.sdJwt, pidWithTrustedAuthorities, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.valid).toBe(false);
        expect(result.submission).toBeNull();
        expect(result.match.satisfied).toBe(false);
        expect(result.match.unmatched).toHaveLength(1);
        expect(result.match.unmatched[0]).toEqual({
            queryId: 'pid',
            reason: 'no_credential_found',
        });
    });
});

describe('verifyPresentation — error paths (throws)', () => {
    // NOTE: The plan speculated about two throw cases. Reality:
    //   - Empty query (`{ credentials: [] }`) is tolerated by matchQuery —
    //     it returns `{ satisfied: true, matches: [], unmatched: [] }`, not
    //     a DcqlValidationError. That test was removed as a non-throw case.
    //   - `validateQuery` would reject an empty credentials array, but
    //     verifyPresentation deliberately calls matchQuery directly to expose
    //     per-claim diagnostics, so the tolerant path is what ships.
    //   - A non-SD-JWT / non-mDOC string ('not-a-real-vp-token') fails the
    //     parsers' canParse checks entirely. parsePresentation returns a
    //     PresentationResult with `valid: false, error: 'Unsupported
    //     credential format'` — it does NOT throw. Tested below.
    //   - Only a string that *looks* like SD-JWT (contains '~') but has a
    //     malformed issuer JWT reaches the throw path.

    it('throws MalformedCredentialError for SD-JWT-shaped garbage', async () => {
        // Contains '~' so SdJwtParser.canParse returns true, but the issuer
        // JWT header cannot be decoded → MalformedCredentialError.
        await expect(
            verifyPresentation('bad~thing~', pidAgeOnlyQuery, {
                trustedCertificates: [issuerKey.certDerBytes],
                nonce: vpNonce,
            })
        ).rejects.toBeInstanceOf(MalformedCredentialError);
    });

    it('returns valid:false (does not throw) for completely unrecognized tokens', async () => {
        // No '~' and not a Uint8Array → no parser matches → parsePresentation
        // returns an "Unsupported credential format" PresentationResult.
        // verifyPresentation then builds a DecodedCredential with empty claims,
        // which matchQuery tolerates as no_credential_found. Nothing throws.
        const result = await verifyPresentation('not-a-real-vp-token', pidAgeOnlyQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.valid).toBe(false);
        expect(result.parsed.valid).toBe(false);
        expect(result.parsed.error).toBe('Unsupported credential format');
        expect(result.match.satisfied).toBe(false);
        expect(result.submission).toBeNull();
    });
});
