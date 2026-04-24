import { describe, it, expect, beforeAll } from 'vitest';

import type { DcqlQuery } from '@openeudi/dcql';

import { MalformedCredentialError } from '../src/errors.js';
import { verifyPresentation } from '../src/verify.js';
import { StaticTrustStore } from '../src/trust/TrustStore.js';
import { getSkiHex } from '../src/trust/x509-utils.js';

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
    // NOTE on reasons: @openeudi/dcql@0.1.1 `matchQuery` collapses every
    // per-credential rejection to `no_credential_found` at its public API —
    // the internal `matchCredentialQuery` knows the specific cause
    // (format_mismatch / missing_claims / trusted_authority_mismatch / etc.)
    // but it is not surfaced. `verifyPresentation` now post-processes
    // `match.unmatched` via a local classifier (`refineUnmatched` in
    // `src/verify.ts`) that replicates dcql's internal classification logic
    // against the decoded credential so callers see specific
    // `UnmatchedReason` values. This workaround can be removed once
    // @openeudi/dcql surfaces specific reasons at the outer API.

    it('reports format_mismatch (SD-JWT vs mso_mdoc query)', async () => {
        const result = await verifyPresentation(signedSdJwtVp.sdJwt, mdlMdocQuery, {
            trustedCertificates: [issuerKey.certDerBytes],
            nonce: vpNonce,
        });

        expect(result.valid).toBe(false);
        expect(result.submission).toBeNull();
        expect(result.match.satisfied).toBe(false);
        expect(result.match.matches).toHaveLength(0);
        expect(result.match.unmatched).toHaveLength(1);
        expect(result.match.unmatched[0]).toEqual({
            queryId: 'mdl',
            reason: 'format_mismatch',
        });
    });

    it('reports missing_claims with claim-path detail', async () => {
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
        expect(result.match.unmatched[0]).toMatchObject({
            reason: 'missing_claims',
            detail: '/definitely_not_present_in_fixture_xyz',
        });
    });

    it('reports trusted_authority_mismatch', async () => {
        // 0.4.0 limitation: DecodedCredential.trusted_authority_ids is always
        // empty (parsers do not yet extract trusted-list identifiers), so any
        // query with a non-empty trusted_authorities clause fails this check.
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
            reason: 'trusted_authority_mismatch',
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

describe('verifyPresentation — trusted_authority_ids wiring (Task 17)', () => {
    // Verifies that the trust result produced by TrustEvaluator (Task 16) is
    // forwarded into DecodedCredential.trusted_authority_ids so that DCQL's
    // trusted_authorities filter can pass.
    //
    // Setup: CA-signed leaf. StaticTrustStore holds the root. TrustEvaluator
    // synthesises trustedAuthorityIds = [rootSkiHex] for static anchors
    // (deriveAuthorityIds fallback path). The DCQL query carries an 'aki'
    // filter whose value is that same SKI hex. Before Task 17 this always
    // returned trusted_authority_mismatch; after, valid: true.
    //
    // Note: synthetic-ca registers @peculiar/webcrypto as the x509 provider,
    // which is incompatible with the Node.js built-in WebCrypto used by
    // buildSignedSdJwt / generateTestKeyMaterial. We therefore build the
    // CA chain and sign the SD-JWT entirely through the peculiar provider
    // by using createLeaf's keys directly with jose (which accepts any
    // CryptoKey), and we use dynamic import to isolate the provider setup
    // from the file-level beforeAll.

    it('populates DecodedCredential.trusted_authority_ids from trust result so trusted_authorities filter passes', async () => {
        // Dynamic import avoids executing x509.cryptoProvider.set() at
        // module-load time, which would break the file-level beforeAll.
        const { createCa, createLeaf } = await import('./trust/helpers/synthetic-ca.js');

        // Build a CA → leaf certificate chain. createCa adds SKI to the root,
        // which deriveAuthorityIds uses to synthesise the trustedAuthorityIds.
        const root = await createCa({ name: 'CN=Test Root CA' });
        const leaf = await createLeaf(root, { name: 'CN=Test Issuer' });

        // Derive the root's SKI hex — TrustEvaluator will place this in
        // trustedAuthorityIds for a static-store anchor.
        const rootSkiHex = getSkiHex(root.certificate);
        expect(rootSkiHex).not.toBeNull();

        const leafDerBytes = new Uint8Array(leaf.certificate.rawData);
        const rootDerBytes = new Uint8Array(root.certificate.rawData);
        const leafX5cBase64 = Buffer.from(leafDerBytes).toString('base64');
        const rootX5cBase64 = Buffer.from(rootDerBytes).toString('base64');

        // leaf.keys are generated by @peculiar/webcrypto's SubtleCrypto.
        // Convert to Node.js built-in CryptoKey via JWK round-trip so that
        // jose (which calls crypto.subtle.sign) can use them.
        const nodePrivateKey = await toNodeCryptoKey(leaf.keys.privateKey as unknown as CryptoKey, 'sign');
        const nodePublicKey = await toNodeCryptoKey(leaf.keys.publicKey as unknown as CryptoKey, 'verify');

        const leafKeyMaterial: TestKeyMaterial = {
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
            x5cBase64: leafX5cBase64,
            certDerBytes: leafDerBytes,
        };

        // Sign a minimal PID SD-JWT under the leaf certificate.
        const sdJwt = await buildSignedSdJwt({
            issuerKey: leafKeyMaterial,
            claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
            disclosureClaims: [['age_over_18', true]],
        });

        // Build a DCQL query that requires the credential to be issued under
        // the root CA identified by its SKI hex (aki type).
        const queryWithAki: DcqlQuery = {
            credentials: [
                {
                    id: 'pid',
                    format: 'dc+sd-jwt',
                    meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] },
                    claims: [{ path: ['age_over_18'] }],
                    trusted_authorities: [
                        { type: 'aki', values: [rootSkiHex!] },
                    ],
                },
            ],
        };

        // StaticTrustStore holds both leaf and root so ChainBuilder can
        // validate the chain. SdJwtParser sends an AKI hint (= root's SKI),
        // the store resolves it to the root anchor, TrustEvaluator derives
        // trustedAuthorityIds = [rootSkiHex].
        const trustStore = new StaticTrustStore([rootDerBytes, leafDerBytes]);

        // Rebuild the issuer JWT with a full x5c chain [leaf, root] so that
        // ChainBuilder can verify without a separate trustedCertificates list.
        const chainSdJwt = sdJwt.sdJwt.replace(
            sdJwt.issuerJwt,
            await rebuildIssuerJwtWithChain(leaf, [leafX5cBase64, rootX5cBase64], sdJwt.issuerJwt)
        );

        const result = await verifyPresentation(chainSdJwt, queryWithAki, {
            trustStore,
        });

        // Task 17: trusted_authority_ids must be populated from the trust result.
        expect(result.parsed.trust?.trustedAuthorityIds).toContain(rootSkiHex);

        // The DCQL match must now succeed because trusted_authority_ids
        // includes the root SKI that the query's aki filter specifies.
        expect(result.valid).toBe(true);
        expect(result.match.satisfied).toBe(true);
    });

    it('still reports trusted_authority_mismatch when trust result has no matching id', async () => {
        // Sanity-check: when the credential IS trusted (chain validates) but
        // the query asks for a *different* authority id, the filter still
        // rejects. This distinguishes "no ids at all" from "wrong ids".
        const { createCa, createLeaf } = await import('./trust/helpers/synthetic-ca.js');

        const root = await createCa({ name: 'CN=Root A' });
        const otherRoot = await createCa({ name: 'CN=Root B' });
        const leaf = await createLeaf(root, { name: 'CN=Issuer A' });

        const otherSkiHex = getSkiHex(otherRoot.certificate)!;

        const leafDerBytes = new Uint8Array(leaf.certificate.rawData);
        const rootDerBytes = new Uint8Array(root.certificate.rawData);
        const leafX5cBase64 = Buffer.from(leafDerBytes).toString('base64');
        const rootX5cBase64 = Buffer.from(rootDerBytes).toString('base64');

        const nodePrivateKeyB = await toNodeCryptoKey(leaf.keys.privateKey as unknown as CryptoKey, 'sign');
        const nodePublicKeyB = await toNodeCryptoKey(leaf.keys.publicKey as unknown as CryptoKey, 'verify');

        const leafKeyMaterial: TestKeyMaterial = {
            privateKey: nodePrivateKeyB,
            publicKey: nodePublicKeyB,
            x5cBase64: leafX5cBase64,
            certDerBytes: leafDerBytes,
        };

        const sdJwt = await buildSignedSdJwt({
            issuerKey: leafKeyMaterial,
            claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
            disclosureClaims: [['age_over_18', true]],
        });

        const queryWithWrongAki: DcqlQuery = {
            credentials: [
                {
                    id: 'pid',
                    format: 'dc+sd-jwt',
                    meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] },
                    claims: [{ path: ['age_over_18'] }],
                    // Points to Root B's SKI, but credential is under Root A.
                    trusted_authorities: [
                        { type: 'aki', values: [otherSkiHex] },
                    ],
                },
            ],
        };

        const trustStore = new StaticTrustStore([rootDerBytes, leafDerBytes]);

        const chainSdJwt = sdJwt.sdJwt.replace(
            sdJwt.issuerJwt,
            await rebuildIssuerJwtWithChain(leaf, [leafX5cBase64, rootX5cBase64], sdJwt.issuerJwt)
        );

        const result = await verifyPresentation(chainSdJwt, queryWithWrongAki, {
            trustStore,
        });

        expect(result.valid).toBe(false);
        expect(result.match.unmatched).toHaveLength(1);
        expect(result.match.unmatched[0]).toEqual({
            queryId: 'pid',
            reason: 'trusted_authority_mismatch',
        });
    });
});

// ----------------------------------------------------------------
// Helper: rebuild issuer JWT with a multi-cert x5c chain
// ----------------------------------------------------------------

/**
 * Converts a @peculiar/webcrypto CryptoKey to a Node.js built-in CryptoKey
 * via JWK round-trip so that `jose` (which calls `crypto.subtle.sign`) can
 * use it. Both providers speak the same JWK format.
 */
async function toNodeCryptoKey(
    peculiarKey: CryptoKey,
    usage: KeyUsage
): Promise<CryptoKey> {
    const { Crypto: PeculiarCrypto } = await import('@peculiar/webcrypto');
    const provider = new PeculiarCrypto();
    const jwk = await provider.subtle.exportKey('jwk', peculiarKey);
    const isPrivate = usage === 'sign';
    return crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        [usage]
    );
}

/**
 * Decodes an existing issuer JWT's header/payload, re-signs it with the
 * leaf's private key using an updated x5c that carries the full chain.
 * This lets us reuse buildSignedSdJwt while swapping in the chain cert list.
 * The leaf key is converted from @peculiar/webcrypto to Node's built-in
 * CryptoKey so that jose can use it.
 */
async function rebuildIssuerJwtWithChain(
    leaf: { keys: { privateKey: CryptoKey } },
    x5cChain: string[],
    originalIssuerJwt: string
): Promise<string> {
    const { SignJWT } = await import('jose');

    const [rawHeader, rawPayload] = originalIssuerJwt.split('.');
    const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(rawPayload, 'base64url').toString());

    const nodePrivateKey = await toNodeCryptoKey(leaf.keys.privateKey, 'sign');

    return new SignJWT(payload)
        .setProtectedHeader({ ...header, x5c: x5cChain })
        .sign(nodePrivateKey);
}
