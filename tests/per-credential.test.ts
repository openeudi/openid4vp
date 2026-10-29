/**
 * `perCredential`: per-DCQL-credential trust and status options for a
 * `credential_sets` disjunction (EID-240, gap G3 of the eidas-pro DC API list).
 *
 * The query is the real "EU AV Proof of Age attestation OR PID" shape. Two
 * synthetic issuers stand in for the two trusted lists: a PID Provider whose
 * Document Signer carries the ISO 18013-5 DS EKU, and an AV Attestation
 * Provider whose Document Signer carries ONLY the AV DS EKU. The security
 * property under test: an anchor configured for one credential query never
 * vouches for a presentation answered as another.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import type { DcqlQuery } from '@openeudi/dcql';

import { AV_DOCUMENT_SIGNER_EKU } from '../src/av/constants.js';
import {
    buildOpenID4VPDCAPIHandoverSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from '../src/crypto/session-transcript.js';
import { verifyDcApiResponse } from '../src/dc-api/response.js';
import { CertificateChainError, PerCredentialOptionsError, TrustAnchorNotFoundError } from '../src/errors.js';
import * as publicApi from '../src/index.js';
import { StatusListResolver } from '../src/status/StatusListResolver.js';
import { ISO_18013_5_DS_EKU } from '../src/trust/ChainBuilder.js';
import type { PerCredentialVerifyOptionsMap } from '../src/types/verify.js';
import { verifyAuthorizationResponse } from '../src/verify.js';
import { buildSignedSdJwt, type TestKeyMaterial } from './fixtures/crypto-helpers.js';
import { buildSignedMdoc } from './fixtures/mdoc-helpers.js';
import type { GeneratedCa } from './trust/helpers/synthetic-ca.js';
import { createIssuer, nodeDeviceKey, storeOf } from './av/helpers.js';

const AV = 'eu.europa.ec.av.1';
const PID_VCT = 'urn:eudi:pid:1';

interface Issuer {
    ca: GeneratedCa;
    ds: TestKeyMaterial;
}

let pidIssuer: Issuer;
let avIssuer: Issuer;
let holderKey: TestKeyMaterial;

beforeAll(async () => {
    pidIssuer = await createIssuer('PID Provider', [ISO_18013_5_DS_EKU]);
    avIssuer = await createIssuer('AV Attestation Provider', [AV_DOCUMENT_SIGNER_EKU]);
    holderKey = await nodeDeviceKey();
});

function randomBirthDate(): string {
    const year = 1950 + Math.floor(Math.random() * 50);
    const month = String(1 + Math.floor(Math.random() * 12)).padStart(2, '0');
    const day = String(1 + Math.floor(Math.random() * 28)).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

/** "AV Proof of Age attestation OR PID", with random credential query ids. */
function ageOrPidQuery(): { query: DcqlQuery; avId: string; pidId: string } {
    const avId = `av-${crypto.randomUUID()}`;
    const pidId = `pid-${crypto.randomUUID()}`;
    return {
        avId,
        pidId,
        query: {
            credentials: [
                {
                    id: avId,
                    format: 'mso_mdoc',
                    meta: { doctype_value: AV },
                    claims: [{ path: [AV, 'age_over_18'] }],
                },
                {
                    id: pidId,
                    format: 'dc+sd-jwt',
                    meta: { vct_values: [PID_VCT] },
                    claims: [{ path: ['birthdate'] }],
                },
            ],
            credential_sets: [{ options: [[avId], [pidId]] }],
        },
    };
}

/** The intended configuration: each option only against its own anchors. */
function separateTrust(avId: string, pidId: string): PerCredentialVerifyOptionsMap {
    return {
        [avId]: { trustStore: storeOf(avIssuer.ca), avProfile: true },
        [pidId]: { trustStore: storeOf(pidIssuer.ca) },
    };
}

function redirectContext() {
    return {
        clientId: `x509_san_dns:verifier-${crypto.randomUUID()}.example`,
        responseUri: `https://verifier-${crypto.randomUUID()}.example/response`,
        nonce: crypto.randomUUID(),
    };
}

async function pidPresentation(params: { issuer?: Issuer; nonce: string; audience: string }): Promise<string> {
    const built = await buildSignedSdJwt({
        issuerKey: (params.issuer ?? pidIssuer).ds,
        holderKey,
        claims: { vct: PID_VCT },
        disclosureClaims: [['birthdate', randomBirthDate()]],
        nonce: params.nonce,
        audience: params.audience,
    });
    return built.sdJwt;
}

async function avPresentation(params: {
    sessionTranscript: Uint8Array;
    issuer?: Issuer;
    namespaces?: Record<string, Record<string, unknown>>;
}): Promise<string> {
    const mdoc = await buildSignedMdoc({
        issuerKey: (params.issuer ?? avIssuer).ds,
        deviceKey: await nodeDeviceKey(),
        docType: AV,
        namespaces: params.namespaces ?? { [AV]: { age_over_18: Math.random() < 0.5 } },
        sessionTranscript: params.sessionTranscript,
    });
    return Buffer.from(mdoc.mdocBytes).toString('base64url');
}

async function redirectAvTranscript(ctx: ReturnType<typeof redirectContext>): Promise<Uint8Array> {
    return buildOpenID4VPHandoverSessionTranscript(ctx);
}

describe('verifyAuthorizationResponse — perCredential (credential_sets disjunction)', () => {
    describe('the wallet answers the PID option', () => {
        it('verifies the PID against the PID entry only, with its own status policy', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });
            const statusListResolver = new StatusListResolver({ trustStore: storeOf(pidIssuer.ca) });

            const result = await verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                ...ctx,
                perCredential: {
                    [avId]: { trustStore: storeOf(avIssuer.ca), avProfile: true },
                    [pidId]: {
                        trustStore: storeOf(pidIssuer.ca),
                        statusPolicy: 'require',
                        statusListResolver,
                        revocationPolicy: 'skip',
                    },
                },
            });

            expect(result.valid).toBe(true);
            expect(result.match.matches.map((m) => m.queryId)).toEqual([pidId]);
            // The entry's statusPolicy replaced the (absent) top-level one.
            expect(result.parsed.credentialStatus).toMatchObject({ policy: 'require', outcome: 'absent' });
        });

        it('REJECTS the PID when only the AV entry holds the PID issuer anchor', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });

            await expect(
                verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                    ...ctx,
                    perCredential: {
                        [avId]: { trustStore: storeOf(pidIssuer.ca, avIssuer.ca), avProfile: true },
                        [pidId]: { trustStore: storeOf(avIssuer.ca) },
                    },
                }),
            ).rejects.toThrow(TrustAnchorNotFoundError);
        });

        it('never falls back to, or merges with, the top-level trust options', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });

            await expect(
                verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                    ...ctx,
                    // Every anchor at the top level, in both forms…
                    trustStore: storeOf(pidIssuer.ca, avIssuer.ca),
                    trustedCertificates: [pidIssuer.ds.certDerBytes],
                    perCredential: {
                        [avId]: { trustStore: storeOf(avIssuer.ca), avProfile: true },
                        // …but the PID entry carries only the AV anchor.
                        [pidId]: { trustStore: storeOf(avIssuer.ca) },
                    },
                }),
            ).rejects.toThrow(TrustAnchorNotFoundError);
        });

        it('does not borrow a top-level trustStore the entry leaves out', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });

            const result = await verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                ...ctx,
                trustStore: storeOf(pidIssuer.ca),
                perCredential: {
                    [avId]: { trustStore: storeOf(avIssuer.ca), avProfile: true },
                    // No trustStore: the top-level one must not stand in for it.
                    [pidId]: { trustedCertificates: [avIssuer.ds.certDerBytes] },
                },
            });

            expect(result.parsed.valid).toBe(false);
            expect(result.valid).toBe(false);
        });

        it('takes the top-level status policy away from the answered credential', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });

            // Top-level 'require' without a resolver would throw a configuration
            // StatusListError; the PID entry replaces it with its default 'skip'.
            const result = await verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                ...ctx,
                statusPolicy: 'require',
                perCredential: separateTrust(avId, pidId),
            });

            expect(result.valid).toBe(true);
            expect(result.parsed.credentialStatus).toBeUndefined();
        });

        it('cannot satisfy another query entry than the one it was answered as', async () => {
            // Two SD-JWT options with different trust. A PID keyed as the OTHER
            // option, whose entry happens to trust the PID issuer, still matches
            // the PID entry by content — DCQL matches every entry — so the
            // presentation must be pinned to the id it was answered as.
            const pidId = `pid-${crypto.randomUUID()}`;
            const otherId = `other-${crypto.randomUUID()}`;
            const query: DcqlQuery = {
                credentials: [
                    { id: pidId, format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] }, claims: [{ path: ['birthdate'] }] },
                    {
                        id: otherId,
                        format: 'dc+sd-jwt',
                        meta: { vct_values: [`urn:example:${crypto.randomUUID()}`] },
                        claims: [{ path: ['birthdate'] }],
                    },
                ],
                credential_sets: [{ options: [[pidId], [otherId]] }],
            };
            const ctx = redirectContext();
            const pid = await pidPresentation({ issuer: avIssuer, nonce: ctx.nonce, audience: ctx.clientId });

            const result = await verifyAuthorizationResponse({ vp_token: { [otherId]: [pid] } }, query, {
                ...ctx,
                perCredential: {
                    [pidId]: { trustStore: storeOf(pidIssuer.ca) },
                    [otherId]: { trustStore: storeOf(avIssuer.ca) },
                },
            });

            expect(result.parsed.valid).toBe(true);
            expect(result.valid).toBe(false);
            expect(result.match.satisfied).toBe(false);
            expect(result.match.matches).toEqual([]);
            expect(result.match.unmatched.map((u) => u.queryId).sort()).toEqual([otherId, pidId].sort());
            expect(result.submission).toBeNull();
        });
    });

    describe('the wallet answers the AV Proof of Age option', () => {
        it('verifies the attestation against the AV entry with the avProfile checks', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const ageOver18 = Math.random() < 0.5;
            const av = await avPresentation({
                sessionTranscript: await redirectAvTranscript(ctx),
                namespaces: { [AV]: { age_over_18: ageOver18 } },
            });

            const result = await verifyAuthorizationResponse({ vp_token: { [avId]: [av] } }, query, {
                ...ctx,
                perCredential: separateTrust(avId, pidId),
            });

            expect(result.valid).toBe(true);
            expect(result.match.matches.map((m) => m.queryId)).toEqual([avId]);
            expect(result.parsed.namespacedClaims?.[AV]?.age_over_18).toBe(ageOver18);
        });

        it('REJECTS the attestation when only the PID entry holds the AV anchor', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const av = await avPresentation({ sessionTranscript: await redirectAvTranscript(ctx) });

            await expect(
                verifyAuthorizationResponse({ vp_token: { [avId]: [av] } }, query, {
                    ...ctx,
                    trustStore: storeOf(avIssuer.ca),
                    perCredential: {
                        [avId]: { trustStore: storeOf(pidIssuer.ca), avProfile: true },
                        [pidId]: { trustStore: storeOf(pidIssuer.ca, avIssuer.ca) },
                    },
                }),
            ).rejects.toThrow(TrustAnchorNotFoundError);
        });

        it('rejects an attribute the AV data model does not allow', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const av = await avPresentation({
                sessionTranscript: await redirectAvTranscript(ctx),
                namespaces: { [AV]: { age_over_18: true, birth_date: randomBirthDate() } },
            });

            const result = await verifyAuthorizationResponse({ vp_token: { [avId]: [av] } }, query, {
                ...ctx,
                perCredential: separateTrust(avId, pidId),
            });

            expect(result.valid).toBe(false);
            expect(result.parsed.valid).toBe(false);
            expect(result.parsed.error).toMatch(/avProfile: unexpected_attribute/);
        });

        it('rejects a document of another doctype under avProfile', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const otherDoctype = `org.example.${crypto.randomUUID()}`;
            const mdoc = await buildSignedMdoc({
                issuerKey: avIssuer.ds,
                deviceKey: await nodeDeviceKey(),
                docType: otherDoctype,
                namespaces: { [otherDoctype]: { age_over_18: true } },
                sessionTranscript: await redirectAvTranscript(ctx),
            });

            const result = await verifyAuthorizationResponse(
                { vp_token: { [avId]: [Buffer.from(mdoc.mdocBytes).toString('base64url')] } },
                query,
                { ...ctx, perCredential: separateTrust(avId, pidId) },
            );

            expect(result.valid).toBe(false);
            expect(result.parsed.error).toMatch(/avProfile: wrong_doctype/);
        });

        it('applies the AV Document Signer EKU only under avProfile', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const av = await avPresentation({ sessionTranscript: await redirectAvTranscript(ctx) });

            // Same anchors, no avProfile: the generic mdoc profile wants the
            // ISO 18013-5 DS EKU, which the AV Document Signer does not carry.
            await expect(
                verifyAuthorizationResponse({ vp_token: { [avId]: [av] } }, query, {
                    ...ctx,
                    perCredential: {
                        [avId]: { trustStore: storeOf(avIssuer.ca) },
                        [pidId]: { trustStore: storeOf(pidIssuer.ca) },
                    },
                }),
            ).rejects.toThrow(CertificateChainError);
        });
    });

    describe('configuration', () => {
        it('rejects an answered credential that has no perCredential entry', async () => {
            const { query, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });

            const attempt = verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                ...ctx,
                trustStore: storeOf(pidIssuer.ca),
                perCredential: { [query.credentials[0].id]: { trustStore: storeOf(avIssuer.ca), avProfile: true } },
            });

            await expect(attempt).rejects.toThrow(PerCredentialOptionsError);
            await expect(attempt).rejects.toMatchObject({ code: 'missing_credential_options', credentialId: pidId });
        });

        it('rejects a perCredential key that is not a credential id of the query, before reading the response', async () => {
            const { query, avId, pidId } = ageOrPidQuery();
            const unknownId = `unknown-${crypto.randomUUID()}`;

            const attempt = verifyAuthorizationResponse(
                // Not even a valid envelope: the configuration is checked first.
                { response: crypto.randomUUID() },
                query,
                {
                    nonce: crypto.randomUUID(),
                    perCredential: { ...separateTrust(avId, pidId), [unknownId]: { trustStore: storeOf(pidIssuer.ca) } },
                },
            );

            await expect(attempt).rejects.toThrow(PerCredentialOptionsError);
            await expect(attempt).rejects.toMatchObject({ code: 'unknown_credential_id', credentialId: unknownId });
        });

        it.each([
            ['an empty map', (_avId: string, _pidId: string) => ({})],
            ['avProfile on a dc+sd-jwt query', (_avId: string, pidId: string) => ({ [pidId]: { trustStore: storeOf(pidIssuer.ca), avProfile: true } })],
            ['avProfile without a trustStore', (avId: string) => ({ [avId]: { avProfile: true } })],
            ['a non-object entry', (avId: string) => ({ [avId]: null })],
        ])('rejects %s as invalid_per_credential_options', async (_label, build) => {
            const { query, avId, pidId } = ageOrPidQuery();
            const attempt = verifyAuthorizationResponse({ vp_token: { [pidId]: [crypto.randomUUID()] } }, query, {
                nonce: crypto.randomUUID(),
                perCredential: build(avId, pidId) as unknown as PerCredentialVerifyOptionsMap,
            });
            await expect(attempt).rejects.toMatchObject({ code: 'invalid_per_credential_options' });
        });

        it('leaves verification unchanged without perCredential', async () => {
            const { query, pidId } = ageOrPidQuery();
            const ctx = redirectContext();
            const pid = await pidPresentation({ nonce: ctx.nonce, audience: ctx.clientId });

            const result = await verifyAuthorizationResponse({ vp_token: { [pidId]: [pid] } }, query, {
                ...ctx,
                trustStore: storeOf(pidIssuer.ca, avIssuer.ca),
            });

            expect(result.valid).toBe(true);
            expect(result.match.matches.map((m) => m.queryId)).toEqual([pidId]);
        });

        it('exports the error and the option types from the package entry point', () => {
            expect(publicApi.PerCredentialOptionsError).toBe(PerCredentialOptionsError);
        });
    });
});

describe('verifyDcApiResponse — perCredential (openid4vp-v1-unsigned, dc_api)', () => {
    function origin(): string {
        return `https://shop-${crypto.randomUUID()}.example`;
    }

    it('verifies the PID answer against the PID entry', async () => {
        const { query, avId, pidId } = ageOrPidQuery();
        const verifierOrigin = origin();
        const nonce = crypto.randomUUID();
        const pid = await pidPresentation({ nonce, audience: `origin:${verifierOrigin}` });

        const result = await verifyDcApiResponse(
            { protocol: 'openid4vp-v1-unsigned', data: { vp_token: { [pidId]: [pid] } } },
            query,
            { origin: verifierOrigin, nonce, responseMode: 'dc_api', perCredential: separateTrust(avId, pidId) },
        );

        expect(result.valid).toBe(true);
        expect(result.match.matches.map((m) => m.queryId)).toEqual([pidId]);
    });

    it('REJECTS the PID answer when only the AV entry holds the PID issuer anchor', async () => {
        const { query, avId, pidId } = ageOrPidQuery();
        const verifierOrigin = origin();
        const nonce = crypto.randomUUID();
        const pid = await pidPresentation({ nonce, audience: `origin:${verifierOrigin}` });

        await expect(
            verifyDcApiResponse({ protocol: 'openid4vp-v1-unsigned', data: { vp_token: { [pidId]: [pid] } } }, query, {
                origin: verifierOrigin,
                nonce,
                responseMode: 'dc_api',
                trustStore: storeOf(pidIssuer.ca),
                perCredential: {
                    [avId]: { trustStore: storeOf(pidIssuer.ca, avIssuer.ca), avProfile: true },
                    [pidId]: { trustStore: storeOf(avIssuer.ca) },
                },
            }),
        ).rejects.toThrow(TrustAnchorNotFoundError);
    });

    it('verifies the AV answer with avProfile over the OpenID4VPDCAPIHandover transcript', async () => {
        const { query, avId, pidId } = ageOrPidQuery();
        const verifierOrigin = origin();
        const nonce = crypto.randomUUID();
        const av = await avPresentation({
            sessionTranscript: await buildOpenID4VPDCAPIHandoverSessionTranscript({ origin: verifierOrigin, nonce }),
        });

        const result = await verifyDcApiResponse(
            { protocol: 'openid4vp-v1-unsigned', data: { vp_token: { [avId]: [av] } } },
            query,
            { origin: verifierOrigin, nonce, responseMode: 'dc_api', perCredential: separateTrust(avId, pidId) },
        );

        expect(result.valid).toBe(true);
        expect(result.match.matches.map((m) => m.queryId)).toEqual([avId]);
    });

    it('rejects an unknown perCredential key up front', async () => {
        const { query, avId, pidId } = ageOrPidQuery();
        const unknownId = `unknown-${crypto.randomUUID()}`;
        await expect(
            verifyDcApiResponse({ protocol: 'openid4vp-v1-unsigned', data: crypto.randomUUID() }, query, {
                origin: origin(),
                nonce: crypto.randomUUID(),
                perCredential: { ...separateTrust(avId, pidId), [unknownId]: {} },
            }),
        ).rejects.toMatchObject({ code: 'unknown_credential_id', credentialId: unknownId });
    });

    it('refuses perCredential on the org-iso-mdoc path', async () => {
        const { query, avId, pidId } = ageOrPidQuery();
        await expect(
            verifyDcApiResponse(
                { protocol: 'org-iso-mdoc', data: { response: crypto.randomUUID() } },
                query,
                {
                    protocol: 'org-iso-mdoc',
                    origin: origin(),
                    encryptionInfo: crypto.randomUUID(),
                    decryptionKey: {} as JsonWebKey,
                    perCredential: separateTrust(avId, pidId),
                } as unknown as Parameters<typeof verifyDcApiResponse>[2],
            ),
        ).rejects.toMatchObject({ code: 'invalid_per_credential_options' });
    });
});
