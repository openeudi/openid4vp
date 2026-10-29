/**
 * EU Age Verification profile — verifying the AV app's direct_post response
 * (AV Annex A §A.4 data model, §A.6 OpenID4VP fallback, OpenID4VP 1.0 §B.2.6.1).
 */
import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { AV_DOCUMENT_SIGNER_EKU } from '../../src/av/constants.js';
import { AvResponseError } from '../../src/av/errors.js';
import { createAvAuthorizationRequest } from '../../src/av/request.js';
import type { AvAuthorizationRequest } from '../../src/av/types.js';
import { verifyAvPresentation } from '../../src/av/verify.js';
import { decodeCoseSign1 } from '../../src/crypto/cose-sign1.js';
import { verifyDeviceAuth } from '../../src/crypto/device-auth.js';
import { decodeMso, type MobileSecurityObject } from '../../src/crypto/mso.js';
import { buildOpenID4VPHandoverSessionTranscript } from '../../src/crypto/session-transcript.js';
import { WalletErrorResponseError } from '../../src/errors.js';
import { CertificateChainError, TrustAnchorNotFoundError } from '../../src/errors.js';
import { ISO_18013_5_DS_EKU } from '../../src/trust/ChainBuilder.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import {
    ANNEX_A_DEVICE_RESPONSE,
    ANNEX_A_REQUEST,
    ANNEX_A_SESSION_TRANSCRIPT_HEX,
    ANNEX_A_VERIFICATION_TIME,
} from '../fixtures/av-annex-a-example.js';
import type { TestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { AV_REFERENCE_ISSUER_CA_DER_BASE64 } from '../fixtures/av-reference-issuer-ca.js';
import { buildSignedMdoc } from '../fixtures/mdoc-helpers.js';
import type { GeneratedCa } from '../trust/helpers/synthetic-ca.js';
import { createIssuer, nodeDeviceKey, storeOf } from './helpers.js';

const AV = 'eu.europa.ec.av.1';
const PID = 'eu.europa.ec.eudi.pid.1';
const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

function randomRequest(overrides: Partial<Parameters<typeof createAvAuthorizationRequest>[0]> = {}) {
    return createAvAuthorizationRequest({
        responseUri: `https://rp-${crypto.randomUUID()}.example/av/${crypto.randomUUID()}`,
        state: crypto.randomUUID(),
        ...overrides,
    });
}

/** The wallet side: the transcript the AV app binds into DeviceAuthentication. */
function transcriptFor(
    request: Pick<AvAuthorizationRequest, 'clientId' | 'nonce' | 'responseUri'>,
): Promise<Uint8Array> {
    return buildOpenID4VPHandoverSessionTranscript({
        clientId: request.clientId,
        nonce: request.nonce,
        responseUri: request.responseUri,
    });
}

interface PresentOptions {
    issuer: TestKeyMaterial;
    docType?: string;
    namespaces?: Record<string, Record<string, unknown>>;
    sessionTranscript: Uint8Array;
}

async function present(opts: PresentOptions): Promise<string> {
    const mdoc = await buildSignedMdoc({
        issuerKey: opts.issuer,
        deviceKey: await nodeDeviceKey(),
        docType: opts.docType ?? AV,
        namespaces: opts.namespaces ?? { [AV]: { age_over_18: true } },
        sessionTranscript: opts.sessionTranscript,
    });
    return Buffer.from(mdoc.mdocBytes).toString('base64url');
}

/** The AV app's form-encoded direct_post body. */
function formBody(presentation: string, state?: string, credentialId = 'proof_of_age'): string {
    const body = new URLSearchParams({ vp_token: JSON.stringify({ [credentialId]: [presentation] }) });
    if (state !== undefined) body.set('state', state);
    return body.toString();
}

let av: { ca: GeneratedCa; ds: TestKeyMaterial };
let pidProvider: { ca: GeneratedCa; ds: TestKeyMaterial };

beforeAll(async () => {
    av = await createIssuer('AV', [AV_DOCUMENT_SIGNER_EKU]);
    pidProvider = await createIssuer('PID', [ISO_18013_5_DS_EKU]);
});

afterEach(() => {
    vi.useRealTimers();
});

describe('verifyAvPresentation — round trip', () => {
    it('verifies an eu.europa.ec.av.1 DeviceResponse bound to the OpenID4VP 1.0 handover', async () => {
        const request = randomRequest();
        const presentation = await present({ issuer: av.ds, sessionTranscript: await transcriptFor(request) });

        const result = await verifyAvPresentation(formBody(presentation, request.state), {
            request,
            trustStore: storeOf(av.ca),
        });

        expect(result).toMatchObject({
            valid: true,
            ageVerified: true,
            ageOver: true,
            ageThreshold: 18,
            ageOverAttribute: 'age_over_18',
            decidedBy: 'age_over_18',
            state: request.state,
        });
        expect(result.failure).toBeUndefined();
        expect(result.issuer.certificate).toEqual(av.ds.certDerBytes);
        expect(result.trust?.chain).toHaveLength(2);
        expect(new Uint8Array(result.trust!.anchor.certificate.rawData)).toEqual(
            new Uint8Array(av.ca.certificate.rawData),
        );
    });

    it('accepts the body as URLSearchParams or a parsed object, and only the persisted subset of the request', async () => {
        const request = randomRequest();
        const presentation = await present({ issuer: av.ds, sessionTranscript: await transcriptFor(request) });
        const persisted = { responseUri: request.responseUri, nonce: request.nonce, state: request.state };
        const options = { request: persisted, trustStore: storeOf(av.ca) };

        const fromParams = await verifyAvPresentation(new URLSearchParams(formBody(presentation, request.state)), options);
        const fromObject = await verifyAvPresentation(
            { vp_token: { proof_of_age: [presentation] }, state: request.state },
            options,
        );
        expect(fromParams.ageVerified).toBe(true);
        expect(fromObject.ageVerified).toBe(true);
    });

    it('returns a valid presentation with ageOver false when age_over_18 is false', async () => {
        const request = randomRequest();
        const presentation = await present({
            issuer: av.ds,
            namespaces: { [AV]: { age_over_18: false } },
            sessionTranscript: await transcriptFor(request),
        });

        const result = await verifyAvPresentation(formBody(presentation, request.state), {
            request,
            trustStore: storeOf(av.ca),
        });
        expect(result.valid).toBe(true);
        expect(result.ageOver).toBe(false);
        expect(result.ageVerified).toBe(false);
    });

    it('verifies age_over_NN for another threshold and tolerates other age_over_NN elements', async () => {
        const request = randomRequest({ ageThreshold: 21 });
        const presentation = await present({
            issuer: av.ds,
            namespaces: { [AV]: { age_over_18: true, age_over_21: true } },
            sessionTranscript: await transcriptFor(request),
        });

        const result = await verifyAvPresentation(formBody(presentation, request.state), {
            request,
            trustStore: storeOf(av.ca),
        });
        expect(result).toMatchObject({ valid: true, ageVerified: true, ageOverAttribute: 'age_over_21' });
    });

    it('accepts a Document Signer with the ISO 18013-5 EKU and rejects one with neither EKU', async () => {
        const iso = await createIssuer('AV ISO', [ISO_18013_5_DS_EKU]);
        const request = randomRequest();
        const transcript = await transcriptFor(request);

        const ok = await verifyAvPresentation(formBody(await present({ issuer: iso.ds, sessionTranscript: transcript }), request.state), {
            request,
            trustStore: storeOf(iso.ca),
        });
        expect(ok.valid).toBe(true);

        const other = await createIssuer('AV other', ['1.3.6.1.5.5.7.3.4']);
        const rejected = verifyAvPresentation(
            formBody(await present({ issuer: other.ds, sessionTranscript: transcript }), request.state),
            { request, trustStore: storeOf(other.ca) },
        );
        await expect(rejected).rejects.toBeInstanceOf(CertificateChainError);
        await expect(rejected).rejects.toMatchObject({ reason: 'extended_key_usage' });
    });
});

describe('verifyAvPresentation — thresholds other than 18 (ISO/IEC 18013-5 §7.2.5)', () => {
    async function verifyThreshold(ageThreshold: number, disclosed: Record<string, boolean>) {
        const request = randomRequest({ ageThreshold });
        const presentation = await present({
            issuer: av.ds,
            namespaces: { [AV]: disclosed },
            sessionTranscript: await transcriptFor(request),
        });
        return verifyAvPresentation(formBody(presentation, request.state), { request, trustStore: storeOf(av.ca) });
    }

    it.each([
        // [threshold, disclosed, ageOver, decidedBy]
        [16, { age_over_16: true }, true, 'age_over_16'],
        [16, { age_over_16: false }, false, 'age_over_16'],
        [16, { age_over_18: true }, true, 'age_over_18'],
        [16, { age_over_16: true, age_over_18: true }, true, 'age_over_16'],
        [21, { age_over_25: true }, true, 'age_over_25'],
        [21, { age_over_18: false }, false, 'age_over_18'],
        [21, { age_over_18: true, age_over_21: false }, false, 'age_over_21'],
    ] as const)('NN=%i, disclosed %o → valid, ageOver %s, decided by %s', async (threshold, disclosed, ageOver, decidedBy) => {
        const result = await verifyThreshold(threshold, disclosed);
        expect(result.error).toBeUndefined();
        expect(result).toMatchObject({
            valid: true,
            ageVerified: ageOver,
            ageOver,
            ageThreshold: threshold,
            ageOverAttribute: `age_over_${threshold}`,
            decidedBy,
        });
        expect(result.trust).toBeDefined();
    });

    it.each([
        [16, { age_over_18: false }],
        [21, { age_over_18: true }],
    ] as const)('NN=%i, disclosed %o → no statement: missing_attribute, not ageOver false', async (threshold, disclosed) => {
        const result = await verifyThreshold(threshold, disclosed);
        expect(result).toMatchObject({ valid: false, ageVerified: false, ageOver: undefined, failure: 'missing_attribute' });
        expect(result.decidedBy).toBeUndefined();
    });

    it.each([
        [16, { age_over_16: false, age_over_18: true }],
        [21, { age_over_18: true, age_over_16: false }],
        [21, { age_over_25: true, age_over_21: false }],
    ] as const)('NN=%i, contradictory %o → inconsistent_attributes', async (threshold, disclosed) => {
        const result = await verifyThreshold(threshold, disclosed);
        expect(result).toMatchObject({ valid: false, ageVerified: false, ageOver: undefined, failure: 'inconsistent_attributes' });
        expect(result.error).toMatch(/is true but .* is false/);
    });
});

describe('verifyAvPresentation — rejections', () => {
    async function verifyWith(
        presentOpts: Omit<PresentOptions, 'sessionTranscript'> & { sessionTranscript?: Uint8Array },
        request: AvAuthorizationRequest = randomRequest(),
        trustStore = storeOf(av.ca),
    ) {
        const presentation = await present({
            sessionTranscript: presentOpts.sessionTranscript ?? (await transcriptFor(request)),
            ...presentOpts,
        });
        return verifyAvPresentation(formBody(presentation, request.state), { request, trustStore });
    }

    it('rejects a document whose docType is not eu.europa.ec.av.1', async () => {
        const result = await verifyWith({ issuer: av.ds, docType: `${AV}.x`, namespaces: { [AV]: { age_over_18: true } } });
        expect(result).toMatchObject({ valid: false, ageVerified: false, failure: 'wrong_doctype' });
    });

    it('rejects a PID presented under the AV trust store, even from an AV-trusted signer', async () => {
        const result = await verifyWith({ issuer: av.ds, docType: PID, namespaces: { [PID]: { age_over_18: true } } });
        expect(result).toMatchObject({ valid: false, failure: 'wrong_doctype' });
    });

    it('rejects an AV attestation from an issuer that is only a PID provider', async () => {
        const result = verifyWith({ issuer: pidProvider.ds }, randomRequest(), storeOf(av.ca));
        await expect(result).rejects.toBeInstanceOf(TrustAnchorNotFoundError);
    });

    it('rejects an attestation that carries any attribute besides age_over_NN', async () => {
        const extra = await verifyWith({
            issuer: av.ds,
            namespaces: { [AV]: { age_over_18: true, [`family_name_${crypto.randomUUID().slice(0, 4)}`]: 'Doe' } },
        });
        expect(extra).toMatchObject({ valid: false, failure: 'unexpected_attribute' });

        const otherNamespace = await verifyWith({
            issuer: av.ds,
            namespaces: { [AV]: { age_over_18: true }, [PID]: { birth_date: '2000-01-01' } },
        });
        expect(otherNamespace).toMatchObject({ valid: false, failure: 'unexpected_attribute' });
    });

    it('rejects a non-boolean age_over_NN', async () => {
        const result = await verifyWith({ issuer: av.ds, namespaces: { [AV]: { age_over_18: 'yes' } } });
        expect(result).toMatchObject({ valid: false, failure: 'invalid_attribute_value' });
    });

    it('rejects a presentation that lacks the requested age_over_NN', async () => {
        const result = await verifyWith(
            { issuer: av.ds, namespaces: { [AV]: { age_over_18: true } } },
            randomRequest({ ageThreshold: 21 }),
        );
        expect(result).toMatchObject({ valid: false, ageOver: undefined, failure: 'missing_attribute' });
    });

    it('rejects a device signature over a different nonce', async () => {
        const request = randomRequest();
        const result = await verifyWith(
            { issuer: av.ds, sessionTranscript: await transcriptFor({ ...request, nonce: crypto.randomUUID() }) },
            request,
        );
        expect(result).toMatchObject({ valid: false, failure: 'invalid_credential' });
        expect(result.error).toMatch(/device authentication/i);
    });

    it('rejects a device signature over a different response_uri', async () => {
        const request = randomRequest();
        const otherUri = `https://attacker-${crypto.randomUUID()}.example/cb`;
        const result = await verifyWith(
            {
                issuer: av.ds,
                sessionTranscript: await transcriptFor({ ...request, responseUri: otherUri, clientId: `redirect_uri:${otherUri}` }),
            },
            request,
        );
        expect(result).toMatchObject({ valid: false, failure: 'invalid_credential' });
    });

    it('rejects a transcript that binds the response_uri but a different client_id', async () => {
        const request = randomRequest();
        const result = await verifyWith(
            {
                issuer: av.ds,
                sessionTranscript: await transcriptFor({ ...request, clientId: `x509_hash:${crypto.randomUUID()}` }),
            },
            request,
        );
        expect(result).toMatchObject({ valid: false, failure: 'invalid_credential' });
    });

    it('rejects device-signed elements', async () => {
        const request = randomRequest();
        const presentation = await present({ issuer: av.ds, sessionTranscript: await transcriptFor(request) });
        const deviceResponse = cbor.decode(Buffer.from(presentation, 'base64url')) as Map<string, unknown>;
        const document = (deviceResponse.get('documents') as Map<string, unknown>[])[0]!;
        const deviceSigned = document.get('deviceSigned') as Map<string, unknown>;
        const elements = new Map([[AV, new Map([['age_over_18', true]])]]);
        deviceSigned.set('nameSpaces', new Tag(cbor.encode(elements), 24));
        const tampered = Buffer.from(cbor.encode(deviceResponse)).toString('base64url');

        const result = await verifyAvPresentation(formBody(tampered, request.state), {
            request,
            trustStore: storeOf(av.ca),
        });
        expect(result).toMatchObject({ valid: false, failure: 'device_signed_elements' });
    });

    it('throws AvResponseError on a state mismatch', async () => {
        const request = randomRequest();
        const presentation = await present({ issuer: av.ds, sessionTranscript: await transcriptFor(request) });
        const result = verifyAvPresentation(formBody(presentation, crypto.randomUUID()), {
            request,
            trustStore: storeOf(av.ca),
        });
        await expect(result).rejects.toBeInstanceOf(AvResponseError);
        await expect(result).rejects.toMatchObject({ code: 'state_mismatch' });
    });

    it('throws AvResponseError unless vp_token holds exactly one presentation for the requested id', async () => {
        const request = randomRequest();
        const presentation = await present({ issuer: av.ds, sessionTranscript: await transcriptFor(request) });
        const options = { request, trustStore: storeOf(av.ca) };
        const bodies: Record<string, unknown>[] = [
            { vp_token: { proof_of_age: [presentation, presentation] }, state: request.state },
            { vp_token: { [crypto.randomUUID()]: [presentation] }, state: request.state },
            { vp_token: { proof_of_age: [presentation], pid: [presentation] }, state: request.state },
        ];
        for (const body of bodies) {
            await expect(verifyAvPresentation(body, options)).rejects.toMatchObject({ code: 'unexpected_presentation' });
        }
        await expect(verifyAvPresentation({ state: request.state }, options)).rejects.toMatchObject({
            code: 'malformed_response',
        });
        await expect(verifyAvPresentation({ vp_token: '{not json', state: request.state }, options)).rejects.toMatchObject(
            { code: 'malformed_response' },
        );
    });

    it('throws WalletErrorResponseError for a wallet error response', async () => {
        const request = randomRequest();
        const description = `declined ${crypto.randomUUID()}`;
        const body = new URLSearchParams({ error: 'access_denied', error_description: description, state: request.state! });

        const result = verifyAvPresentation(body.toString(), { request, trustStore: storeOf(av.ca) });
        await expect(result).rejects.toBeInstanceOf(WalletErrorResponseError);
        await expect(result).rejects.toMatchObject({ code: 'access_denied', description });
    });

    it('throws AvResponseError for a clientId that is not redirect_uri:<responseUri>', async () => {
        const request = randomRequest();
        const result = verifyAvPresentation(formBody('AA', request.state), {
            request: { ...request, clientId: `redirect_uri:https://other-${crypto.randomUUID()}.example` },
            trustStore: storeOf(av.ca),
        });
        await expect(result).rejects.toMatchObject({ code: 'invalid_context' });
    });
});

describe('verifyAvPresentation — Annex A §A.11 example (AV reference implementation)', () => {
    function annexDocument(): { document: Map<string, unknown>; dsCertificate: Uint8Array; mso: MobileSecurityObject } {
        const deviceResponse = cbor.decode(Buffer.from(ANNEX_A_DEVICE_RESPONSE, 'base64url')) as Map<string, unknown>;
        const document = (deviceResponse.get('documents') as Map<string, unknown>[])[0]!;
        const issuerAuth = (document.get('issuerSigned') as Map<string, unknown>).get('issuerAuth');
        const cose = decodeCoseSign1(new Uint8Array(cbor.encode(issuerAuth)));
        return { document, dsCertificate: cose.x5chain[0]!, mso: decodeMso(cose.payload) };
    }

    async function verifyAnnexDeviceAuth(nonce: string): Promise<void> {
        const { document, mso } = annexDocument();
        await verifyDeviceAuth({
            deviceSigned: document.get('deviceSigned') as Map<unknown, unknown>,
            deviceKeyCose: mso.deviceKey,
            docType: mso.docType,
            sessionTranscript: await transcriptFor({ ...ANNEX_A_REQUEST, nonce }),
            allowedAlgorithms: ['ES256'],
        });
    }

    it('builds the exact SessionTranscript of the example', async () => {
        const transcript = await transcriptFor(ANNEX_A_REQUEST);
        expect(Buffer.from(transcript).toString('hex')).toBe(ANNEX_A_SESSION_TRANSCRIPT_HEX);
    });

    it("verifies the AV app's device signature over that transcript, and only for the request's nonce", async () => {
        const { mso } = annexDocument();
        expect(mso.docType).toBe(AV);
        await expect(verifyAnnexDeviceAuth(ANNEX_A_REQUEST.nonce)).resolves.toBeUndefined();
        await expect(verifyAnnexDeviceAuth(crypto.randomUUID())).rejects.toThrow(/device authentication/i);
    });

    it('verifies the example against the AV-TL reference issuer CA despite its malformed IssuerAltName', async () => {
        // The reference PKI encodes IssuerAltName as a nested Extension, not
        // GeneralNames, on both the CA and the Document Signer. A malformed
        // non-critical IssuerAltName is tolerated (owner decision, EID-216):
        // it plays no part in path validation. Any other malformed extension
        // still fails closed (tests/trust/extensions.test.ts).
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(ANNEX_A_VERIFICATION_TIME);
        const referenceCa = Buffer.from(AV_REFERENCE_ISSUER_CA_DER_BASE64, 'base64');
        const result = await verifyAvPresentation(formBody(ANNEX_A_DEVICE_RESPONSE, ANNEX_A_REQUEST.state), {
            request: ANNEX_A_REQUEST,
            trustStore: new StaticTrustStore([new Uint8Array(referenceCa)]),
        });
        expect(result).toMatchObject({ valid: true, ageVerified: true, ageThreshold: 18 });
    });

    it('does not trust the example under any other anchor', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(ANNEX_A_VERIFICATION_TIME);
        const result = verifyAvPresentation(formBody(ANNEX_A_DEVICE_RESPONSE, ANNEX_A_REQUEST.state), {
            request: ANNEX_A_REQUEST,
            trustStore: storeOf(av.ca),
        });
        await expect(result).rejects.toBeInstanceOf(TrustAnchorNotFoundError);
    });
});
