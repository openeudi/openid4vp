import { Encoder as CborEncoder, Tag } from 'cbor-x';

import { buildOpenID4VPHandoverSessionTranscript } from '../crypto/session-transcript.js';
import { WalletErrorResponseError } from '../errors.js';
import { MdocParser } from '../parsers/mdoc.parser.js';
import { ISO_18013_5_DS_EKU } from '../trust/ChainBuilder.js';
import type { IssuerInfo } from '../types/issuer.js';
import { type AvAgeOverElement, decideAvAgeOver } from './age-over.js';
import {
    AV_DEFAULT_AGE_THRESHOLD,
    AV_DEFAULT_CREDENTIAL_ID,
    AV_DOCTYPE,
    AV_DOCUMENT_SIGNER_EKU,
    AV_NAMESPACE,
    avAgeOverAttribute,
    isAvAgeOverAttribute,
} from './constants.js';
import { AvResponseError } from './errors.js';
import { avClientIdFor } from './request.js';
import type {
    AvAuthorizationResponseInput,
    AvVerificationFailure,
    AvVerificationResult,
    VerifyAvPresentationOptions,
} from './types.js';

const decoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });
const parser = new MdocParser();
const NO_ISSUER: IssuerInfo = { certificate: new Uint8Array(), country: '' };

/**
 * Verify the AV app's answer to {@link createAvAuthorizationRequest}: the
 * EU Age Verification OpenID4VP fallback (Annex A §A.6), an unencrypted
 * `direct_post` carrying a plain ISO mdoc `DeviceResponse`.
 *
 * Checks, in order:
 * 1. Wallet error response → throws `WalletErrorResponseError`.
 * 2. `state` equals the request's (when the request had one) and `vp_token`
 *    holds exactly one presentation for the requested credential id →
 *    otherwise throws `AvResponseError`.
 * 3. Exactly one document, `docType` `eu.europa.ec.av.1`, status 0; issuer-signed
 *    elements are only `age_over_NN` booleans in namespace `eu.europa.ec.av.1`
 *    (Annex A §A.4.2: "SHALL NOT include any other attribute"); no
 *    device-signed elements.
 * 4. Issuer signature, digests, MSO validity and docType, issuer chain against
 *    `trustStore`, and device authentication over the OpenID4VP 1.0
 *    `OpenID4VPHandover` SessionTranscript `[clientId, nonce, null, responseUri]`.
 * 5. Under `statusPolicy` `'prefer'` / `'require'`, the MSO `status` (Token
 *    Status List, `statuslist+cwt`) when present.
 * 6. The disclosed `age_over_NN` elements are consistent (no `true` at one
 *    threshold with a `false` at the same or a lower one →
 *    `inconsistent_attributes`) and decide the requested threshold NN:
 *    `age_over_NN` itself, else the nearest `true` above NN, else the nearest
 *    `false` below NN (ISO/IEC 18013-5 §7.2.5). Nothing that decides it →
 *    `missing_attribute`. `decidedBy` names the element used.
 *
 * Credential failures return `{ valid: false, failure, error }`. Trust failures
 * propagate as `TrustAnchorNotFoundError` / `CertificateChainError`, as on
 * every other verification path of this library. Gate access on `ageVerified`,
 * not on `valid`: `age_over_18: false` is a valid presentation.
 */
export async function verifyAvPresentation(
    response: AvAuthorizationResponseInput,
    options: VerifyAvPresentationOptions,
): Promise<AvVerificationResult> {
    const { request, trustStore } = options;
    if (typeof request?.responseUri !== 'string' || typeof request.nonce !== 'string' || request.nonce.length === 0) {
        throw new AvResponseError('invalid_context', 'request.responseUri and request.nonce are required');
    }
    if (!trustStore) {
        throw new AvResponseError('invalid_context', 'trustStore is required: pass the AV Attestation Provider anchors');
    }
    const clientId = avClientIdFor(request.responseUri);
    if (request.clientId !== undefined && request.clientId !== clientId) {
        throw new AvResponseError(
            'invalid_context',
            `request.clientId must be "redirect_uri:" followed by request.responseUri (Annex A §A.6), got "${request.clientId}"`,
        );
    }
    const ageThreshold = request.ageThreshold ?? AV_DEFAULT_AGE_THRESHOLD;
    avAgeOverAttribute(ageThreshold); // a bad threshold is a caller error: throw before reading the body
    const credentialId = request.credentialId ?? AV_DEFAULT_CREDENTIAL_ID;

    const body = toBody(response);
    throwIfWalletError(body);

    const state = typeof body.state === 'string' ? body.state : undefined;
    if (request.state !== undefined && state !== request.state) {
        throw new AvResponseError('state_mismatch', 'response state does not match the request state');
    }

    const presentation = extractPresentation(body, credentialId);
    const deviceResponse = decodeBase64Url(presentation);

    const sessionTranscript = await buildOpenID4VPHandoverSessionTranscript({
        clientId,
        nonce: request.nonce,
        responseUri: request.responseUri,
    });
    return verifyAvDeviceResponse(deviceResponse, { sessionTranscript, nonce: request.nonce, ageThreshold, state }, options);
}

/** What {@link verifyAvDeviceResponse} binds the presentation to, per transport. */
export interface AvDeviceResponseContext {
    /** CBOR SessionTranscript the device signature must cover. */
    sessionTranscript: Uint8Array;
    nonce: string;
    ageThreshold: number;
    state?: string;
}

/**
 * The transport-independent part of AV verification, shared by the OpenID4VP
 * fallback ({@link verifyAvPresentation}) and the Digital Credentials API
 * (`verifyAvDcApiResponse`): the Annex A §A.4 data-model checks, issuer and
 * device authentication over `context.sessionTranscript`, trust, status, and
 * the age decision for the requested threshold. Steps 3–6 of
 * {@link verifyAvPresentation}.
 */
export async function verifyAvDeviceResponse(
    deviceResponse: Uint8Array,
    context: AvDeviceResponseContext,
    options: Omit<VerifyAvPresentationOptions, 'request'>,
): Promise<AvVerificationResult> {
    const { ageThreshold, state } = context;
    const ageOverAttribute = avAgeOverAttribute(ageThreshold);
    const base = { ageThreshold, ageOverAttribute, state };
    const fail = (failure: AvVerificationFailure, error: string, issuer: IssuerInfo = NO_ISSUER): AvVerificationResult => ({
        ...base,
        valid: false,
        ageVerified: false,
        ageOver: undefined,
        issuer,
        failure,
        error,
    });

    const structural = checkStructure(deviceResponse);
    if ('failure' in structural) return fail(structural.failure, structural.error);

    const parsed = await parser.parse(deviceResponse, {
        trustedCertificates: [],
        nonce: context.nonce,
        trustStore: options.trustStore,
        mdocDocumentSignerEkus: options.documentSignerEkus ?? [AV_DOCUMENT_SIGNER_EKU, ISO_18013_5_DS_EKU],
        mdocSessionTranscript: context.sessionTranscript,
        expectedDocType: AV_DOCTYPE,
        allowedAlgorithms: options.allowedAlgorithms,
        revocationPolicy: options.revocationPolicy ?? 'skip',
        fetcher: options.fetcher,
        cache: options.cache,
        clockSkewTolerance: options.clockSkewTolerance,
        statusPolicy: options.statusPolicy,
        statusListResolver: options.statusListResolver,
    });
    const credentialStatus = parsed.credentialStatus ? { credentialStatus: parsed.credentialStatus } : {};
    if (!parsed.valid) {
        // The parser only sets credentialStatus once everything else verified,
        // so an invalid result carrying it was rejected by the status check.
        const failure = parsed.credentialStatus ? 'credential_status' : 'invalid_credential';
        return { ...fail(failure, parsed.error ?? 'mdoc verification failed', parsed.issuer), ...credentialStatus };
    }

    // The parser has now verified the digest of every IssuerSignedItem, so the
    // elements the structure check decoded are the issuer-signed values. They
    // are read from there rather than from `parsed.namespacedClaims`, which
    // keeps only the last of two items with the same identifier: a conflicting
    // duplicate must surface as inconsistent, not be silently dropped.
    const decision = decideAvAgeOver(structural.elements, ageThreshold);
    if ('failure' in decision) {
        return { ...fail(decision.failure, decision.error, parsed.issuer), ...credentialStatus };
    }

    return {
        ...base,
        valid: true,
        ageVerified: decision.ageOver,
        ageOver: decision.ageOver,
        decidedBy: decision.decidedBy,
        issuer: parsed.issuer,
        trust: parsed.trust,
        ...credentialStatus,
    };
}

function toBody(response: AvAuthorizationResponseInput): Record<string, unknown> {
    if (typeof response === 'string') {
        return Object.fromEntries(new URLSearchParams(response));
    }
    if (response instanceof URLSearchParams) {
        return Object.fromEntries(response);
    }
    if (typeof response !== 'object' || response === null || Array.isArray(response)) {
        throw new AvResponseError('malformed_response', 'response must be a form body string, URLSearchParams or object');
    }
    return response;
}

function throwIfWalletError(body: Record<string, unknown>): void {
    if (body.error === undefined) return;
    // Any `error` member is a wallet error, even a malformed one: it must never
    // fall through to presentation parsing.
    const error = typeof body.error === 'string' ? body.error : 'invalid_response';
    throw new WalletErrorResponseError({ ...body, error });
}

/** OpenID4VP 1.0 §8.1: `vp_token` is a JSON object keyed by DCQL credential id, each value an array. */
function extractPresentation(body: Record<string, unknown>, credentialId: string): string {
    let vpToken = body.vp_token;
    if (typeof vpToken === 'string') {
        try {
            vpToken = JSON.parse(vpToken);
        } catch (err) {
            throw new AvResponseError('malformed_response', 'vp_token is not valid JSON (OpenID4VP 1.0 §8.1)', {
                cause: err as Error,
            });
        }
    }
    if (typeof vpToken !== 'object' || vpToken === null || Array.isArray(vpToken)) {
        throw new AvResponseError('malformed_response', 'response must contain vp_token as a JSON object (OpenID4VP 1.0 §8.1)');
    }
    const ids = Object.keys(vpToken);
    const entry = (vpToken as Record<string, unknown>)[credentialId];
    if (ids.length !== 1 || !Array.isArray(entry) || entry.length !== 1 || typeof entry[0] !== 'string') {
        throw new AvResponseError(
            'unexpected_presentation',
            `vp_token must hold exactly one mso_mdoc presentation under "${credentialId}"`,
        );
    }
    return entry[0];
}

function decodeBase64Url(value: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) {
        throw new AvResponseError('malformed_response', 'the mso_mdoc presentation is not base64url');
    }
    const base64 = value.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
    let binary: string;
    try {
        binary = globalThis.atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
    } catch (err) {
        throw new AvResponseError('malformed_response', 'the mso_mdoc presentation is not base64url', {
            cause: err as Error,
        });
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

/**
 * Annex A §A.4 data-model checks on the decoded (not yet verified) structure.
 * Returns the `age_over_NN` elements, which the caller may use only after the
 * parser has verified every item's digest against the signed MSO.
 */
export function checkStructure(
    bytes: Uint8Array,
): { failure: AvVerificationFailure; error: string } | { elements: AvAgeOverElement[] } {
    let deviceResponse: unknown;
    try {
        deviceResponse = decoder.decode(bytes);
    } catch {
        return { failure: 'malformed_credential', error: 'vp_token is not a CBOR DeviceResponse' };
    }
    if (!(deviceResponse instanceof Map)) {
        return { failure: 'malformed_credential', error: 'DeviceResponse must be a CBOR map' };
    }
    const status = deviceResponse.get('status');
    if (status !== undefined && status !== 0) {
        return { failure: 'malformed_credential', error: `DeviceResponse status is ${String(status)}, expected 0` };
    }
    const documents = deviceResponse.get('documents');
    if (!Array.isArray(documents) || documents.length !== 1 || !(documents[0] instanceof Map)) {
        return { failure: 'wrong_doctype', error: 'DeviceResponse must contain exactly one document' };
    }
    const document = documents[0] as Map<unknown, unknown>;
    const docType = document.get('docType');
    if (docType !== AV_DOCTYPE) {
        return { failure: 'wrong_doctype', error: `docType is "${String(docType)}", expected "${AV_DOCTYPE}"` };
    }

    const issuerSigned = document.get('issuerSigned');
    const nameSpaces = issuerSigned instanceof Map ? issuerSigned.get('nameSpaces') : undefined;
    if (!(nameSpaces instanceof Map)) {
        return { failure: 'malformed_credential', error: 'issuerSigned.nameSpaces must be a map' };
    }
    const elements: AvAgeOverElement[] = [];
    for (const [namespace, items] of nameSpaces) {
        if (namespace !== AV_NAMESPACE) {
            return {
                failure: 'unexpected_attribute',
                error: `namespace "${String(namespace)}" is not allowed in a Proof of Age attestation`,
            };
        }
        if (!Array.isArray(items)) {
            return { failure: 'malformed_credential', error: `nameSpaces["${AV_NAMESPACE}"] must be an array` };
        }
        for (const item of items) {
            const element = decodeEmbedded(item);
            const identifier = element instanceof Map ? element.get('elementIdentifier') : undefined;
            if (typeof identifier !== 'string') {
                return { failure: 'malformed_credential', error: 'IssuerSignedItem has no elementIdentifier' };
            }
            if (!isAvAgeOverAttribute(identifier)) {
                return {
                    failure: 'unexpected_attribute',
                    error: `attribute "${identifier}" is not allowed in a Proof of Age attestation (Annex A §A.4.2)`,
                };
            }
            const value = (element as Map<unknown, unknown>).get('elementValue');
            if (typeof value !== 'boolean') {
                return { failure: 'invalid_attribute_value', error: `${identifier} must be a boolean` };
            }
            elements.push({ identifier, value });
        }
    }

    const deviceSigned = document.get('deviceSigned');
    if (deviceSigned instanceof Map) {
        const deviceNameSpaces = decodeEmbedded(deviceSigned.get('nameSpaces'));
        if (deviceNameSpaces instanceof Map && deviceNameSpaces.size > 0) {
            return {
                failure: 'device_signed_elements',
                error: 'device-signed elements are not part of a Proof of Age attestation',
            };
        }
    }
    return { elements };
}

/** Decode a tag-24 embedded CBOR value (Tag, extension object or raw bytes) to its content. */
function decodeEmbedded(value: unknown): unknown {
    let inner: unknown = value;
    if (value instanceof Tag && value.tag === 24) {
        inner = value.value;
    } else if (
        value !== null &&
        typeof value === 'object' &&
        !(value instanceof Uint8Array) &&
        !(value instanceof Map) &&
        'value' in value &&
        (value as { value: unknown }).value instanceof Uint8Array
    ) {
        inner = (value as { value: Uint8Array }).value;
    }
    if (!(inner instanceof Uint8Array)) return inner;
    try {
        return decoder.decode(inner);
    } catch {
        return undefined;
    }
}
