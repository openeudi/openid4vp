import type { CredentialQuery, DcqlQuery } from '@openeudi/dcql';

import {
    AV_DEFAULT_AGE_THRESHOLD,
    AV_DEFAULT_BASE_URI,
    AV_DEFAULT_CREDENTIAL_ID,
    AV_DOCTYPE,
    AV_NAMESPACE,
    avRequestedAgeOverAttributes,
} from './constants.js';
import { AvRequestBuildError } from './errors.js';
import type { AvAuthorizationRequest, AvAuthorizationRequestInput } from './types.js';

// What the AV reference verifier (av-srv-verifier-endpoint VerifierConfig.kt)
// advertises: ES256, ES384, ES512 — the COSE algorithms the mdoc parser accepts
// by default. ES256 (-7) is the one every AV entity MUST support (Annex A §A.7).
function defaultVpFormatsSupported(): Record<string, unknown> {
    return { mso_mdoc: { issuerauth_alg_values: [-7, -35, -36], deviceauth_alg_values: [-7, -35, -36] } };
}

// RFC 3986 unreserved characters; a nonce outside this set would be
// percent-encoded on the way out and is easy to mangle when persisted.
const NONCE_PATTERN = /^[A-Za-z0-9._~-]{22,}$/;
const CREDENTIAL_ID_PATTERN = /^[A-Za-z0-9_-]+$/;
const SCHEME_ONLY_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/$/i;

/**
 * `client_id` for the AV profile: the `redirect_uri:` Client Identifier
 * Prefix followed by the `response_uri` (Annex A §A.6, OpenID4VP 1.0 §5.9.3).
 */
export function avClientIdFor(responseUri: string): string {
    return `redirect_uri:${responseUri}`;
}

/**
 * Build the EU Age Verification OpenID4VP fallback request (Annex A §A.6):
 * an unsigned request passed by value as URL query parameters to the AV app
 * (`av://` by default).
 *
 * - `response_type=vp_token`, `response_mode=direct_post` — both fixed by the profile.
 * - `client_id=redirect_uri:<response_uri>`. No signing, no `x5c`, no
 *   `request` / `request_uri` (Annex A: "MUST NOT be used").
 * - `dcql_query` for one `mso_mdoc` credential of doctype `eu.europa.ec.av.1`
 *   with claim path `["eu.europa.ec.av.1", "age_over_NN"]` (default NN = 18).
 *   Below 18 it also accepts `age_over_18` (every attestation carries it;
 *   `age_over_NN` is optional): both claims get an `id` and `claim_sets`
 *   prefers `age_over_NN`.
 * - `client_metadata.vp_formats_supported` for `mso_mdoc`. Under the
 *   `redirect_uri` prefix all verifier metadata travels in `client_metadata`
 *   (OpenID4VP 1.0 §5.9.3), and §5.1 makes `vp_formats_supported` REQUIRED
 *   when the wallet has no other way to learn it. Pass
 *   `vpFormatsSupported: null` to omit `client_metadata`, as the Annex A
 *   §A.11 example and the reference web verifier's deep link do.
 * - `nonce` generated (256 bits) when not supplied; `state` only when supplied.
 *
 * Persist the returned object (or at least `responseUri`, `nonce`, `state`,
 * `ageThreshold`, `credentialId`) and hand it to `verifyAvPresentation`.
 */
export function createAvAuthorizationRequest(input: AvAuthorizationRequestInput): AvAuthorizationRequest {
    const responseUri = validateResponseUri(input.responseUri);
    const nonce = input.nonce ?? generateNonce();
    if (typeof nonce !== 'string' || !NONCE_PATTERN.test(nonce)) {
        throw new AvRequestBuildError(
            'invalid_nonce',
            'nonce must be at least 22 characters (128 bits as base64url) from [A-Za-z0-9._~-]',
        );
    }
    if (input.state !== undefined && (typeof input.state !== 'string' || input.state.length === 0)) {
        throw new AvRequestBuildError('invalid_state', 'state must be a non-empty string when supplied');
    }
    const credentialId = input.credentialId ?? AV_DEFAULT_CREDENTIAL_ID;
    if (typeof credentialId !== 'string' || !CREDENTIAL_ID_PATTERN.test(credentialId)) {
        throw new AvRequestBuildError(
            'invalid_credential_id',
            'credentialId must be a non-empty string of [A-Za-z0-9_-] (OpenID4VP 1.0 §6.1)',
        );
    }
    const ageThreshold = input.ageThreshold ?? AV_DEFAULT_AGE_THRESHOLD;
    let requestedAgeOverAttributes: string[];
    try {
        requestedAgeOverAttributes = avRequestedAgeOverAttributes(ageThreshold);
    } catch (err) {
        throw new AvRequestBuildError('invalid_age_threshold', (err as Error).message);
    }
    const ageOverAttribute = requestedAgeOverAttributes[0]!;
    const baseUri = validateBaseUri(input.baseUri ?? AV_DEFAULT_BASE_URI);

    const clientId = avClientIdFor(responseUri);
    const dcqlQuery: DcqlQuery = {
        credentials: [
            {
                id: credentialId,
                format: 'mso_mdoc',
                meta: { doctype_value: AV_DOCTYPE },
                ...ageOverClaims(requestedAgeOverAttributes),
            },
        ],
    };
    const clientMetadata: Record<string, unknown> | undefined =
        input.vpFormatsSupported === null
            ? undefined
            : { vp_formats_supported: input.vpFormatsSupported ?? defaultVpFormatsSupported() };

    const params = new URLSearchParams({
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id: clientId,
        response_uri: responseUri,
        nonce,
        dcql_query: JSON.stringify(dcqlQuery),
    });
    if (clientMetadata !== undefined) params.set('client_metadata', JSON.stringify(clientMetadata));
    if (input.state !== undefined) params.set('state', input.state);

    const separator = baseUri.includes('?') ? (baseUri.endsWith('?') || baseUri.endsWith('&') ? '' : '&') : '?';
    const result: AvAuthorizationRequest = {
        uri: `${baseUri}${separator}${params.toString()}`,
        clientId,
        responseUri,
        nonce,
        ageThreshold,
        ageOverAttribute,
        requestedAgeOverAttributes,
        credentialId,
        dcqlQuery,
    };
    if (clientMetadata !== undefined) result.clientMetadata = clientMetadata;
    if (input.state !== undefined) result.state = input.state;
    return result;
}

/**
 * DCQL claims for the requested `age_over_NN` elements. One element: a single
 * claim without `id`, exactly as the Annex A §A.11 example. Several: each
 * claim gets its element identifier as `id`, and `claim_sets` lists them one
 * per option in preference order (OpenID4VP 1.0 §6.4.1), so the wallet
 * discloses `age_over_NN` when it has it and `age_over_18` otherwise.
 */
function ageOverClaims(attributes: string[]): Pick<CredentialQuery, 'claims' | 'claim_sets'> {
    if (attributes.length === 1) {
        return { claims: [{ path: [AV_NAMESPACE, attributes[0]!] }] };
    }
    return {
        claims: attributes.map((attribute) => ({ id: attribute, path: [AV_NAMESPACE, attribute] })),
        claim_sets: attributes.map((attribute) => [attribute]),
    };
}

function validateResponseUri(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new AvRequestBuildError('invalid_response_uri', 'responseUri is required');
    }
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new AvRequestBuildError('invalid_response_uri', `responseUri is not an absolute URL: "${value}"`);
    }
    // The profile authenticates the verifier through TLS and the Web PKI only
    // (Annex A §A.10), so the response endpoint must be https.
    if (url.protocol !== 'https:') {
        throw new AvRequestBuildError('invalid_response_uri', `responseUri must use https, got "${url.protocol}"`);
    }
    if (url.hash !== '') {
        throw new AvRequestBuildError('invalid_response_uri', 'responseUri must not contain a fragment');
    }
    return value;
}

function validateBaseUri(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new AvRequestBuildError('invalid_base_uri', 'baseUri must be a non-empty string');
    }
    if (SCHEME_ONLY_PATTERN.test(value)) return value;
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new AvRequestBuildError('invalid_base_uri', `baseUri is not an absolute URI: "${value}"`);
    }
    if (url.hash !== '') {
        throw new AvRequestBuildError('invalid_base_uri', 'baseUri must not contain a fragment');
    }
    if (url.protocol === 'http:') {
        throw new AvRequestBuildError('invalid_base_uri', 'baseUri must not use http');
    }
    return value;
}

function generateNonce(): string {
    const bytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(bytes);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
