import { calculateJwkThumbprint, type JWK } from 'jose';
import type { DcqlQuery } from '@openeudi/dcql';

import { resolveRequestSigner, signRequestObject } from '../request-signing.js';
import { serializeVerifierInfo, verifierInfoProblem } from '../verifier-info.js';
import { DcApiRequestBuildError } from './errors.js';
import {
    describeUnsupportedProtocol,
    isSecureSerializedOrigin,
    isSupportedDcApiProtocol,
} from './protocols.js';
import type { DcApiRequest, DcApiRequestInput, DcApiResponseMode } from './types.js';

// Must stay a subset of what decryptAuthorizationResponse accepts, or the
// verifier would advertise an `enc` it then refuses to decrypt.
const SUPPORTED_ENC_VALUES: readonly string[] = ['A128GCM', 'A256GCM'];
const SUPPORTED_ENCRYPTION_ALG = 'ECDH-ES';
const DEFAULT_REQUEST_OBJECT_TTL_SECONDS = 300;

/**
 * Build an OpenID4VP 1.0 request for the W3C Digital Credentials API
 * (Appendix A). Returns the `{ protocol, data }` entry the integrator's
 * frontend passes to
 * `navigator.credentials.get({ digital: { requests: [request] } })`.
 *
 * - `openid4vp-v1-unsigned` (§A.3.1): parameters are sent as plain members of
 *   `data`; `client_id` is omitted, as §A.2 requires.
 * - `openid4vp-v1-signed` (§A.3.2.1): parameters go in a JWS Request Object
 *   (`data.request`) carrying `client_id` (`x509_hash` by default) and the
 *   REQUIRED `expected_origins`. Signed with the same checks as
 *   `createSignedAuthorizationRequest` (certificate binding, self-signed leaf,
 *   `trust_anchor_in_chain`).
 *
 * `verifierInfo` is validated as for the redirect-flow builders and emitted as
 * `verifier_info` in both variants.
 *
 * `openid4vp-v1-multisigned` and `org-iso-mdoc` are rejected with
 * `DcApiRequestBuildError('unsupported_protocol')`.
 */
export async function createDcApiRequest(
    input: DcApiRequestInput,
    query: DcqlQuery,
): Promise<DcApiRequest> {
    const protocol: unknown = input.protocol;
    if (!isSupportedDcApiProtocol(protocol)) {
        throw new DcApiRequestBuildError('unsupported_protocol', describeUnsupportedProtocol(protocol));
    }
    if (typeof input.nonce !== 'string' || input.nonce.length === 0) {
        throw new DcApiRequestBuildError('missing_nonce', 'nonce is required and must be a non-empty string');
    }
    if (!input.vpFormatsSupported || Object.keys(input.vpFormatsSupported).length === 0) {
        throw new DcApiRequestBuildError(
            'missing_vp_formats',
            'vpFormatsSupported is required and must be non-empty',
        );
    }

    if (input.verifierInfo !== undefined) {
        const problem = verifierInfoProblem(input.verifierInfo, query);
        if (problem) throw new DcApiRequestBuildError('invalid_verifier_info', problem);
    }

    const responseMode: unknown = input.responseMode ?? 'dc_api.jwt';
    if (responseMode !== 'dc_api' && responseMode !== 'dc_api.jwt') {
        throw new DcApiRequestBuildError(
            'unsupported_response_mode',
            `responseMode must be "dc_api" or "dc_api.jwt" (OpenID4VP 1.0 §A.2), got "${String(responseMode)}"`,
        );
    }

    const clientMetadata = await buildClientMetadata(input, responseMode);
    const params: Record<string, unknown> = {
        response_type: 'vp_token',
        response_mode: responseMode,
        nonce: input.nonce,
        dcql_query: query,
        client_metadata: clientMetadata,
    };
    if (input.verifierInfo !== undefined) {
        params.verifier_info = serializeVerifierInfo(input.verifierInfo);
    }

    if (input.protocol === 'openid4vp-v1-unsigned') {
        return {
            request: { protocol: 'openid4vp-v1-unsigned', data: params },
            nonce: input.nonce,
            responseMode,
            dcqlQuery: query,
        };
    }

    const expectedOrigins = validateExpectedOrigins(input.expectedOrigins);
    const signer = await resolveRequestSigner(input, 'x509_hash');
    const now = Math.floor(Date.now() / 1000);
    const ttl = input.requestObjectTtlSeconds ?? DEFAULT_REQUEST_OBJECT_TTL_SECONDS;

    const requestObject = await signRequestObject(
        {
            iss: signer.clientId,
            aud: 'https://self-issued.me/v2',
            client_id: signer.clientId,
            expected_origins: expectedOrigins,
            ...params,
            iat: now,
            exp: now + ttl,
        },
        signer,
    );

    return {
        request: { protocol: 'openid4vp-v1-signed', data: { request: requestObject } },
        nonce: input.nonce,
        responseMode,
        dcqlQuery: query,
        clientId: signer.clientId,
        expectedOrigins,
    };
}

async function buildClientMetadata(
    input: DcApiRequestInput,
    responseMode: DcApiResponseMode,
): Promise<Record<string, unknown>> {
    const clientMetadata: Record<string, unknown> = {
        vp_formats_supported: input.vpFormatsSupported,
    };
    if (responseMode !== 'dc_api.jwt') {
        return clientMetadata;
    }

    const publicJwk = input.encryptionKey?.publicJwk;
    if (!publicJwk) {
        throw new DcApiRequestBuildError(
            'missing_encryption_jwk',
            'dc_api.jwt response mode requires encryptionKey.publicJwk',
        );
    }
    // The JWK is sent to the browser. A private member here would leak the
    // decryption key to every page script and to the wallet.
    if ('d' in publicJwk) {
        throw new DcApiRequestBuildError(
            'private_key_in_jwk',
            'encryptionKey.publicJwk contains a private key member ("d"); pass the public JWK only',
        );
    }
    if (!publicJwk.alg) {
        throw new DcApiRequestBuildError(
            'missing_encryption_alg',
            'encryptionKey.publicJwk must carry alg (OpenID4VP 1.0 §8.3)',
        );
    }
    if (publicJwk.alg !== SUPPORTED_ENCRYPTION_ALG || publicJwk.kty !== 'EC') {
        throw new DcApiRequestBuildError(
            'unsupported_encryption_key',
            `encryptionKey.publicJwk must be an EC key with alg "${SUPPORTED_ENCRYPTION_ALG}" (got kty=${String(publicJwk.kty)}, alg=${publicJwk.alg})`,
        );
    }

    const encValues = input.encryptionKey?.supportedEncValues ?? [...SUPPORTED_ENC_VALUES];
    if (encValues.length === 0) {
        throw new DcApiRequestBuildError(
            'empty_supported_enc_values',
            'encryptionKey.supportedEncValues must not be empty (omit to use defaults [A128GCM, A256GCM])',
        );
    }
    const unsupported = encValues.filter((e) => !SUPPORTED_ENC_VALUES.includes(e));
    if (unsupported.length > 0) {
        throw new DcApiRequestBuildError(
            'unsupported_enc_value',
            `encryptionKey.supportedEncValues [${unsupported.join(', ')}] cannot be decrypted (supported: ${SUPPORTED_ENC_VALUES.join(', ')})`,
        );
    }

    // OpenID4VP 1.0 §5.1: "Each JWK in the set MUST have a kid".
    const kid = (publicJwk as JWK).kid ?? (await calculateJwkThumbprint(publicJwk as JWK, 'sha256'));
    clientMetadata.jwks = { keys: [{ ...publicJwk, use: 'enc', kid }] };
    clientMetadata.encrypted_response_enc_values_supported = encValues;
    return clientMetadata;
}

function validateExpectedOrigins(value: unknown): string[] {
    if (!Array.isArray(value) || value.length === 0) {
        throw new DcApiRequestBuildError(
            'missing_expected_origins',
            'expectedOrigins is required for openid4vp-v1-signed and must be a non-empty array (OpenID4VP 1.0 §A.2)',
        );
    }
    for (const origin of value) {
        if (!isSecureSerializedOrigin(origin)) {
            throw new DcApiRequestBuildError(
                'invalid_origin',
                `expectedOrigins entry "${String(origin)}" is not a serialized https origin (scheme://host[:port], no path or trailing slash)`,
            );
        }
    }
    return [...value];
}
