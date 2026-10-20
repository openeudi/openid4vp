import { v4 as uuidv4 } from 'uuid';
import { calculateJwkThumbprint, type JWK } from 'jose';
import type { DcqlQuery } from '@openeudi/dcql';

import { SignedRequestBuildError } from './errors.js';
import {
    resolveRequestSigner,
    signRequestObject,
    validateRequestSignerInput,
} from './request-signing.js';
import { serializeVerifierInfo, verifierInfoProblem } from './verifier-info.js';
import type {
    SignedAuthorizationRequestInput,
    SignedAuthorizationRequest,
} from './types/authorization.js';

const DEFAULT_SUPPORTED_ENC_VALUES: readonly string[] = ['A128GCM', 'A256GCM'];

/**
 * Build a signed authorization request (JAR) per OpenID4VP 1.0 §5.10 / RFC 9101.
 *
 * Validates that the signing key is bound to the leaf certificate and that the
 * leaf cert's SAN DNSName equals the declared hostname. Emits a short URI
 * carrying only `client_id` + `request_uri`, plus the JWS string the caller
 * must host at `requestUri` with Content-Type `application/oauth-authz-req+jwt`.
 *
 * Client Identifier Prefix defaults to `x509_san_dns`; pass
 * `clientIdPrefix: 'x509_hash'` to use the leaf certificate's SHA-256 hash
 * instead (OpenID4VP 1.0 §5.9.3). `hostname` is required only for
 * `x509_san_dns`.
 *
 * `certificateChain` is the leaf followed by any intermediates. It MUST NOT
 * end in the trust anchor (HAIP 1.0 §5): a multi-certificate chain whose last
 * certificate is self-signed is refused with `trust_anchor_in_chain`.
 *
 * `encryptionKey` MUST be a fresh, ephemeral key pair generated for this one
 * request (HAIP 1.0 §5) — never reuse it across requests. Its JWK goes into
 * `client_metadata.jwks`; a JWK without `kid` gets its RFC 7638 SHA-256
 * thumbprint as `kid` (OpenID4VP 1.0 §5.1 requires one).
 */
export async function createSignedAuthorizationRequest(
    input: SignedAuthorizationRequestInput,
    query: DcqlQuery,
): Promise<SignedAuthorizationRequest> {
    validateRequestSignerInput(input);

    if (!input.vpFormatsSupported || Object.keys(input.vpFormatsSupported).length === 0) {
        throw new SignedRequestBuildError(
            'missing_vp_formats',
            'vpFormatsSupported is required and must be non-empty',
        );
    }

    if (input.verifierInfo !== undefined) {
        const problem = verifierInfoProblem(input.verifierInfo, query);
        if (problem) throw new SignedRequestBuildError('invalid_verifier_info', problem);
    }

    // Leaf/SAN binding, signer-key match, self-signed leaf and
    // trust_anchor_in_chain (HAIP 1.0 §5) are all enforced in request-signing.ts.
    const signer = await resolveRequestSigner(input, 'x509_san_dns');

    const responseMode = input.responseMode ?? 'direct_post.jwt';

    if (responseMode === 'direct_post.jwt') {
        if (!input.encryptionKey?.publicJwk) {
            throw new SignedRequestBuildError(
                'missing_encryption_jwk',
                'direct_post.jwt response mode requires encryptionKey.publicJwk',
            );
        }
        if (!input.encryptionKey.publicJwk.alg) {
            throw new SignedRequestBuildError(
                'missing_encryption_alg',
                'encryptionKey.publicJwk must carry alg (OpenID4VP 1.0 §8.3)',
            );
        }
    }

    const state = input.state ?? uuidv4();
    const clientId = signer.clientId;
    const now = Math.floor(Date.now() / 1000);

    const clientMetadata: Record<string, unknown> = {
        vp_formats_supported: input.vpFormatsSupported,
    };

    if (responseMode === 'direct_post.jwt' && input.encryptionKey) {
        const enc = input.encryptionKey.supportedEncValues;
        if (enc !== undefined && enc.length === 0) {
            throw new SignedRequestBuildError(
                'empty_supported_enc_values',
                'encryptionKey.supportedEncValues must not be empty (omit to use defaults [A128GCM, A256GCM])',
            );
        }
        const publicJwk = input.encryptionKey.publicJwk as JWK;
        const kid = publicJwk.kid ?? (await calculateJwkThumbprint(publicJwk, 'sha256'));
        const jwk = { ...publicJwk, kid, use: 'enc' };
        clientMetadata.jwks = { keys: [jwk] };
        const encValues = enc ?? [...DEFAULT_SUPPORTED_ENC_VALUES];
        clientMetadata.encrypted_response_enc_values_supported = encValues;
    }

    const payload: Record<string, unknown> = {
        iss: clientId,
        aud: 'https://self-issued.me/v2',
        response_type: 'vp_token',
        response_mode: responseMode,
        client_id: clientId,
        response_uri: input.responseUri,
        nonce: input.nonce,
        state,
        dcql_query: query,
        client_metadata: clientMetadata,
        iat: now,
        exp: now + 120,
    };
    if (input.verifierInfo !== undefined) {
        payload.verifier_info = serializeVerifierInfo(input.verifierInfo);
    }

    const jws = await signRequestObject(payload, signer);

    const uriParams = new URLSearchParams({
        client_id: clientId,
        request_uri: input.requestUri,
    });

    return {
        uri: `openid4vp://authorize?${uriParams.toString()}`,
        requestObject: jws,
        dcqlQuery: query,
        nonce: input.nonce,
        state,
    };
}
