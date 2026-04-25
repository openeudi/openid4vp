import { v4 as uuidv4 } from 'uuid';
import { SignJWT } from 'jose';
import { X509Certificate } from '@peculiar/x509';
import type { DcqlQuery } from '@openeudi/dcql';

import { SignedRequestBuildError } from './errors.js';
import type {
    SignedAuthorizationRequestInput,
    SignedAuthorizationRequest,
} from './types/authorization.js';

const DEFAULT_SUPPORTED_ENC_VALUES: readonly string[] = ['A128GCM', 'A256GCM'];
const SUPPORTED_SIGNING_ALGS = new Set(['ES256', 'ES384', 'RS256']);

/**
 * Build a signed authorization request (JAR) per OpenID4VP 1.0 §5.10 / RFC 9101.
 *
 * Validates that the signing key is bound to the leaf certificate and that the
 * leaf cert's SAN DNSName equals the declared hostname. Emits a short URI
 * carrying only `client_id` + `request_uri`, plus the JWS string the caller
 * must host at `requestUri` with Content-Type `application/oauth-authz-req+jwt`.
 *
 * Client Identifier Prefix is always `x509_san_dns` — other prefixes deferred.
 */
export async function createSignedAuthorizationRequest(
    input: SignedAuthorizationRequestInput,
    query: DcqlQuery,
): Promise<SignedAuthorizationRequest> {
    if (input.certificateChain.length === 0) {
        throw new SignedRequestBuildError(
            'empty_cert_chain',
            'certificateChain must contain at least the leaf certificate',
        );
    }

    const signingAlg = input.signingAlgorithm ?? 'ES256';
    if (!SUPPORTED_SIGNING_ALGS.has(signingAlg)) {
        throw new SignedRequestBuildError(
            'unsupported_signing_alg',
            `signingAlgorithm ${signingAlg} is not supported (expected ES256/ES384/RS256)`,
        );
    }

    if (!input.vpFormatsSupported || Object.keys(input.vpFormatsSupported).length === 0) {
        throw new SignedRequestBuildError(
            'missing_vp_formats',
            'vpFormatsSupported is required and must be non-empty',
        );
    }

    const leafCert = new X509Certificate(toArrayBuffer(input.certificateChain[0]));

    const sanDnsNames = extractDnsNames(leafCert);
    if (!sanDnsNames.includes(input.hostname)) {
        throw new SignedRequestBuildError(
            'hostname_cert_mismatch',
            `leaf cert SAN DNSName values [${sanDnsNames.join(', ')}] do not include hostname "${input.hostname}"`,
        );
    }

    const signerPublicSpki = new Uint8Array(
        await crypto.subtle.exportKey('spki', input.signer.publicKey),
    );
    const leafSpki = new Uint8Array(leafCert.publicKey.rawData);
    if (!bytesEqual(signerPublicSpki, leafSpki)) {
        throw new SignedRequestBuildError(
            'signing_key_cert_mismatch',
            'signer.publicKey SPKI does not match leaf certificate SPKI',
        );
    }

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
    const clientId = `x509_san_dns:${input.hostname}`;
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
        const jwk = { ...input.encryptionKey.publicJwk, use: 'enc' };
        clientMetadata.jwks = { keys: [jwk] };
        clientMetadata.encrypted_response_enc_values_supported =
            enc ?? [...DEFAULT_SUPPORTED_ENC_VALUES];
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

    const x5c = input.certificateChain.map((der) => bytesToBase64(der));

    const jws = await new SignJWT(payload)
        .setProtectedHeader({ typ: 'oauth-authz-req+jwt', alg: signingAlg, x5c })
        .sign(input.signer.privateKey);

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

function extractDnsNames(cert: X509Certificate): string[] {
    // The @peculiar/x509 SubjectAlternativeName extension is identified by OID
    // 2.5.29.17. Its `.names.items` (a GeneralNames collection) yields entries
    // with { type, value } — where `type: 'dns'` entries are DNSNames.
    const SAN_OID = '2.5.29.17';
    const ext = cert.extensions.find((e) => e.type === SAN_OID);
    if (!ext) return [];
    // Dynamic narrowing: the extension carries a `names` GeneralNames object.
    const names = (ext as unknown as { names?: { items?: Array<{ type: string; value: string }> } }).names;
    const items = names?.items ?? [];
    return items.filter((e) => e.type === 'dns').map((e) => e.value);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

function bytesToBase64(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    // @peculiar/x509 expects ArrayBuffer (not ArrayBufferLike). Copy bytes to
    // a fresh ArrayBuffer to satisfy the type and handle any buffer backing.
    const out = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(out).set(bytes);
    return out;
}
