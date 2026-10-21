import type { DcqlQuery } from '@openeudi/dcql';

export interface AuthorizationRequestInput {
    clientId: string;
    responseUri: string;
    nonce: string;
    state?: string;
    responseMode?: 'direct_post' | 'direct_post.jwt';
}

export interface AuthorizationRequest {
    uri: string;
    dcqlQuery: DcqlQuery;
    nonce: string;
    state: string;
}

export interface SignedAuthorizationRequestInput {
    clientIdPrefix?: 'x509_san_dns' | 'x509_hash';
    hostname?: string;
    /**
     * Permit a self-signed leaf certificate for the verifier's own identity.
     *
     * Defaults to `false`. HAIP 1.0 Final requires the verifier certificate to
     * chain to a trust anchor the wallet recognises; a self-signed leaf asserts
     * an identity nothing vouches for, so wallets enforcing the profile will
     * reject the request object. Set this only for local development or tests.
     */
    allowSelfSignedCertificate?: boolean;
    requestUri: string;
    responseUri: string;
    nonce: string;
    state?: string;
    responseMode?: 'direct_post' | 'direct_post.jwt';
    signer: CryptoKeyPair;
    signingAlgorithm?: 'ES256' | 'ES384' | 'RS256';
    /** DER certificates for `x5c`: the leaf, then intermediates — never the trust anchor (HAIP 1.0 §5). */
    certificateChain: Uint8Array[];
    /**
     * Response-encryption key for `direct_post.jwt`. Generate a fresh,
     * ephemeral key pair for every request (HAIP 1.0 §5) and keep the private
     * key only for decrypting that request's response. `publicJwk` must carry
     * `alg`; without `kid`, its RFC 7638 thumbprint is used as `kid`.
     */
    encryptionKey?: {
        publicJwk: JsonWebKey;
        supportedEncValues?: string[];
    };
    vpFormatsSupported: Record<string, unknown>;
}

export interface SignedAuthorizationRequest {
    uri: string;
    requestObject: string;
    dcqlQuery: DcqlQuery;
    nonce: string;
    state: string;
}

export interface AuthorizationResponse {
    vp_token: Record<string, Array<string | object>>;
    state?: string;
    [key: string]: unknown;
}
