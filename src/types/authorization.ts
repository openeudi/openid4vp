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
    hostname: string;
    requestUri: string;
    responseUri: string;
    nonce: string;
    state?: string;
    responseMode?: 'direct_post' | 'direct_post.jwt';
    signer: CryptoKeyPair;
    signingAlgorithm?: 'ES256' | 'ES384' | 'RS256';
    certificateChain: Uint8Array[];
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
