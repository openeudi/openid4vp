import type { DcqlQuery } from '@openeudi/dcql';

import type { RequestSignerInput } from '../request-signing.js';
import type { VerifierInfo } from '../types/verifier-info.js';
import type { VerifyOptions } from '../types/verify.js';
import type { DcApiOpenId4VpProtocol } from './protocols.js';

/**
 * `dc_api` returns the Authorization Response in the clear; `dc_api.jwt`
 * returns it as a JWE encrypted to the verifier's key (OpenID4VP 1.0 §A.2,
 * §8.3). HAIP 1.0 §5.2 requires `dc_api.jwt`.
 */
export type DcApiResponseMode = 'dc_api' | 'dc_api.jwt';

interface DcApiRequestCommonInput {
    /** Fresh, unpredictable per-request value; bound into the presentation. */
    nonce: string;

    /** Default `'dc_api.jwt'` (HAIP 1.0 §5.2). */
    responseMode?: DcApiResponseMode;

    /**
     * Response-encryption public key, REQUIRED for `dc_api.jwt`. An EC P-256
     * JWK with `alg: 'ECDH-ES'`, normally ephemeral per request. Published in
     * `client_metadata.jwks` with `use: 'enc'`; a missing `kid` defaults to the
     * key's RFC 7638 thumbprint (§5.1 requires one). Ignored for `dc_api`.
     */
    encryptionKey?: {
        publicJwk: JsonWebKey;
        /** Default `['A128GCM', 'A256GCM']` — the set `decryptAuthorizationResponse` accepts. */
        supportedEncValues?: string[];
    };

    /** `client_metadata.vp_formats_supported` (OpenID4VP 1.0 §11.1). */
    vpFormatsSupported: Record<string, unknown>;

    /**
     * Attestations about the Verifier, emitted as `verifier_info` (OpenID4VP 1.0
     * §5.1): inside the Request Object for `openid4vp-v1-signed`, as a plain
     * `data` member for `openid4vp-v1-unsigned`. An unsigned request cannot
     * bind them to the Verifier, so wallets enforcing ETSI TS 119 472-2 or HAIP
     * expect them in a signed request. Build entries with
     * `registrarDatasetVerifierInfo` and `registrationCertVerifierInfo`.
     */
    verifierInfo?: VerifierInfo[];
}

/** OpenID4VP 1.0 §A.3.1: parameters sent in the clear, `client_id` omitted. */
export interface DcApiUnsignedRequestInput extends DcApiRequestCommonInput {
    protocol: 'openid4vp-v1-unsigned';
}

/**
 * OpenID4VP 1.0 §A.3.2.1: parameters in a JWS (compact) Request Object passed
 * as `data.request`. `clientIdPrefix` defaults to `x509_hash`, which HAIP 1.0
 * requires for signed requests; `x509_san_dns` is also accepted.
 */
export interface DcApiSignedRequestInput extends DcApiRequestCommonInput, RequestSignerInput {
    protocol: 'openid4vp-v1-signed';
    /**
     * Origins the request may be presented from (§A.2 `expected_origins`,
     * REQUIRED for signed requests). Serialized origins, e.g.
     * `https://shop.example` — no path, no trailing slash.
     */
    expectedOrigins: string[];
    /** Request Object lifetime (`exp - iat`). Default 300 seconds. */
    requestObjectTtlSeconds?: number;
}

export type DcApiRequestInput = DcApiUnsignedRequestInput | DcApiSignedRequestInput;

/**
 * One entry of `navigator.credentials.get({ digital: { requests: [...] } })`.
 * Serializable as JSON so the server can hand it to the browser as-is.
 */
export interface DcApiCredentialRequest {
    protocol: DcApiOpenId4VpProtocol;
    data: Record<string, unknown>;
}

export interface DcApiRequest {
    /** Send this to the browser and pass it in `digital.requests`. */
    request: DcApiCredentialRequest;
    nonce: string;
    responseMode: DcApiResponseMode;
    dcqlQuery: DcqlQuery;
    /** Signed requests only: the `client_id` the Request Object carries. */
    clientId?: string;
    /** Signed requests only: the `expected_origins` the Request Object carries. */
    expectedOrigins?: string[];
}

/**
 * What the browser resolves with: the `DigitalCredential`'s `protocol` and
 * `data`, posted to the server by the integrator's frontend (for example
 * `JSON.stringify({ protocol: credential.protocol, data: credential.data })`).
 * A `data` that arrives as a JSON string is parsed.
 */
export interface DcApiResponse {
    protocol: string;
    data: unknown;
}

export type VerifyDcApiResponseOptions = Omit<VerifyOptions, 'audience'> & {
    /**
     * The verifier's web origin as the browser serializes it, e.g.
     * `https://shop.example`. Take it from server configuration — never from
     * the request being verified. The KB-JWT `aud` must equal
     * `origin:<origin>` and the mdoc SessionTranscript binds it.
     */
    origin: string;

    /** The response mode the request asked for. Default `'dc_api.jwt'`. */
    responseMode?: DcApiResponseMode;

    /** When set, the response's `protocol` must equal it. */
    protocol?: DcApiOpenId4VpProtocol;

    /** Private key matching the request's encryption JWK (`dc_api.jwt`). */
    decryptionKey?: CryptoKey;

    /**
     * The public encryption JWK sent in the request. Needed for an `mso_mdoc`
     * response under `dc_api.jwt`: its thumbprint is part of the
     * `OpenID4VPDCAPIHandover` SessionTranscript.
     */
    verifierEncryptionJwk?: JsonWebKey;

    /**
     * Require a KB-JWT even when the SD-JWT VC carries no `cnf`. Defaults to
     * `true` here (unlike the redirect flow): over the DC API, the KB-JWT is
     * what binds an SD-JWT presentation to the origin and nonce.
     */
    requireKeyBinding?: boolean;
};
