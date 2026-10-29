import type { DcqlQuery } from '@openeudi/dcql';

import type { RequestSignerInput } from '../request-signing.js';
import type { VerifierInfo } from '../types/verifier-info.js';
import type { PerCredentialVerifyOptionsMap, VerifyOptions } from '../types/verify.js';
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
 * ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): an ISO 18013-5 `DeviceRequest`
 * (version `"1.0"`, no reader authentication) plus an `EncryptionInfo` that
 * carries the nonce and a fresh P-256 recipient key for the HPKE-encrypted
 * response. The DCQL query must hold exactly one `mso_mdoc` credential with a
 * `doctype_value` and `[namespace, element]` claim paths; it is translated
 * into the `DeviceRequest`.
 */
export interface DcApiIsoMdocRequestInput {
    protocol: 'org-iso-mdoc';
    /**
     * The `EncryptionInfo` nonce as base64url, at least 16 bytes once decoded.
     * Generated (16 random bytes, as the multipaz reference verifier does)
     * when omitted.
     */
    nonce?: string;
}

/**
 * The `{ protocol, data }` entry for `navigator.credentials.get()`. Both values
 * are base64url (no padding) of CBOR, and `data` holds nothing else: the EU AV
 * iOS library parses it as a string-to-string map.
 */
export interface DcApiIsoMdocCredentialRequest {
    protocol: 'org-iso-mdoc';
    data: { deviceRequest: string; encryptionInfo: string };
}

/** The request plus every secret `verifyDcApiResponse` needs. Keep it server-side. */
export interface DcApiIsoMdocRequest {
    /** Send this to the browser and pass it in `digital.requests`. */
    request: DcApiIsoMdocCredentialRequest;
    /** The `EncryptionInfo` nonce as base64url. */
    nonce: string;
    /**
     * `request.data.encryptionInfo`, the exact base64url string the wallet
     * hashes into the SessionTranscript. Store it verbatim.
     */
    encryptionInfo: string;
    /**
     * The ephemeral HPKE recipient private key (P-256 JWK with `d`). It opens
     * the response, so store it server-side only and drop it once used.
     */
    recipientPrivateJwk: JsonWebKey;
    dcqlQuery: DcqlQuery;
}

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

    /**
     * Trust and status options per DCQL credential query id, as on
     * `verifyAuthorizationResponse` (`VerifyAuthorizationResponseOptions.perCredential`):
     * the answered credential's entry replaces the top-level trust and status
     * options, with no fallback and no merging.
     */
    perCredential?: PerCredentialVerifyOptionsMap;
};

/**
 * Options for verifying an `org-iso-mdoc` (ISO/IEC 18013-7 Annex C) response.
 * `protocol: 'org-iso-mdoc'` selects this variant.
 */
export type VerifyDcApiIsoMdocResponseOptions = Omit<VerifyOptions, 'audience' | 'nonce' | 'mdocSessionTranscript'> & {
    protocol: 'org-iso-mdoc';

    /**
     * The web origin the request was made from, as the browser serializes it
     * (`https://shop.example`). Take it from server configuration — never from
     * the request being verified. It is bound into the SessionTranscript, which
     * is also the HPKE `info`.
     */
    origin: string;

    /** The stored `encryptionInfo` string of the request, byte for byte. */
    encryptionInfo: string;

    /**
     * The stored recipient private key: the `recipientPrivateJwk` the builder
     * returned, or an ECDH P-256 private `CryptoKey` (usage `deriveBits`).
     */
    decryptionKey: CryptoKey | JsonWebKey;

    /** When set, must equal the nonce inside `encryptionInfo` (base64url). */
    nonce?: string;
};
