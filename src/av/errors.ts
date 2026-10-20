import { OpenID4VPError } from '../errors.js';

// ---------------------------------------------------------------------------
// EU Age Verification (AV) profile, OpenID4VP fallback (Annex A §A.6)
// ---------------------------------------------------------------------------

export type AvRequestBuildErrorCode =
    | 'invalid_response_uri'
    | 'invalid_nonce'
    | 'invalid_state'
    | 'invalid_base_uri'
    | 'invalid_age_threshold'
    | 'invalid_credential_id';

/** `createAvAuthorizationRequest` refused its input. */
export class AvRequestBuildError extends OpenID4VPError {
    readonly code: AvRequestBuildErrorCode;
    constructor(code: AvRequestBuildErrorCode, message: string) {
        super(message);
        this.code = code;
    }
}

export type AvResponseErrorCode =
    /** The body is not an OpenID4VP §8.1 response: no `vp_token`, or it is not a JSON object. */
    | 'malformed_response'
    /** `state` does not match the value sent in the request. */
    | 'state_mismatch'
    /** `vp_token` is not exactly one presentation for the requested credential id. */
    | 'unexpected_presentation'
    /** The verification context does not describe an AV `redirect_uri` request. */
    | 'invalid_context';

/**
 * An AV authorization response was rejected before the Proof of Age
 * attestation was examined. A wallet error response raises
 * `WalletErrorResponseError` instead.
 */
export class AvResponseError extends OpenID4VPError {
    readonly code: AvResponseErrorCode;
    constructor(code: AvResponseErrorCode, message: string, options?: { cause?: Error }) {
        super(message, options);
        this.code = code;
    }
}
