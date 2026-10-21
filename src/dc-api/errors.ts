import { OpenID4VPError } from '../errors.js';

// ---------------------------------------------------------------------------
// W3C Digital Credentials API (OpenID4VP 1.0 Appendix A)
// ---------------------------------------------------------------------------

export type DcApiRequestBuildErrorCode =
    | 'unsupported_protocol'
    | 'unsupported_response_mode'
    | 'missing_nonce'
    | 'missing_vp_formats'
    | 'missing_encryption_jwk'
    | 'missing_encryption_alg'
    | 'unsupported_encryption_key'
    | 'private_key_in_jwk'
    | 'empty_supported_enc_values'
    | 'unsupported_enc_value'
    | 'missing_expected_origins'
    | 'invalid_origin'
    | 'invalid_verifier_info';

/** `createDcApiRequest` refused its input. */
export class DcApiRequestBuildError extends OpenID4VPError {
    readonly code: DcApiRequestBuildErrorCode;
    constructor(code: DcApiRequestBuildErrorCode, message: string) {
        super(message);
        this.code = code;
    }
}

export type DcApiResponseErrorCode =
    | 'invalid_origin'
    | 'unsupported_protocol'
    | 'protocol_mismatch'
    | 'malformed_response'
    | 'unencrypted_response'
    | 'unexpected_encrypted_response'
    | 'audience_conflict';

/**
 * A Digital Credentials API response was rejected before any credential was
 * parsed: wrong protocol, wrong envelope shape for the requested response
 * mode, or a misconfigured verifier origin.
 */
export class DcApiResponseError extends OpenID4VPError {
    readonly code: DcApiResponseErrorCode;
    constructor(code: DcApiResponseErrorCode, message: string, options?: { cause?: Error }) {
        super(message, options);
        this.code = code;
    }
}

/**
 * Over the DC API a wallet error (§8.5) arrives as a fulfilled promise whose
 * `data` is `{ error }` (Appendix A.4), so `verifyDcApiResponse` detects it
 * explicitly. It throws the same class as the redirect flow: one
 * `WalletErrorResponseError` (`code`, `description`, `state`, `uri`).
 */
export { WalletErrorResponseError } from '../errors.js';
