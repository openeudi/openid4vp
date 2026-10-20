export class InvalidSignatureError extends Error {
    constructor(message = 'Credential signature validation failed') {
        super(message);
        this.name = 'InvalidSignatureError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class ExpiredCredentialError extends Error {
    constructor(message = 'Credential has expired') {
        super(message);
        this.name = 'ExpiredCredentialError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class UnsupportedFormatError extends Error {
    constructor(format: string) {
        super(`Unsupported credential format: ${format}`);
        this.name = 'UnsupportedFormatError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class MalformedCredentialError extends Error {
    constructor(message = 'Credential structure is malformed') {
        super(message);
        this.name = 'MalformedCredentialError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class NonceValidationError extends Error {
    constructor(message = 'Nonce does not match expected value') {
        super(message);
        this.name = 'NonceValidationError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export type HaipValidationCode =
    | 'EMPTY_QUERY'
    | 'UNSUPPORTED_FORMAT'
    | 'MISSING_SDJWT_META'
    | 'MISSING_MDOC_META'
    | 'NO_CLAIMS'
    | 'CLAIM_SETS_DISALLOWED'
    | 'CREDENTIAL_SETS_DISALLOWED'
    // Added in 0.12.0 for the credential_sets disjunction profile.
    | 'EMPTY_OPTIONS'
    | 'DUPLICATE_CREDENTIAL_ID'
    | 'MISSING_CREDENTIAL_SETS'
    | 'UNKNOWN_OPTION_REFERENCE';

export class HaipValidationError extends Error {
    readonly code: HaipValidationCode;
    readonly credentialId?: string;

    constructor(code: HaipValidationCode, message: string, credentialId?: string) {
        super(message);
        this.name = 'HaipValidationError';
        this.code = code;
        this.credentialId = credentialId;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ---------------------------------------------------------------------------
// New in 0.5.0: OpenID4VPError base + trust-module error classes
// ---------------------------------------------------------------------------

export abstract class OpenID4VPError extends Error {
    abstract readonly code: string;

    constructor(message: string, options?: { cause?: Error }) {
        super(message);
        this.name = new.target.name;
        if (options?.cause !== undefined) {
            (this as { cause?: unknown }).cause = options.cause;
        }
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class TrustAnchorNotFoundError extends OpenID4VPError {
    readonly code = 'trust_anchor_not_found' as const;
}

export type ChainErrorReason =
    | 'signature'
    | 'validity'
    | 'name_constraints'
    | 'key_usage'
    | 'extended_key_usage'
    | 'basic_constraints'
    | 'path_length'
    | 'algorithm_disallowed'
    | 'aki_ski_mismatch'
    | 'unrecognised_critical_extension';

export class CertificateChainError extends OpenID4VPError {
    readonly code = 'chain_invalid' as const;
    readonly reason: ChainErrorReason;

    constructor(
        message: string,
        options: { reason: ChainErrorReason; cause?: Error }
    ) {
        super(message, { cause: options.cause });
        this.reason = options.reason;
    }
}

export class RevokedCertificateError extends OpenID4VPError {
    readonly code = 'certificate_revoked' as const;
    readonly serial: string;
    readonly revokedAt: Date;
    readonly reason?: string;

    constructor(
        message: string,
        options: { serial: string; revokedAt: Date; reason?: string; cause?: Error }
    ) {
        super(message, { cause: options.cause });
        this.serial = options.serial;
        this.revokedAt = options.revokedAt;
        this.reason = options.reason;
    }
}

export class RevocationCheckFailedError extends OpenID4VPError {
    readonly code = 'revocation_check_failed' as const;
}

export class LotlFetchError extends OpenID4VPError {
    readonly code = 'lotl_fetch_failed' as const;
    readonly url: string;

    constructor(
        message: string,
        options: { url: string; cause?: Error }
    ) {
        super(message, { cause: options.cause });
        this.url = options.url;
    }
}

export class LotlSignatureError extends OpenID4VPError {
    readonly code = 'lotl_signature_invalid' as const;
}

/**
 * The environment is not configured to verify trusted-list signatures at all —
 * distinct from a list whose signature did not verify.
 *
 * `xmldsigjs` needs a WebCrypto engine registered once per process, and this
 * library deliberately leaves that to the consumer rather than picking a
 * provider on their behalf. Without it, no trusted list can ever verify, so
 * this is raised eagerly instead of degrading per-list: a configuration fault
 * reported as a trust failure sends people bisecting valid XML.
 */
export class LotlConfigurationError extends OpenID4VPError {
    readonly code = 'lotl_configuration_invalid' as const;
}

// ---------------------------------------------------------------------------
// New in 0.7.0: workstream B-remaining (signed requests + direct_post.jwt)
// ---------------------------------------------------------------------------

export type SignedRequestBuildErrorCode =
    | 'empty_cert_chain'
    | 'hostname_cert_mismatch'
    | 'signing_key_cert_mismatch'
    | 'missing_encryption_jwk'
    | 'missing_encryption_alg'
    | 'missing_vp_formats'
    | 'unsupported_signing_alg'
    | 'empty_supported_enc_values'
    | 'missing_hostname'
    | 'self_signed_leaf'
    | 'trust_anchor_in_chain'
    | 'invalid_verifier_info';

export class SignedRequestBuildError extends OpenID4VPError {
    readonly code: SignedRequestBuildErrorCode;
    constructor(code: SignedRequestBuildErrorCode, message: string) {
        super(message);
        this.code = code;
    }
}

export class UnsupportedJweError extends OpenID4VPError {
    readonly code = 'unsupported_jwe' as const;
    readonly alg: string;
    readonly enc: string;
    constructor(alg: string, enc: string) {
        super(`Unsupported JWE algorithms: alg=${alg}, enc=${enc}`);
        this.alg = alg;
        this.enc = enc;
    }
}

export class DecryptionFailedError extends OpenID4VPError {
    readonly code = 'decryption_failed' as const;
    constructor(message = 'Failed to decrypt authorization response', options?: { cause?: Error }) {
        super(message, options);
    }
}

export class MissingDecryptionKeyError extends OpenID4VPError {
    readonly code = 'missing_decryption_key' as const;
    constructor(message = 'decryptionKey is required to verify a direct_post.jwt response') {
        super(message);
    }
}

export class MissingVerifierEncryptionKeyError extends OpenID4VPError {
    readonly code = 'missing_verifier_encryption_key' as const;
    constructor(
        message = 'verifierEncryptionJwk is required to build the OID4VP 1.0 OpenID4VPHandover SessionTranscript for an encrypted response'
    ) {
        super(message);
    }
}

export class MultipleCredentialsNotSupportedError extends OpenID4VPError {
    readonly code = 'multi_credential_unsupported' as const;
    readonly entryCount: number;
    readonly presentationCount: number;
    constructor(entryCount: number, presentationCount: number) {
        super(
            `Multi-credential presentations are not yet supported: ` +
                `${entryCount} queryId entries, ${presentationCount} presentations`
        );
        this.entryCount = entryCount;
        this.presentationCount = presentationCount;
    }
}

/**
 * A Key Binding JWT has to be checked against the verifier's own identifier,
 * but none was configured.
 *
 * OpenID4VP 1.0 Appendix B.3.6 requires the KB-JWT `aud` to equal the
 * verifier's Client Identifier, and RFC 9901 §7.3 makes checking it part of
 * holder-binding verification. Without an expected audience, a presentation
 * made out to a different verifier would be accepted. This is a configuration
 * fault, so it is thrown rather than reported as `valid: false`.
 *
 * Pass `audience` (or `clientId` to `verifyAuthorizationResponse`, which uses
 * it as the default audience).
 */
export class MissingAudienceError extends OpenID4VPError {
    readonly code = 'missing_audience' as const;
    constructor(
        message = 'An expected audience is required to verify a key binding JWT: pass `audience` ' +
            '(or `clientId` to verifyAuthorizationResponse)'
    ) {
        super(message);
    }
}

/** Longest wallet-supplied string copied into an error message. */
const MAX_WALLET_ERROR_TEXT = 200;

/**
 * The wallet answered with an OpenID4VP 1.0 §8.5 error response (for example
 * `access_denied` when the user declined) instead of a `vp_token`.
 *
 * `code` is the wallet's `error` value as sent, so callers can tell a declined
 * request from a malformed response without parsing the message. `description`
 * and `state` are the wallet's `error_description` and `state`, when present.
 * The library does not check `state`; compare it with the value you issued.
 */
export class WalletErrorResponseError extends OpenID4VPError {
    readonly code: string;
    readonly description?: string;
    readonly state?: string;
    readonly uri?: string;

    constructor(response: { error: string; error_description?: unknown; error_uri?: unknown; state?: unknown }) {
        super(`Wallet returned an error response: ${response.error.slice(0, MAX_WALLET_ERROR_TEXT)}`);
        this.code = response.error;
        if (typeof response.error_description === 'string') this.description = response.error_description;
        if (typeof response.error_uri === 'string') this.uri = response.error_uri;
        if (typeof response.state === 'string') this.state = response.state;
    }
}

// ---------------------------------------------------------------------------
// Guarded HTTP retrieval (SD-JWT VC draft-19 §"HTTP retrieval" alignment)
// ---------------------------------------------------------------------------

export type GuardedFetchRejectReason =
    | 'invalid_url'
    | 'insecure_scheme'
    | 'private_address'
    | 'dns_resolution_failed'
    | 'too_many_redirects'
    | 'invalid_redirect'
    | 'response_too_large'
    | 'timeout';

/**
 * A request was refused (or cut off) by the guarded fetcher before an
 * untrusted endpoint could be reached or could exhaust resources.
 */
export class GuardedFetchError extends OpenID4VPError {
    readonly code = 'guarded_fetch_rejected' as const;
    readonly reason: GuardedFetchRejectReason;
    readonly url: string;

    constructor(
        reason: GuardedFetchRejectReason,
        message: string,
        options: { url: string; cause?: Error }
    ) {
        super(message, { cause: options.cause });
        this.reason = reason;
        this.url = options.url;
    }
}

// ---------------------------------------------------------------------------
// Token Status List (draft-ietf-oauth-status-list-21)
// ---------------------------------------------------------------------------

export type StatusListErrorReason =
    /** Resolver / policy misconfiguration (e.g. `statusPolicy` set without a resolver). */
    | 'configuration'
    /** The credential's `status` claim is malformed (HAIP 1.0 §6.1: it MUST contain `status_list`). */
    | 'invalid_reference'
    /** The Status List Token could not be retrieved (network, guard, non-2xx). */
    | 'fetch_failed'
    /** Not a well-formed `statuslist+jwt`: bad JWS, wrong `typ`, missing or invalid claims. */
    | 'invalid_token'
    /** The JWS signature does not verify with the `x5c` signer key. */
    | 'signature_invalid'
    /** The `x5c` signer does not chain to a configured status-list trust anchor. */
    | 'untrusted_signer'
    /** `sub` differs from the `uri` the credential references (§8.3 step 4a). */
    | 'subject_mismatch'
    /** `exp` has passed (§8.3 step 4c). */
    | 'expired'
    /** `iat`/`nbf` lies in the future, or `iat` is older than the configured freshness limit. */
    | 'not_fresh'
    /** `status_list` is not a valid `bits` / `lst` structure or does not decompress. */
    | 'malformed_status_list'
    /** The decompressed list exceeds the configured size cap. */
    | 'list_too_large'
    /** `idx` lies past the end of an authentic list (§8.3 step 6: MUST reject). */
    | 'index_out_of_range';

/**
 * A Status List Token could not be resolved or validated, or a credential's
 * status reference is unusable. `reason` tells a definitive answer about the
 * credential (`invalid_reference`, `index_out_of_range`) apart from "no
 * statement can be made" (everything else).
 */
export class StatusListError extends OpenID4VPError {
    readonly code = 'status_list_error' as const;
    readonly reason: StatusListErrorReason;
    /** The Status List Token URI involved, when known. */
    readonly uri?: string;

    constructor(reason: StatusListErrorReason, message: string, options: { uri?: string; cause?: Error } = {}) {
        super(message, { cause: options.cause });
        this.reason = reason;
        this.uri = options.uri;
    }
}
