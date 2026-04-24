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
    | 'CREDENTIAL_SETS_DISALLOWED';

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
    | 'basic_constraints'
    | 'path_length'
    | 'algorithm_disallowed'
    | 'aki_ski_mismatch';

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
    | 'unsupported_signing_alg';

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
