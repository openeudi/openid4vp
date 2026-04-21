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
