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
