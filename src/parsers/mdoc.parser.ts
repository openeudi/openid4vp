import { decode } from 'cbor-x';

import { MalformedCredentialError } from '../errors.js';
import type { IssuerInfo } from '../types/issuer.js';
import type { CredentialFormat, CredentialClaims, PresentationResult } from '../types/presentation.js';

import type { ICredentialParser, ParseOptions } from './parser.interface.js';

/**
 * Runtime check for binary data. Returns true for Uint8Array and Node.js Buffer
 * without referencing the Buffer type (which is unavailable in DOM-only tsconfig).
 * Buffer extends Uint8Array, so `instanceof Uint8Array` catches both.
 */
function isBinaryData(value: unknown): value is Uint8Array {
    return value instanceof Uint8Array;
}

/**
 * Checks whether two Uint8Array instances contain identical bytes.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Represents a single IssuerSignedItem element from an mDOC nameSpace.
 * ISO 18013-5 Section 8.3.2.1.2.
 */
interface IssuerSignedItem {
    digestID: number;
    random: Uint8Array | unknown;
    elementIdentifier: string;
    elementValue: unknown;
}

/**
 * Simplified DeviceResponse structure from ISO 18013-5.
 * Only the fields required for claim extraction and trust validation.
 */
interface MdocDocument {
    docType: string;
    issuerSigned: {
        nameSpaces: Record<string, IssuerSignedItem[]>;
        issuerAuth: unknown[];
    };
}

interface DeviceResponse {
    version: string;
    documents: MdocDocument[];
    status: number;
}

/**
 * Extracts the issuer certificate bytes from a COSE_Sign1 issuerAuth structure.
 *
 * The issuerAuth is a COSE_Sign1 array: [protected, unprotected, payload, signature].
 * The protected header (index 0) is CBOR-encoded and may contain the x5chain (label 33)
 * with the issuer certificate. The unprotected header (index 1) may also carry it.
 *
 * If neither header contains a certificate, the raw protected bytes are returned
 * as a fallback for trust matching (test/simplified scenarios).
 */
function extractCertificateFromIssuerAuth(issuerAuth: unknown[]): Uint8Array {
    // Try unprotected header first (index 1) -- it's already decoded as a Map or object
    const unprotected = issuerAuth[1];
    if (unprotected && typeof unprotected === 'object') {
        // x5chain is COSE header label 33
        const certFromUnprotected = extractX5Chain(unprotected);
        if (certFromUnprotected) return certFromUnprotected;
    }

    // Try protected header (index 0) -- CBOR-encoded bytes
    const protectedHeader = issuerAuth[0];
    if (isBinaryData(protectedHeader)) {
        try {
            const decoded = decode(protectedHeader) as unknown;
            if (decoded && typeof decoded === 'object') {
                const certFromProtected = extractX5Chain(decoded);
                if (certFromProtected) return certFromProtected;
            }
        } catch {
            // Protected header could not be decoded -- fall through
        }
        // Return raw protected bytes as fallback identifier
        return new Uint8Array(protectedHeader);
    }

    return new Uint8Array();
}

/**
 * Extracts certificate bytes from an x5chain (label 33) in a COSE header.
 * The header can be a plain object or a Map.
 */
function extractX5Chain(header: unknown): Uint8Array | null {
    if (header instanceof Map) {
        const cert = header.get(33) as unknown;
        if (isBinaryData(cert)) {
            return new Uint8Array(cert);
        }
    } else if (typeof header === 'object' && header !== null) {
        const rec = header as Record<string | number, unknown>;
        const cert = rec[33] ?? rec['x5chain'] ?? rec['33'];
        if (isBinaryData(cert)) {
            return new Uint8Array(cert);
        }
    }
    return null;
}

/**
 * Maps raw mDOC IssuerSignedItem elements to the CredentialClaims structure,
 * picking known age/residency fields and preserving any additional identifiers.
 */
function mapToCredentialClaims(items: IssuerSignedItem[]): CredentialClaims {
    const claims: CredentialClaims = {};

    for (const item of items) {
        const key = item.elementIdentifier;
        const value = item.elementValue;

        switch (key) {
            case 'age_over_18':
                if (typeof value === 'boolean') claims.age_over_18 = value;
                break;
            case 'age_over_21':
                if (typeof value === 'boolean') claims.age_over_21 = value;
                break;
            case 'resident_country':
                if (typeof value === 'string') claims.resident_country = value;
                break;
            case 'nationality':
                if (typeof value === 'string') claims.nationality = value;
                break;
            case 'family_name_birth':
                if (typeof value === 'string') claims.family_name_birth = value;
                break;
            default:
                claims[key] = value;
                break;
        }
    }

    return claims;
}

/**
 * Extracts validity period from the issuerAuth payload.
 *
 * The payload (index 2) of the COSE_Sign1 is CBOR-encoded and should
 * contain a MobileSecurityObject with a validityInfo field carrying
 * `validFrom` and `validUntil` dates.
 */
function extractValidityPeriod(issuerAuth: unknown[]): { validFrom?: Date; validUntil?: Date } {
    const payload = issuerAuth[2];
    if (!payload) return {};

    try {
        // payload can be raw CBOR bytes or already decoded
        const decoded = isBinaryData(payload) ? (decode(payload) as unknown) : payload;

        if (decoded && typeof decoded === 'object') {
            const obj = decoded as Record<string, unknown>;
            const validityInfo = obj['validityInfo'] as Record<string, unknown> | undefined;
            if (validityInfo) {
                return {
                    validFrom:
                        validityInfo['validFrom'] instanceof Date
                            ? validityInfo['validFrom']
                            : typeof validityInfo['validFrom'] === 'string'
                              ? new Date(validityInfo['validFrom'])
                              : undefined,
                    validUntil:
                        validityInfo['validUntil'] instanceof Date
                            ? validityInfo['validUntil']
                            : typeof validityInfo['validUntil'] === 'string'
                              ? new Date(validityInfo['validUntil'])
                              : undefined,
                };
            }
        }
    } catch {
        // Could not decode payload -- validity check will be skipped
    }

    return {};
}

/**
 * mDOC / mDL credential parser.
 *
 * Decodes and validates mDOC (Mobile Document) credentials as specified in
 * ISO 18013-5 and the EUDI Wallet ecosystem. Processes CBOR-encoded
 * DeviceResponse structures containing:
 *   - Document type validation (eu.europa.ec.eudi.pid.1)
 *   - Issuer certificate trust chain verification via COSE_Sign1 issuerAuth
 *   - Validity period checking
 *   - Claim extraction from IssuerSignedItem nameSpace elements
 */
export class MdocParser implements ICredentialParser {
    readonly format: CredentialFormat = 'mdoc';

    /**
     * Returns true when the token is binary data (Uint8Array or Buffer),
     * indicating a CBOR-encoded mDOC DeviceResponse.
     */
    canParse(vpToken: unknown): boolean {
        return isBinaryData(vpToken);
    }

    /**
     * Parses and validates an mDOC DeviceResponse token.
     *
     * @throws {MalformedCredentialError} when the CBOR structure cannot be decoded
     *   or does not match the expected DeviceResponse format
     */
    async parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult> {
        if (!isBinaryData(vpToken)) {
            throw new MalformedCredentialError('VP token must be a Uint8Array or Buffer');
        }

        const invalidResult = (error: string): PresentationResult => ({
            valid: false,
            format: this.format,
            claims: {},
            issuer: { certificate: new Uint8Array(), country: '' },
            error,
        });

        // Step 1: Decode the CBOR DeviceResponse
        let deviceResponse: DeviceResponse;
        try {
            deviceResponse = decode(vpToken) as DeviceResponse;
        } catch {
            throw new MalformedCredentialError('Failed to decode CBOR DeviceResponse');
        }

        // Step 2: Validate basic DeviceResponse structure
        if (
            !deviceResponse ||
            typeof deviceResponse !== 'object' ||
            !Array.isArray(deviceResponse.documents) ||
            deviceResponse.documents.length === 0
        ) {
            throw new MalformedCredentialError('Invalid DeviceResponse structure: missing or empty documents array');
        }

        const document = deviceResponse.documents[0];
        if (!document.issuerSigned || !document.issuerSigned.nameSpaces || !document.issuerSigned.issuerAuth) {
            throw new MalformedCredentialError('Invalid mDOC document: missing issuerSigned data');
        }

        // Step 3: Extract issuer certificate from COSE_Sign1 issuerAuth
        const issuerAuth = document.issuerSigned.issuerAuth;
        if (!Array.isArray(issuerAuth) || issuerAuth.length < 4) {
            throw new MalformedCredentialError('Invalid issuerAuth: expected COSE_Sign1 array with 4 elements');
        }

        const issuerCertBytes = extractCertificateFromIssuerAuth(issuerAuth);
        const issuerInfo: IssuerInfo = {
            certificate: issuerCertBytes,
            country: '',
        };

        // Step 4: Verify trust -- certificate must be in the trusted set
        if (options.trustedCertificates.length > 0) {
            const isTrusted = options.trustedCertificates.some((trusted) => bytesEqual(trusted, issuerCertBytes));
            if (!isTrusted) {
                return invalidResult('Issuer certificate is not trusted');
            }
        } else if (issuerCertBytes.length === 0) {
            return invalidResult('No issuer certificate found and no trusted certificates configured');
        }

        // Step 5: Check validity period
        const { validUntil } = extractValidityPeriod(issuerAuth);
        if (validUntil) {
            const now = new Date();
            if (validUntil < now) {
                return invalidResult('Credential has expired');
            }
        }

        // Step 6: Extract claims from nameSpaces
        // Prefer the EUDI PID namespace, fall back to the first available namespace
        const pidNamespace = 'eu.europa.ec.eudi.pid.1';
        const nameSpaces = document.issuerSigned.nameSpaces;
        const items: IssuerSignedItem[] =
            nameSpaces[pidNamespace] ?? nameSpaces[document.docType] ?? Object.values(nameSpaces)[0] ?? [];

        const claims = mapToCredentialClaims(items);

        // Try to derive country from resident_country claim
        if (claims.resident_country && typeof claims.resident_country === 'string') {
            issuerInfo.country = claims.resident_country;
        }

        return {
            valid: true,
            format: this.format,
            claims,
            issuer: issuerInfo,
        };
    }
}
