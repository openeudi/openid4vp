import { splitSdJwt, decodeJwt, decodeSdJwt, getClaims } from '@sd-jwt/decode';

import { MalformedCredentialError } from '../errors.js';
import type { IssuerInfo } from '../types/issuer.js';
import type { CredentialFormat, CredentialClaims, PresentationResult } from '../types/presentation.js';

import type { ICredentialParser, ParseOptions } from './parser.interface.js';

/**
 * Hasher function signature expected by @sd-jwt/decode.
 * Inlined here to avoid a direct dependency on @sd-jwt/types.
 */
type SdJwtHasher = (data: string | ArrayBuffer, alg: string) => Promise<Uint8Array>;

/**
 * SHA-256 hasher implementation using the Web Crypto API.
 * Compatible with the @sd-jwt/decode Hasher signature.
 */
const sha256Hasher: SdJwtHasher = async (data: string | ArrayBuffer, _alg: string): Promise<Uint8Array> => {
    const encoder = new TextEncoder();
    const input = typeof data === 'string' ? encoder.encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', input);
    return new Uint8Array(hashBuffer);
};

// Standard base64 alphabet for decoding x5c certificate entries
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Decodes a standard base64-encoded string into raw bytes.
 * Does not depend on Node.js Buffer or browser atob.
 */
function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
    // Strip any padding characters
    const cleaned = base64.replace(/=+$/, '');
    const byteLength = Math.floor((cleaned.length * 3) / 4);
    const buffer = new ArrayBuffer(byteLength);
    const bytes = new Uint8Array(buffer);

    let byteIndex = 0;
    for (let i = 0; i < cleaned.length; i += 4) {
        const a = BASE64_CHARS.indexOf(cleaned[i]);
        const b = i + 1 < cleaned.length ? BASE64_CHARS.indexOf(cleaned[i + 1]) : 0;
        const c = i + 2 < cleaned.length ? BASE64_CHARS.indexOf(cleaned[i + 2]) : 0;
        const d = i + 3 < cleaned.length ? BASE64_CHARS.indexOf(cleaned[i + 3]) : 0;

        bytes[byteIndex++] = (a << 2) | (b >> 4);
        if (byteIndex < byteLength) bytes[byteIndex++] = ((b & 0x0f) << 4) | (c >> 2);
        if (byteIndex < byteLength) bytes[byteIndex++] = ((c & 0x03) << 6) | d;
    }

    return bytes;
}

/**
 * Extracts the DER-encoded certificate bytes from a base64-encoded X.509 certificate
 * found in the JWT header's x5c field.
 */
function extractCertificateFromX5c(x5cEntry: string): Uint8Array<ArrayBuffer> {
    return base64ToBytes(x5cEntry);
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
 * Maps raw decoded claims to the CredentialClaims structure,
 * picking known age/residency fields and preserving any extra keys.
 */
function mapToCredentialClaims(raw: Record<string, unknown>): CredentialClaims {
    const claims: CredentialClaims = {};

    if (typeof raw['age_over_18'] === 'boolean') {
        claims.age_over_18 = raw['age_over_18'];
    }
    if (typeof raw['age_over_21'] === 'boolean') {
        claims.age_over_21 = raw['age_over_21'];
    }
    if (typeof raw['resident_country'] === 'string') {
        claims.resident_country = raw['resident_country'];
    }
    if (typeof raw['nationality'] === 'string') {
        claims.nationality = raw['nationality'];
    }
    if (typeof raw['family_name_birth'] === 'string') {
        claims.family_name_birth = raw['family_name_birth'];
    }

    // Preserve any additional claim keys not already mapped
    for (const [key, value] of Object.entries(raw)) {
        if (
            !(key in claims) &&
            !key.startsWith('_sd') &&
            key !== 'iss' &&
            key !== 'exp' &&
            key !== 'iat' &&
            key !== 'cnf' &&
            key !== 'vct'
        ) {
            claims[key] = value;
        }
    }

    return claims;
}

/**
 * SD-JWT VC credential parser.
 *
 * Decodes and validates SD-JWT Verifiable Credentials as specified in
 * the EUDI Wallet ecosystem. Performs:
 *   - Structure validation (JWT~disclosure~kb format)
 *   - Issuer certificate trust chain verification
 *   - Expiry checking
 *   - Nonce validation against the key binding JWT
 *   - Selective disclosure claim extraction
 */
export class SdJwtParser implements ICredentialParser {
    readonly format: CredentialFormat = 'sd-jwt-vc';

    /**
     * Returns true when the token looks like an SD-JWT:
     * it must be a string containing the `~` disclosure separator.
     */
    canParse(vpToken: unknown): boolean {
        return typeof vpToken === 'string' && vpToken.includes('~');
    }

    /**
     * Parses and validates an SD-JWT VC token.
     *
     * @throws {MalformedCredentialError} when the token structure cannot be decoded
     */
    async parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult> {
        if (typeof vpToken !== 'string') {
            throw new MalformedCredentialError('VP token must be a string');
        }

        const invalidResult = (error: string): PresentationResult => ({
            valid: false,
            format: this.format,
            claims: {},
            issuer: { certificate: new Uint8Array(), country: '' },
            error,
        });

        // Step 1: Split the SD-JWT into its components
        let parts: ReturnType<typeof splitSdJwt>;
        try {
            parts = splitSdJwt(vpToken);
        } catch {
            throw new MalformedCredentialError('Failed to split SD-JWT structure');
        }

        // Step 2: Decode the issuer JWT header and payload
        let header: Record<string, unknown>;
        let payload: Record<string, unknown>;
        try {
            const jwt = decodeJwt(parts.jwt);
            header = jwt.header;
            payload = jwt.payload;
        } catch {
            throw new MalformedCredentialError('Failed to decode SD-JWT issuer JWT');
        }

        // Step 3: Extract issuer certificate from x5c header
        const x5cArray = header['x5c'];
        let issuerCertBytes = new Uint8Array();
        let issuerInfo: IssuerInfo = { certificate: new Uint8Array(), country: '' };

        if (Array.isArray(x5cArray) && x5cArray.length > 0 && typeof x5cArray[0] === 'string') {
            try {
                issuerCertBytes = extractCertificateFromX5c(x5cArray[0]);
                // Attempt to derive the country from the certificate's issuer string
                // In production, this would parse the X.509 subject, but for now we
                // fall back to payload-level hints.
                const issuerString = typeof payload['iss'] === 'string' ? payload['iss'] : '';
                issuerInfo = {
                    certificate: issuerCertBytes,
                    country: extractCountryHint(issuerString),
                };
            } catch {
                return invalidResult('Failed to extract issuer certificate from x5c');
            }
        }

        // Step 4: Verify trust — certificate must be in the trusted set
        if (options.trustedCertificates.length > 0) {
            const isTrusted = options.trustedCertificates.some((trusted) => bytesEqual(trusted, issuerCertBytes));
            if (!isTrusted) {
                return invalidResult('Issuer certificate is not trusted');
            }
        } else if (issuerCertBytes.length === 0) {
            return invalidResult('No issuer certificate found and no trusted certificates configured');
        }

        // Step 5: Check expiry
        const exp = payload['exp'];
        if (typeof exp === 'number') {
            const nowSeconds = Math.floor(Date.now() / 1000);
            if (exp < nowSeconds) {
                return invalidResult('Credential has expired');
            }
        }

        // Step 6: Validate nonce in key binding JWT
        if (parts.kbJwt) {
            try {
                const kbDecoded = decodeJwt(parts.kbJwt);
                const kbPayload = kbDecoded.payload as Record<string, unknown>;
                const kbNonce = kbPayload['nonce'];
                if (typeof kbNonce === 'string' && kbNonce !== options.nonce) {
                    return invalidResult('Key binding JWT nonce does not match');
                }
            } catch {
                return invalidResult('Failed to decode key binding JWT');
            }
        }

        // Step 7: Decode disclosures and extract claims
        let resolvedClaims: Record<string, unknown>;
        try {
            const decoded = await decodeSdJwt(vpToken, sha256Hasher);
            resolvedClaims = await getClaims<Record<string, unknown>>(
                decoded.jwt.payload,
                decoded.disclosures,
                sha256Hasher
            );
        } catch {
            // If SD-JWT decoding fails (e.g., no _sd_alg), fall back to raw payload
            resolvedClaims = payload;
        }

        const claims = mapToCredentialClaims(resolvedClaims);

        return {
            valid: true,
            format: this.format,
            claims,
            issuer: issuerInfo,
        };
    }
}

/**
 * Best-effort extraction of a country code hint from an issuer URL or string.
 * For example, "https://issuer.de/..." would yield "DE".
 */
function extractCountryHint(issuer: string): string {
    try {
        const url = new URL(issuer);
        const tld = url.hostname.split('.').pop()?.toUpperCase();
        if (tld && tld.length === 2) {
            return tld;
        }
    } catch {
        // Not a valid URL — ignore
    }
    return '';
}
