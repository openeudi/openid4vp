import { splitSdJwt, decodeSdJwt, getClaims } from '@sd-jwt/decode';
import { decodeProtectedHeader, jwtVerify, importX509, importJWK } from 'jose';

import { MalformedCredentialError } from '../errors.js';
import type { TrustEvaluationResult } from '../trust/TrustEvaluator.js';
import type { IssuerInfo } from '../types/issuer.js';
import type { CredentialFormat, CredentialClaims, PresentationResult } from '../types/presentation.js';

import type { ICredentialParser, ParseOptions } from './parser.interface.js';

/**
 * Hasher function signature expected by @sd-jwt/decode.
 * Inlined here to avoid a direct dependency on @sd-jwt/types.
 */
type SdJwtHasher = (data: string | ArrayBuffer, alg: string) => Promise<Uint8Array>;

const DEFAULT_ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'ES512'];

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
 * Converts a base64-encoded DER certificate to PEM format for jose.importX509.
 */
function derToPem(base64Der: string): string {
    const lines = base64Der.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

/**
 * Encodes a Uint8Array to base64url (no padding).
 * Used by disclosure hash verification (Task 5) and KB-JWT verification (Task 6).
 */
function bytesToBase64url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
 * Best-effort extraction of a country code hint from an issuer URL or string.
 */
function extractCountryHint(issuer: string): string {
    try {
        const url = new URL(issuer);
        const tld = url.hostname.split('.').pop()?.toUpperCase();
        if (tld && tld.length === 2) {
            return tld;
        }
    } catch {
        // Not a valid URL
    }
    return '';
}

/**
 * SD-JWT VC credential parser.
 *
 * Decodes and cryptographically validates SD-JWT Verifiable Credentials:
 *   - JWT signature verification via x5c public key (jose)
 *   - Issuer certificate trust chain verification
 *   - Disclosure hash integrity verification
 *   - Key binding JWT signature and sd_hash verification
 *   - Selective disclosure claim extraction
 */
export class SdJwtParser implements ICredentialParser {
    readonly format: CredentialFormat = 'sd-jwt-vc';

    canParse(vpToken: unknown): boolean {
        return typeof vpToken === 'string' && vpToken.includes('~');
    }

    async parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult> {
        if (typeof vpToken !== 'string') {
            throw new MalformedCredentialError('VP token must be a string');
        }

        const allowedAlgorithms = options.allowedAlgorithms ?? DEFAULT_ALLOWED_ALGORITHMS;

        const invalidResult = (error: string): PresentationResult => ({
            valid: false,
            format: this.format,
            claims: {},
            issuer: { certificate: new Uint8Array(), country: '' },
            error,
        });

        // Step 1: Split the SD-JWT into components
        let parts: ReturnType<typeof splitSdJwt>;
        try {
            parts = splitSdJwt(vpToken);
        } catch {
            throw new MalformedCredentialError('Failed to split SD-JWT structure');
        }

        // Step 2: Peek at issuer JWT header (need alg and x5c before verification)
        let header: ReturnType<typeof decodeProtectedHeader>;
        try {
            header = decodeProtectedHeader(parts.jwt);
        } catch {
            throw new MalformedCredentialError('Failed to decode SD-JWT issuer JWT header');
        }

        // Step 3: Check algorithm against allowlist
        const alg = header.alg;
        if (typeof alg !== 'string' || !allowedAlgorithms.includes(alg)) {
            return invalidResult(`Unsupported algorithm: ${alg}`);
        }

        // Step 4: Extract public key from x5c certificate
        const x5cArray = header.x5c;
        if (!Array.isArray(x5cArray) || x5cArray.length === 0 || typeof x5cArray[0] !== 'string') {
            throw new MalformedCredentialError('Missing or invalid x5c in JWT header');
        }

        let issuerKey: Awaited<ReturnType<typeof importX509>>;
        let issuerCertBytes: Uint8Array;
        try {
            issuerKey = await importX509(derToPem(x5cArray[0]), alg);
            issuerCertBytes = base64ToBytes(x5cArray[0]);
        } catch (err) {
            if (err instanceof MalformedCredentialError) throw err;
            throw new MalformedCredentialError('Failed to import issuer certificate');
        }

        // Step 5: Verify issuer JWT signature (also validates exp, iat via jose)
        let payload: Record<string, unknown>;
        try {
            const result = await jwtVerify(parts.jwt, issuerKey, { algorithms: allowedAlgorithms });
            payload = result.payload as unknown as Record<string, unknown>;
        } catch {
            return invalidResult('Issuer JWT signature verification failed');
        }

        // Step 6: Trust check — certificate must be in the trusted set
        // unless the caller explicitly opts out via skipTrustCheck.
        const issuerString = typeof payload['iss'] === 'string' ? payload['iss'] : '';
        const issuerInfo: IssuerInfo = {
            certificate: issuerCertBytes,
            country: extractCountryHint(issuerString),
        };

        let trustResult: TrustEvaluationResult | undefined;

        if (options.trustStore) {
            // 0.5.0 path: RFC 5280 chain validation via TrustEvaluator.
            // Dynamic import keeps the evaluator out of 0.4.0-style callers' bundles.
            const { TrustEvaluator } = await import('../trust/TrustEvaluator.js');
            const evaluator = new TrustEvaluator({
                trustStore: options.trustStore,
                revocationPolicy: options.revocationPolicy ?? 'skip',
                fetcher: options.fetcher,
                cache: options.cache,
                clockSkewTolerance: options.clockSkewTolerance,
            });
            const { X509Certificate } = await import('@peculiar/x509');
            const leaf = new X509Certificate(issuerCertBytes as Uint8Array<ArrayBuffer>);
            trustResult = await evaluator.evaluate(leaf);
        } else {
            // 0.4.0 byte-equality path — preserved verbatim for backward compatibility.
            if (options.trustedCertificates.length === 0) {
                if (options.skipTrustCheck !== true) {
                    throw new MalformedCredentialError(
                        'trustedCertificates must not be empty unless skipTrustCheck is true'
                    );
                }
            } else {
                const isTrusted = options.trustedCertificates.some((trusted) => bytesEqual(trusted, issuerCertBytes));
                if (!isTrusted) {
                    return invalidResult('Issuer certificate is not trusted');
                }
            }
        }

        // Step 7: Verify disclosure hashes against _sd array
        const sdArray = payload['_sd'];
        if (parts.disclosures.length > 0) {
            if (!Array.isArray(sdArray) || sdArray.length === 0) {
                return invalidResult('Disclosures present but no _sd array in issuer JWT');
            }
            for (const disclosure of parts.disclosures) {
                const hashBytes = await sha256Hasher(disclosure, 'sha-256');
                const hashB64url = bytesToBase64url(hashBytes);
                if (!sdArray.includes(hashB64url)) {
                    return invalidResult('Disclosure hash mismatch');
                }
            }
        }

        // Step 8: Verify key binding JWT (if present)
        if (parts.kbJwt) {
            // Extract holder public key from cnf claim
            const cnf = payload['cnf'] as Record<string, unknown> | undefined;
            if (!cnf || typeof cnf !== 'object' || !cnf['jwk']) {
                throw new MalformedCredentialError('Missing cnf.jwk in issuer JWT for key binding');
            }

            let holderKey: Awaited<ReturnType<typeof importJWK>>;
            try {
                const kbHeader = decodeProtectedHeader(parts.kbJwt);
                const kbAlg = kbHeader.alg;
                if (typeof kbAlg !== 'string' || !allowedAlgorithms.includes(kbAlg)) {
                    return invalidResult(`Unsupported KB-JWT algorithm: ${kbAlg}`);
                }
                holderKey = await importJWK(cnf['jwk'] as Record<string, unknown>, kbAlg);
            } catch (err) {
                if (err instanceof MalformedCredentialError) throw err;
                throw new MalformedCredentialError('Failed to import holder key from cnf.jwk');
            }

            // Verify KB-JWT signature
            let kbPayload: Record<string, unknown>;
            try {
                const kbResult = await jwtVerify(parts.kbJwt, holderKey, {
                    algorithms: allowedAlgorithms,
                    ...(options.audience ? { audience: options.audience } : {}),
                });
                kbPayload = kbResult.payload as unknown as Record<string, unknown>;
            } catch {
                return invalidResult('Key binding JWT signature verification failed');
            }

            // Validate nonce — must be present and match when KB-JWT is used
            if (kbPayload['nonce'] !== options.nonce) {
                return invalidResult('Key binding JWT nonce does not match');
            }

            // Verify sd_hash — hash of the SD-JWT content before the KB-JWT
            const disclosurePart = parts.disclosures.length > 0 ? parts.disclosures.join('~') + '~' : '';
            const sdJwtForHash = parts.jwt + '~' + disclosurePart;
            const sdHashBytes = await sha256Hasher(sdJwtForHash, 'sha-256');
            const expectedSdHash = bytesToBase64url(sdHashBytes);
            if (kbPayload['sd_hash'] !== expectedSdHash) {
                return invalidResult('Key binding JWT sd_hash does not match');
            }
        }

        // Step 9: Decode disclosures and extract claims
        let resolvedClaims: Record<string, unknown>;
        try {
            const decoded = await decodeSdJwt(vpToken, sha256Hasher);
            resolvedClaims = await getClaims<Record<string, unknown>>(
                decoded.jwt.payload,
                decoded.disclosures,
                sha256Hasher
            );
        } catch {
            throw new MalformedCredentialError('Failed to decode SD-JWT disclosures');
        }

        const vct = typeof payload['vct'] === 'string' ? (payload['vct'] as string) : undefined;

        const result: PresentationResult = {
            valid: true,
            format: this.format,
            claims: mapToCredentialClaims(resolvedClaims),
            issuer: issuerInfo,
            ...(vct !== undefined ? { vct } : {}),
        };
        if (trustResult) result.trust = trustResult;
        return result;
    }
}
