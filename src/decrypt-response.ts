import { compactDecrypt, decodeProtectedHeader } from 'jose';

import { UnsupportedJweError, DecryptionFailedError } from './errors.js';
import type { AuthorizationResponse } from './types/authorization.js';

const SUPPORTED_ALG = 'ECDH-ES';
const SUPPORTED_ENC = new Set(['A128GCM', 'A256GCM']);

/**
 * Decrypt a JWE-wrapped OpenID4VP Authorization Response (response_mode =
 * direct_post.jwt). Returns the inner §8.1 envelope.
 *
 * Supported JWE algorithms (others throw UnsupportedJweError):
 *   - alg: ECDH-ES
 *   - enc: A128GCM, A256GCM (HAIP requires both)
 *
 * Cryptographic failures (wrong key, tampered ciphertext) throw
 * DecryptionFailedError.
 */
export async function decryptAuthorizationResponse(
    jwe: string,
    privateKey: CryptoKey,
): Promise<AuthorizationResponse> {
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
        header = decodeProtectedHeader(jwe);
    } catch (err) {
        throw new DecryptionFailedError('Malformed JWE header', {
            cause: err as Error,
        });
    }

    const alg = typeof header.alg === 'string' ? header.alg : '';
    const enc = typeof header.enc === 'string' ? header.enc : '';

    if (alg !== SUPPORTED_ALG || !SUPPORTED_ENC.has(enc)) {
        throw new UnsupportedJweError(alg, enc);
    }

    let plaintext: Uint8Array;
    try {
        const result = await compactDecrypt(jwe, privateKey);
        plaintext = result.plaintext;
    } catch (err) {
        throw new DecryptionFailedError(undefined, { cause: err as Error });
    }

    try {
        const text = new TextDecoder().decode(plaintext);
        return JSON.parse(text) as AuthorizationResponse;
    } catch (err) {
        throw new DecryptionFailedError('Decrypted plaintext is not valid JSON', {
            cause: err as Error,
        });
    }
}
