import { describe, it, expect } from 'vitest';
import { CompactEncrypt } from 'jose';

import { decryptAuthorizationResponse } from '../src/decrypt-response.js';
import { UnsupportedJweError, DecryptionFailedError } from '../src/errors.js';
import {
    createEncryptionKeypair,
    encryptAuthorizationResponseJwe,
} from './fixtures/crypto-helpers.js';

describe('decryptAuthorizationResponse', () => {
    it('round-trips ECDH-ES + A256GCM to the full AuthorizationResponse envelope', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const envelope = {
            vp_token: { pid: ['eyJhb...presentation...'] },
            state: 's',
        };
        const jwe = await encryptAuthorizationResponseJwe(envelope, publicJwk, 'A256GCM');
        const result = await decryptAuthorizationResponse(jwe, privateKey);
        expect(result).toEqual(envelope);
    });

    it('round-trips ECDH-ES + A128GCM (HAIP requires both enc options)', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const envelope = { vp_token: { q: ['abc'] } };
        const jwe = await encryptAuthorizationResponseJwe(envelope, publicJwk, 'A128GCM');
        const result = await decryptAuthorizationResponse(jwe, privateKey);
        expect(result).toEqual(envelope);
    });

    it('rejects unsupported alg (e.g. RSA-OAEP-256) with UnsupportedJweError', async () => {
        const rsa = (await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt'],
        )) as CryptoKeyPair;
        const jwe = await new CompactEncrypt(new TextEncoder().encode('{}'))
            .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
            .encrypt(rsa.publicKey);
        await expect(decryptAuthorizationResponse(jwe, rsa.privateKey)).rejects.toMatchObject({
            name: 'UnsupportedJweError',
            alg: 'RSA-OAEP-256',
        });
    });

    it('rejects unsupported enc (e.g. A128CBC-HS256) with UnsupportedJweError', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const recipient = await crypto.subtle.importKey(
            'jwk',
            publicJwk,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            [],
        );
        const jwe = await new CompactEncrypt(new TextEncoder().encode('{}'))
            .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128CBC-HS256' })
            .encrypt(recipient);
        await expect(decryptAuthorizationResponse(jwe, privateKey)).rejects.toMatchObject({
            name: 'UnsupportedJweError',
            enc: 'A128CBC-HS256',
        });
    });

    it('rejects wrong decryption key with DecryptionFailedError', async () => {
        const a = await createEncryptionKeypair();
        const b = await createEncryptionKeypair();
        const jwe = await encryptAuthorizationResponseJwe({ vp_token: {} }, a.publicJwk);
        await expect(
            decryptAuthorizationResponse(jwe, b.privateKey),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('rejects tampered ciphertext with DecryptionFailedError', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const jwe = await encryptAuthorizationResponseJwe({ vp_token: {} }, publicJwk);
        const parts = jwe.split('.');
        parts[3] = parts[3].slice(0, -4) + 'AAAA';
        await expect(
            decryptAuthorizationResponse(parts.join('.'), privateKey),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('exposes UnsupportedJweError as instanceof', async () => {
        const rsa = (await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt'],
        )) as CryptoKeyPair;
        const jwe = await new CompactEncrypt(new TextEncoder().encode('{}'))
            .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
            .encrypt(rsa.publicKey);
        await expect(
            decryptAuthorizationResponse(jwe, rsa.privateKey),
        ).rejects.toBeInstanceOf(UnsupportedJweError);
    });

    it('preserves additional top-level fields beyond vp_token/state', async () => {
        const { publicJwk, privateKey } = await createEncryptionKeypair();
        const envelope = { vp_token: { q: ['p'] }, state: 's', iss: 'wallet' };
        const jwe = await encryptAuthorizationResponseJwe(envelope, publicJwk);
        const result = await decryptAuthorizationResponse(jwe, privateKey);
        expect((result as Record<string, unknown>).iss).toBe('wallet');
    });
});
