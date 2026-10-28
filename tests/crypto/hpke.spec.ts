/**
 * HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
 * AES-128-GCM — the suite ISO/IEC 18013-7 Annex C uses for `org-iso-mdoc`
 * responses.
 */
import { describe, expect, it } from 'vitest';

import { hpkeOpenBase, hpkeSealBase } from '../../src/crypto/hpke.js';
import { DecryptionFailedError } from '../../src/errors.js';
import { bytesToBase64Url, bytesToHex, hexToBytes } from '../../src/encoding/base64url.js';

// RFC 9180 Appendix A.3.1: mode_base, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
// AES-128-GCM. Sequence number 0 only: Annex C seals exactly one message.
const A31 = {
    info: '4f6465206f6e2061204772656369616e2055726e',
    skEm: '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
    pkEm:
        '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32' +
        '5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
    skRm: 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
    pkRm:
        '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70' +
        '6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
    aad: '436f756e742d30',
    pt: '4265617574792069732074727574682c20747275746820626561757479',
    ct:
        '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f' +
        '9076ac232e3ab2523f39513434',
};

/** Raw P-256 scalar + uncompressed point → private JWK. */
function privateJwk(skHex: string, pkHex: string): JsonWebKey {
    const pk = hexToBytes(pkHex);
    return {
        kty: 'EC',
        crv: 'P-256',
        x: bytesToBase64Url(pk.slice(1, 33)),
        y: bytesToBase64Url(pk.slice(33, 65)),
        d: bytesToBase64Url(hexToBytes(skHex)),
    };
}

async function importEcdh(jwk: JsonWebKey, usages: KeyUsage[]): Promise<CryptoKey> {
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, usages);
}

async function ecdhKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
}

async function rawPublic(key: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

function randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
}

describe('HPKE base mode — RFC 9180 A.3.1 test vector', () => {
    it('opens the published ciphertext', async () => {
        const recipient = await importEcdh(privateJwk(A31.skRm, A31.pkRm), ['deriveBits']);

        const pt = await hpkeOpenBase({
            recipientPrivateKey: recipient,
            recipientPublicKey: hexToBytes(A31.pkRm),
            enc: hexToBytes(A31.pkEm),
            info: hexToBytes(A31.info),
            aad: hexToBytes(A31.aad),
            ciphertext: hexToBytes(A31.ct),
        });

        expect(bytesToHex(pt)).toBe(A31.pt);
    });

    it('seals to the published ciphertext with the published ephemeral key', async () => {
        const ephemeral = await importEcdh(privateJwk(A31.skEm, A31.pkEm), ['deriveBits']);

        const sealed = await hpkeSealBase({
            recipientPublicKey: hexToBytes(A31.pkRm),
            info: hexToBytes(A31.info),
            aad: hexToBytes(A31.aad),
            plaintext: hexToBytes(A31.pt),
            ephemeralKeyPair: { privateKey: ephemeral, publicKey: hexToBytes(A31.pkEm) },
        });

        expect(bytesToHex(sealed.enc)).toBe(A31.pkEm);
        expect(bytesToHex(sealed.ciphertext)).toBe(A31.ct);
    });
});

describe('HPKE base mode — round trip and failures', () => {
    it('round-trips with a fresh ephemeral key and empty aad', async () => {
        const recipient = await ecdhKeyPair();
        const recipientPublicKey = await rawPublic(recipient.publicKey);
        const info = randomBytes(40);
        const plaintext = randomBytes(300);

        const sealed = await hpkeSealBase({ recipientPublicKey, info, aad: new Uint8Array(), plaintext });
        const opened = await hpkeOpenBase({
            recipientPrivateKey: recipient.privateKey,
            recipientPublicKey,
            enc: sealed.enc,
            info,
            aad: new Uint8Array(),
            ciphertext: sealed.ciphertext,
        });

        expect(bytesToHex(opened)).toBe(bytesToHex(plaintext));
    });

    it('fails with a different info (the SessionTranscript binding)', async () => {
        const recipient = await ecdhKeyPair();
        const recipientPublicKey = await rawPublic(recipient.publicKey);
        const sealed = await hpkeSealBase({
            recipientPublicKey,
            info: randomBytes(32),
            aad: new Uint8Array(),
            plaintext: randomBytes(64),
        });

        await expect(
            hpkeOpenBase({
                recipientPrivateKey: recipient.privateKey,
                recipientPublicKey,
                enc: sealed.enc,
                info: randomBytes(32),
                aad: new Uint8Array(),
                ciphertext: sealed.ciphertext,
            }),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('fails on a tampered ciphertext', async () => {
        const recipient = await ecdhKeyPair();
        const recipientPublicKey = await rawPublic(recipient.publicKey);
        const info = randomBytes(32);
        const sealed = await hpkeSealBase({ recipientPublicKey, info, aad: new Uint8Array(), plaintext: randomBytes(64) });
        const tampered = sealed.ciphertext.slice();
        const index = Math.floor(Math.random() * tampered.length);
        tampered[index] ^= 1 + Math.floor(Math.random() * 255);

        await expect(
            hpkeOpenBase({
                recipientPrivateKey: recipient.privateKey,
                recipientPublicKey,
                enc: sealed.enc,
                info,
                aad: new Uint8Array(),
                ciphertext: tampered,
            }),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('fails with the wrong recipient key', async () => {
        const recipient = await ecdhKeyPair();
        const other = await ecdhKeyPair();
        const recipientPublicKey = await rawPublic(recipient.publicKey);
        const info = randomBytes(32);
        const sealed = await hpkeSealBase({ recipientPublicKey, info, aad: new Uint8Array(), plaintext: randomBytes(64) });

        await expect(
            hpkeOpenBase({
                recipientPrivateKey: other.privateKey,
                recipientPublicKey,
                enc: sealed.enc,
                info,
                aad: new Uint8Array(),
                ciphertext: sealed.ciphertext,
            }),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('rejects an encapsulated key that is not an uncompressed P-256 point', async () => {
        const recipient = await ecdhKeyPair();
        const recipientPublicKey = await rawPublic(recipient.publicKey);
        const notAPoint = randomBytes(65);
        notAPoint[0] = 0x04;

        for (const enc of [randomBytes(33), notAPoint]) {
            await expect(
                hpkeOpenBase({
                    recipientPrivateKey: recipient.privateKey,
                    recipientPublicKey,
                    enc,
                    info: randomBytes(8),
                    aad: new Uint8Array(),
                    ciphertext: randomBytes(48),
                }),
            ).rejects.toBeInstanceOf(DecryptionFailedError);
        }
    });
});
