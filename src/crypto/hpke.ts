import { DecryptionFailedError } from '../errors.js';

// HPKE (RFC 9180), base mode only, for the one cipher suite ISO/IEC 18013-7
// Annex C uses: DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
// Built on WebCrypto so the library stays runtime-agnostic. Annex C seals a
// single message per context, so only sequence number 0 is implemented and the
// nonce is the key schedule's base_nonce. Checked against RFC 9180 A.3.1.

const KEM_ID = 0x0010; // DHKEM(P-256, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0001; // AES-128-GCM
const MODE_BASE = 0x00;

const N_SECRET = 32;
const N_H = 32;
const N_K = 16;
const N_N = 12;
/** Uncompressed SEC1 P-256 point: 0x04 || x || y. */
const N_PK = 65;

const ENCODER = new TextEncoder();
const HPKE_V1 = ENCODER.encode('HPKE-v1');
const KEM_SUITE_ID = concat(ENCODER.encode('KEM'), i2osp(KEM_ID, 2));
const HPKE_SUITE_ID = concat(ENCODER.encode('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface HpkeOpenInput {
    /** The recipient's ECDH P-256 private key (usage `deriveBits`). */
    recipientPrivateKey: CryptoKey;
    /** The recipient's public key as an uncompressed point; part of the KEM context. */
    recipientPublicKey: Uint8Array;
    /** The sender's encapsulated key (`enc`), an uncompressed P-256 point. */
    enc: Uint8Array;
    info: Uint8Array;
    aad: Uint8Array;
    ciphertext: Uint8Array;
}

export interface HpkeSealInput {
    recipientPublicKey: Uint8Array;
    info: Uint8Array;
    aad: Uint8Array;
    plaintext: Uint8Array;
    /** Fixed ephemeral key, for test vectors only. Generated when omitted. */
    ephemeralKeyPair?: { privateKey: CryptoKey; publicKey: Uint8Array };
}

/**
 * HPKE `SetupBaseR` + `Open` (sequence 0). Every failure — a malformed or
 * off-curve `enc`, the wrong key, a different `info` or `aad`, a modified
 * ciphertext — throws `DecryptionFailedError`.
 */
export async function hpkeOpenBase(input: HpkeOpenInput): Promise<Uint8Array> {
    const { recipientPrivateKey, recipientPublicKey, enc, info, aad, ciphertext } = input;
    if (enc.length !== N_PK || enc[0] !== 0x04) {
        throw new DecryptionFailedError('HPKE encapsulated key is not an uncompressed P-256 point');
    }
    let ephemeralPublic: CryptoKey;
    try {
        ephemeralPublic = await crypto.subtle.importKey('raw', toArrayBuffer(enc), ECDH_P256, false, []);
    } catch (err) {
        throw new DecryptionFailedError('HPKE encapsulated key is not a valid P-256 point', { cause: err as Error });
    }

    let plaintext: ArrayBuffer;
    try {
        const dh = new Uint8Array(
            await crypto.subtle.deriveBits({ name: 'ECDH', public: ephemeralPublic }, recipientPrivateKey, 256),
        );
        const sharedSecret = await extractAndExpand(dh, concat(enc, recipientPublicKey));
        const { key, baseNonce } = await keySchedule(sharedSecret, info);
        const aesKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), 'AES-GCM', false, ['decrypt']);
        plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: toArrayBuffer(baseNonce), additionalData: toArrayBuffer(aad), tagLength: 128 },
            aesKey,
            toArrayBuffer(ciphertext),
        );
    } catch (err) {
        throw new DecryptionFailedError('HPKE decryption failed', { cause: err as Error });
    }
    return new Uint8Array(plaintext);
}

/** HPKE `SetupBaseS` + `Seal` (sequence 0). The wallet side; used by tests. */
export async function hpkeSealBase(input: HpkeSealInput): Promise<{ enc: Uint8Array; ciphertext: Uint8Array }> {
    const { recipientPublicKey, info, aad, plaintext } = input;
    const ephemeral = input.ephemeralKeyPair ?? (await generateEphemeral());
    const recipient = await crypto.subtle.importKey('raw', toArrayBuffer(recipientPublicKey), ECDH_P256, false, []);
    const dh = new Uint8Array(
        await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, ephemeral.privateKey, 256),
    );
    const sharedSecret = await extractAndExpand(dh, concat(ephemeral.publicKey, recipientPublicKey));
    const { key, baseNonce } = await keySchedule(sharedSecret, info);
    const aesKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), 'AES-GCM', false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(baseNonce), additionalData: toArrayBuffer(aad), tagLength: 128 },
        aesKey,
        toArrayBuffer(plaintext),
    );
    return { enc: ephemeral.publicKey, ciphertext: new Uint8Array(ciphertext) };
}

async function generateEphemeral(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
    const pair = await crypto.subtle.generateKey(ECDH_P256, true, ['deriveBits']);
    return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) };
}

/** RFC 9180 §4.1 `ExtractAndExpand` of DHKEM. */
async function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Promise<Uint8Array> {
    const eaePrk = await labeledExtract(KEM_SUITE_ID, new Uint8Array(), 'eae_prk', dh);
    return labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, N_SECRET);
}

/** RFC 9180 §5.1 `KeySchedule` for mode_base (empty psk and psk_id). */
async function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): Promise<{ key: Uint8Array; baseNonce: Uint8Array }> {
    const empty = new Uint8Array();
    const pskIdHash = await labeledExtract(HPKE_SUITE_ID, empty, 'psk_id_hash', empty);
    const infoHash = await labeledExtract(HPKE_SUITE_ID, empty, 'info_hash', info);
    const context = concat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash);
    const secret = await labeledExtract(HPKE_SUITE_ID, sharedSecret, 'secret', empty);
    return {
        key: await labeledExpand(HPKE_SUITE_ID, secret, 'key', context, N_K),
        baseNonce: await labeledExpand(HPKE_SUITE_ID, secret, 'base_nonce', context, N_N),
    };
}

function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Promise<Uint8Array> {
    return hkdfExtract(salt, concat(HPKE_V1, suiteId, ENCODER.encode(label), ikm));
}

function labeledExpand(
    suiteId: Uint8Array,
    prk: Uint8Array,
    label: string,
    info: Uint8Array,
    length: number,
): Promise<Uint8Array> {
    return hkdfExpand(prk, concat(i2osp(length, 2), HPKE_V1, suiteId, ENCODER.encode(label), info), length);
}

/**
 * RFC 5869 Extract. An empty salt is HashLen zero bytes (§2.2); HMAC pads
 * both to the same block, and WebCrypto refuses zero-length HMAC keys.
 */
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
    return hmacSha256(salt.length === 0 ? new Uint8Array(N_H) : salt, ikm);
}

/** RFC 5869 Expand. */
async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
    const out = new Uint8Array(length);
    let block: Uint8Array = new Uint8Array();
    for (let i = 1, offset = 0; offset < length; i++) {
        block = await hmacSha256(prk, concat(block, info, new Uint8Array([i])));
        out.set(block.subarray(0, Math.min(block.length, length - offset)), offset);
        offset += block.length;
    }
    return out;
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const hmacKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'HMAC', hash: 'SHA-256' }, false, [
        'sign',
    ]);
    return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, toArrayBuffer(data)));
}

function i2osp(value: number, length: number): Uint8Array {
    const out = new Uint8Array(length);
    for (let i = length - 1, v = value; i >= 0; i--, v >>>= 8) out[i] = v & 0xff;
    return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

/**
 * An exact-length copy, so WebCrypto never sees a view into a larger buffer.
 * Not `bytes.slice()`: on a Node `Buffer` that is a view into the shared pool.
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return new Uint8Array(bytes).buffer as ArrayBuffer;
}
