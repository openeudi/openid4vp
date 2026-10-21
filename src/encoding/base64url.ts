// base64url (RFC 4648 §5) helpers shared across the library. Implemented
// without Node's Buffer or the browser's atob/btoa decoding so the library
// stays runtime-agnostic.

const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Decodes an unpadded (or `=`-padded) base64url string.
 *
 * Throws `TypeError` on any character outside the base64url alphabet — in
 * particular the standard-alphabet `+` and `/` — and on an impossible length
 * (one leftover character), so a corrupted input is never silently decoded
 * into different bytes.
 */
export function base64UrlToBytes(input: string): Uint8Array<ArrayBuffer> {
    const cleaned = input.replace(/=+$/, '');
    if (cleaned.length % 4 === 1) {
        throw new TypeError('Invalid base64url length');
    }
    const byteLength = Math.floor((cleaned.length * 3) / 4);
    const bytes = new Uint8Array(new ArrayBuffer(byteLength));
    let byteIndex = 0;
    for (let i = 0; i < cleaned.length; i += 4) {
        const a = BASE64URL_CHARS.indexOf(cleaned[i]);
        const b = i + 1 < cleaned.length ? BASE64URL_CHARS.indexOf(cleaned[i + 1]) : 0;
        const c = i + 2 < cleaned.length ? BASE64URL_CHARS.indexOf(cleaned[i + 2]) : 0;
        const d = i + 3 < cleaned.length ? BASE64URL_CHARS.indexOf(cleaned[i + 3]) : 0;
        if (a === -1 || b === -1 || c === -1 || d === -1) {
            throw new TypeError('Invalid base64url character');
        }
        bytes[byteIndex++] = (a << 2) | (b >> 4);
        if (byteIndex < byteLength) bytes[byteIndex++] = ((b & 0x0f) << 4) | (c >> 2);
        if (byteIndex < byteLength) bytes[byteIndex++] = ((c & 0x03) << 6) | d;
    }
    return bytes;
}

/** Encodes bytes as unpadded base64url. */
export function bytesToBase64Url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Lower-case hex encoding of `bytes`. */
export function bytesToHex(bytes: Uint8Array): string {
    let out = '';
    for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
    return out;
}

/** Decodes a hex string (non-hex characters such as `:` separators are ignored). */
export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
    const clean = hex.replace(/[^0-9a-f]/gi, '');
    const out = new Uint8Array(new ArrayBuffer(Math.floor(clean.length / 2)));
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
