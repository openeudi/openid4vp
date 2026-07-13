import { Encoder as CborEncoder } from 'cbor-x';

import { MalformedCredentialError } from '../errors.js';

// Plain-bstr encoder (tagUint8Array:false → byte strings are major-type-2, not
// the typed-array tag 64), matching how conformant issuers/holders encode COSE.
const enc = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

const HEADER_ALG = 1;
const COSE_ALG_TO_NAME: Record<number, 'ES256' | 'ES384' | 'ES512'> = {
    [-7]: 'ES256',
    [-35]: 'ES384',
    [-36]: 'ES512',
};
const ALG_TO_HASH: Record<string, string> = { ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512' };

// COSE_Key (EC2) label map and curve labels (RFC 9052 / RFC 9053).
const COSE_KEY_KTY = 1;
const COSE_KEY_CRV = -1;
const COSE_KEY_X = -2;
const COSE_KEY_Y = -3;
const COSE_KTY_EC2 = 2;
const COSE_CRV_TO_JWK: Record<number, string> = { 1: 'P-256', 2: 'P-384', 3: 'P-521' };

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
    let len = 0;
    for (const c of chunks) len += c.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const c of chunks) {
        out.set(c, off);
        off += c.length;
    }
    return out;
}

function bytesToBase64Url(bytes: Uint8Array): string {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return globalThis.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Encode a CBOR tag-24 (embedded CBOR) wrapping `inner` as a byte string. */
function encodeTag24(inner: Uint8Array): Uint8Array {
    // 0xD8 0x18 = tag(24); enc.encode(Uint8Array) yields the bstr encoding of `inner`.
    return concatBytes(new Uint8Array([0xd8, 0x18]), new Uint8Array(enc.encode(inner)));
}

/**
 * Deterministically build `DeviceAuthenticationBytes` per ISO 18013-5 §9.1.3.4:
 *
 *   DeviceAuthentication = [ "DeviceAuthentication", SessionTranscript, DocType,
 *                            DeviceNameSpacesBytes ]
 *   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
 *
 * The SessionTranscript is spliced in as its exact caller-supplied bytes (never
 * decoded/re-encoded) so the digest input is byte-identical to what the holder
 * signed. Shared by the verifier and the test fixture to guarantee that.
 *
 * @param sessionTranscript      CBOR bytes of the SessionTranscript data item.
 * @param docType                mDOC docType string.
 * @param deviceNameSpacesInner  CBOR bytes of the DeviceNameSpaces map (the
 *                               content wrapped by the tag-24 DeviceNameSpacesBytes).
 */
export function buildDeviceAuthenticationBytes(params: {
    sessionTranscript: Uint8Array;
    docType: string;
    deviceNameSpacesInner: Uint8Array;
}): Uint8Array {
    const deviceAuthentication = concatBytes(
        new Uint8Array([0x84]), // array(4)
        new Uint8Array(enc.encode('DeviceAuthentication')),
        params.sessionTranscript,
        new Uint8Array(enc.encode(params.docType)),
        encodeTag24(params.deviceNameSpacesInner),
    );
    return encodeTag24(deviceAuthentication);
}

/** Encode the COSE `Sig_structure` for a detached-payload Signature1. */
export function encodeDeviceSigStructure(protectedBytes: Uint8Array, deviceAuthBytes: Uint8Array): Uint8Array {
    const sig = ['Signature1', protectedBytes, new Uint8Array(0), deviceAuthBytes];
    return new Uint8Array(enc.encode(sig));
}

/** Import an mdoc device public key from its COSE_Key (EC2) representation. */
export async function importDeviceKeyFromCose(coseKey: unknown): Promise<CryptoKey> {
    if (!(coseKey instanceof Map)) {
        throw new MalformedCredentialError('MSO deviceKeyInfo.deviceKey is not a COSE_Key map');
    }
    const kty = coseKey.get(COSE_KEY_KTY);
    if (kty !== COSE_KTY_EC2) {
        throw new MalformedCredentialError(`Unsupported COSE key type for device key: ${String(kty)}`);
    }
    const crv = coseKey.get(COSE_KEY_CRV);
    const crvName = typeof crv === 'number' ? COSE_CRV_TO_JWK[crv] : undefined;
    const x = coseKey.get(COSE_KEY_X);
    const y = coseKey.get(COSE_KEY_Y);
    if (!crvName || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
        throw new MalformedCredentialError('Malformed EC2 COSE_Key in MSO deviceKeyInfo');
    }
    return crypto.subtle.importKey(
        'jwk',
        { kty: 'EC', crv: crvName, x: bytesToBase64Url(x), y: bytesToBase64Url(y) },
        { name: 'ECDSA', namedCurve: crvName },
        false,
        ['verify'],
    );
}

/**
 * Verify mdoc device authentication (ISO 18013-5 §9.1.3): the holder proves
 * possession of the MSO-committed device key by signing the DeviceAuthentication
 * (which binds the SessionTranscript/nonce). Throws {@link MalformedCredentialError}
 * when the DeviceSignature is missing, malformed, uses a disallowed algorithm, or
 * fails to verify. DeviceMac (COSE_Mac0) is not supported and is rejected.
 */
export async function verifyDeviceAuth(params: {
    deviceSigned: Map<unknown, unknown>;
    deviceKeyCose: unknown;
    docType: string;
    sessionTranscript: Uint8Array;
    allowedAlgorithms: string[];
}): Promise<void> {
    const { deviceSigned, deviceKeyCose, docType, sessionTranscript, allowedAlgorithms } = params;

    const deviceAuth = deviceSigned.get('deviceAuth');
    if (!(deviceAuth instanceof Map)) {
        throw new MalformedCredentialError('deviceSigned.deviceAuth is missing or malformed');
    }
    if (deviceAuth.has('deviceMac') && !deviceAuth.has('deviceSignature')) {
        throw new MalformedCredentialError('mDOC DeviceMac authentication is not supported');
    }
    const deviceSignature = deviceAuth.get('deviceSignature');
    if (!Array.isArray(deviceSignature) || deviceSignature.length !== 4) {
        throw new MalformedCredentialError('deviceAuth.deviceSignature must be a COSE_Sign1 array');
    }
    const protectedBytes = deviceSignature[0];
    const signature = deviceSignature[3];
    if (!(protectedBytes instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
        throw new MalformedCredentialError('DeviceSignature protected header / signature must be byte strings');
    }

    let alg: 'ES256' | 'ES384' | 'ES512' | undefined;
    try {
        const ph = enc.decode(protectedBytes);
        const label = ph instanceof Map ? ph.get(HEADER_ALG) : undefined;
        alg = typeof label === 'number' ? COSE_ALG_TO_NAME[label] : undefined;
    } catch {
        throw new MalformedCredentialError('DeviceSignature protected header is not decodable CBOR');
    }
    if (!alg || !allowedAlgorithms.includes(alg)) {
        throw new MalformedCredentialError(`DeviceSignature uses a disallowed algorithm: ${String(alg)}`);
    }

    // DeviceNameSpacesBytes = deviceSigned["nameSpaces"] (a tag-24 wrapped map).
    // Extract the inner CBOR bytes so we can rebuild the digest input identically.
    const deviceNameSpacesInner = extractTag24Inner(deviceSigned.get('nameSpaces'));

    const deviceAuthBytes = buildDeviceAuthenticationBytes({ sessionTranscript, docType, deviceNameSpacesInner });
    const sigInput = encodeDeviceSigStructure(protectedBytes, deviceAuthBytes);

    const deviceKey = await importDeviceKeyFromCose(deviceKeyCose);
    const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: ALG_TO_HASH[alg] },
        deviceKey,
        new Uint8Array(signature) as Uint8Array<ArrayBuffer>,
        sigInput as Uint8Array<ArrayBuffer>,
    );
    if (!ok) {
        throw new MalformedCredentialError('mDOC device authentication (DeviceSignature) failed to verify');
    }
}

/**
 * Extract the inner CBOR bytes of a tag-24 wrapped value across the three shapes
 * that arise (Tag(24,bytes) in production, EmbeddedCbor-like in tests, or a plain
 * bstr already holding the inner bytes).
 */
function extractTag24Inner(value: unknown): Uint8Array {
    if (value instanceof Uint8Array) return value;
    if (
        value !== null &&
        typeof value === 'object' &&
        'value' in (value as object) &&
        (value as { value: unknown }).value instanceof Uint8Array &&
        // Tag(24,bytes) and EmbeddedCbor both expose .value; both are fine here.
        ('tag' in (value as object) ? (value as { tag: unknown }).tag === 24 : true)
    ) {
        return (value as { value: Uint8Array }).value;
    }
    throw new MalformedCredentialError('deviceSigned.nameSpaces must be tag-24 wrapped CBOR');
}
