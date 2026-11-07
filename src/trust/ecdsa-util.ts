/**
 * Internal ECDSA helpers for CRL and OCSP signature checks. `@peculiar/x509` +
 * WebCrypto use different wire formats for ECDSA signatures; these helpers
 * bridge DER (ASN.1 SEQUENCE { r, s }) and IEEE P1363 (r||s fixed-width), and
 * pick the curve and hash from the signer's key and the signatureAlgorithm
 * instead of assuming P-256 / SHA-256.
 *
 * NOT exported from the package root.
 */
import { AsnConvert } from '@peculiar/asn1-schema';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509';

const ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

/** DER-encoded `ECParameters.namedCurve` (hex) → WebCrypto curve. RFC 5480 §2.1.1.1. */
const NAMED_CURVES: ReadonlyMap<string, { namedCurve: string; coordBytes: number }> = new Map([
    ['06082a8648ce3d030107', { namedCurve: 'P-256', coordBytes: 32 }], // secp256r1
    ['06052b81040022', { namedCurve: 'P-384', coordBytes: 48 }], // secp384r1
    ['06052b81040023', { namedCurve: 'P-521', coordBytes: 66 }], // secp521r1
]);

/** ecdsa-with-SHA* signatureAlgorithm OIDs → WebCrypto hash. RFC 5758 §3.2. */
const ECDSA_HASHES: ReadonlyMap<string, string> = new Map([
    ['1.2.840.10045.4.3.2', 'SHA-256'],
    ['1.2.840.10045.4.3.3', 'SHA-384'],
    ['1.2.840.10045.4.3.4', 'SHA-512'],
]);

function invalid(reason: string): Error {
    return new Error(`invalid DER signature: ${reason}`);
}

/**
 * Read one DER TLV with tag `tag` at `pos`, not reaching past `limit`. Handles
 * the short and the long length form (a P-521 signature is longer than 127
 * bytes, so its SEQUENCE length is `0x81 xx`), and rejects indefinite and
 * non-minimal lengths, which DER forbids.
 */
function readTlv(
    der: Uint8Array,
    pos: number,
    limit: number,
    tag: number,
    name: string
): { start: number; end: number } {
    if (pos >= limit || der[pos] !== tag) throw invalid(`expected ${name}`);
    pos++;
    if (pos >= limit) throw invalid(`truncated length of ${name}`);
    let len = der[pos++];
    if (len & 0x80) {
        const n = len & 0x7f;
        if (n === 0) throw invalid(`indefinite length for ${name}`);
        // Two length bytes cover 65535 bytes, far more than any ECDSA signature.
        if (n > 2) throw invalid(`length of ${name} too large`);
        if (pos + n > limit) throw invalid(`truncated length of ${name}`);
        len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | der[pos++];
        if (len < 0x80 || (n === 2 && len < 0x100)) {
            throw invalid(`non-minimal length for ${name}`);
        }
    }
    if (pos + len > limit) throw invalid(`${name} runs past the end of its container`);
    return { start: pos, end: pos + len };
}

/** Left-pad a positive DER INTEGER to `coordBytes`, dropping sign-padding zeros. */
function toFixedWidth(value: Uint8Array, coordBytes: number, name: string): Uint8Array {
    if (value.length === 0) throw invalid(`empty ${name}`);
    if (value[0] & 0x80) throw invalid(`negative ${name}`);
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    const digits = value.subarray(start);
    if (digits.length > coordBytes) throw invalid(`${name} is wider than the curve`);
    const out = new Uint8Array(coordBytes);
    out.set(digits, coordBytes - digits.length);
    return out;
}

export function ecdsaDerToIeee(der: Uint8Array, coordBytes: number): Uint8Array {
    const seq = readTlv(der, 0, der.length, 0x30, 'SEQUENCE');
    if (seq.end !== der.length) throw invalid('trailing bytes after SEQUENCE');
    const r = readTlv(der, seq.start, seq.end, 0x02, 'INTEGER r');
    const s = readTlv(der, r.end, seq.end, 0x02, 'INTEGER s');
    if (s.end !== seq.end) throw invalid('trailing bytes inside SEQUENCE');
    const out = new Uint8Array(coordBytes * 2);
    out.set(toFixedWidth(der.subarray(r.start, r.end), coordBytes, 'INTEGER r'), 0);
    out.set(toFixedWidth(der.subarray(s.start, s.end), coordBytes, 'INTEGER s'), coordBytes);
    return out;
}

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export interface EcdsaSignedObject {
    /** What is being verified, for error messages: `'CRL'`, `'OCSP response'`. */
    context: string;
    /** `signatureAlgorithm.algorithm` OID of the signed object. */
    signatureAlgorithm: string;
    /** DER-encoded ECDSA-Sig-Value. */
    signature: Uint8Array;
    /** The signed bytes (`tbsCertList`, `tbsResponseData`). */
    data: Uint8Array;
    /** DER SubjectPublicKeyInfo of the signer. */
    signerSpki: Uint8Array;
}

/**
 * Verify an ECDSA signature over `data`. The hash comes from the
 * signatureAlgorithm OID, the curve from the signer's SubjectPublicKeyInfo.
 * Throws on an unsupported algorithm, key or curve, or malformed DER;
 * returns `false` when the signature does not verify.
 *
 * The key is imported from raw SPKI bytes into Node's global SubtleCrypto.
 * The `@peculiar/x509`-exported CryptoKey may belong to a non-global provider
 * (e.g. `@peculiar/webcrypto` in tests), and Node's global
 * `crypto.subtle.verify` rejects foreign-provider keys with "2nd argument is
 * not of type CryptoKey".
 */
export async function verifyEcdsaSignature(obj: EcdsaSignedObject): Promise<boolean> {
    const hash = ECDSA_HASHES.get(obj.signatureAlgorithm);
    if (!hash) {
        throw new Error(
            `unsupported ${obj.context} signature algorithm ${obj.signatureAlgorithm}; ` +
                'only ecdsa-with-SHA256/384/512 are supported'
        );
    }
    const spki = AsnConvert.parse(obj.signerSpki, SubjectPublicKeyInfo);
    if (spki.algorithm.algorithm !== ID_EC_PUBLIC_KEY) {
        throw new Error(
            `unsupported ${obj.context} signer key algorithm ${spki.algorithm.algorithm}; ` +
                'expected an EC key for an ECDSA signature'
        );
    }
    const params = spki.algorithm.parameters;
    const curve = params ? NAMED_CURVES.get(hex(new Uint8Array(params))) : undefined;
    if (!curve) {
        throw new Error(
            `unsupported ${obj.context} signer key curve; only P-256, P-384 and P-521 are supported`
        );
    }
    const signature = ecdsaDerToIeee(obj.signature, curve.coordBytes);
    const publicKey = await crypto.subtle.importKey(
        'spki',
        obj.signerSpki as Uint8Array<ArrayBuffer>,
        { name: 'ECDSA', namedCurve: curve.namedCurve },
        false,
        ['verify']
    );
    return crypto.subtle.verify(
        { name: 'ECDSA', hash },
        publicKey,
        signature as Uint8Array<ArrayBuffer>,
        obj.data as Uint8Array<ArrayBuffer>
    );
}
