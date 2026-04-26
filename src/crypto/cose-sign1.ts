import { Encoder as CborEncoder, Tag } from 'cbor-x';

import { MalformedCredentialError } from '../errors.js';

// Decoder that preserves CBOR maps as JS Maps (cbor-x default converts them to objects).
const decoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });

/**
 * COSE label for the `alg` header parameter.
 */
const HEADER_ALG = 1;

/**
 * COSE label for the `x5chain` header parameter (RFC 9360).
 */
const HEADER_X5CHAIN = 33;

const COSE_ALG_TO_NAME: Record<number, string> = {
    [-7]: 'ES256',
    [-35]: 'ES384',
    [-36]: 'ES512',
};

export interface CoseSign1 {
    protectedHeaderBytes: Uint8Array;
    protectedHeader: Map<number, unknown>;
    unprotectedHeader: Map<number, unknown>;
    payload: Uint8Array;
    signature: Uint8Array;
    x5chain: Uint8Array[];
    alg: 'ES256' | 'ES384' | 'ES512';
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1 {
    let outer: unknown = decoder.decode(bytes);
    if (outer instanceof Tag && outer.tag === 18) {
        // tag-18 value may be the raw bytes of the COSE_Sign1 structure — decode again
        const tagValue = outer.value;
        outer = tagValue instanceof Uint8Array ? decoder.decode(tagValue) : tagValue;
    }
    if (!Array.isArray(outer) || outer.length !== 4) {
        throw new MalformedCredentialError('COSE_Sign1 must be a CBOR array of length 4');
    }
    const [protectedHeaderBytes, unprotectedHeader, payloadRaw, signature] = outer;
    if (!(protectedHeaderBytes instanceof Uint8Array)) {
        throw new MalformedCredentialError('COSE_Sign1 protected header must be a bstr');
    }
    if (!(unprotectedHeader instanceof Map)) {
        throw new MalformedCredentialError('COSE_Sign1 unprotected header must be a Map');
    }
    if (!(signature instanceof Uint8Array)) {
        throw new MalformedCredentialError('COSE_Sign1 signature must be a bstr');
    }

    let protectedHeader: Map<number, unknown>;
    try {
        const decoded = decoder.decode(protectedHeaderBytes);
        if (!(decoded instanceof Map)) {
            throw new Error('protected header not a Map');
        }
        protectedHeader = decoded as Map<number, unknown>;
    } catch {
        throw new MalformedCredentialError('COSE_Sign1 protected header is not decodable CBOR');
    }

    const algLabel = protectedHeader.get(HEADER_ALG);
    const alg = typeof algLabel === 'number' ? COSE_ALG_TO_NAME[algLabel] : undefined;
    if (!alg) {
        throw new MalformedCredentialError(`COSE_Sign1 uses unknown alg label: ${String(algLabel)}`);
    }

    // Payload may be a bstr, tag-24 bstr (embedded CBOR), or absent (detached — not supported here)
    let payload: Uint8Array;
    if (payloadRaw instanceof Uint8Array) {
        payload = payloadRaw;
    } else if (payloadRaw instanceof Tag && payloadRaw.tag === 24 && payloadRaw.value instanceof Uint8Array) {
        payload = payloadRaw.value;
    } else {
        throw new MalformedCredentialError('COSE_Sign1 payload must be a byte string');
    }

    // x5chain may be a single cert bstr or an array of bstrs
    const x5raw = unprotectedHeader.get(HEADER_X5CHAIN);
    let x5chain: Uint8Array[];
    if (x5raw === undefined) {
        throw new MalformedCredentialError('COSE_Sign1 missing x5chain in unprotected header (label 33)');
    }
    if (x5raw instanceof Uint8Array) {
        x5chain = [x5raw];
    } else if (Array.isArray(x5raw) && x5raw.every((v) => v instanceof Uint8Array)) {
        x5chain = x5raw as Uint8Array[];
    } else {
        throw new MalformedCredentialError('COSE_Sign1 x5chain must be a bstr or array of bstr');
    }

    return {
        protectedHeaderBytes,
        protectedHeader,
        unprotectedHeader: unprotectedHeader as Map<number, unknown>,
        payload,
        signature,
        x5chain,
        alg: alg as 'ES256' | 'ES384' | 'ES512',
    };
}

const ALG_TO_HASH: Record<string, string> = {
    ES256: 'SHA-256',
    ES384: 'SHA-384',
    ES512: 'SHA-512',
};

/**
 * Verifies the COSE_Sign1 signature using the provided public key.
 * Throws when the algorithm is not in the allowlist or the signature is invalid.
 */
export async function verifyCoseSign1(
    coseSign1: CoseSign1,
    publicKey: CryptoKey,
    allowedAlgorithms: string[]
): Promise<void> {
    if (!allowedAlgorithms.includes(coseSign1.alg)) {
        throw new MalformedCredentialError(`COSE_Sign1 algorithm ${coseSign1.alg} not in allowlist`);
    }
    const hashAlg = ALG_TO_HASH[coseSign1.alg];
    if (!hashAlg) {
        throw new MalformedCredentialError(`no hash mapping for alg ${coseSign1.alg}`);
    }

    // Sig_structure1 = ["Signature1", protected_header_bytes, external_aad (empty bstr), payload]
    // coseSign1.payload is the raw bstr from the COSE array — it already contains the tag-24
    // encoded MSO bytes as stored by the signer, so we use it directly without re-wrapping.
    const sigStructure = ['Signature1', coseSign1.protectedHeaderBytes, new Uint8Array(0), coseSign1.payload];
    // cbor-x's encode() returns a Buffer<ArrayBufferLike>; copy into a Uint8Array<ArrayBuffer>
    // so the strict BufferSource shape (post-@types/node) is satisfied.
    const sigInput = new Uint8Array(decoder.encode(sigStructure)) as Uint8Array<ArrayBuffer>;

    const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: hashAlg },
        publicKey,
        new Uint8Array(coseSign1.signature) as Uint8Array<ArrayBuffer>,
        sigInput
    );
    if (!ok) {
        throw new MalformedCredentialError('COSE_Sign1 signature verification failed');
    }
}
