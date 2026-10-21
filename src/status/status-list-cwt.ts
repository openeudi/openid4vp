import { Decoder as CborDecoder, Tag } from 'cbor-x';

import { StatusListError } from '../errors.js';

/**
 * CWT Status List Token structure (draft-ietf-oauth-status-list-21 §5.2).
 *
 * Parsing only: this module never decides trust. The resolver verifies the
 * COSE_Sign1 signature with `x5chain[0]` and the chain against its own trust
 * store, exactly as for the JWT format.
 */

/** COSE `typ` (RFC 9596) of a CWT Status List Token (§5.2). */
export const STATUS_LIST_CWT_TYP = 'application/statuslist+cwt';
/** HTTP media type requested for, and served with, a CWT Status List Token (§8.1). */
export const STATUS_LIST_CWT_MEDIA_TYPE = 'application/statuslist+cwt';

const HEADER_ALG = 1;
const HEADER_TYP = 16;
const HEADER_X5CHAIN = 33;

const CWT_SUB = 2;
const CWT_EXP = 4;
const CWT_NBF = 5;
const CWT_IAT = 6;
const CWT_STATUS_LIST = 65533;
const CWT_TTL = 65534;

const TAG_CWT = 61;
const TAG_COSE_SIGN1 = 18;

const COSE_ALG_TO_NAME: Record<number, 'ES256' | 'ES384' | 'ES512'> = {
    [-7]: 'ES256',
    [-35]: 'ES384',
    [-36]: 'ES512',
};

// Maps stay Maps: CWT claim keys and COSE header labels are integers.
const decoder = new CborDecoder({ mapsAsObjects: false, useRecords: false });

export interface DecodedStatusListCwt {
    protectedHeaderBytes: Uint8Array;
    protectedHeader: Map<number, unknown>;
    unprotectedHeader: Map<number, unknown>;
    /** The COSE payload: the encoded CWT Claims Set, exactly as signed. */
    payload: Uint8Array;
    signature: Uint8Array;
    alg: 'ES256' | 'ES384' | 'ES512';
    /** Signer first. Not trusted by itself. */
    x5chain: Uint8Array[];
    /**
     * The claims the resolver checks, under their JWT names so the JWT and CWT
     * formats share one claim validator: `sub` (2), `iat` (6), `exp` (4),
     * `nbf` (5), `ttl` (65534), `status_list` (65533). Absent claims are absent.
     */
    claims: Record<string, unknown>;
}

/**
 * Decodes a CWT Status List Token: an untagged, `#6.18`- or `#6.61(#6.18)`-
 * tagged COSE_Sign1 whose protected header carries `alg` and
 * `typ` = `application/statuslist+cwt`, with an `x5chain` (protected or
 * unprotected, not both) and an attached payload that is a CWT Claims Set map.
 *
 * Throws {@link StatusListError} `invalid_token` on any structural defect.
 */
export function decodeStatusListCwt(bytes: Uint8Array, uri: string): DecodedStatusListCwt {
    const invalid = (message: string, cause?: unknown): StatusListError =>
        new StatusListError('invalid_token', message, { uri, cause: cause instanceof Error ? cause : undefined });

    if (bytes.length === 0) throw invalid(`Status List Token from ${uri} is empty`);
    let outer: unknown;
    try {
        outer = decoder.decode(bytes);
    } catch (err) {
        throw invalid(`Status List Token from ${uri} is not CBOR`, err);
    }
    if (outer instanceof Tag && outer.tag === TAG_CWT) outer = outer.value;
    if (outer instanceof Tag && outer.tag === TAG_COSE_SIGN1) outer = outer.value;
    if (!Array.isArray(outer) || outer.length !== 4) {
        throw invalid(`Status List Token from ${uri} is not a COSE_Sign1 (CBOR array of four elements)`);
    }
    const [protectedHeaderBytes, unprotectedRaw, payloadRaw, signature] = outer as unknown[];
    if (!(protectedHeaderBytes instanceof Uint8Array) || protectedHeaderBytes.length === 0) {
        throw invalid('Status List Token protected header must be a non-empty byte string');
    }
    if (!(unprotectedRaw instanceof Map)) {
        throw invalid('Status List Token unprotected header must be a map');
    }
    if (!(payloadRaw instanceof Uint8Array)) {
        // A nil (detached) payload cannot be a Status List: the token is fetched on its own.
        throw invalid('Status List Token payload must be an attached byte string');
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
        throw invalid('Status List Token signature must be a byte string');
    }

    let protectedHeader: unknown;
    try {
        protectedHeader = decoder.decode(protectedHeaderBytes);
    } catch (err) {
        throw invalid('Status List Token protected header is not CBOR', err);
    }
    if (!(protectedHeader instanceof Map)) {
        throw invalid('Status List Token protected header must be a map');
    }
    const unprotectedHeader = unprotectedRaw as Map<number, unknown>;

    // --- typ (§5.2: REQUIRED, application/statuslist+cwt, protected) --------
    const typ = protectedHeader.get(HEADER_TYP);
    if (typeof typ !== 'string' || typ.toLowerCase() !== STATUS_LIST_CWT_TYP) {
        const where = unprotectedHeader.has(HEADER_TYP) ? ' (typ must be in the protected header)' : '';
        throw invalid(
            `Status List Token typ must be '${STATUS_LIST_CWT_TYP}' (got ${JSON.stringify(typ ?? null)})${where}`,
        );
    }

    // --- alg (protected only, so it is covered by the signature) -----------
    const algLabel = protectedHeader.get(HEADER_ALG);
    const alg = typeof algLabel === 'number' ? COSE_ALG_TO_NAME[algLabel] : undefined;
    if (!alg) {
        throw invalid(`Status List Token alg ${String(algLabel)} is not supported`);
    }

    // --- x5chain (RFC 9360: protected or unprotected, never both) ----------
    const inProtected = protectedHeader.has(HEADER_X5CHAIN);
    if (inProtected && unprotectedHeader.has(HEADER_X5CHAIN)) {
        throw invalid('Status List Token carries x5chain in both the protected and unprotected header');
    }
    const x5raw = inProtected ? protectedHeader.get(HEADER_X5CHAIN) : unprotectedHeader.get(HEADER_X5CHAIN);
    let x5chain: Uint8Array[];
    if (x5raw instanceof Uint8Array && x5raw.length > 0) {
        x5chain = [x5raw];
    } else if (
        Array.isArray(x5raw) &&
        x5raw.length > 0 &&
        x5raw.every((c) => c instanceof Uint8Array && c.length > 0)
    ) {
        x5chain = x5raw as Uint8Array[];
    } else {
        throw invalid('Status List Token must carry an x5chain certificate chain (COSE header 33)');
    }

    // --- CWT Claims Set ------------------------------------------------------
    let claimsSet: unknown;
    try {
        claimsSet = decoder.decode(payloadRaw);
    } catch (err) {
        throw invalid('Status List Token payload is not CBOR', err);
    }
    if (!(claimsSet instanceof Map)) {
        throw invalid('Status List Token payload is not a CWT Claims Set map');
    }
    const claims: Record<string, unknown> = {};
    const copy = (label: number, name: string): void => {
        if (claimsSet.has(label)) claims[name] = claimsSet.get(label);
    };
    copy(CWT_SUB, 'sub');
    copy(CWT_IAT, 'iat');
    copy(CWT_EXP, 'exp');
    copy(CWT_NBF, 'nbf');
    copy(CWT_TTL, 'ttl');
    copy(CWT_STATUS_LIST, 'status_list');

    return {
        protectedHeaderBytes,
        protectedHeader: protectedHeader as Map<number, unknown>,
        unprotectedHeader,
        payload: payloadRaw,
        signature,
        alg,
        x5chain,
        claims,
    };
}

/**
 * Converts a CBOR value whose maps all have text keys into plain objects, so
 * the mdoc MSO `status` (draft-21 §6.3) can be read like the JOSE `status`
 * claim. A map with any non-text key is returned unchanged, which the status
 * checks then reject as malformed.
 */
export function cborToPlain(value: unknown): unknown {
    if (value instanceof Map) {
        const entries: Array<[string, unknown]> = [];
        for (const [key, inner] of value) {
            if (typeof key !== 'string') return value;
            entries.push([key, cborToPlain(inner)]);
        }
        return Object.fromEntries(entries);
    }
    if (Array.isArray(value)) return value.map(cborToPlain);
    return value;
}
