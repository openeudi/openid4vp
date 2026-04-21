import { Encoder as CborEncoder, Tag } from 'cbor-x';

import { MalformedCredentialError } from '../errors.js';

import type { MobileSecurityObject } from './mso.js';

// Decoder that preserves CBOR maps as JS Maps (cbor-x default converts them to objects).
const decoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });

const ALLOWED_HASH_ALGS = new Set(['SHA-256', 'SHA-384', 'SHA-512']);

export async function computeItemDigest(itemBytes: Uint8Array, digestAlgorithm: string): Promise<Uint8Array> {
    if (!ALLOWED_HASH_ALGS.has(digestAlgorithm)) {
        throw new MalformedCredentialError(`Unknown digest algorithm: ${digestAlgorithm}`);
    }
    // Copy into a plain Uint8Array<ArrayBuffer> to satisfy TypeScript's BufferSource constraint.
    const buf = await crypto.subtle.digest(digestAlgorithm, new Uint8Array(itemBytes));
    return new Uint8Array(buf);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Unwrap an IssuerSignedItem from its tag-24 encoding and return the inner Map.
 *
 * Three shapes arise depending on test vs. production paths:
 *   A) Tag(24, Uint8Array)    — production cbor-x path (no addExtension)
 *   B) EmbeddedCbor-like obj  — test-fixture path (addExtension in mdoc-helpers.ts registers a
 *                               custom class whose instances have `.value: Uint8Array`)
 *   C) Plain Map              — if cbor-x auto-unwraps deeper than expected
 */
function unwrapItemMap(itemBytes: Uint8Array): Map<string, unknown> {
    let decoded: unknown;
    try {
        decoded = decoder.decode(itemBytes);
    } catch {
        throw new MalformedCredentialError('IssuerSignedItem is not decodable CBOR');
    }

    let inner: unknown;
    if (decoded instanceof Tag && decoded.tag === 24 && decoded.value instanceof Uint8Array) {
        // Path A: tag-24 Tag object
        inner = decoder.decode(decoded.value as Uint8Array);
    } else if (
        decoded !== null &&
        typeof decoded === 'object' &&
        !(decoded instanceof Tag) &&
        !(decoded instanceof Map) &&
        !(decoded instanceof Uint8Array) &&
        'value' in (decoded as object) &&
        (decoded as { value: unknown }).value instanceof Uint8Array
    ) {
        // Path B: EmbeddedCbor-like object from test fixture's addExtension
        inner = decoder.decode((decoded as { value: Uint8Array }).value);
    } else if (decoded instanceof Map) {
        // Path C: already a Map
        inner = decoded;
    } else {
        throw new MalformedCredentialError('IssuerSignedItem must be a tag-24 wrapped CBOR Map');
    }

    if (!(inner instanceof Map)) {
        throw new MalformedCredentialError('IssuerSignedItem must decode to a Map');
    }
    return inner as Map<string, unknown>;
}

/**
 * Verifies every IssuerSignedItem across every namespace against the MSO's valueDigests.
 * All items must match — no partial acceptance.
 *
 * @param nameSpaces  Per-namespace arrays of tag-24-wrapped IssuerSignedItem bytes
 *                    (exactly the bytes used as digest input during issuance).
 * @param mso         Decoded MobileSecurityObject carrying the expected valueDigests.
 */
export async function verifyAllDigests(
    nameSpaces: Map<string, Uint8Array[]>,
    mso: MobileSecurityObject
): Promise<void> {
    for (const [ns, items] of nameSpaces) {
        const expected = mso.valueDigests.get(ns);
        if (!expected) {
            throw new MalformedCredentialError(`namespace ${ns} has no valueDigests entry in MSO`);
        }
        for (const itemBytes of items) {
            // Hash the raw tag-24 bytes — this is what the issuer hashed during issuance.
            const hash = await computeItemDigest(itemBytes, mso.digestAlgorithm);

            // Decode to extract digestID for lookup.
            const item = unwrapItemMap(itemBytes);
            const digestID = item.get('digestID');
            if (typeof digestID !== 'number') {
                throw new MalformedCredentialError('IssuerSignedItem missing digestID');
            }

            const expectedDigest = expected.get(digestID);
            if (!expectedDigest) {
                throw new MalformedCredentialError(`digestID ${digestID} missing from MSO valueDigests[${ns}]`);
            }
            if (!bytesEqual(hash, expectedDigest)) {
                throw new MalformedCredentialError(`digest mismatch for ns=${ns} digestID=${digestID}`);
            }
        }
    }
}
