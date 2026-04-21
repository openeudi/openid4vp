/**
 * Test fixture builder for cryptographically valid mDOC credentials.
 * Mirrors the pattern from tests/fixtures/crypto-helpers.ts for SD-JWT.
 *
 * All CBOR encoding uses cbor-x. All crypto uses Web Crypto (no COSE library).
 *
 * Build flow:
 *   1. For each claim in each namespace, create an IssuerSignedItem.
 *   2. CBOR-encode each item, wrap as tag-24 (embedded CBOR).
 *   3. SHA-256 of each tag-24 byte string → valueDigests.
 *   4. Build MSO { version, digestAlgorithm, valueDigests, deviceKeyInfo, docType, validityInfo }.
 *   5. CBOR-encode MSO as COSE_Sign1 payload.
 *   6. Build Sig_structure1, sign with issuer key via Web Crypto.
 *   7. Assemble COSE_Sign1 [protected, unprotected, payload, signature] with x5chain in unprotected[33].
 *   8. Wrap in mdoc DeviceResponse { version, documents: [...], status }.
 *   9. CBOR-encode the DeviceResponse.
 */

import { Encoder as CborEncoder, addExtension } from 'cbor-x';

import type { TestKeyMaterial } from './crypto-helpers.js';

// ----------------------------------------------------------------
// Public API
// ----------------------------------------------------------------

export interface BuildSignedMdocOptions {
    issuerKey: TestKeyMaterial;
    /** Default: 'eu.europa.ec.eudi.pid.1' */
    docType?: string;
    /**
     * Claim values grouped by namespace.
     * Example: { 'eu.europa.ec.eudi.pid.1': { age_over_18: true, family_name: 'Doe' } }
     */
    namespaces: Record<string, Record<string, unknown>>;
    /** Default: now - 1 hour */
    validFrom?: Date;
    /** Default: now + 1 hour */
    validUntil?: Date;
    /** Default: now */
    signed?: Date;
    /** Default: 'ES256'. Also accepts 'ES384' or 'ES512'. */
    alg?: string;
}

export interface BuildSignedMdocResult {
    /** CBOR-encoded DeviceResponse bytes — pass directly as vpToken. */
    mdocBytes: Uint8Array;
    /** The raw COSE_Sign1 bytes inside issuerAuth — for targeted tampering. */
    issuerAuth: Uint8Array;
    /** The MSO object (decoded) for assertions. */
    mso: unknown;
    /** Tag-24 bytes of each IssuerSignedItem, indexed by namespace. */
    itemBytesByNamespace: Record<string, Uint8Array[]>;
}

// ----------------------------------------------------------------
// Algorithm mapping
// ----------------------------------------------------------------

const ALG_TO_COSE_LABEL: Record<string, number> = {
    ES256: -7,
    ES384: -35,
    ES512: -36,
};

const ALG_TO_HASH: Record<string, string> = {
    ES256: 'SHA-256',
    ES384: 'SHA-384',
    ES512: 'SHA-512',
};

const DIGEST_ALG_NAME: Record<string, string> = {
    ES256: 'SHA-256',
    ES384: 'SHA-384',
    ES512: 'SHA-512',
};

// ----------------------------------------------------------------
// Tag-24 (embedded CBOR) wrapping
// ----------------------------------------------------------------

class EmbeddedCbor {
    constructor(public readonly value: Uint8Array) {}
}
addExtension({
    Class: EmbeddedCbor,
    tag: 24,
    encode(instance, encode) {
        return encode(instance.value);
    },
    decode(value: Uint8Array) {
        return new EmbeddedCbor(value);
    },
});

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false });

// ----------------------------------------------------------------
// Main builder
// ----------------------------------------------------------------

export async function buildSignedMdoc(options: BuildSignedMdocOptions): Promise<BuildSignedMdocResult> {
    const {
        issuerKey,
        docType = 'eu.europa.ec.eudi.pid.1',
        namespaces,
        validFrom = new Date(Date.now() - 60 * 60 * 1000),
        validUntil = new Date(Date.now() + 60 * 60 * 1000),
        signed = new Date(),
        alg = 'ES256',
    } = options;

    const coseAlg = ALG_TO_COSE_LABEL[alg];
    if (coseAlg === undefined) throw new Error(`Unsupported alg: ${alg}`);
    const hashAlg = ALG_TO_HASH[alg]!;
    const digestAlg = DIGEST_ALG_NAME[alg]!;

    // 1 & 2: Build IssuerSignedItems, CBOR-encode each, wrap as tag 24
    let digestID = 0;
    const itemBytesByNamespace: Record<string, Uint8Array[]> = {};
    const valueDigestsByNamespace = new Map<string, Map<number, Uint8Array>>();

    for (const [ns, claims] of Object.entries(namespaces)) {
        const nsItems: Uint8Array[] = [];
        const nsDigests = new Map<number, Uint8Array>();
        for (const [elementIdentifier, elementValue] of Object.entries(claims)) {
            const random = crypto.getRandomValues(new Uint8Array(16));
            const item = new Map<string, unknown>([
                ['digestID', digestID],
                ['random', random],
                ['elementIdentifier', elementIdentifier],
                ['elementValue', elementValue],
            ]);
            const itemCbor = cbor.encode(item);
            const itemTag24 = cbor.encode(new EmbeddedCbor(itemCbor));
            nsItems.push(itemTag24);
            // 3: Compute digest of the tag-24 bytes
            const digest = await crypto.subtle.digest(hashAlg, itemTag24);
            nsDigests.set(digestID, new Uint8Array(digest));
            digestID++;
        }
        itemBytesByNamespace[ns] = nsItems;
        valueDigestsByNamespace.set(ns, nsDigests);
    }

    // 4: Build MSO
    const mso = new Map<string, unknown>([
        ['version', '1.0'],
        ['digestAlgorithm', digestAlg],
        ['valueDigests', valueDigestsByNamespace],
        ['deviceKeyInfo', new Map([['deviceKey', new Map()]])],
        ['docType', docType],
        [
            'validityInfo',
            new Map<string, unknown>([
                ['signed', signed],
                ['validFrom', validFrom],
                ['validUntil', validUntil],
            ]),
        ],
    ]);

    // 5: CBOR-encode MSO. The COSE payload MUST be a tag-24 byte string
    const msoCbor = cbor.encode(mso);
    const msoTag24 = cbor.encode(new EmbeddedCbor(msoCbor));

    // 6 & 7: Build COSE_Sign1 and sign it
    const protectedHeader = new Map<number, unknown>([[1, coseAlg]]);
    const protectedBytes = cbor.encode(protectedHeader);

    const unprotectedHeader = new Map<number, unknown>([[33, issuerKey.certDerBytes]]);

    // Sig_structure1 = ["Signature1", protected_bytes, external_aad (empty), payload]
    const sigStructure1 = ['Signature1', protectedBytes, new Uint8Array(0), msoTag24];
    const sigInput = cbor.encode(sigStructure1);

    const rawSig = await crypto.subtle.sign({ name: 'ECDSA', hash: hashAlg }, issuerKey.privateKey, sigInput);
    const signature = new Uint8Array(rawSig);

    // Assemble COSE_Sign1 array
    const coseSign1 = [protectedBytes, unprotectedHeader, msoTag24, signature];
    const issuerAuth = cbor.encode(coseSign1);

    // 8 & 9: Wrap in DeviceResponse
    const document = new Map<string, unknown>([
        ['docType', docType],
        [
            'issuerSigned',
            new Map<string, unknown>([
                [
                    'nameSpaces',
                    new Map(
                        Object.entries(itemBytesByNamespace).map(([ns, items]) => [
                            ns,
                            items.map((b) => new EmbeddedCbor(b)),
                        ])
                    ),
                ],
                ['issuerAuth', coseSign1],
            ]),
        ],
    ]);
    const deviceResponse = new Map<string, unknown>([
        ['version', '1.0'],
        ['documents', [document]],
        ['status', 0],
    ]);

    const mdocBytes = cbor.encode(deviceResponse);

    return {
        mdocBytes,
        issuerAuth,
        mso: Object.fromEntries(mso),
        itemBytesByNamespace,
    };
}

// ----------------------------------------------------------------
// Tampering / negative-case builders
// ----------------------------------------------------------------

/**
 * Build an mDOC whose `signed` date is in the future — should be rejected.
 */
export async function buildMdocWithFutureSigned(
    base: Omit<BuildSignedMdocOptions, 'signed'>
): Promise<BuildSignedMdocResult> {
    return buildSignedMdoc({ ...base, signed: new Date(Date.now() + 2 * 60 * 60 * 1000) });
}

/**
 * Build an mDOC whose `validFrom` is in the future — not-yet-valid.
 */
export async function buildMdocWithFutureValidFrom(
    base: Omit<BuildSignedMdocOptions, 'validFrom'>
): Promise<BuildSignedMdocResult> {
    return buildSignedMdoc({
        ...base,
        validFrom: new Date(Date.now() + 2 * 60 * 60 * 1000),
    });
}

/**
 * Build an mDOC whose `validUntil` is in the past — expired.
 */
export async function buildMdocWithExpiredValidity(
    base: Omit<BuildSignedMdocOptions, 'validUntil' | 'validFrom' | 'signed'>
): Promise<BuildSignedMdocResult> {
    const pastFrom = new Date(Date.now() - 4 * 60 * 60 * 1000);
    const pastUntil = new Date(Date.now() - 2 * 60 * 60 * 1000);
    return buildSignedMdoc({
        ...base,
        signed: pastFrom,
        validFrom: pastFrom,
        validUntil: pastUntil,
    });
}

/**
 * Replace the signature bytes of a signed mDOC with zeros — signature verification fails.
 */
export async function stripCoseSignature(mdocBytes: Uint8Array): Promise<Uint8Array> {
    // Use the map-preserving cbor encoder, not the default cborDecode which converts Maps to objects
    const dr = cbor.decode(mdocBytes) as Map<string, unknown>;
    const doc = (dr.get('documents') as unknown[])[0] as Map<string, unknown>;
    const issuerSigned = doc.get('issuerSigned') as Map<string, unknown>;
    const coseSign1 = issuerSigned.get('issuerAuth') as unknown[];
    const sig = coseSign1[3] as Uint8Array;
    const zeroed = new Uint8Array(sig.length); // all zeros
    coseSign1[3] = zeroed;
    return cbor.encode(dr);
}
