import { Encoder as CborEncoder, Tag } from 'cbor-x';
import { importX509 } from 'jose';

import { decodeCoseSign1, verifyCoseSign1 } from '../crypto/cose-sign1.js';
import { verifyDeviceAuth } from '../crypto/device-auth.js';
import { verifyAllDigests } from '../crypto/digest.js';
import { decodeMso, validateMsoValidity, validateMsoDocType } from '../crypto/mso.js';
import { MalformedCredentialError, ExpiredCredentialError } from '../errors.js';
import type { TrustEvaluationResult } from '../trust/TrustEvaluator.js';
import type { IssuerInfo } from '../types/issuer.js';
import type { CredentialFormat, CredentialClaims, PresentationResult } from '../types/presentation.js';

import type { ICredentialParser, ParseOptions } from './parser.interface.js';

// Decoder that preserves CBOR maps as JS Maps (cbor-x default converts them to objects).
const decoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });
const encoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });

const DEFAULT_ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'ES512'];

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

function derToPem(der: Uint8Array): string {
    let binary = '';
    for (const b of der) binary += String.fromCharCode(b);
    const b64 = globalThis.btoa(binary);
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

function extractCountryHintFromCert(_certDer: Uint8Array): string {
    // Placeholder — full X.509 subject parsing is workstream 3.
    return '';
}

/**
 * Reconstructs the canonical CBOR byte-string header (major type 2) for a bstr of
 * the given length, using the shortest (deterministic) length encoding — matching
 * how wallets/issuers serialize IssuerSignedItemBytes. Content bytes are appended
 * verbatim by the caller.
 */
function cborByteStringHeader(length: number): Uint8Array {
    if (length < 24) return Uint8Array.of(0x40 | length);
    if (length < 0x100) return Uint8Array.of(0x58, length);
    if (length < 0x10000) return Uint8Array.of(0x59, (length >> 8) & 0xff, length & 0xff);
    if (length < 0x100000000) {
        return Uint8Array.of(
            0x5a,
            (length >>> 24) & 0xff,
            (length >>> 16) & 0xff,
            (length >>> 8) & 0xff,
            length & 0xff
        );
    }
    // 64-bit lengths (>4 GiB) never occur for a single IssuerSignedItem.
    const hi = Math.floor(length / 0x100000000);
    const lo = length >>> 0;
    return Uint8Array.of(
        0x5b,
        (hi >>> 24) & 0xff,
        (hi >>> 16) & 0xff,
        (hi >>> 8) & 0xff,
        hi & 0xff,
        (lo >>> 24) & 0xff,
        (lo >>> 16) & 0xff,
        (lo >>> 8) & 0xff,
        lo & 0xff
    );
}

/**
 * Wraps inner IssuerSignedItem CBOR into IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem):
 *   0xD8 0x18 ++ <bstr-header(inner.length)> ++ inner
 *
 * The inner content is copied verbatim (never re-encoded), so no map-key reordering
 * or int/bstr re-serialization can occur — only the deterministic tag+length header
 * is prepended. This reproduces the exact on-wire bytes the issuer hashed.
 */
export function wrapIssuerSignedItemBytes(inner: Uint8Array): Uint8Array {
    const header = cborByteStringHeader(inner.length);
    const out = new Uint8Array(2 + header.length + inner.length);
    out[0] = 0xd8;
    out[1] = 0x18;
    out.set(header, 2);
    out.set(inner, 2 + header.length);
    return out;
}

/**
 * Returns the full IssuerSignedItemBytes — the tag-24 encoding #6.24(bstr .cbor IssuerSignedItem)
 * — for a decoded nameSpaces element. This is the exact byte sequence ISO 18013-5 §9.1.2.4
 * commits in MSO.valueDigests, so it (not the inner CBOR) is what must be hashed.
 *
 * cbor-x decodes the single tag-24 wrapper to its inner content, so we reconstruct the
 * tag-24 header around that inner content. Three decode shapes arise:
 *   A) Tag(24, Uint8Array)    — production cbor-x path (no addExtension); .value = inner CBOR
 *   B) EmbeddedCbor-like obj  — test-fixture path (mdoc-helpers.ts registers a tag-24
 *                               addExtension globally); .value = inner CBOR
 *   C) Plain Uint8Array       — a bare bstr. If it already starts with the tag-24 prefix
 *                               (0xD8 0x18) it is IssuerSignedItemBytes as-is; otherwise it
 *                               is inner CBOR to be wrapped.
 */
function extractRawItemBytes(item: unknown): Uint8Array {
    if (item instanceof Tag && item.tag === 24 && item.value instanceof Uint8Array) {
        return wrapIssuerSignedItemBytes(item.value);
    }
    if (item instanceof Uint8Array) {
        if (item.length >= 2 && item[0] === 0xd8 && item[1] === 0x18) {
            return item;
        }
        return wrapIssuerSignedItemBytes(item);
    }
    if (
        item !== null &&
        typeof item === 'object' &&
        !(item instanceof Tag) &&
        !(item instanceof Map) &&
        'value' in (item as object) &&
        (item as { value: unknown }).value instanceof Uint8Array
    ) {
        return wrapIssuerSignedItemBytes((item as { value: Uint8Array }).value);
    }
    throw new MalformedCredentialError('IssuerSignedItem must be a tag-24 byte string');
}

/**
 * Maps raw IssuerSignedItem bytes (from all namespaces) to CredentialClaims
 * plus a namespace-grouped structure (for DCQL path addressing).
 *
 * Handles all three tag-24 shapes (Tag(24,bytes), EmbeddedCbor-like object, plain bytes).
 */
function mapRawToClaims(nameSpaces: Map<string, Uint8Array[]>): {
    flat: CredentialClaims;
    namespaced: Record<string, Record<string, unknown>>;
} {
    const flat: CredentialClaims = {};
    const namespaced: Record<string, Record<string, unknown>> = {};
    for (const [ns, items] of nameSpaces.entries()) {
        const nsBucket: Record<string, unknown> = namespaced[ns] ?? {};
        for (const itemBytes of items) {
            let decoded: unknown;
            try {
                decoded = decoder.decode(itemBytes);
            } catch {
                continue;
            }

            // Unwrap all three tag-24 shapes to get the inner CBOR bytes
            let inner: unknown;
            if (decoded instanceof Tag && decoded.tag === 24 && decoded.value instanceof Uint8Array) {
                // Path A: Tag(24, bytes)
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
                continue;
            }

            if (inner instanceof Map) {
                const id = (inner as Map<string, unknown>).get('elementIdentifier');
                const val = (inner as Map<string, unknown>).get('elementValue');
                if (typeof id === 'string') {
                    (flat as Record<string, unknown>)[id] = val;
                    nsBucket[id] = val;
                }
            }
        }
        namespaced[ns] = nsBucket;
    }
    return { flat, namespaced };
}

/**
 * mDOC / mDL credential parser.
 *
 * Decodes and validates mDOC (Mobile Document) credentials as specified in
 * ISO 18013-5 and the EUDI Wallet ecosystem. Composes the crypto modules
 * to perform full verification:
 *   - COSE_Sign1 decode + signature verification
 *   - MSO decode + validity + docType validation
 *   - Digest verification for all IssuerSignedItems
 *   - Issuer certificate trust chain check
 */
export class MdocParser implements ICredentialParser {
    readonly format: CredentialFormat = 'mdoc';

    /**
     * Returns true when the token is binary data (Uint8Array or Buffer),
     * indicating a CBOR-encoded mDOC DeviceResponse.
     * Buffer extends Uint8Array, so `instanceof Uint8Array` catches both.
     */
    canParse(vpToken: unknown): boolean {
        return vpToken instanceof Uint8Array;
    }

    /**
     * Parses and validates an mDOC DeviceResponse token.
     *
     * @throws {MalformedCredentialError} when the CBOR structure cannot be decoded
     *   or does not match the expected DeviceResponse format
     */
    async parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult> {
        if (!(vpToken instanceof Uint8Array)) {
            throw new MalformedCredentialError('mDOC vpToken must be a Uint8Array');
        }
        const allowedAlgorithms = options.allowedAlgorithms ?? DEFAULT_ALLOWED_ALGORITHMS;

        // Step 1: Decode DeviceResponse
        let deviceResponse: Map<unknown, unknown>;
        try {
            const decoded = decoder.decode(vpToken);
            if (!(decoded instanceof Map)) throw new Error();
            deviceResponse = decoded as Map<unknown, unknown>;
        } catch {
            throw new MalformedCredentialError('vpToken is not a CBOR DeviceResponse Map');
        }

        // Step 2: Extract first document
        const docs = deviceResponse.get('documents');
        if (!Array.isArray(docs) || docs.length === 0) {
            throw new MalformedCredentialError('DeviceResponse has no documents');
        }
        const document = docs[0];
        if (!(document instanceof Map)) {
            throw new MalformedCredentialError('document must be a Map');
        }
        const issuerSigned = document.get('issuerSigned');
        if (!(issuerSigned instanceof Map)) {
            throw new MalformedCredentialError('document.issuerSigned must be a Map');
        }
        const issuerAuth = issuerSigned.get('issuerAuth');
        if (!Array.isArray(issuerAuth)) {
            throw new MalformedCredentialError('issuerAuth must be a COSE_Sign1 array');
        }

        // Re-encode issuerAuth as bytes so we can pass to decodeCoseSign1
        const issuerAuthBytes = encoder.encode(issuerAuth);

        // Step 3: Decode COSE_Sign1 + algorithm check
        const cose = decodeCoseSign1(issuerAuthBytes);
        if (!allowedAlgorithms.includes(cose.alg)) {
            return {
                valid: false,
                format: this.format,
                claims: {},
                issuer: { certificate: new Uint8Array(), country: '' },
                error: `Unsupported algorithm: ${cose.alg}`,
            };
        }

        // Step 4: Trust check (reuse 0.2.1 skipTrustCheck semantics)
        const issuerCertBytes = cose.x5chain[0];
        if (!issuerCertBytes) {
            throw new MalformedCredentialError('Missing issuer certificate in x5chain');
        }

        let trustResult: TrustEvaluationResult | undefined;

        if (options.trustStore) {
            // 0.5.0 path: RFC 5280 chain validation via TrustEvaluator.
            // Dynamic import keeps the evaluator out of 0.4.0-style callers' bundles.
            const { TrustEvaluator } = await import('../trust/TrustEvaluator.js');
            const evaluator = new TrustEvaluator({
                trustStore: options.trustStore,
                revocationPolicy: options.revocationPolicy ?? 'skip',
                fetcher: options.fetcher,
                cache: options.cache,
                clockSkewTolerance: options.clockSkewTolerance,
            });
            const { X509Certificate } = await import('@peculiar/x509');
            const leaf = new X509Certificate(issuerCertBytes as Uint8Array<ArrayBuffer>);
            trustResult = await evaluator.evaluate(leaf);
        } else {
            // 0.4.0 byte-equality path — preserved verbatim for backward compatibility.
            if (options.trustedCertificates.length === 0) {
                if (options.skipTrustCheck !== true) {
                    throw new MalformedCredentialError(
                        'trustedCertificates must not be empty unless skipTrustCheck is true'
                    );
                }
            } else {
                const trusted = options.trustedCertificates.some((t) => bytesEqual(t, issuerCertBytes));
                if (!trusted) {
                    return {
                        valid: false,
                        format: this.format,
                        claims: {},
                        issuer: { certificate: issuerCertBytes, country: '' },
                        error: 'Issuer certificate is not trusted',
                    };
                }
            }
        }

        // Step 5: Import public key + verify signature
        const publicKey = await importX509(derToPem(issuerCertBytes), cose.alg);
        try {
            await verifyCoseSign1(cose, publicKey, allowedAlgorithms);
        } catch (err) {
            if (err instanceof MalformedCredentialError) {
                return {
                    valid: false,
                    format: this.format,
                    claims: {},
                    issuer: { certificate: issuerCertBytes, country: '' },
                    error: err.message,
                };
            }
            throw err;
        }

        // Step 6: Decode + validate MSO
        const mso = decodeMso(cose.payload);
        try {
            validateMsoValidity(mso, new Date());
        } catch (err) {
            if (err instanceof ExpiredCredentialError) {
                return {
                    valid: false,
                    format: this.format,
                    claims: {},
                    issuer: { certificate: issuerCertBytes, country: '' },
                    error: 'Credential expired',
                };
            }
            throw err;
        }

        if (options.expectedDocType !== undefined) {
            try {
                validateMsoDocType(mso, options.expectedDocType);
            } catch (err) {
                if (err instanceof MalformedCredentialError) {
                    return {
                        valid: false,
                        format: this.format,
                        claims: {},
                        issuer: { certificate: issuerCertBytes, country: '' },
                        error: err.message,
                    };
                }
                throw err;
            }
        }

        // Step 7: Extract items from nameSpaces, verify all digests
        const nsRaw = issuerSigned.get('nameSpaces');
        if (!(nsRaw instanceof Map)) {
            throw new MalformedCredentialError('issuerSigned.nameSpaces must be a Map');
        }
        const nameSpaces = new Map<string, Uint8Array[]>();
        for (const [ns, items] of (nsRaw as Map<unknown, unknown>).entries()) {
            if (typeof ns !== 'string' || !Array.isArray(items)) {
                throw new MalformedCredentialError('nameSpaces entry malformed');
            }
            nameSpaces.set(ns, items.map(extractRawItemBytes));
        }
        await verifyAllDigests(nameSpaces, mso);

        // Step 7.5: Device authentication (ISO 18013-5 §9.1.3) — holder proof-of-
        // possession. Without this an attacker who captures another holder's
        // `issuerSigned` structure can replay it, because issuerAuth alone carries
        // no binding to the presenter or the current session/nonce. Fail closed.
        // (CWE-294 capture-replay · CWE-345 insufficient authenticity verification)
        const deviceSigned = document.get('deviceSigned');
        if (!(deviceSigned instanceof Map)) {
            return {
                valid: false,
                format: this.format,
                claims: {},
                issuer: { certificate: issuerCertBytes, country: '' },
                error: 'Missing deviceSigned — mDOC device authentication is required',
            };
        }
        if (!(options.mdocSessionTranscript instanceof Uint8Array) || options.mdocSessionTranscript.length === 0) {
            return {
                valid: false,
                format: this.format,
                claims: {},
                issuer: { certificate: issuerCertBytes, country: '' },
                error: 'mdocSessionTranscript is required to verify mDOC device authentication',
            };
        }
        if (!mso.deviceKey) {
            return {
                valid: false,
                format: this.format,
                claims: {},
                issuer: { certificate: issuerCertBytes, country: '' },
                error: 'MSO is missing deviceKeyInfo.deviceKey; cannot verify device authentication',
            };
        }
        try {
            await verifyDeviceAuth({
                deviceSigned: deviceSigned as Map<unknown, unknown>,
                deviceKeyCose: mso.deviceKey,
                docType: mso.docType,
                sessionTranscript: options.mdocSessionTranscript,
                allowedAlgorithms,
            });
        } catch (err) {
            if (err instanceof MalformedCredentialError) {
                return {
                    valid: false,
                    format: this.format,
                    claims: {},
                    issuer: { certificate: issuerCertBytes, country: '' },
                    error: err.message,
                };
            }
            throw err;
        }

        // Step 8: Map to claims
        const { flat: claims, namespaced: namespacedClaims } = mapRawToClaims(nameSpaces);

        const issuer: IssuerInfo = {
            certificate: issuerCertBytes,
            country: extractCountryHintFromCert(issuerCertBytes),
        };
        const result: PresentationResult = {
            valid: true,
            format: this.format,
            claims,
            issuer,
            docType: mso.docType,
            namespacedClaims,
        };
        if (trustResult) result.trust = trustResult;
        return result;
    }
}
