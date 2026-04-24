import { X509Certificate } from '@peculiar/x509';
import { DOMParser } from '@xmldom/xmldom';
import type { Document as XmlDocument } from '@xmldom/xmldom';
import * as xmldsig from 'xmldsigjs';
import { LotlFetchError, LotlSignatureError } from '../errors.js';
import type { Fetcher } from './Fetcher.js';

const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

export interface LotlFetcherOptions {
    fetcher?: Fetcher;
}

/**
 * Private — NOT exported from the package root. Fetches a TSL XML document
 * from HTTP(S) and verifies its enveloped XML-DSig against a caller-supplied
 * set of signing anchors. Any anchor that verifies wins; the remainder are
 * ignored. Consumed by `LotlTrustStore` (for the EU LOTL) and
 * `NationalTlResolver` (for per-country TLs).
 */
export class LotlFetcher {
    private readonly fetcher: Fetcher;

    constructor(opts: LotlFetcherOptions = {}) {
        this.fetcher = opts.fetcher ?? globalThis.fetch.bind(globalThis);
    }

    async fetchSigned(
        url: string,
        signingAnchors: readonly X509Certificate[]
    ): Promise<XmlDocument> {
        let xmlText: string;
        try {
            const response = await this.fetcher(url, { method: 'GET' });
            if (!response.ok) {
                throw new LotlFetchError(
                    `LOTL fetch failed: HTTP ${response.status} for ${url}`,
                    { url }
                );
            }
            xmlText = await response.text();
        } catch (err) {
            if (err instanceof LotlFetchError) throw err;
            throw new LotlFetchError(`LOTL fetch failed for ${url}`, {
                url,
                cause: err instanceof Error ? err : new Error(String(err)),
            });
        }

        let doc: XmlDocument;
        try {
            const parsed = new DOMParser().parseFromString(
                xmlText,
                'application/xml'
            );
            // @xmldom/xmldom signals parse failures via a <parsererror> element.
            const parseError = parsed.getElementsByTagName('parsererror')[0];
            if (parseError) {
                throw new Error(
                    `XML parse error: ${parseError.textContent ?? 'unknown'}`
                );
            }
            if (!parsed.documentElement) {
                throw new Error('empty XML document');
            }
            doc = parsed;
        } catch (err) {
            throw new LotlFetchError(`LOTL XML parse failed for ${url}`, {
                url,
                cause: err instanceof Error ? err : new Error(String(err)),
            });
        }

        const sigEl = doc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature').item(0);
        if (!sigEl) {
            throw new LotlSignatureError(`no ds:Signature element in ${url}`);
        }

        for (const anchor of signingAnchors) {
            const verified = await verifyAgainst(doc, sigEl as unknown as Element, anchor);
            if (verified) return doc;
        }
        throw new LotlSignatureError(
            `no signing anchor verified the signature on ${url}`
        );
    }
}

/**
 * Verify an enveloped XML-DSig against a specific anchor certificate.
 *
 * Deviation from the reference snippet: `Verify(key)` in xmldsigjs 2.8.7
 * resolves the key for `ValidateSignatureValue` by calling `reimportKey`, which
 * re-imports via `Application.crypto`. If no crypto engine was registered this
 * path throws. Instead we bypass `Verify()` entirely and call the two
 * sub-operations directly:
 *   1. `ValidateReferences` — checks digests (document integrity).
 *   2. `ValidateSignatureValue([key])` — verifies the cryptographic signature.
 *
 * This guarantees the anchor key is the one used for verification — the
 * `Verify(key)` shortcut falls back to embedded `<X509Data>` when no key is
 * supplied, which would let any self-signed cert in the XML pass. That is
 * unacceptable for a trust-anchor-constrained verification.
 *
 * Keys MUST be imported using `xmldsig.Application.crypto.subtle` (the
 * registered provider, e.g. @peculiar/webcrypto) so that `ValidateSignatureValue`
 * receives a compatible CryptoKey instance. Native `crypto.subtle` keys are
 * rejected by webcrypto-core's type guard.
 */
async function verifyAgainst(
    doc: XmlDocument,
    sigEl: Element,
    anchor: X509Certificate
): Promise<boolean> {
    try {
        const signed = new xmldsig.SignedXml(doc as unknown as Document);
        signed.LoadXml(sigEl as unknown as Element);

        // Clone the content element for ValidateReferences (it mutates internally).
        const docEl = doc.documentElement;
        const cloned = docEl?.cloneNode(true);
        // ValidateReferences and ValidateSignatureValue are protected in the
        // xmldsigjs type declarations but accessible at runtime. Cast through
        // unknown to bypass the visibility restriction.
        const signedAny = signed as unknown as {
            ValidateReferences(el: unknown): Promise<boolean>;
            ValidateSignatureValue(keys: CryptoKey[]): Promise<boolean>;
        };
        const refsOk = await signedAny.ValidateReferences(cloned);
        if (!refsOk) return false;

        // Import the anchor's SPKI DER bytes using the registered crypto provider
        // so that ValidateSignatureValue receives a compatible CryptoKey.
        // Detect algorithm + curve from the anchor certificate's public key to
        // support P-256, P-384, P-521, and RSA variants without hardcoding.
        const appCrypto = xmldsig.Application.crypto;
        const spkiDer = anchor.publicKey.rawData as ArrayBuffer;

        const pubKeyAlg = (anchor.publicKey as unknown as { algorithm?: { name?: string; namedCurve?: string; hash?: { name?: string } | string } }).algorithm;
        const algName = pubKeyAlg?.name ?? '';
        const importAlg: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams = buildImportAlgorithm(algName, pubKeyAlg);

        const providerKey = await appCrypto.subtle.importKey(
            'spki',
            spkiDer,
            importAlg,
            true,
            ['verify']
        );

        return await signedAny.ValidateSignatureValue([providerKey]);
    } catch (err) {
        // Signature-value mismatches return `false` cleanly from
        // ValidateSignatureValue. Exceptions here indicate either a key-import
        // failure (wrong curve / malformed SPKI) or a DOM-walk failure. Those
        // are not signature mismatches — log them so a misconfigured anchor
        // doesn't silently exhaust the list.
        if (err instanceof Error) {
            console.warn(
                `[openid4vp] LotlFetcher: anchor ${anchor.subject} failed to verify — ${err.name}: ${err.message}`
            );
        }
        return false;
    }
}

/**
 * Build the algorithm descriptor for `importKey('spki', ...)` by inspecting
 * the `publicKey.algorithm` property populated by `@peculiar/x509`.
 *
 * For EC keys the algorithm looks like `{ name: 'ECDSA', namedCurve: 'P-256' }`.
 * For RSA keys it looks like `{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }`
 * (or with the hash as a plain string). We map the curve to its conventional
 * matching hash so that the import parameters are correct for the key material.
 */
function buildImportAlgorithm(
    algName: string,
    pubKeyAlg: { name?: string; namedCurve?: string; hash?: { name?: string } | string } | undefined
): AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams {
    if (algName.includes('EC') || algName.includes('ECDSA')) {
        const namedCurve = pubKeyAlg?.namedCurve ?? 'P-256';
        return { name: 'ECDSA', namedCurve } as EcKeyImportParams;
    }

    // RSA family: extract hash from the algorithm descriptor if available,
    // otherwise default to SHA-256.
    const rawHash = pubKeyAlg?.hash;
    let hashName: string;
    if (typeof rawHash === 'string') {
        hashName = rawHash;
    } else if (typeof rawHash === 'object' && rawHash !== null && rawHash.name) {
        hashName = rawHash.name;
    } else {
        hashName = 'SHA-256';
    }

    return {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: hashName },
    } as RsaHashedImportParams;
}
