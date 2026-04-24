import { X509Certificate } from '@peculiar/x509';
import { DOMParser } from '@xmldom/xmldom';
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
    ): Promise<Document> {
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

        let doc: Document;
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
            doc = parsed as unknown as Document;
        } catch (err) {
            throw new LotlFetchError(`LOTL XML parse failed for ${url}`, {
                url,
                cause: err instanceof Error ? err : new Error(String(err)),
            });
        }

        // getElementsByTagNameNS is available on the xmldom Document.
        const xmldomDoc = doc as unknown as {
            getElementsByTagNameNS(ns: string, name: string): { item(i: number): unknown; length: number };
        };
        const sigEl = xmldomDoc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature').item(0);
        if (!sigEl) {
            throw new LotlSignatureError(`no ds:Signature element in ${url}`);
        }

        for (const anchor of signingAnchors) {
            const verified = await verifyAgainst(doc, sigEl as Element, anchor);
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
    doc: Document,
    sigEl: Element,
    anchor: X509Certificate
): Promise<boolean> {
    try {
        const signed = new xmldsig.SignedXml(doc as unknown as Document);
        signed.LoadXml(sigEl as unknown as Element);

        // Clone the content element for ValidateReferences (it mutates internally).
        const docEl = (doc as unknown as { documentElement: unknown }).documentElement;
        const cloned = (docEl as { cloneNode(deep: boolean): unknown }).cloneNode(true);
        const refsOk = await signed.ValidateReferences(cloned as Element);
        if (!refsOk) return false;

        // Import the anchor's SPKI DER bytes using the registered crypto provider
        // so that ValidateSignatureValue receives a compatible CryptoKey.
        const appCrypto = xmldsig.Application.crypto;
        const spkiDer = anchor.publicKey.rawData as ArrayBuffer;
        const algId = (anchor.publicKey as unknown as { algorithm?: { name?: string } }).algorithm?.name ?? '';
        const importAlg: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams =
            algId.includes('EC') || algId.includes('ECDSA')
                ? { name: 'ECDSA', namedCurve: 'P-256' }
                : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

        const providerKey = await appCrypto.subtle.importKey(
            'spki',
            spkiDer,
            importAlg,
            true,
            ['verify']
        );

        return await signed.ValidateSignatureValue([providerKey]);
    } catch {
        return false;
    }
}
