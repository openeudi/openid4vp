import { X509Certificate } from '@peculiar/x509';
import { DOMParser } from '@xmldom/xmldom';
import type { Document as XmlDocument, Element as XmlElement, Node as XmlNode } from '@xmldom/xmldom';
import * as xmldsig from 'xmldsigjs';
import { LotlConfigurationError, LotlFetchError, LotlSignatureError } from '../errors.js';
import { createDefaultTrustFetcher } from '../http/guarded-fetch.js';
import type { Fetcher } from './Fetcher.js';

const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#';
const XADES_SIGNED_PROPERTIES_TYPE = 'http://uri.etsi.org/01903#SignedProperties';
const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const CANONICALIZATIONS: ReadonlySet<string> = new Set([
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
    'http://www.w3.org/2001/10/xml-exc-c14n#',
    'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
]);
/** RSA public keys carry no hash, so it comes from the signature method. */
const RSA_SIGNATURE_HASHES: ReadonlyMap<string, string> = new Map([
    ['http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'SHA-1'],
    ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 'SHA-256'],
    ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', 'SHA-384'],
    ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', 'SHA-512'],
]);
const ELEMENT_NODE = 1;
const ID_ATTRIBUTES = ['Id', 'ID', 'id'] as const;

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
        this.fetcher = opts.fetcher ?? createDefaultTrustFetcher();
    }

    async fetchSigned(
        url: string,
        signingAnchors: readonly X509Certificate[]
    ): Promise<XmlDocument> {
        // Checked up front: without an engine NO list can verify, so failing
        // here beats fetching, walking every anchor, and reporting the result
        // as an unverified signature.
        assertCryptoEngineRegistered();

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

        const sigEl = checkEnvelopedSignature(doc, url);

        for (const anchor of signingAnchors) {
            const verified = await verifyAgainst(doc, sigEl, anchor);
            if (verified) {
                // Callers read list content from this document. Removing the
                // signature leaves only what its digest covered, so nothing
                // unsigned under ds:Object can be read as list content.
                sigEl.parentNode!.removeChild(sigEl);
                return doc;
            }
        }
        throw new LotlSignatureError(
            `no signing anchor verified the signature on ${url}`
        );
    }
}

function isElement(node: XmlNode | null | undefined): node is XmlElement {
    return !!node && node.nodeType === ELEMENT_NODE;
}

/** Direct element children of `parent`, optionally filtered by namespace + local name. */
function childElements(parent: XmlElement, ns?: string, name?: string): XmlElement[] {
    const out: XmlElement[] = [];
    for (let n = parent.firstChild; n; n = n.nextSibling) {
        if (!isElement(n)) continue;
        if (ns !== undefined && n.namespaceURI !== ns) continue;
        if (name !== undefined && n.localName !== name) continue;
        out.push(n);
    }
    return out;
}

function transformAlgorithms(reference: XmlElement): string[] {
    return childElements(reference, XMLDSIG_NS, 'Transforms')
        .flatMap((t) => childElements(t, XMLDSIG_NS, 'Transform'))
        .map((t) => t.getAttribute('Algorithm') ?? '');
}

function elementsWithId(root: XmlElement, id: string): XmlElement[] {
    const found: XmlElement[] = [];
    const visit = (el: XmlElement): void => {
        if (ID_ATTRIBUTES.some((attr) => el.getAttribute(attr) === id)) found.push(el);
        for (const c of childElements(el)) visit(c);
    };
    visit(root);
    return found;
}

function isInside(node: XmlElement, ancestor: XmlElement): boolean {
    for (let n: XmlNode | null = node.parentNode; n; n = n.parentNode) {
        if (n === ancestor) return true;
    }
    return false;
}

/**
 * Refuse XML Signature Wrapping by shape, before any cryptography
 * (GHSA-28mg-45r4-j8jr). `xmldsigjs` checks that the references it finds
 * digest correctly; it does not check that they cover the list. So:
 *
 * - the document holds exactly one `ds:Signature`, a direct child of the root;
 * - exactly one reference covers the root, as `URI=""` or `URI="#<root Id>"`
 *   with that Id carried by no other element, using the enveloped-signature
 *   transform and at most one canonicalization;
 * - any other reference is the XAdES SignedProperties inside this signature;
 * - a `ds:Object` holds only `xades:QualifyingProperties`, since the
 *   enveloped transform drops the whole signature from the digest.
 */
function checkEnvelopedSignature(doc: XmlDocument, url: string): XmlElement {
    const fail = (why: string): never => {
        throw new LotlSignatureError(`signature structure refused on ${url}: ${why}`);
    };
    const root = doc.documentElement!;
    const signatures = doc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature');
    if (signatures.length === 0) {
        throw new LotlSignatureError(`no ds:Signature element in ${url}`);
    }
    if (signatures.length > 1) fail(`expected one ds:Signature, found ${signatures.length}`);
    const signature = signatures.item(0)!;
    if (signature.parentNode !== root) fail('ds:Signature is not a direct child of the list root');

    for (const c of childElements(signature)) {
        const allowed =
            c.namespaceURI === XMLDSIG_NS &&
            ['SignedInfo', 'SignatureValue', 'KeyInfo', 'Object'].includes(c.localName ?? '');
        if (!allowed) fail(`unexpected {${c.namespaceURI ?? ''}}${c.localName ?? ''} in ds:Signature`);
    }
    // Counted over the whole subtree: a lookup by tag name inside the library
    // must not find a second SignedInfo hidden in a ds:Object.
    for (const name of ['SignedInfo', 'SignatureValue']) {
        const count = signature.getElementsByTagNameNS(XMLDSIG_NS, name).length;
        if (count !== 1) fail(`expected one ds:${name}, found ${count}`);
    }
    for (const object of childElements(signature, XMLDSIG_NS, 'Object')) {
        const content = childElements(object);
        if (content.some((el) => el.namespaceURI !== XADES_NS || el.localName !== 'QualifyingProperties')) {
            fail('ds:Object may only hold xades:QualifyingProperties');
        }
    }

    const signedInfo = childElements(signature, XMLDSIG_NS, 'SignedInfo')[0]!;
    const rootId = ID_ATTRIBUTES.map((attr) => root.getAttribute(attr)).find((v) => !!v);
    const references = childElements(signedInfo, XMLDSIG_NS, 'Reference');
    const coversRoot = (ref: XmlElement): boolean => {
        // A Reference without a URI attribute is application-defined: it does
        // not stand in for "".
        if (!ref.hasAttribute('URI')) return false;
        const uri = ref.getAttribute('URI');
        return uri === '' || (!!rootId && uri === `#${rootId}`);
    };
    const rootRefs = references.filter(coversRoot);
    if (rootRefs.length !== 1) fail(`expected one reference covering the list root, found ${rootRefs.length}`);
    const rootRef = rootRefs[0]!;
    if (rootRef.getAttribute('URI') !== '' && elementsWithId(root, rootId!).length !== 1) {
        fail(`Id "${rootId}" is carried by more than one element`);
    }
    const [first, ...rest] = transformAlgorithms(rootRef);
    if (first !== ENVELOPED_SIGNATURE || rest.length > 1 || (rest[0] !== undefined && !CANONICALIZATIONS.has(rest[0]))) {
        fail('the list reference must use enveloped-signature and at most one canonicalization');
    }

    for (const ref of references) {
        if (ref === rootRef) continue;
        const uri = ref.getAttribute('URI') ?? '';
        if (ref.getAttribute('Type') !== XADES_SIGNED_PROPERTIES_TYPE || !uri.startsWith('#') || uri.length < 2) {
            fail(`unexpected reference URI="${uri}"`);
        }
        const targets = elementsWithId(root, uri.slice(1));
        const target = targets[0];
        if (
            targets.length !== 1 ||
            !target ||
            target.namespaceURI !== XADES_NS ||
            target.localName !== 'SignedProperties' ||
            !isInside(target, signature)
        ) {
            fail(`reference ${uri} must resolve to one xades:SignedProperties inside the signature`);
        }
        const transforms = transformAlgorithms(ref);
        if (transforms.length > 1 || transforms.some((a) => !CANONICALIZATIONS.has(a))) {
            fail(`reference ${uri} may only use one canonicalization transform`);
        }
    }
    return signature;
}

/**
 * Fail fast when the consumer never registered an `xmldsigjs` crypto engine.
 *
 * `Application.crypto` is a getter that THROWS `XmlError`
 * ("XMLJS0014: WebCrypto module is not found") when unset rather than returning
 * a falsy value, so the access has to be guarded — a plain
 * `if (!Application.crypto)` would propagate that raw error instead of this one.
 *
 * Engine registration is deliberately left to the consumer (see the comments on
 * `verifyAgainst`), so this reports the omission as configuration rather than
 * silently treating every trusted list as unverifiable.
 */
function assertCryptoEngineRegistered(): void {
    let engine: unknown;
    try {
        engine = xmldsig.Application.crypto;
    } catch (err) {
        throw new LotlConfigurationError(
            'no xmldsigjs crypto engine registered — trusted-list signatures cannot be ' +
                "verified. Call xmldsig.Application.setEngine('NodeJS', new Crypto()) " +
                '(e.g. from @peculiar/webcrypto) once at startup, before using ' +
                `LotlTrustStore. Underlying error: ${err instanceof Error ? err.message : String(err)}`,
            { cause: err instanceof Error ? err : undefined }
        );
    }
    if (!engine) {
        throw new LotlConfigurationError(
            'no xmldsigjs crypto engine registered — trusted-list signatures cannot be ' +
                "verified. Call xmldsig.Application.setEngine('NodeJS', new Crypto()) " +
                '(e.g. from @peculiar/webcrypto) once at startup, before using LotlTrustStore.'
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
    sigEl: XmlElement,
    anchor: X509Certificate
): Promise<boolean> {
    try {
        const signed = new xmldsig.SignedXml(doc as unknown as Document);
        signed.LoadXml(sigEl as unknown as Element);
        const signatureMethod =
            sigEl.getElementsByTagNameNS(XMLDSIG_NS, 'SignatureMethod').item(0)?.getAttribute('Algorithm') ?? '';

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
        const importAlg: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams = buildImportAlgorithm(algName, pubKeyAlg, signatureMethod);

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
    pubKeyAlg: { name?: string; namedCurve?: string; hash?: { name?: string } | string } | undefined,
    signatureMethod: string
): AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams {
    if (algName.includes('EC') || algName.includes('ECDSA')) {
        const namedCurve = pubKeyAlg?.namedCurve ?? 'P-256';
        return { name: 'ECDSA', namedCurve } as EcKeyImportParams;
    }

    // RSA family. An RSA public key carries no hash, and the key's hash must
    // match the signature's: the EU LOTL is signed rsa-sha512, which a key
    // imported for SHA-256 never verifies. Take it from the SignatureMethod,
    // then from the key descriptor, then default to SHA-256.
    const rawHash = pubKeyAlg?.hash;
    let hashName: string;
    const methodHash = RSA_SIGNATURE_HASHES.get(signatureMethod);
    if (methodHash) {
        hashName = methodHash;
    } else if (typeof rawHash === 'string') {
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
