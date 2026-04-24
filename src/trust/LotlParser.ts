import { X509Certificate } from '@peculiar/x509';
import type { Document as XmlDocument, Element as XmlElement } from '@xmldom/xmldom';
import type { LotlSnapshot, OtherTslPointer } from './lotl-types.js';

const TSL_NS = 'http://uri.etsi.org/02231/v2#';

/**
 * Private — NOT exported from the package root. Parses a verified LOTL
 * XML `Document` into the normalized `LotlSnapshot` used by the rest of
 * the module. Does not fetch; does not verify signatures (that is the
 * `LotlFetcher`'s job). Pure XML-to-value conversion.
 */
export class LotlParser {
    parse(doc: XmlDocument): LotlSnapshot {
        const root = doc.documentElement!;
        const scheme = firstChild(root, TSL_NS, 'SchemeInformation');
        if (!scheme) {
            throw new Error(
                'LOTL XML: missing SchemeInformation element'
            );
        }
        const issueDateText = textOf(scheme, TSL_NS, 'ListIssueDateTime');
        if (!issueDateText) {
            throw new Error(
                'LOTL XML: missing ListIssueDateTime element'
            );
        }
        const issueDate = new Date(issueDateText);
        if (isNaN(issueDate.getTime())) {
            throw new Error(
                `LOTL XML: invalid ListIssueDateTime "${issueDateText}"`
            );
        }
        const nextUpdate = parseNextUpdate(scheme);
        const pointersContainer = firstChild(
            scheme,
            TSL_NS,
            'PointersToOtherTSL'
        );
        const pointers: OtherTslPointer[] = [];
        if (pointersContainer) {
            const items = pointersContainer.getElementsByTagNameNS(
                TSL_NS,
                'OtherTSLPointer'
            );
            for (let i = 0; i < items.length; i++) {
                const p = parsePointer(items.item(i)!);
                if (p) pointers.push(p);
            }
        }
        return { issueDate, nextUpdate, pointers };
    }
}

function parseNextUpdate(scheme: XmlElement): Date | null {
    const nu = firstChild(scheme, TSL_NS, 'NextUpdate');
    if (!nu) return null;
    const dt = textOf(nu, TSL_NS, 'dateTime');
    if (!dt) return null;
    const d = new Date(dt);
    return isNaN(d.getTime()) ? null : d;
}

function parsePointer(el: XmlElement): OtherTslPointer | null {
    const tslLocation = textOf(el, TSL_NS, 'TSLLocation');
    if (!tslLocation) return null;
    // SchemeTerritory can be nested under AdditionalInformation/OtherInformation.
    const territory =
        textOfDeep(el, TSL_NS, 'SchemeTerritory') ?? 'XX';
    const certs: X509Certificate[] = [];
    const certEls = el.getElementsByTagNameNS(TSL_NS, 'X509Certificate');
    for (let i = 0; i < certEls.length; i++) {
        const cert = base64DerToCert(certEls.item(i)!.textContent ?? '');
        if (cert) certs.push(cert);
    }
    return {
        country: territory,
        tslLocation,
        signingCertificates: certs,
    };
}

function base64DerToCert(base64: string): X509Certificate | null {
    const cleaned = base64.replace(/\s+/g, '');
    if (!cleaned) return null;
    try {
        const der = base64ToBytes(cleaned);
        return new X509Certificate(der as Uint8Array<ArrayBuffer>);
    } catch {
        return null;
    }
}

function base64ToBytes(b64: string): Uint8Array {
    const bin = (globalThis as { atob: (s: string) => string }).atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function firstChild(parent: XmlElement, ns: string, name: string): XmlElement | null {
    const list = parent.getElementsByTagNameNS(ns, name);
    return list.length > 0 ? (list.item(0) as XmlElement) : null;
}

function textOf(parent: XmlElement, ns: string, name: string): string | null {
    const el = firstChild(parent, ns, name);
    return el?.textContent?.trim() ?? null;
}

// Walks descendants — used for elements that may be nested under variable
// parent chains (e.g., SchemeTerritory is sometimes directly under the
// pointer, sometimes under AdditionalInformation/OtherInformation).
function textOfDeep(
    parent: XmlElement,
    ns: string,
    name: string
): string | null {
    const list = parent.getElementsByTagNameNS(ns, name);
    return list.length > 0
        ? list.item(0)!.textContent?.trim() ?? null
        : null;
}
