import { X509Certificate } from '@peculiar/x509';
import type { Document as XmlDocument, Element as XmlElement } from '@xmldom/xmldom';
import type { LotlSnapshot, OtherTslPointer } from './lotl-types.js';
import { base64DerToCert, firstChild, textOfDeep } from './xml-util.js';

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
        const issueDateText = textOfDeep(scheme, TSL_NS, 'ListIssueDateTime');
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
    const dt = textOfDeep(nu, TSL_NS, 'dateTime');
    if (!dt) return null;
    const d = new Date(dt);
    return isNaN(d.getTime()) ? null : d;
}

function parsePointer(el: XmlElement): OtherTslPointer | null {
    const tslLocation = textOfDeep(el, TSL_NS, 'TSLLocation');
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
