import { X509Certificate } from '@peculiar/x509';
import type { Element as XmlElement } from '@xmldom/xmldom';

/**
 * Returns the first element with the given namespace + local name that is a
 * descendant of `parent` (including direct children).
 * Equivalent to getElementsByTagNameNS(ns, name).item(0).
 */
export function firstChild(
    parent: XmlElement,
    ns: string,
    name: string
): XmlElement | null {
    const list = parent.getElementsByTagNameNS(ns, name);
    return list.length > 0 ? (list.item(0) as XmlElement) : null;
}

/**
 * Returns the trimmed text content of the first element with the given
 * namespace + local name anywhere under `parent`, or null if not found.
 * Works for both direct children and deeper descendants.
 */
export function textOfDeep(
    parent: XmlElement,
    ns: string,
    name: string
): string | null {
    const list = parent.getElementsByTagNameNS(ns, name);
    return list.length > 0
        ? list.item(0)!.textContent?.trim() ?? null
        : null;
}

/**
 * Parse a base64-encoded DER certificate. Returns null on any parse failure.
 */
export function base64DerToCert(base64: string): X509Certificate | null {
    const cleaned = base64.replace(/\s+/g, '');
    if (!cleaned) return null;
    try {
        const bin = (globalThis as { atob: (s: string) => string }).atob(cleaned);
        const der = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
        return new X509Certificate(der as Uint8Array<ArrayBuffer>);
    } catch {
        return null;
    }
}
