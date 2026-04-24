import { X509Certificate } from '@peculiar/x509';
import type { TrustAnchor } from './TrustAnchor.js';
import type { NationalTlSnapshot } from './lotl-types.js';
import { getSkiHex } from './x509-utils.js';

/**
 * Resolves trust anchors for a given leaf credential. The library calls
 * `getAnchors()` once per verification after extracting the leaf's issuer
 * hints (DN, Authority Key Identifier, JWT/COSE key ID).
 *
 * Implementations MUST be safe to call concurrently. Stores that cannot
 * satisfy the hint MUST return `[]`, not throw.
 */
export interface TrustStore {
    getAnchors(hint: TrustStoreHint): Promise<TrustAnchor[]>;
}

export interface TrustStoreHint {
    /** Leaf cert's Issuer DN (RFC 4514 string). */
    issuer?: string;
    /** Leaf cert's Authority Key Identifier extension bytes. */
    aki?: Uint8Array;
    /** JWT/COSE key ID, used by LOTL-backed stores. */
    kid?: string;
}

export type TrustStoreInput = X509Certificate | Uint8Array | string;

/**
 * Trust store backed by a fixed list of certificates supplied at construction
 * time. No I/O, no refresh. Suitable for development, testing, and consumers
 * with a static issuer allowlist.
 */
export class StaticTrustStore implements TrustStore {
    private readonly anchors: TrustAnchor[] = [];
    private readonly skiIndex: Map<string, TrustAnchor[]> = new Map();
    private readonly subjectIndex: Map<string, TrustAnchor[]> = new Map();

    constructor(certs: Iterable<TrustStoreInput>) {
        for (const input of certs) {
            const cert = toCertificate(input);
            const anchor: TrustAnchor = { certificate: cert, source: 'static' };
            this.anchors.push(anchor);
            pushInto(this.subjectIndex, cert.subject, anchor);
            const ski = getSkiHex(cert);
            if (ski) pushInto(this.skiIndex, ski, anchor);
        }
    }

    async getAnchors(hint: TrustStoreHint): Promise<TrustAnchor[]> {
        const results: TrustAnchor[] = [];
        if (hint.aki) {
            const key = bytesToHex(hint.aki);
            const matches = this.skiIndex.get(key);
            if (matches) results.push(...matches);
        }
        if (hint.issuer) {
            const matches = this.subjectIndex.get(hint.issuer);
            if (matches) {
                for (const m of matches) {
                    if (!results.includes(m)) results.push(m);
                }
            }
        }
        return results;
    }
}

/**
 * Combines multiple `TrustStore` instances. Children are queried in parallel;
 * results concatenate in child-order; duplicate anchors are dropped by
 * Subject Key Identifier.
 */
export class CompositeTrustStore implements TrustStore {
    constructor(private readonly stores: TrustStore[]) {}

    async getAnchors(hint: TrustStoreHint): Promise<TrustAnchor[]> {
        const results = await Promise.all(
            this.stores.map((store) => store.getAnchors(hint))
        );
        const seen = new Set<string>();
        const out: TrustAnchor[] = [];
        for (const batch of results) {
            for (const anchor of batch) {
                const ski = getSkiHex(anchor.certificate);
                const key = ski ?? anchor.certificate.serialNumber;
                if (seen.has(key)) continue;
                seen.add(key);
                out.push(anchor);
            }
        }
        return out;
    }

    async getNationalTls(): Promise<readonly NationalTlSnapshot[]> {
        for (const store of this.stores) {
            const s = store as TrustStore & {
                getNationalTls?: () => Promise<readonly NationalTlSnapshot[]>;
            };
            if (typeof s.getNationalTls === 'function') {
                return s.getNationalTls();
            }
        }
        return [];
    }
}

function toCertificate(input: TrustStoreInput): X509Certificate {
    if (input instanceof X509Certificate) return input;
    if (input instanceof Uint8Array) return new X509Certificate(input as Uint8Array<ArrayBuffer>);
    return new X509Certificate(input); // PEM string path
}

function pushInto<K>(map: Map<K, TrustAnchor[]>, key: K, anchor: TrustAnchor): void {
    const list = map.get(key);
    if (list) list.push(anchor);
    else map.set(key, [anchor]);
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
