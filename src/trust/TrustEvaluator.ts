import {
    AuthorityKeyIdentifierExtension,
    X509Certificate,
} from '@peculiar/x509';
import { TrustAnchorNotFoundError } from '../errors.js';
import type { Cache } from './Cache.js';
import { ChainBuilder, type ChainBuilderOptions } from './ChainBuilder.js';
import type { Fetcher } from './Fetcher.js';
import type { TrustAnchor } from './TrustAnchor.js';
import type { TrustStore } from './TrustStore.js';

export type RevocationPolicy = 'skip' | 'prefer' | 'require';

export interface TrustEvaluatorOptions extends ChainBuilderOptions {
    trustStore: TrustStore;
    revocationPolicy?: RevocationPolicy;
    fetcher?: Fetcher;
    cache?: Cache;
}

export interface EvaluateContext {
    intermediates?: X509Certificate[];
}

export interface TrustEvaluationResult {
    chain: X509Certificate[];
    anchor: TrustAnchor;
    revocationStatus: 'good' | 'revoked' | 'unknown' | 'skipped';
    revocationCheckedAt?: Date;
    revokedAt?: Date;
    revocationReason?: string;
    provenance?: {
        loa?: 'substantial' | 'high';
        qualified?: boolean;
        country?: string;
        serviceName?: string;
    };
}

/**
 * Private internal coordinator — NOT exported from the package root.
 * Orchestrates `TrustStore` + `ChainBuilder` (+ `RevocationChecker` in A.2
 * + `ProvenanceResolver` in A.3). Signature is stable across A.1/A.2/A.3
 * so parsers don't need to change when later workstreams land.
 */
export class TrustEvaluator {
    private readonly trustStore: TrustStore;
    private readonly chainBuilder: ChainBuilder;

    constructor(private readonly opts: TrustEvaluatorOptions) {
        this.trustStore = opts.trustStore;
        this.chainBuilder = new ChainBuilder(opts);
        const policy = opts.revocationPolicy ?? 'skip';
        if (policy !== 'skip') {
            throw new Error(
                `revocationPolicy='${policy}' is not implemented yet — ships in 0.5.0 A.2`
            );
        }
    }

    async evaluate(
        leaf: X509Certificate,
        context: EvaluateContext = {}
    ): Promise<TrustEvaluationResult> {
        const hint = deriveHint(leaf);
        const seen = new Set<string>();
        const anchors: TrustAnchor[] = [];
        const pushUnique = (batch: TrustAnchor[]) => {
            for (const a of batch) {
                const key = a.certificate.serialNumber;
                if (seen.has(key)) continue;
                seen.add(key);
                anchors.push(a);
            }
        };
        pushUnique(await this.trustStore.getAnchors(hint));
        // When the leaf points to an intermediate (not a root in the store),
        // the direct leaf hint won't resolve. Ask the store about each
        // supplied intermediate too so a chain can close through them.
        for (const inter of context.intermediates ?? []) {
            pushUnique(await this.trustStore.getAnchors(deriveHint(inter)));
        }
        if (anchors.length === 0) {
            throw new TrustAnchorNotFoundError(
                `no trust anchor for issuer=${hint.issuer ?? '(none)'}`
            );
        }
        const anchorCerts = anchors.map((a) => a.certificate);
        const chain = await this.chainBuilder.build(
            leaf,
            anchorCerts,
            context.intermediates ?? []
        );
        const terminusCert = chain[chain.length - 1];
        const anchor =
            anchors.find(
                (a) => a.certificate.serialNumber === terminusCert.serialNumber
            ) ?? anchors[0];
        return {
            chain,
            anchor,
            revocationStatus: 'skipped',
        };
    }
}

function deriveHint(leaf: X509Certificate) {
    const aki = leaf.getExtension(AuthorityKeyIdentifierExtension);
    const keyIdHex = aki?.keyId;
    const akiBytes = keyIdHex ? hexToBytes(keyIdHex) : undefined;
    return {
        issuer: leaf.issuer,
        aki: akiBytes,
    };
}

function hexToBytes(s: string): Uint8Array {
    const clean = s.replace(/[^0-9a-f]/gi, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
