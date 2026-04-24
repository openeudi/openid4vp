import {
    AuthorityKeyIdentifierExtension,
    X509Certificate,
} from '@peculiar/x509';
import { RevokedCertificateError, TrustAnchorNotFoundError } from '../errors.js';
import type { Cache } from './Cache.js';
import { ChainBuilder, type ChainBuilderOptions } from './ChainBuilder.js';
import type { Fetcher } from './Fetcher.js';
import { RevocationChecker } from './RevocationChecker.js';
import type { TrustAnchor } from './TrustAnchor.js';
import type { TrustStore } from './TrustStore.js';
import type { NationalTlSnapshot } from './lotl-types.js';
import { getSkiHex } from './x509-utils.js';

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
    trustedAuthorityIds?: readonly string[];
    provenance?: {
        loa?: 'substantial' | 'high';
        qualified?: boolean;
        country?: string;
        serviceName?: string;
    };
}

/**
 * Private internal coordinator — NOT exported from the package root.
 * Orchestrates `TrustStore` + `ChainBuilder` + `RevocationChecker` (A.2)
 * (+ `ProvenanceResolver` in A.3). Signature is stable across A.1/A.2/A.3
 * so parsers don't need to change when later workstreams land.
 */
export class TrustEvaluator {
    private readonly trustStore: TrustStore;
    private readonly chainBuilder: ChainBuilder;
    private readonly revocationChecker: RevocationChecker;

    constructor(private readonly opts: TrustEvaluatorOptions) {
        this.trustStore = opts.trustStore;
        this.chainBuilder = new ChainBuilder(opts);
        const policy = opts.revocationPolicy ?? 'skip';
        // A.2: policy='prefer'/'require' now supported.
        this.revocationChecker = new RevocationChecker({
            policy,
            fetcher: opts.fetcher,
            cache: opts.cache,
        });
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

        // Revocation check — runs against the leaf (chain[0]) with the
        // leaf's direct issuer (chain[1]) as the signing CA.
        const issuerForRevocation = chain.length > 1 ? chain[1] : terminusCert;
        const revocation = await this.revocationChecker.check(
            leaf,
            issuerForRevocation
        );

        if (revocation.status === 'revoked') {
            throw new RevokedCertificateError(
                `certificate ${leaf.subject} is revoked`,
                {
                    serial: leaf.serialNumber,
                    revokedAt: revocation.revokedAt!,
                    reason: revocation.revocationReason,
                }
            );
        }

        const trustedAuthorityIds = deriveAuthorityIds(anchor);
        const provenance = await resolveProvenance(this.trustStore, anchor);

        return {
            chain,
            anchor,
            // skip-policy yields source='none'/status='good' — keep the A.1
            // 'skipped' contract. Otherwise surface 'good' | 'unknown' as-is.
            revocationStatus:
                revocation.source === 'none' && revocation.status === 'good'
                    ? 'skipped'
                    : revocation.status,
            revocationCheckedAt: revocation.checkedAt,
            trustedAuthorityIds,
            ...(provenance ? { provenance } : {}),
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

function deriveAuthorityIds(anchor: TrustAnchor): readonly string[] {
    if (anchor.trustedAuthorityIds && anchor.trustedAuthorityIds.length > 0) {
        return anchor.trustedAuthorityIds;
    }
    // Static-store fallback: synthesize from the anchor's SKI.
    const ski = getSkiHex(anchor.certificate);
    return ski ? [ski] : [];
}

async function resolveProvenance(
    store: TrustStore,
    anchor: TrustAnchor
): Promise<TrustEvaluationResult['provenance']> {
    if (anchor.source !== 'lotl') return undefined;
    const withTls = store as TrustStore & {
        getNationalTls?: () => Promise<readonly NationalTlSnapshot[]>;
    };
    if (typeof withTls.getNationalTls !== 'function') return undefined;
    const tls = await withTls.getNationalTls();
    const { ProvenanceResolver } = await import('./ProvenanceResolver.js');
    const resolved = new ProvenanceResolver().resolve(anchor.certificate, tls);
    return resolved?.provenance;
}
