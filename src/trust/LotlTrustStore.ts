import { X509Certificate } from '@peculiar/x509';
import type { Cache } from './Cache.js';
import type { Fetcher } from './Fetcher.js';
import { EU_LOTL_SIGNING_ANCHORS } from './lotl-signing-anchors.js';
import type {
    LotlSnapshot,
    NationalTlSnapshot,
    TspService,
} from './lotl-types.js';
import { LotlFetcher } from './LotlFetcher.js';
import { LotlParser } from './LotlParser.js';
import { NationalTlResolver } from './NationalTlResolver.js';
import type { LotlAnchorMetadata, TrustAnchor } from './TrustAnchor.js';
import type { TrustStore, TrustStoreHint } from './TrustStore.js';
import { deriveServiceMetadata } from './service-metadata.js';
import { getSkiBytes, getSkiHex } from './x509-utils.js';

const DEFAULT_LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';
const DEFAULT_REFRESH_INTERVAL_MS = 24 * 3600 * 1000;

export interface LotlTrustStoreOptions {
    /** Override the bundled signing anchors. Empty is rejected. */
    signingAnchors?: readonly X509Certificate[];
    fetcher?: Fetcher;
    cache?: Cache;
    /** ms between snapshot refreshes. Default: 24h. */
    refreshInterval?: number;
    /** Override the LOTL URL. Defaults to the EC production URL. */
    lotlUrl?: string;
}

interface Snapshot {
    readonly lotl: LotlSnapshot;
    readonly nationalTls: readonly NationalTlSnapshot[];
    readonly fetchedAt: number;
}

/**
 * Public TrustStore backed by the EU LOTL + national TLs. Loads lazily on
 * the first `getAnchors()` call; subsequent calls within `refreshInterval`
 * hit the in-memory snapshot. Graceful degradation: refresh failures serve
 * the prior snapshot with a `console.warn`. Single-flight: concurrent
 * refreshes share one in-flight promise.
 */
export class LotlTrustStore implements TrustStore {
    private readonly fetcher: LotlFetcher;
    private readonly resolver: NationalTlResolver;
    private readonly signingAnchors: readonly X509Certificate[];
    private readonly refreshInterval: number;
    private readonly lotlUrl: string;
    private readonly cache: Cache | undefined;
    private snapshot: Snapshot | null = null;
    private inFlight: Promise<Snapshot> | null = null;

    constructor(opts: LotlTrustStoreOptions = {}) {
        const anchors =
            opts.signingAnchors && opts.signingAnchors.length > 0
                ? opts.signingAnchors
                : EU_LOTL_SIGNING_ANCHORS;
        if (anchors.length === 0) {
            throw new Error(
                'LotlTrustStore: no signing anchors available — supply signingAnchors or populate EU_LOTL_SIGNING_ANCHORS'
            );
        }
        this.signingAnchors = anchors;
        this.fetcher = new LotlFetcher({ fetcher: opts.fetcher });
        this.resolver = new NationalTlResolver({ fetcher: this.fetcher });
        this.refreshInterval =
            opts.refreshInterval ?? DEFAULT_REFRESH_INTERVAL_MS;
        this.lotlUrl = opts.lotlUrl ?? DEFAULT_LOTL_URL;
        this.cache = opts.cache;
    }

    async getAnchors(hint: TrustStoreHint): Promise<TrustAnchor[]> {
        const snap = await this.getSnapshot();
        const out: TrustAnchor[] = [];
        for (const tl of snap.nationalTls) {
            for (const service of tl.services) {
                for (const cert of service.certificates) {
                    if (!matchesHint(cert, hint)) continue;
                    out.push(buildAnchor(service, cert));
                }
            }
        }
        return out;
    }

    /**
     * Internal accessor — used by `TrustEvaluator` for `ProvenanceResolver`.
     * Not part of the public `TrustStore` contract.
     */
    async getNationalTls(): Promise<readonly NationalTlSnapshot[]> {
        const snap = await this.getSnapshot();
        return snap.nationalTls;
    }

    private async getSnapshot(): Promise<Snapshot> {
        const now = Date.now();
        if (
            this.snapshot &&
            now - this.snapshot.fetchedAt < this.refreshInterval
        ) {
            return this.snapshot;
        }
        return this.refresh();
    }

    private async refresh(): Promise<Snapshot> {
        if (this.inFlight) return this.inFlight;
        this.inFlight = (async () => {
            try {
                const doc = await this.fetcher.fetchSigned(
                    this.lotlUrl,
                    this.signingAnchors
                );
                const lotl = new LotlParser().parse(doc);
                const nationalTls = await this.resolver.resolve(lotl);
                this.snapshot = {
                    lotl,
                    nationalTls,
                    fetchedAt: Date.now(),
                };
                return this.snapshot;
            } catch (err) {
                if (this.snapshot) {
                    console.warn(
                        `[openid4vp] LOTL refresh failed; serving cached snapshot (${(err as Error).message})`
                    );
                    return this.snapshot;
                }
                throw err;
            } finally {
                this.inFlight = null;
            }
        })();
        return this.inFlight;
    }
}

function matchesHint(cert: X509Certificate, hint: TrustStoreHint): boolean {
    if (hint.aki) {
        const ski = getSkiBytes(cert);
        if (ski && equalBytes(ski, hint.aki)) return true;
    }
    if (hint.issuer && cert.subject === hint.issuer) return true;
    return false;
}

function buildAnchor(service: TspService, cert: X509Certificate): TrustAnchor {
    const derived = deriveServiceMetadata(service);
    const metadata: LotlAnchorMetadata = {
        country: service.country,
        serviceName: service.serviceName,
        serviceTypeIdentifier: service.serviceTypeIdentifier,
        serviceStatus: service.serviceStatus,
        ...derived,
    };
    const ski = getSkiHex(cert);
    return {
        certificate: cert,
        source: 'lotl',
        metadata,
        trustedAuthorityIds: ski ? [ski] : [],
    };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}
