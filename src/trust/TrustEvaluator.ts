import {
    AuthorityKeyIdentifierExtension,
    X509Certificate,
} from '@peculiar/x509';
import {
    MalformedCredentialError,
    RevokedCertificateError,
    TrustAnchorNotFoundError,
} from '../errors.js';
import type { Cache } from './Cache.js';
import { ChainBuilder, type ChainBuilderOptions } from './ChainBuilder.js';
import type { Fetcher } from './Fetcher.js';
import { RevocationChecker } from './RevocationChecker.js';
import type { TrustAnchor } from './TrustAnchor.js';
import type { TrustStore } from './TrustStore.js';
import type { NationalTlSnapshot } from './lotl-types.js';
import { certificatesEqual, getSkiHex } from './x509-utils.js';

export type RevocationPolicy = 'skip' | 'prefer' | 'require';

export interface TrustEvaluatorOptions extends ChainBuilderOptions {
    trustStore: TrustStore;
    revocationPolicy?: RevocationPolicy;
    fetcher?: Fetcher;
    cache?: Cache;
}

export interface EvaluateContext {
    /** Additional, untrusted certificates (e.g. `x5c[1..]`) used only as path candidates. */
    intermediates?: X509Certificate[];
    /** Credential signing time; the chain must also have been valid then. */
    issuedAt?: Date;
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
        const anchors: TrustAnchor[] = [];
        // De-duplicate by DER identity. serialNumber is only unique per issuer,
        // so keying on it could silently drop a distinct anchor from another CA.
        const pushUnique = (batch: TrustAnchor[]) => {
            for (const a of batch) {
                if (anchors.some((x) => certificatesEqual(x.certificate, a.certificate))) continue;
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
        // Direct match: the signer certificate may itself be the listed anchor
        // (a trusted list that publishes the document signer rather than its
        // root). Ask the store about the leaf's own identity; `ChainBuilder`
        // accepts such a candidate only if it is byte-identical to the leaf.
        pushUnique(await this.trustStore.getAnchors(deriveSelfHint(leaf)));
        if (anchors.length === 0) {
            throw new TrustAnchorNotFoundError(
                `no trust anchor for issuer=${hint.issuer ?? '(none)'}`
            );
        }
        const anchorCerts = anchors.map((a) => a.certificate);
        const chain = await this.chainBuilder.build(
            leaf,
            anchorCerts,
            context.intermediates ?? [],
            { issuedAt: context.issuedAt }
        );
        const terminusCert = chain[chain.length - 1];
        // Select the anchor the chain actually closed at by DER byte-identity —
        // NOT by serialNumber (collidable across CAs) and NOT by a silent
        // fallback to anchors[0], which would attribute a chain to an anchor it
        // did not terminate at. `ChainBuilder` guarantees the terminus is one of
        // `anchorCerts`, so a miss here is a broken invariant, not a valid input.
        const anchor = anchors.find((a) =>
            certificatesEqual(a.certificate, terminusCert)
        );
        if (!anchor) {
            throw new TrustAnchorNotFoundError(
                `chain terminus ${terminusCert.subject} does not match any trust anchor certificate`
            );
        }

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

function deriveSelfHint(cert: X509Certificate) {
    const skiHex = getSkiHex(cert);
    return {
        issuer: cert.subject,
        aki: skiHex ? hexToBytes(skiHex) : undefined,
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
    try {
        const tls = await withTls.getNationalTls();
        const { ProvenanceResolver } = await import('./ProvenanceResolver.js');
        const resolved = new ProvenanceResolver().resolve(anchor.certificate, tls);
        return resolved?.provenance;
    } catch (err) {
        console.warn(
            `[openid4vp] provenance lookup failed for ${anchor.certificate.subject} — ${(err as Error).message}`
        );
        return undefined;
    }
}

export interface CredentialIssuerTrustInput extends Omit<TrustEvaluatorOptions, 'now'> {
    /** DER certificates exactly as carried by the credential (`x5c` / `x5chain`), signer first. */
    chain: readonly Uint8Array[];
    issuedAt?: Date;
}

/**
 * Parser entry point: evaluate the signer certificate of a credential against
 * the trust store, using the rest of the credential's certificate list as
 * untrusted path candidates. Certificates supplied by the credential are never
 * treated as anchors.
 */
export async function evaluateCredentialIssuer(
    input: CredentialIssuerTrustInput
): Promise<TrustEvaluationResult> {
    const [signerDer, ...rest] = input.chain;
    if (!signerDer) {
        throw new MalformedCredentialError('Missing issuer certificate');
    }
    const parse = (bytes: Uint8Array, position: number): X509Certificate => {
        try {
            return new X509Certificate(bytes as Uint8Array<ArrayBuffer>);
        } catch (err) {
            throw new MalformedCredentialError(
                `Invalid certificate at x5c/x5chain position ${position}: ${(err as Error).message}`
            );
        }
    };
    const leaf = parse(signerDer, 0);
    const intermediates = rest.map((bytes, i) => parse(bytes, i + 1));
    const { chain, issuedAt, ...evaluatorOptions } = input;
    void chain;
    return new TrustEvaluator(evaluatorOptions).evaluate(leaf, { intermediates, issuedAt });
}
