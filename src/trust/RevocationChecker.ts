import {
    AuthorityInfoAccessSyntax,
    CRLDistributionPoints,
} from '@peculiar/asn1-x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { X509Certificate } from '@peculiar/x509';
import { RevocationCheckFailedError } from '../errors.js';
import type { Cache } from './Cache.js';
import { CrlFetcher } from './CrlFetcher.js';
import type { Fetcher } from './Fetcher.js';
import { OcspClient } from './OcspClient.js';
import type { RevocationResult } from './revocation-types.js';

export type RevocationPolicy = 'skip' | 'prefer' | 'require';

export interface RevocationCheckerOptions {
    policy: RevocationPolicy;
    fetcher?: Fetcher;
    cache?: Cache;
}

/**
 * Private — NOT exported from the package root. Coordinates OCSP + CRL
 * revocation checking per spec §7. Used only by `TrustEvaluator`.
 */
export class RevocationChecker {
    private readonly policy: RevocationPolicy;
    private readonly ocsp: OcspClient;
    private readonly crl: CrlFetcher;

    constructor(opts: RevocationCheckerOptions) {
        this.policy = opts.policy;
        this.ocsp = new OcspClient({ fetcher: opts.fetcher, cache: opts.cache });
        this.crl = new CrlFetcher({ fetcher: opts.fetcher, cache: opts.cache });
    }

    async check(
        subjectCert: X509Certificate,
        issuerCert: X509Certificate,
        now: Date = new Date()
    ): Promise<RevocationResult> {
        if (this.policy === 'skip') {
            return { status: 'good', source: 'none', checkedAt: now };
        }

        const hints = this.extractUrls(subjectCert);

        if (!hints.ocspUrl && hints.crlUrls.length === 0) {
            if (this.policy === 'require') {
                throw new RevocationCheckFailedError(
                    `no revocation sources declared on ${subjectCert.subject}`
                );
            }
            return { status: 'unknown', source: 'none', checkedAt: now };
        }

        // OCSP first.
        if (hints.ocspUrl) {
            try {
                return await this.ocsp.checkCached(subjectCert, issuerCert, hints.ocspUrl, now);
            } catch {
                // fall through to CRL
            }
        }

        // CRL fallback.
        for (const url of hints.crlUrls) {
            try {
                const parsed = await this.crl.fetchAndParseCached(url, now);
                await this.crl.verifyCrl(parsed, issuerCert);
                if (this.crl.isStale(parsed, now)) {
                    if (this.policy === 'require') {
                        throw new RevocationCheckFailedError(
                            `CRL from ${url} is stale (nextUpdate=${parsed.nextUpdate.toISOString()})`
                        );
                    }
                    continue;
                }
                const outcome = this.crl.isRevoked(parsed, subjectCert.serialNumber);
                if (outcome.status === 'revoked') {
                    return {
                        status: 'revoked',
                        source: 'crl',
                        revokedAt: outcome.revokedAt,
                        revocationReason: outcome.revocationReason,
                        checkedAt: now,
                    };
                }
                return { status: 'good', source: 'crl', checkedAt: now };
            } catch (err) {
                if (err instanceof RevocationCheckFailedError) throw err;
                continue;
            }
        }

        // All sources failed.
        if (this.policy === 'require') {
            throw new RevocationCheckFailedError(
                `all revocation sources failed for ${subjectCert.subject}`
            );
        }
        return { status: 'unknown', source: 'none', checkedAt: now };
    }

    private extractUrls(cert: X509Certificate): { ocspUrl?: string; crlUrls: string[] } {
        const ocspUrl = extractOcspUrl(cert);
        const crlUrls = extractCrlUrls(cert);
        return { ocspUrl, crlUrls };
    }
}

function extractOcspUrl(cert: X509Certificate): string | undefined {
    const ext = cert.extensions.find((e) => e.type === '1.3.6.1.5.5.7.1.1');
    if (!ext) return undefined;
    try {
        const aia = AsnConvert.parse(new Uint8Array(ext.value), AuthorityInfoAccessSyntax);
        for (const desc of aia) {
            if (desc.accessMethod === '1.3.6.1.5.5.7.48.1') {
                const uri = desc.accessLocation.uniformResourceIdentifier;
                if (uri) return uri;
            }
        }
    } catch {
        return undefined;
    }
    return undefined;
}

function extractCrlUrls(cert: X509Certificate): string[] {
    const ext = cert.extensions.find((e) => e.type === '2.5.29.31');
    if (!ext) return [];
    try {
        const cdp = AsnConvert.parse(new Uint8Array(ext.value), CRLDistributionPoints);
        const out: string[] = [];
        for (const dp of cdp) {
            const fullName = dp.distributionPoint?.fullName;
            if (!fullName) continue;
            for (const gn of fullName) {
                if (gn.uniformResourceIdentifier) out.push(gn.uniformResourceIdentifier);
            }
        }
        return out;
    } catch {
        return [];
    }
}
