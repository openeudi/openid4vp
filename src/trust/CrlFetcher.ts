import { AsnConvert } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';
import type { Fetcher } from './Fetcher.js';

export interface CrlFetcherOptions {
    fetcher?: Fetcher;
}

export interface ParsedCrl {
    thisUpdate: Date;
    nextUpdate: Date;
    /** Uppercase hex serials from the CRL's revokedCertificates list. */
    revokedSerialsHex: string[];
    /**
     * Original DER bytes — retained so the caller can verify the CRL
     * signature against the issuer's public key without re-serializing.
     */
    der: Uint8Array;
    /** Parsed asn1 CertificateList for signature verification. */
    raw: CertificateList;
}

/**
 * Private — NOT exported from the package root. Fetches a CRL from an
 * HTTP(S) URL via the injected `Fetcher`, parses `CertificateList`,
 * and returns normalized metadata. Signature verification happens in
 * Task 7 via `verifyCrl(parsed, issuerCert)` — kept separate so tests
 * can drive parsing and signature concerns independently.
 */
export class CrlFetcher {
    private readonly fetcher: Fetcher;

    constructor(opts: CrlFetcherOptions = {}) {
        this.fetcher = opts.fetcher ?? globalThis.fetch.bind(globalThis);
    }

    async fetchAndParse(url: string): Promise<ParsedCrl> {
        const response = await this.fetcher(url, { method: 'GET' });
        if (!response.ok) {
            throw new Error(`CRL fetch failed: HTTP ${response.status} for ${url}`);
        }
        const der = new Uint8Array(await response.arrayBuffer());
        const parsed = AsnConvert.parse(der, CertificateList);

        const thisUpdate = parsed.tbsCertList.thisUpdate.getTime();
        const nextUpdate = parsed.tbsCertList.nextUpdate?.getTime();
        if (!nextUpdate) {
            throw new Error(`CRL missing nextUpdate — unsupported (RFC 5280 §5.1.2.5)`);
        }

        const revokedSerialsHex =
            parsed.tbsCertList.revokedCertificates?.map((r) =>
                Buffer.from(r.userCertificate).toString('hex').toUpperCase().replace(/^0+/, '')
            ) ?? [];

        return {
            thisUpdate,
            nextUpdate,
            revokedSerialsHex,
            der,
            raw: parsed,
        };
    }
}
