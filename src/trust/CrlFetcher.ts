import { AsnConvert } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';
import { X509Certificate } from '@peculiar/x509';
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

    /**
     * Verify the CRL signature against the issuer CA's public key.
     * RFC 5280 §5.1.1.3: signature is computed over the DER encoding of
     * `tbsCertList`. We prefer `tbsCertListRaw` when `@peculiar/asn1-schema`
     * exposes it (avoids a re-serialization roundtrip); fall back to
     * `AsnConvert.serialize(tbsCertList)` otherwise.
     *
     * ECDSA signatures in `CertificateList.signature` are DER-encoded
     * SEQUENCE { r, s } — WebCrypto `verify()` expects IEEE P1363 (r||s
     * fixed-width), so we convert first.
     */
    async verifyCrl(parsed: ParsedCrl, issuer: X509Certificate): Promise<void> {
        const tbsDer = parsed.raw.tbsCertListRaw
            ? new Uint8Array(parsed.raw.tbsCertListRaw)
            : new Uint8Array(AsnConvert.serialize(parsed.raw.tbsCertList));
        const sigDer = new Uint8Array(parsed.raw.signature);
        const sigIeee = ecdsaDerToIeee(sigDer, 32); // 32 bytes per coord for P-256

        // Re-import the issuer's public key via Node's global SubtleCrypto from
        // raw SPKI bytes. The `@peculiar/x509`-exported CryptoKey may belong to
        // a non-global provider (e.g. `@peculiar/webcrypto` in tests), and
        // Node's global `crypto.subtle.verify` rejects foreign-provider keys
        // with "2nd argument is not of type CryptoKey". Importing from SPKI
        // produces a key owned by the global provider — production-correct
        // and works under test.
        const spki = new Uint8Array(issuer.publicKey.rawData);
        const publicKey = await crypto.subtle.importKey(
            'spki',
            spki,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['verify']
        );
        const ok = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            publicKey,
            sigIeee,
            tbsDer
        );
        if (!ok) {
            throw new Error(
                `CRL signature verification failed against issuer ${issuer.subject}`
            );
        }
    }
}

/**
 * Convert ECDSA DER-encoded SEQUENCE { r, s } signature to IEEE P1363
 * r||s fixed-width (as WebCrypto verify() expects). Inlined here to keep
 * Task 7 focused; Task 14 extracts this + its sibling to `src/trust/ecdsa-util.ts`.
 */
function ecdsaDerToIeee(der: Uint8Array, coordBytes: number): Uint8Array {
    let pos = 0;
    if (der[pos++] !== 0x30) throw new Error('invalid DER signature: expected SEQUENCE');
    pos++; // skip seq-length
    if (der[pos++] !== 0x02) throw new Error('invalid DER signature: expected INTEGER r');
    const rLen = der[pos++];
    let r = der.slice(pos, pos + rLen);
    pos += rLen;
    if (der[pos++] !== 0x02) throw new Error('invalid DER signature: expected INTEGER s');
    const sLen = der[pos++];
    let s = der.slice(pos, pos + sLen);
    if (r.length > coordBytes) r = r.slice(r.length - coordBytes); // strip leading 0x00 sign byte
    if (s.length > coordBytes) s = s.slice(s.length - coordBytes);
    const out = new Uint8Array(coordBytes * 2);
    out.set(r, coordBytes - r.length);
    out.set(s, coordBytes * 2 - s.length);
    return out;
}
