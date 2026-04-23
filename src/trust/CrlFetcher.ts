import { AsnConvert } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';
import { X509Certificate } from '@peculiar/x509';
import type { Cache } from './Cache.js';
import type { Fetcher } from './Fetcher.js';

export interface CrlFetcherOptions {
    fetcher?: Fetcher;
    cache?: Cache;
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
 * Outcome of a serial-number lookup against a parsed CRL. Kept decoupled
 * from `RevocationResult` so `CrlFetcher` stays a pure sub-component;
 * `RevocationChecker` (Task 17) maps this into the public `RevocationResult`.
 */
export type CrlRevokedOutcome =
    | { status: 'good' }
    | { status: 'revoked'; revokedAt: Date; revocationReason?: string };

/**
 * Private — NOT exported from the package root. Fetches a CRL from an
 * HTTP(S) URL via the injected `Fetcher`, parses `CertificateList`,
 * and returns normalized metadata. Signature verification happens in
 * Task 7 via `verifyCrl(parsed, issuerCert)` — kept separate so tests
 * can drive parsing and signature concerns independently.
 */
export class CrlFetcher {
    private readonly fetcher: Fetcher;
    private readonly cache: Cache | undefined;

    constructor(opts: CrlFetcherOptions = {}) {
        this.fetcher = opts.fetcher ?? globalThis.fetch.bind(globalThis);
        this.cache = opts.cache;
    }

    async fetchAndParse(url: string): Promise<ParsedCrl> {
        const response = await this.fetcher(url, { method: 'GET' });
        if (!response.ok) {
            throw new Error(`CRL fetch failed: HTTP ${response.status} for ${url}`);
        }
        const der = new Uint8Array(await response.arrayBuffer());
        const parsed = AsnConvert.parse(der, CertificateList);

        // `fetchAndParse` enforces RFC 5280 §5.1.2.5 — a CRL without
        // nextUpdate is not usable. The cache-hit path in
        // `fetchAndParseCached` deliberately skips this check: anything
        // that made it into the cache was valid when stored, and freshness
        // is enforced separately via `isStale`.
        if (!parsed.tbsCertList.nextUpdate) {
            throw new Error(`CRL missing nextUpdate — unsupported (RFC 5280 §5.1.2.5)`);
        }

        return normalizeCrl(parsed, der);
    }

    /**
     * Caching wrapper around `fetchAndParse`. On cache hit, re-parses the
     * stored DER bytes and returns a fresh `ParsedCrl` (parsing is idempotent
     * on DER). On miss, delegates to `fetchAndParse` and stores `parsed.der`
     * under key `crl:{url}` with `TTL = max(floor((nextUpdate - now) / 1000), 60)`
     * seconds — never less than 60s even if the CRL is already near/past
     * expiry, to avoid cache thrash while `isStale` handles the verdict.
     */
    async fetchAndParseCached(url: string, now: Date = new Date()): Promise<ParsedCrl> {
        const key = `crl:${url}`;
        if (this.cache) {
            const hit = await this.cache.get(key);
            if (hit) {
                const parsed = AsnConvert.parse(hit, CertificateList);
                return normalizeCrl(parsed, hit);
            }
        }
        const parsed = await this.fetchAndParse(url);
        if (this.cache) {
            const ttl = Math.max(
                Math.floor((parsed.nextUpdate.getTime() - now.getTime()) / 1000),
                60
            );
            await this.cache.set(key, parsed.der, ttl);
        }
        return parsed;
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

    /**
     * Look up a certificate serial number against the CRL's revokedCertificates
     * list. Returns `{ status: 'revoked', revokedAt }` when found, `{ status: 'good' }`
     * otherwise. Hex comparison is normalized via `normalizeHexUnsignedInt` on
     * both sides so that ASN.1 sign padding and input formatting differences
     * (case, leading zeros) don't yield false negatives.
     *
     * `revocationReason` is intentionally omitted in 0.5.0 — decoding the
     * optional CRLReason extension on each `RevokedCertificate` is non-blocking
     * for a verdict and can be added without breaking the return shape.
     */
    isRevoked(parsed: ParsedCrl, serialHex: string): CrlRevokedOutcome {
        const normalized = normalizeHexUnsignedInt(serialHex);
        for (const revoked of parsed.raw.tbsCertList.revokedCertificates ?? []) {
            const candidateHex = normalizeHexUnsignedInt(
                Buffer.from(revoked.userCertificate).toString('hex')
            );
            if (candidateHex === normalized) {
                return {
                    status: 'revoked',
                    revokedAt: revoked.revocationDate.getTime(),
                };
            }
        }
        return { status: 'good' };
    }

    /**
     * True when `now` is past the CRL's `nextUpdate` — the CA has published
     * a new CRL (or should have) and this one should not be relied on.
     * RFC 5280 §5.1.2.5.
     */
    isStale(parsed: ParsedCrl, now: Date = new Date()): boolean {
        return now.getTime() > parsed.nextUpdate.getTime();
    }
}

/**
 * Derive the `ParsedCrl` shape from a decoded `CertificateList` plus its
 * original DER bytes. Extracted so both `fetchAndParse` and the cache-hit
 * branch of `fetchAndParseCached` produce identical results — DRY.
 *
 * `nextUpdate` is assumed present here; callers are responsible for the
 * RFC 5280 §5.1.2.5 check before invoking (the cache-hit path intentionally
 * skips it, since cached entries were validated at store time).
 */
function normalizeCrl(parsed: CertificateList, der: Uint8Array): ParsedCrl {
    const thisUpdate = parsed.tbsCertList.thisUpdate.getTime();
    const nextUpdate = parsed.tbsCertList.nextUpdate!.getTime();
    const revokedSerialsHex =
        parsed.tbsCertList.revokedCertificates?.map((r) =>
            normalizeHexUnsignedInt(Buffer.from(r.userCertificate).toString('hex'))
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
 * Normalize a hex-encoded unsigned integer to canonical uppercase form
 * without the ASN.1-mandated leading 0x00 sign byte. Using `BigInt` strips
 * *only* the leading zeros that would make the value larger than itself —
 * so `00AF01` → `AF01` but `0B01` stays `B01` and `0A` stays `A`. The prior
 * `.replace(/^0+/, '')` over-stripped any run of leading zeros including
 * legitimate nibble-level zeros, yielding intermittent compare misses when
 * a serial happened to begin with `0x0X` for non-zero X.
 */
function normalizeHexUnsignedInt(hex: string): string {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length === 0) return '';
    return BigInt('0x' + clean).toString(16).toUpperCase();
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
