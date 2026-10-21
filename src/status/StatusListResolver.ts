import { compactVerify, decodeProtectedHeader, importX509 } from 'jose';

import { verifyCoseSign1 } from '../crypto/cose-sign1.js';
import { StatusListError } from '../errors.js';
import { createGuardedFetcher } from '../http/guarded-fetch.js';
import type { Cache } from '../trust/Cache.js';
import type { Fetcher } from '../trust/Fetcher.js';
import type { RevocationPolicy, TrustEvaluationResult } from '../trust/TrustEvaluator.js';
import type { TrustStore } from '../trust/TrustStore.js';

import {
    DEFAULT_MAX_STATUS_LIST_BYTES,
    decodeStatusList,
    readStatusValue,
    toTokenStatusType,
    type StatusListBits,
    type TokenStatusType,
} from './status-list.js';
import { STATUS_LIST_CWT_MEDIA_TYPE, decodeStatusListCwt } from './status-list-cwt.js';

/**
 * Status List Token format (§5): `'jwt'` (`statuslist+jwt`, referenced by the
 * SD-JWT VC `status` claim) or `'cwt'` (`statuslist+cwt`, referenced by the
 * mdoc MSO `status`, §6.3).
 */
export type StatusListTokenFormat = 'jwt' | 'cwt';

/** Which Status List Token format to fetch and verify. Default `'jwt'`. */
export interface StatusListFormatOptions {
    format?: StatusListTokenFormat;
}

/** JOSE `typ` of a Status List Token in JWT format (§5.1). */
export const STATUS_LIST_JWT_TYP = 'statuslist+jwt';
/** HTTP media type requested for, and served with, a JWT Status List Token (§8.1). */
export const STATUS_LIST_JWT_MEDIA_TYPE = 'application/statuslist+jwt';

const DEFAULT_ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'ES512'];

/** The `status.status_list` object of a Referenced Token (§6.2). */
export interface StatusListReference {
    /** Index of the credential in the list. Non-negative integer. */
    idx: number;
    /** URI of the Status List Token; MUST equal its `sub`. */
    uri: string;
}

/** A Status List Token whose signature, signer chain and claims have been verified. */
export interface VerifiedStatusList {
    uri: string;
    /** Format the token was fetched and verified in. */
    format: StatusListTokenFormat;
    bits: StatusListBits;
    /** Decompressed status bytes. Treat as read-only. */
    bytes: Uint8Array;
    /** Number of addressable entries. */
    size: number;
    issuedAt: Date;
    expiresAt?: Date;
    /** `ttl` claim as issued, in seconds. */
    ttlSeconds?: number;
    /** When this copy was fetched. */
    fetchedAt: Date;
    /** When the resolver will fetch a fresh copy (bounded `ttl`, never after `exp`). */
    cacheUntil: Date;
    /** Signer chain evaluation for the Status List Token. */
    trust: TrustEvaluationResult;
}

/** Status of one credential, read from a verified list. */
export interface StatusListLookup {
    status: TokenStatusType;
    /** Raw Status Type value (0x00 VALID, 0x01 INVALID, 0x02 SUSPENDED, …). */
    value: number;
    uri: string;
    idx: number;
    /** `true` when the list came from the resolver's cache rather than a fetch. */
    fromCache: boolean;
    list: Omit<VerifiedStatusList, 'bytes'>;
}

export interface StatusListResolverOptions {
    /**
     * Anchors for Status List Token signers. Keep this SEPARATE from the
     * credential-issuer trust store: in the EUDI ecosystem status-list signers
     * are published as their own services (TS 119 602 `SvcType/PID/Revocation`
     * in the PID-providers LoTE), not as issuance anchors. If an issuer signs
     * its status lists with its issuance chain, add that anchor here too
     * (e.g. via `CompositeTrustStore`).
     */
    trustStore: TrustStore;
    /**
     * HTTP transport. Defaults to `createGuardedFetcher()` — HTTPS only, no
     * private/loopback/metadata targets, bounded redirects, 15 s, 16 MiB. A
     * caller-supplied fetcher replaces those guards; wrap it with
     * `createGuardedFetcher({ fetch })` to keep them.
     */
    fetcher?: Fetcher;
    /** Clock for token time checks and cache expiry. Defaults to `() => new Date()`. */
    clock?: () => Date;
    /** Seconds of tolerance for `iat` / `nbf` / `exp` checks. Default 60. */
    clockSkewTolerance?: number;
    /**
     * Signature algorithms accepted for the Status List Token, by JOSE name
     * (the CWT format maps COSE -7/-35/-36 to ES256/ES384/ES512). Default
     * ES256/ES384/ES512.
     */
    allowedAlgorithms?: string[];
    /**
     * Revocation policy for the Status List Token's signer certificate chain
     * (OCSP/CRL). Default `'skip'`.
     */
    signerRevocationPolicy?: RevocationPolicy;
    /** Cache used by OCSP/CRL checks of the signer chain (not for Status Lists). */
    signerRevocationCache?: Cache;
    /**
     * Reject a Status List Token whose `iat` is older than this many seconds
     * (§8.3 step 4b local freshness policy). Default: no limit.
     */
    maxListAgeSeconds?: number;
    /** Cache lifetime when the token carries no `ttl`. Default 300 s. */
    defaultTtlSeconds?: number;
    /**
     * Lower bound applied to `ttl`, so an issuer cannot force a fetch on every
     * presentation (§11.5, ARF VCR_15). Default 60 s. `exp` still wins.
     */
    minTtlSeconds?: number;
    /** Upper bound applied to `ttl`. Default 86 400 s (24 h). */
    maxTtlSeconds?: number;
    /** Most Status Lists kept in memory (LRU). Default 100. */
    maxCacheEntries?: number;
    /** Ceiling for one decompressed list, in bytes. Default 16 MiB. */
    maxListBytes?: number;
    /**
     * Accept a Status List Token whose `x5c[0]` signer certificate is itself a
     * configured anchor (a pinned signer). By default the anchor must be a CA
     * and must NOT appear anywhere in `x5c` (HAIP 1.0 / TS 119 472-2: the
     * trust anchor is not carried in `x5c`). Default `false`.
     */
    acceptPinnedSigner?: boolean;
}

interface CacheEntry {
    list: VerifiedStatusList;
}

/**
 * Resolves and verifies IETF Token Status Lists (draft-ietf-oauth-status-list-21)
 * in JWT (§5.1) and CWT (§5.2) format, and answers "what is the status of
 * entry `idx`?".
 *
 * Each Status List Token is:
 *   1. fetched with `Accept: application/statuslist+jwt` (or `+cwt`) through
 *      the SSRF-guarded fetcher;
 *   2. checked to be a compact JWS with `typ: statuslist+jwt` (or a COSE_Sign1
 *      with protected `typ` (16) `application/statuslist+cwt`) and an allowed
 *      `alg`, signed by `x5c[0]` (or `x5chain[0]`, label 33), whose chain
 *      validates against {@link StatusListResolverOptions.trustStore}
 *      (anchors never taken from the token, and not allowed inside it);
 *   3. checked for `sub === uri`, a sane `iat`, an unexpired `exp`, `nbf`, a
 *      positive `ttl`, and a well-formed `status_list` (CWT claims 2, 6, 4, 5,
 *      65534 and 65533);
 *   4. decompressed (bounded) and cached by format and `uri` until the bounded
 *      `ttl` elapses or `exp` arrives, whichever is first.
 *
 * Concurrent lookups of the same format and `uri` share one fetch. One resolver instance
 * is meant to live for the process so its cache is reused across
 * presentations (ARF VCR_13–VCR_15); call {@link prefetch} to warm it out of
 * band.
 */
export class StatusListResolver {
    private readonly trustStore: TrustStore;
    private readonly fetcher: Fetcher;
    private readonly clock: () => Date;
    private readonly skewMs: number;
    private readonly allowedAlgorithms: string[];
    private readonly opts: StatusListResolverOptions;
    private readonly cache = new Map<string, CacheEntry>();
    private readonly inFlight = new Map<string, Promise<VerifiedStatusList>>();

    constructor(options: StatusListResolverOptions) {
        if (!options || !options.trustStore) {
            throw new StatusListError('configuration', 'StatusListResolver requires a trustStore for list signers');
        }
        this.opts = options;
        this.trustStore = options.trustStore;
        this.fetcher = options.fetcher ?? createGuardedFetcher();
        this.clock = options.clock ?? (() => new Date());
        this.skewMs = (options.clockSkewTolerance ?? 60) * 1000;
        this.allowedAlgorithms = options.allowedAlgorithms ?? DEFAULT_ALLOWED_ALGORITHMS;
    }

    /**
     * Status of the credential referenced by `reference`. Throws
     * {@link StatusListError} when no statement can be made (fetch, signature,
     * trust, claims) or when `idx` is out of range.
     */
    async resolve(reference: StatusListReference, options: StatusListFormatOptions = {}): Promise<StatusListLookup> {
        const format = validateFormat(options.format);
        const ref = validateReference(reference);
        const { list, fromCache } = await this.getList(ref.uri, format);
        const value = readStatusValue(list, ref.idx, ref.uri);
        const { bytes, ...meta } = list;
        void bytes;
        return { status: toTokenStatusType(value), value, uri: ref.uri, idx: ref.idx, fromCache, list: meta };
    }

    /** The verified Status List at `uri`, from cache when still fresh. */
    async getStatusList(uri: string, options: StatusListFormatOptions = {}): Promise<VerifiedStatusList> {
        return (await this.getList(validateUri(uri), validateFormat(options.format))).list;
    }

    /** Fetches `uri` now and replaces any cached copy (of the same format). */
    async prefetch(uri: string, options: StatusListFormatOptions = {}): Promise<VerifiedStatusList> {
        const checked = validateUri(uri);
        const format = validateFormat(options.format);
        this.cache.delete(cacheKey(format, checked));
        return (await this.getList(checked, format)).list;
    }

    /** Drops every cached Status List. */
    clearCache(): void {
        this.cache.clear();
    }

    private async getList(
        uri: string,
        format: StatusListTokenFormat,
    ): Promise<{ list: VerifiedStatusList; fromCache: boolean }> {
        // Keyed by format too: a JWT and a CWT served at the same uri are
        // separate tokens, each verified in the format it was fetched in.
        const key = cacheKey(format, uri);
        const now = this.clock();
        const cached = this.cache.get(key);
        if (cached) {
            if (now.getTime() < cached.list.cacheUntil.getTime()) {
                // refresh LRU position
                this.cache.delete(key);
                this.cache.set(key, cached);
                return { list: cached.list, fromCache: true };
            }
            this.cache.delete(key);
        }

        let pending = this.inFlight.get(key);
        if (!pending) {
            pending = (format === 'cwt' ? this.fetchAndVerifyCwt(uri) : this.fetchAndVerify(uri)).finally(() =>
                this.inFlight.delete(key),
            );
            this.inFlight.set(key, pending);
        }
        const list = await pending;
        if (list.cacheUntil.getTime() > this.clock().getTime()) this.store(key, list);
        return { list, fromCache: false };
    }

    private store(key: string, list: VerifiedStatusList): void {
        this.cache.delete(key);
        this.cache.set(key, { list });
        const max = this.opts.maxCacheEntries ?? 100;
        while (this.cache.size > max) {
            const oldest = this.cache.keys().next().value;
            if (oldest === undefined) break;
            this.cache.delete(oldest);
        }
    }

    private async fetchAndVerify(uri: string): Promise<VerifiedStatusList> {
        const jws = await this.fetchToken(uri);
        const fetchedAt = this.clock();

        // --- Header: explicit typing and algorithm, before any crypto -------
        let header: ReturnType<typeof decodeProtectedHeader>;
        try {
            header = decodeProtectedHeader(jws);
        } catch (err) {
            throw new StatusListError('invalid_token', `Status List Token from ${uri} is not a JWS`, {
                uri,
                cause: asError(err),
            });
        }
        if (normalizeTyp(header.typ) !== STATUS_LIST_JWT_TYP) {
            throw new StatusListError(
                'invalid_token',
                `Status List Token typ must be '${STATUS_LIST_JWT_TYP}' (got ${JSON.stringify(header.typ ?? null)})`,
                { uri },
            );
        }
        const alg = header.alg;
        if (typeof alg !== 'string' || !this.allowedAlgorithms.includes(alg)) {
            throw new StatusListError('invalid_token', `Status List Token alg ${String(alg)} is not allowed`, { uri });
        }
        const x5c = header.x5c;
        if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((c) => typeof c === 'string' && c.length > 0)) {
            throw new StatusListError('invalid_token', 'Status List Token must carry an x5c certificate chain', { uri });
        }
        let chainDer: Uint8Array[];
        try {
            chainDer = x5c.map((c) => base64ToBytes(c));
        } catch (err) {
            throw new StatusListError('invalid_token', 'Status List Token x5c entry is not valid base64', {
                uri,
                cause: asError(err),
            });
        }

        // --- Signature with the x5c signer key ------------------------------
        let payloadBytes: Uint8Array;
        try {
            const key = await importX509(derToPem(x5c[0]), alg);
            payloadBytes = (await compactVerify(jws, key, { algorithms: this.allowedAlgorithms })).payload;
        } catch (err) {
            throw new StatusListError('signature_invalid', `Status List Token signature from ${uri} does not verify`, {
                uri,
                cause: asError(err),
            });
        }

        let payload: Record<string, unknown>;
        try {
            const parsed: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
            payload = parsed as Record<string, unknown>;
        } catch (err) {
            throw new StatusListError('invalid_token', 'Status List Token payload is not a JSON object', {
                uri,
                cause: asError(err),
            });
        }

        // --- Signer chain against the status-list anchors -------------------
        // Before the claim checks, so a token from an untrusted signer is
        // reported as such whatever its claims say.
        const iat = payload['iat'];
        const trust = await this.evaluateSigner(chainDer, uri, isNumericDate(iat) ? new Date(iat * 1000) : undefined);

        // --- Claims (§5.1, §8.3 step 4) -------------------------------------
        const claims = this.checkClaims(payload, uri, fetchedAt);

        const decoded = await decodeStatusList(payload['status_list'], {
            uri,
            maxBytes: this.opts.maxListBytes ?? DEFAULT_MAX_STATUS_LIST_BYTES,
        });

        return this.buildVerifiedList(uri, 'jwt', decoded, claims, fetchedAt, trust);
    }

    /**
     * CWT Status List Token (§5.2): COSE_Sign1, protected `typ` (16)
     * `application/statuslist+cwt`, signer in `x5chain` (33), claims `sub` (2),
     * `iat` (6), `exp` (4), `nbf` (5), `ttl` (65534) and `status_list` (65533)
     * whose `lst` is a byte string. Same order of checks as the JWT path.
     */
    private async fetchAndVerifyCwt(uri: string): Promise<VerifiedStatusList> {
        const bytes = await this.fetchCwtToken(uri);
        const fetchedAt = this.clock();

        // --- Structure, typ, alg, x5chain — before any crypto -------------
        const token = decodeStatusListCwt(bytes, uri);
        if (!this.allowedAlgorithms.includes(token.alg)) {
            throw new StatusListError('invalid_token', `Status List Token alg ${token.alg} is not allowed`, { uri });
        }

        // --- Signature with the x5chain signer key -------------------------
        try {
            const key = await importX509(derToPem(bytesToBase64(token.x5chain[0])), token.alg);
            await verifyCoseSign1(
                {
                    protectedHeaderBytes: token.protectedHeaderBytes,
                    protectedHeader: token.protectedHeader,
                    unprotectedHeader: token.unprotectedHeader,
                    payload: token.payload,
                    signature: token.signature,
                    x5chain: token.x5chain,
                    alg: token.alg,
                },
                key as CryptoKey,
                this.allowedAlgorithms,
            );
        } catch (err) {
            throw new StatusListError('signature_invalid', `Status List Token signature from ${uri} does not verify`, {
                uri,
                cause: asError(err),
            });
        }

        // --- Signer chain, then claims (same rules as the JWT path) --------
        const iat = token.claims['iat'];
        const trust = await this.evaluateSigner(token.x5chain, uri, isNumericDate(iat) ? new Date(iat * 1000) : undefined);
        const claims = this.checkClaims(token.claims, uri, fetchedAt);

        const decoded = await decodeStatusList(token.claims['status_list'], {
            uri,
            maxBytes: this.opts.maxListBytes ?? DEFAULT_MAX_STATUS_LIST_BYTES,
            lstEncoding: 'bytes',
        });
        return this.buildVerifiedList(uri, 'cwt', decoded, claims, fetchedAt, trust);
    }

    private buildVerifiedList(
        uri: string,
        format: StatusListTokenFormat,
        decoded: { bits: StatusListBits; bytes: Uint8Array; size: number },
        claims: { issuedAt: Date; expiresAt?: Date; ttlSeconds?: number },
        fetchedAt: Date,
        trust: TrustEvaluationResult,
    ): VerifiedStatusList {
        return {
            uri,
            format,
            bits: decoded.bits,
            bytes: decoded.bytes,
            size: decoded.size,
            issuedAt: claims.issuedAt,
            ...(claims.expiresAt ? { expiresAt: claims.expiresAt } : {}),
            ...(claims.ttlSeconds !== undefined ? { ttlSeconds: claims.ttlSeconds } : {}),
            fetchedAt,
            cacheUntil: this.cacheUntil(fetchedAt, claims.ttlSeconds, claims.expiresAt),
            trust,
        };
    }

    private async fetchResponse(uri: string, accept: string): Promise<Response> {
        let response: Response;
        try {
            response = await this.fetcher(uri, { method: 'GET', headers: { Accept: accept } });
        } catch (err) {
            throw new StatusListError('fetch_failed', `Status List Token fetch failed for ${uri}`, {
                uri,
                cause: asError(err),
            });
        }
        if (!response.ok) {
            await response.body?.cancel().catch(() => {});
            throw new StatusListError('fetch_failed', `Status List Token fetch failed: HTTP ${response.status} for ${uri}`, {
                uri,
            });
        }
        return response;
    }

    private async fetchCwtToken(uri: string): Promise<Uint8Array> {
        const response = await this.fetchResponse(uri, STATUS_LIST_CWT_MEDIA_TYPE);
        // As for JWT, the Content-Type is not enforced: the protected COSE
        // `typ` is the binding type assertion.
        try {
            return new Uint8Array(await response.arrayBuffer());
        } catch (err) {
            throw new StatusListError('fetch_failed', `Status List Token body could not be read from ${uri}`, {
                uri,
                cause: asError(err),
            });
        }
    }

    private async fetchToken(uri: string): Promise<string> {
        const response = await this.fetchResponse(uri, STATUS_LIST_JWT_MEDIA_TYPE);
        // The Content-Type is not enforced: the JOSE `typ` check below is the
        // binding type assertion, and servers mislabel tokens often enough
        // (`application/jwt`) that rejecting on it would only cost availability.
        let body: string;
        try {
            body = (await response.text()).trim();
        } catch (err) {
            throw new StatusListError('fetch_failed', `Status List Token body could not be read from ${uri}`, {
                uri,
                cause: asError(err),
            });
        }
        if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(body)) {
            throw new StatusListError('invalid_token', `Status List Token from ${uri} is not a compact JWS`, { uri });
        }
        return body;
    }

    private checkClaims(
        payload: Record<string, unknown>,
        uri: string,
        now: Date,
    ): { issuedAt: Date; expiresAt?: Date; ttlSeconds?: number } {
        const nowMs = now.getTime();
        const sub = payload['sub'];
        if (typeof sub !== 'string') {
            throw new StatusListError('invalid_token', 'Status List Token is missing the sub claim', { uri });
        }
        if (sub !== uri) {
            throw new StatusListError(
                'subject_mismatch',
                `Status List Token sub ${JSON.stringify(sub)} does not match the referenced uri`,
                { uri },
            );
        }

        const iat = payload['iat'];
        if (!isNumericDate(iat)) {
            throw new StatusListError('invalid_token', 'Status List Token iat must be a NumericDate', { uri });
        }
        const issuedAt = new Date(iat * 1000);
        if (issuedAt.getTime() > nowMs + this.skewMs) {
            throw new StatusListError('not_fresh', `Status List Token iat ${issuedAt.toISOString()} is in the future`, {
                uri,
            });
        }
        const maxAge = this.opts.maxListAgeSeconds;
        if (maxAge !== undefined && nowMs - issuedAt.getTime() > maxAge * 1000 + this.skewMs) {
            throw new StatusListError(
                'not_fresh',
                `Status List Token issued ${issuedAt.toISOString()} is older than ${maxAge} s`,
                { uri },
            );
        }

        const nbf = payload['nbf'];
        if (nbf !== undefined) {
            if (!isNumericDate(nbf)) {
                throw new StatusListError('invalid_token', 'Status List Token nbf must be a NumericDate', { uri });
            }
            if (nbf * 1000 > nowMs + this.skewMs) {
                throw new StatusListError('not_fresh', 'Status List Token is not yet valid (nbf)', { uri });
            }
        }

        let expiresAt: Date | undefined;
        const exp = payload['exp'];
        if (exp !== undefined) {
            if (!isNumericDate(exp)) {
                throw new StatusListError('invalid_token', 'Status List Token exp must be a NumericDate', { uri });
            }
            expiresAt = new Date(exp * 1000);
            if (expiresAt.getTime() <= nowMs - this.skewMs) {
                throw new StatusListError('expired', `Status List Token expired at ${expiresAt.toISOString()}`, { uri });
            }
        }

        let ttlSeconds: number | undefined;
        const ttl = payload['ttl'];
        if (ttl !== undefined) {
            if (typeof ttl !== 'number' || !Number.isFinite(ttl) || ttl <= 0) {
                throw new StatusListError('invalid_token', 'Status List Token ttl must be a positive number', { uri });
            }
            ttlSeconds = ttl;
        }

        return { issuedAt, ...(expiresAt ? { expiresAt } : {}), ...(ttlSeconds !== undefined ? { ttlSeconds } : {}) };
    }

    private async evaluateSigner(
        chainDer: Uint8Array[],
        uri: string,
        issuedAt: Date | undefined,
    ): Promise<TrustEvaluationResult> {
        const { evaluateCredentialIssuer } = await import('../trust/TrustEvaluator.js');
        let trust: TrustEvaluationResult;
        try {
            trust = await evaluateCredentialIssuer({
                chain: chainDer,
                profile: 'generic',
                issuedAt,
                trustStore: this.trustStore,
                revocationPolicy: this.opts.signerRevocationPolicy ?? 'skip',
                fetcher: this.opts.fetcher,
                cache: this.opts.signerRevocationCache,
                clockSkewTolerance: this.opts.clockSkewTolerance,
            });
        } catch (err) {
            throw new StatusListError(
                'untrusted_signer',
                `Status List Token signer for ${uri} is not trusted: ${asError(err).message}`,
                { uri, cause: asError(err) },
            );
        }

        const anchorDer = new Uint8Array(trust.anchor.certificate.rawData);
        const anchorPosition = chainDer.findIndex((der) => bytesEqual(der, anchorDer));
        if (anchorPosition > 0 || (anchorPosition === 0 && this.opts.acceptPinnedSigner !== true)) {
            throw new StatusListError(
                'untrusted_signer',
                `Status List Token x5c must not include the trust anchor (found at position ${anchorPosition})`,
                { uri },
            );
        }
        return trust;
    }

    private cacheUntil(fetchedAt: Date, ttlSeconds: number | undefined, expiresAt: Date | undefined): Date {
        const min = this.opts.minTtlSeconds ?? 60;
        const max = this.opts.maxTtlSeconds ?? 86_400;
        const ttl = Math.min(Math.max(ttlSeconds ?? this.opts.defaultTtlSeconds ?? 300, min), max);
        const byTtl = fetchedAt.getTime() + ttl * 1000;
        return new Date(expiresAt ? Math.min(byTtl, expiresAt.getTime()) : byTtl);
    }
}

function cacheKey(format: StatusListTokenFormat, uri: string): string {
    return `${format} ${uri}`;
}

function validateFormat(format: unknown): StatusListTokenFormat {
    if (format === undefined || format === 'jwt') return 'jwt';
    if (format === 'cwt') return 'cwt';
    throw new StatusListError('configuration', `Unknown Status List Token format ${JSON.stringify(format)}`);
}

function validateUri(uri: unknown): string {
    if (typeof uri !== 'string' || uri.length === 0) {
        throw new StatusListError('invalid_reference', 'status_list.uri must be a non-empty string');
    }
    try {
        new URL(uri);
    } catch (err) {
        throw new StatusListError('invalid_reference', 'status_list.uri must be an absolute URI', {
            uri,
            cause: asError(err),
        });
    }
    return uri;
}

function validateReference(reference: unknown): StatusListReference {
    if (!reference || typeof reference !== 'object' || Array.isArray(reference)) {
        throw new StatusListError('invalid_reference', 'status_list must be a JSON object');
    }
    const { idx, uri } = reference as Record<string, unknown>;
    const checkedUri = validateUri(uri);
    if (typeof idx !== 'number' || !Number.isSafeInteger(idx) || idx < 0) {
        throw new StatusListError('invalid_reference', 'status_list.idx must be a non-negative integer', {
            uri: checkedUri,
        });
    }
    return { idx, uri: checkedUri };
}

function isNumericDate(value: unknown): value is number {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

/** RFC 7515 §4.1.9: the `application/` prefix may be omitted; compare case-insensitively. */
function normalizeTyp(typ: unknown): string | undefined {
    if (typeof typ !== 'string') return undefined;
    const lower = typ.toLowerCase();
    return lower.startsWith('application/') ? lower.slice('application/'.length) : lower;
}

function asError(err: unknown): Error {
    return err instanceof Error ? err : new Error(String(err));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

/** Strict standard-base64 decode (x5c entries are base64, not base64url — RFC 7515 §4.1.6). */
function base64ToBytes(b64: string): Uint8Array {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4 !== 0) {
        throw new Error('invalid base64');
    }
    const binary = globalThis.atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return globalThis.btoa(binary);
}

function derToPem(base64Der: string): string {
    const lines = base64Der.match(/.{1,64}/g) ?? [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}
